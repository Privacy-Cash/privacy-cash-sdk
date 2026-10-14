import { Connection, VersionedTransaction } from '@solana/web3.js';
import bs58 from 'bs58';
import { Buffer } from 'buffer';
import { RELAYER_API_URL } from './constants.js';

export class TransactionStatusUnknownError extends Error {
    readonly code = 'TRANSACTION_STATUS_UNKNOWN';

    constructor(readonly signature?: string, cause?: unknown) {
        super(signature
            ? `Transaction ${signature} may have been submitted. Check its status before retrying.`
            : 'Transaction may have been submitted. Check your balance before retrying.');
        this.name = 'TransactionStatusUnknownError';
        if (cause !== undefined) (this as Error & { cause?: unknown }).cause = cause;
    }
}

export class TransactionExecutionError extends Error {
    readonly code = 'TRANSACTION_FAILED';

    constructor(readonly signature: string, error: unknown) {
        super(`Transaction ${signature} failed on-chain: ${JSON.stringify(error)}`);
        this.name = 'TransactionExecutionError';
    }
}

type RelayResponse = {
    success?: boolean;
    signature?: string;
    referralRecorded?: boolean;
    error?: string;
    code?: string;
};

function signedSignature(serializedTransaction: string): string {
    const transaction = VersionedTransaction.deserialize(Buffer.from(serializedTransaction, 'base64'));
    const signature = transaction.signatures[0];
    if (!signature || signature.every(byte => byte === 0)) throw new Error('Transaction is not signed');
    return bs58.encode(signature);
}

async function chainStatus(connection: Connection, signature: string): Promise<'confirmed' | 'pending'> {
    const response = await connection.getSignatureStatuses([signature], { searchTransactionHistory: true });
    const status = response.value[0];
    if (status?.err) throw new TransactionExecutionError(signature, status.err);
    return status?.confirmationStatus === 'confirmed' || status?.confirmationStatus === 'finalized'
        ? 'confirmed' : 'pending';
}

async function resolveAmbiguousResponse(connection: Connection, signature: string, cause: unknown): Promise<string> {
    const deadline = Date.now() + 30_000;
    do {
        try {
            if (await chainStatus(connection, signature) === 'confirmed') return signature;
        } catch (error) {
            if (error instanceof TransactionExecutionError) throw error;
        }
        if (Date.now() >= deadline) break;
        await new Promise(resolve => setTimeout(resolve, 1500));
    } while (true);
    throw new TransactionStatusUnknownError(signature, cause);
}

export async function submitRelayedTransaction({ path, body, connection, signedTransaction }: {
    path: string;
    body: object;
    connection: Connection;
    signedTransaction?: string;
}): Promise<{ signature: string; referralRecorded?: boolean }> {
    const localSignature = signedTransaction ? signedSignature(signedTransaction) : undefined;
    let response: Response;
    try {
        response = await fetch(`${RELAYER_API_URL}${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
    } catch (error) {
        if (localSignature) return { signature: await resolveAmbiguousResponse(connection, localSignature, error) };
        throw new TransactionStatusUnknownError(undefined, error);
    }

    let data: RelayResponse = {};
    try {
        const parsed: unknown = JSON.parse(await response.text());
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) data = parsed as RelayResponse;
    } catch {
        // A malformed response cannot tell us whether a submitted transaction landed.
    }

    if (response.ok && data.success === true && typeof data.signature === 'string') {
        if (!localSignature || data.signature === localSignature) {
            return { signature: data.signature, referralRecorded: data.referralRecorded };
        }
    }

    const signature = localSignature || (typeof data.signature === 'string' ? data.signature : undefined);
    const reason = new Error(data.error || `Relay request failed (${response.status})`);
    if (signature) {
        return { signature: await resolveAmbiguousResponse(connection, signature, reason), referralRecorded: data.referralRecorded };
    }
    if (response.status >= 500 || response.ok || data.code === 'TRANSACTION_STATUS_UNKNOWN') {
        throw new TransactionStatusUnknownError(undefined, reason);
    }
    throw reason;
}

export async function waitForIndexedOutput(connection: Connection, signature: string, encryptedOutput: string, token?: string): Promise<boolean> {
    const url = `${RELAYER_API_URL}/utxos/check/${encryptedOutput}${token ? `?token=${encodeURIComponent(token)}` : ''}`;
    for (let attempt = 0; attempt < 11; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        try {
            const response = await fetch(url);
            if (response.ok && (await response.json() as { exists?: boolean }).exists) return true;
        } catch {
            // An indexer read error is inconclusive; keep checking until the deadline.
        }
    }
    try {
        if (await chainStatus(connection, signature) === 'confirmed') return false;
    } catch (error) {
        if (error instanceof TransactionExecutionError) throw error;
    }
    throw new TransactionStatusUnknownError(signature);
}
