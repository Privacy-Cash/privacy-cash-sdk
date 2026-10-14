import { afterEach, describe, expect, it, vi } from 'vitest';
import { Keypair, TransactionMessage, VersionedTransaction } from '@solana/web3.js';
import bs58 from 'bs58';
import { submitRelayedTransaction, TransactionExecutionError, TransactionStatusUnknownError, waitForIndexedOutput } from '../src/utils/relayTransaction.js';

const owner = Keypair.generate();
const transaction = new VersionedTransaction(new TransactionMessage({
    payerKey: owner.publicKey,
    recentBlockhash: bs58.encode(new Uint8Array(32).fill(1)),
    instructions: []
}).compileToV0Message());
transaction.sign([owner]);
const signature = bs58.encode(transaction.signatures[0]);
const signedTransaction = Buffer.from(transaction.serialize()).toString('base64');

function connection(status: object | null = { confirmationStatus: 'confirmed', err: null }) {
    return { getSignatureStatuses: vi.fn().mockResolvedValue({ value: [status] }) } as any;
}

function response(status: number, body: object) {
    return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body), json: async () => body } as Response;
}

afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
});

describe.each(['/deposit', '/deposit/spl'])('%s', path => {
    it('keeps the successful response shape without another RPC confirmation', async () => {
        const rpc = connection();
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, { success: true, signature })));
        await expect(submitRelayedTransaction({ path, body: {}, connection: rpc, signedTransaction }))
            .resolves.toEqual({ signature, referralRecorded: undefined });
        expect(rpc.getSignatureStatuses).not.toHaveBeenCalled();
    });

    it('resolves a confirmed signed transaction after an HTTP 500', async () => {
        const rpc = connection();
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(500, { error: 'timeout' })));
        await expect(submitRelayedTransaction({ path, body: {}, connection: rpc, signedTransaction }))
            .resolves.toMatchObject({ signature });
        expect(rpc.getSignatureStatuses).toHaveBeenCalledWith([signature], { searchTransactionHistory: true });
    });

    it('reports an explicit on-chain failure', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(500, {})));
        await expect(submitRelayedTransaction({ path, body: {}, connection: connection({ confirmationStatus: 'confirmed', err: { InstructionError: [0, 'InvalidArgument'] } }), signedTransaction }))
            .rejects.toBeInstanceOf(TransactionExecutionError);
    });

    it('checks the signed signature when the HTTP body is malformed', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 502, text: async () => 'bad gateway' }));
        await expect(submitRelayedTransaction({ path, body: {}, connection: connection(), signedTransaction }))
            .resolves.toMatchObject({ signature });
    });
});

describe.each(['/withdraw', '/withdraw/spl'])('%s', path => {
    it('recovers from a relayer error that includes a confirmed signature', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(503, { code: 'TRANSACTION_STATUS_UNKNOWN', signature })));
        await expect(submitRelayedTransaction({ path, body: {}, connection: connection() }))
            .resolves.toMatchObject({ signature });
    });

    it('reports an ambiguous transport failure without claiming failure', async () => {
        vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('connection reset')));
        await expect(submitRelayedTransaction({ path, body: {}, connection: connection() }))
            .rejects.toMatchObject({ code: 'TRANSACTION_STATUS_UNKNOWN', signature: undefined });
    });
});

it('returns indexingPending when chain is confirmed but the indexer has not caught up', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, { exists: false })));
    const pending = waitForIndexedOutput(connection(), signature, 'abc');
    await vi.advanceTimersByTimeAsync(22_000);
    await expect(pending).resolves.toBe(false);
});

it('accepts an indexed output without an extra RPC confirmation', async () => {
    vi.useFakeTimers();
    const rpc = connection();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(200, { exists: true })));
    const pending = waitForIndexedOutput(rpc, signature, 'abc');
    await vi.advanceTimersByTimeAsync(2000);
    await expect(pending).resolves.toBe(true);
    expect(rpc.getSignatureStatuses).not.toHaveBeenCalled();
});

it('keeps a missing on-chain status ambiguous after the status deadline', async () => {
    vi.useFakeTimers();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(500, {})));
    const pending = expect(submitRelayedTransaction({ path: '/deposit', body: {}, connection: connection(null), signedTransaction }))
        .rejects.toBeInstanceOf(TransactionStatusUnknownError);
    await vi.advanceTimersByTimeAsync(31_500);
    await pending;
});
