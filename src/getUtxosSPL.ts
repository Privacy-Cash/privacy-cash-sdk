import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey } from '@solana/web3.js';
import BN from 'bn.js';
import { Keypair as UtxoKeypair } from './models/keypair.js';
import { Utxo } from './models/utxo.js';
import { EncryptionService } from './utils/encryption.js';
import { WasmFactory } from '@lightprotocol/hasher.rs';
//@ts-ignore
import * as ffjavascript from 'ffjavascript';
import { FETCH_UTXOS_GROUP_SIZE, RELAYER_API_URL, LSK_ENCRYPTED_OUTPUTS, LSK_FETCH_OFFSET, PROGRAM_ID } from './utils/constants.js';
import { logger } from './utils/logger.js';
import { getAssociatedTokenAddress } from '@solana/spl-token';

// Use type assertion for the utility functions (same pattern as in get_verification_keys.ts)
const utils = ffjavascript.utils as any;
const { unstringifyBigInts, leInt2Buff } = utils;

/**
 * Interface for the UTXO data returned from the API
 */
interface ApiUtxo {
    commitment: string;
    encrypted_output: string; // Hex-encoded encrypted UTXO data
    index: number;
    nullifier?: string; // Optional, might not be present for all UTXOs
}

/**
 * Interface for the API response format that includes count and encrypted_outputs
 */
interface ApiResponse {
    count: number;
    encrypted_outputs: string[];
}

function sleep(ms: number): Promise<string> {
    return new Promise(resolve => setTimeout(() => {
        resolve('ok')
    }, ms))
}

export function localstorageKey(key: PublicKey) {
    return PROGRAM_ID.toString().substring(0, 6) + key.toString()
}

type Utxos = { [k: string]: Utxo[] }

let getMyUtxosPromise: Promise<Utxo[]> | null = null
let roundStartIndex = 0
let decryptionTaskFinished = 0;
/**
 * Fetch and decrypt all UTXOs for a user
 * @param signed The user's signature 
 * @param connection Solana connection to fetch on-chain commitment accounts
 * @param setStatus A global state updator. Set live status message showing on webpage
 * @returns Array of decrypted UTXOs that belong to the user
 */

export async function getUtxosSPL({ publicKey, connection, encryptionService, storage, mintAddress, abortSignal, offset }: {
    publicKey: PublicKey,
    connection: Connection,
    encryptionService: EncryptionService,
    storage: Storage,
    mintAddress: PublicKey,
    abortSignal?: AbortSignal
    offset?: number
}): Promise<Utxo[]> {
    let valid_utxos: Utxo[] = []
    let valid_strings: string[] = []
    let history_indexes: number[] = []
    let publicKey_ata: PublicKey
    try {
        publicKey_ata = await getAssociatedTokenAddress(
            mintAddress,
            publicKey
        );
        let offsetStr = storage.getItem(LSK_FETCH_OFFSET + localstorageKey(publicKey_ata))
        if (offsetStr) {
            roundStartIndex = Number(offsetStr)
        } else {
            roundStartIndex = 0
        }
        decryptionTaskFinished = 0
        if (!offset) {
            offset = 0
        }
        roundStartIndex = Math.max(offset, roundStartIndex)
        while (true) {
            if (abortSignal?.aborted) {
                throw new Error('aborted')
            }
            let offsetStr = storage.getItem(LSK_FETCH_OFFSET + localstorageKey(publicKey_ata))
            let fetch_utxo_offset = offsetStr ? Number(offsetStr) : 0
            if (offset) {
                fetch_utxo_offset = Math.max(offset, fetch_utxo_offset)
            }
            let fetch_utxo_end = fetch_utxo_offset + FETCH_UTXOS_GROUP_SIZE
            let fetch_utxo_url = `${RELAYER_API_URL}/utxos/range?token=usdc&start=${fetch_utxo_offset}&end=${fetch_utxo_end}`
            let fetched = await fetchUserUtxos({ publicKey, connection, url: fetch_utxo_url, encryptionService, storage, publicKey_ata, initOffset: offset })
            let am = 0

            const nonZeroUtxos: Utxo[] = [];
            const nonZeroEncrypted: any[] = [];
            for (let [k, utxo] of fetched.utxos.entries()) {
                history_indexes.push(utxo.index)
                if (utxo.amount.toNumber() > 0) {
                    nonZeroUtxos.push(utxo);
                    nonZeroEncrypted.push(fetched.encryptedOutputs[k]);
                }
            }
            if (nonZeroUtxos.length > 0) {
                const spentFlags = await areUtxosSpent(connection, nonZeroUtxos);
                for (let i = 0; i < nonZeroUtxos.length; i++) {
                    if (!spentFlags[i]) {
                        logger.debug(`found unspent encrypted_output ${nonZeroEncrypted[i]}`)
                        am += nonZeroUtxos[i].amount.toNumber();
                        valid_utxos.push(nonZeroUtxos[i]);
                        valid_strings.push(nonZeroEncrypted[i]);
                    }
                }
            }
            storage.setItem(LSK_FETCH_OFFSET + localstorageKey(publicKey_ata), (fetch_utxo_offset + fetched.len).toString())
            if (!fetched.hasMore) {
                break
            }
            await sleep(100)
        }
    } catch (e: any) {
        throw e
    } finally {
        getMyUtxosPromise = null
    }
    // get history index
    let historyKey = 'tradeHistory' + localstorageKey(publicKey_ata)
    let rec = storage.getItem(historyKey)
    let recIndexes: number[] = []
    if (rec?.length) {
        recIndexes = rec.split(',').map(n => Number(n))
    }
    if (recIndexes.length) {
        history_indexes = [...history_indexes, ...recIndexes]
    }
    let unique_history_indexes = Array.from(new Set(history_indexes));
    let top20 = unique_history_indexes.sort((a, b) => b - a).slice(0, 20);
    if (top20.length) {
        storage.setItem(historyKey, top20.join(','))
    }
    // store valid strings
    logger.debug(`valid_strings len before set: ${valid_strings.length}`)
    valid_strings = [...new Set(valid_strings)];
    logger.debug(`valid_strings len after set: ${valid_strings.length}`)
    storage.setItem(LSK_ENCRYPTED_OUTPUTS + localstorageKey(publicKey_ata), JSON.stringify(valid_strings))
    // reorgnize
    return valid_utxos.filter(u => u.mintAddress == mintAddress.toString())
}

async function fetchUserUtxos({ publicKey, connection, url, storage, encryptionService, publicKey_ata, initOffset }: {
    publicKey: PublicKey,
    connection: Connection,
    url: string,
    encryptionService: EncryptionService,
    storage: Storage,
    publicKey_ata: PublicKey
    initOffset: number
}): Promise<{
    encryptedOutputs: string[],
    utxos: Utxo[],
    hasMore: boolean,
    len: number
}> {
    const lightWasm = await WasmFactory.getInstance();

    // Derive the UTXO keypair from the wallet keypair
    const utxoPrivateKey = encryptionService.deriveUtxoPrivateKey();
    const utxoKeypair = new UtxoKeypair(utxoPrivateKey, lightWasm);


    // Fetch all UTXOs from the API
    let encryptedOutputs: string[] = [];
    logger.debug('fetching utxo data', url)
    let res = await fetch(url)
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    const data: any = await res.json()
    logger.debug('got utxo data')
    if (!data) {
        throw new Error('API returned empty data')
    } else if (Array.isArray(data)) {
        // Handle the case where the API returns an array of UTXOs
        const utxos: ApiUtxo[] = data;
        // Extract encrypted outputs from the array of UTXOs
        encryptedOutputs = utxos
            .filter(utxo => utxo.encrypted_output)
            .map(utxo => utxo.encrypted_output);
    } else if (typeof data === 'object' && data.encrypted_outputs) {
        // Handle the case where the API returns an object with encrypted_outputs array
        const apiResponse = data as ApiResponse;
        encryptedOutputs = apiResponse.encrypted_outputs;
    } else {
        throw new Error(`API returned unexpected data format: ${JSON.stringify(data).substring(0, 100)}...`);
    }

    // Try to decrypt each encrypted output
    const myUtxos: Utxo[] = [];
    const myEncryptedOutputs: string[] = [];
    let decryptionAttempts = 0;
    let successfulDecryptions = 0;

    let cachedStringNum = 0
    let cachedString = storage.getItem(LSK_ENCRYPTED_OUTPUTS + localstorageKey(publicKey_ata))
    if (cachedString) {
        cachedStringNum = JSON.parse(cachedString).length
    }


    let decryptionTaskTotal = data.total + cachedStringNum - roundStartIndex;
    let batchRes = await decrypt_outputs(encryptedOutputs, encryptionService, utxoKeypair, lightWasm)
    decryptionTaskFinished += encryptedOutputs.length
    logger.debug('batchReslen', batchRes.length)
    for (let i = 0; i < batchRes.length; i++) {
        let dres = batchRes[i]
        if (dres.status == 'decrypted' && dres.utxo) {
            myUtxos.push(dres.utxo)
            myEncryptedOutputs.push(dres.encryptedOutput!)
        }
    }
    logger.info(`(decrypting cached utxo: ${decryptionTaskFinished + 1}/${decryptionTaskTotal}...)`)
    // check cached string when no more fetching tasks
    if (!data.hasMore) {
        if (cachedString) {
            let cachedEncryptedOutputs = JSON.parse(cachedString)
            if (decryptionTaskFinished % 100 == 0) {
                logger.info(`(decrypting cached utxo: ${decryptionTaskFinished + 1}/${decryptionTaskTotal}...)`)
            }
            let batchRes = await decrypt_outputs(cachedEncryptedOutputs, encryptionService, utxoKeypair, lightWasm)
            decryptionTaskFinished += cachedEncryptedOutputs.length
            logger.debug('cachedbatchReslen', batchRes.length, ' source', cachedEncryptedOutputs.length)
            for (let i = 0; i < batchRes.length; i++) {
                let dres = batchRes[i]
                if (dres.status == 'decrypted' && dres.utxo) {
                    myUtxos.push(dres.utxo)
                    myEncryptedOutputs.push(dres.encryptedOutput!)
                }
            }
        }
    }

    return { encryptedOutputs: myEncryptedOutputs, utxos: myUtxos, hasMore: data.hasMore, len: encryptedOutputs.length };
}

/**
 * Check if a UTXO has been spent
 * @param connection Solana connection
 * @param utxo The UTXO to check
 * @returns Promise<boolean> true if spent, false if unspent
 */
export async function isUtxoSpent(connection: Connection, utxo: Utxo): Promise<boolean> {
    try {
        // Get the nullifier for this UTXO
        const nullifier = await utxo.getNullifier();
        logger.debug(`Checking if UTXO with nullifier ${nullifier} is spent`);

        // Convert decimal nullifier string to byte array (same format as in proofs)
        // This matches how commitments are handled and how the Rust code expects the seeds
        const nullifierBytes = Array.from(
            leInt2Buff(unstringifyBigInts(nullifier), 32)
        ).reverse() as number[];

        // Try nullifier0 seed
        const [nullifier0PDA] = PublicKey.findProgramAddressSync(
            [Buffer.from("nullifier0"), Buffer.from(nullifierBytes)],
            PROGRAM_ID
        );

        logger.debug(`Derived nullifier0 PDA: ${nullifier0PDA.toBase58()}`);
        const nullifier0Account = await connection.getAccountInfo(nullifier0PDA);
        if (nullifier0Account !== null) {
            logger.debug(`UTXO is spent (nullifier0 account exists)`);
            return true;
        }


        const [nullifier1PDA] = PublicKey.findProgramAddressSync(
            [Buffer.from("nullifier1"), Buffer.from(nullifierBytes)],
            PROGRAM_ID
        );

        logger.debug(`Derived nullifier1 PDA: ${nullifier1PDA.toBase58()}`);
        const nullifier1Account = await connection.getAccountInfo(nullifier1PDA);
        if (nullifier1Account !== null) {
            logger.debug(`UTXO is spent (nullifier1 account exists)`);
            return true
        }
        return false;
    } catch (error: any) {
        console.error('Error checking if UTXO is spent:', error);
        await new Promise(resolve => setTimeout(resolve, 3000));
        return await isUtxoSpent(connection, utxo)
    }
}

async function areUtxosSpent(
    connection: Connection,
    utxos: Utxo[]
): Promise<boolean[]> {
    try {
        const allPDAs: { utxoIndex: number; pda: PublicKey }[] = [];

        for (let i = 0; i < utxos.length; i++) {
            const utxo = utxos[i];
            const nullifier = await utxo.getNullifier();

            const nullifierBytes = Array.from(
                leInt2Buff(unstringifyBigInts(nullifier), 32)
            ).reverse() as number[];

            const [nullifier0PDA] = PublicKey.findProgramAddressSync(
                [Buffer.from("nullifier0"), Buffer.from(nullifierBytes)],
                PROGRAM_ID
            );
            const [nullifier1PDA] = PublicKey.findProgramAddressSync(
                [Buffer.from("nullifier1"), Buffer.from(nullifierBytes)],
                PROGRAM_ID
            );

            allPDAs.push({ utxoIndex: i, pda: nullifier0PDA });
            allPDAs.push({ utxoIndex: i, pda: nullifier1PDA });
        }

        const results: any[] =
            await connection.getMultipleAccountsInfo(allPDAs.map((x) => x.pda));

        const spentFlags = new Array(utxos.length).fill(false);
        for (let i = 0; i < allPDAs.length; i++) {
            if (results[i] !== null) {
                spentFlags[allPDAs[i].utxoIndex] = true;
            }
        }

        return spentFlags;
    } catch (error: any) {
        console.error("Error checking if UTXOs are spent:", error);
        await new Promise((resolve) => setTimeout(resolve, 3000));
        return await areUtxosSpent(connection, utxos);
    }
}

// Calculate total balance
export function getBalanceFromUtxosSPL(utxos: Utxo[]): {
    base_units: number
    /** @deprecated use base_units instead */
    lamports: number
} {
    const totalBalance = utxos.reduce((sum, utxo) => sum.add(utxo.amount), new BN(0));
    return { base_units: totalBalance.toNumber(), lamports: totalBalance.toNumber() }
}

// Decrypt single output to Utxo
type DecryptRes = { status: 'decrypted' | 'skipped' | 'unDecrypted', utxo?: Utxo, encryptedOutput?: string }
async function decrypt_output(
    encryptedOutput: string,
    encryptionService: EncryptionService,
    utxoKeypair: UtxoKeypair,
    lightWasm: any,
    connection: Connection
): Promise<DecryptRes> {
    let res: DecryptRes = { status: 'unDecrypted' }
    try {
        if (!encryptedOutput) {
            return { status: 'skipped' }
        }

        // Try to decrypt the UTXO
        res.utxo = await encryptionService.decryptUtxo(
            encryptedOutput,
            lightWasm
        );

        // If we got here, decryption succeeded, so this UTXO belongs to the user
        res.status = 'decrypted'

        // Get the real index from the on-chain commitment account
        try {
            if (!res.utxo) {
                throw new Error('res.utxo undefined')
            }
            const commitment = await res.utxo.getCommitment();
            // Convert decimal commitment string to byte array (same format as in proofs)
            const commitmentBytes = Array.from(
                leInt2Buff(unstringifyBigInts(commitment), 32)
            ).reverse() as number[];

            // Derive the commitment PDA (could be either commitment0 or commitment1)
            // We'll try both seeds since we don't know which one it is
            let commitmentAccount = null;
            let realIndex = null;
            // Try commitment0 seed
            try {
                const [commitment0PDA] = PublicKey.findProgramAddressSync(
                    [Buffer.from("commitment0"), Buffer.from(commitmentBytes)],
                    PROGRAM_ID
                );

                const account0Info = await connection.getAccountInfo(commitment0PDA);
                if (account0Info) {
                    // Parse the index from the account data according to CommitmentAccount structure:
                    // 0-8: Anchor discriminator
                    // 8-40: commitment (32 bytes)  
                    // 40-44: encrypted_output length (4 bytes)
                    // 44-44+len: encrypted_output data
                    // 44+len-52+len: index (8 bytes)
                    const encryptedOutputLength = account0Info.data.readUInt32LE(40);
                    const indexOffset = 44 + encryptedOutputLength;
                    const indexBytes = account0Info.data.slice(indexOffset, indexOffset + 8);
                    realIndex = new BN(indexBytes, 'le').toNumber();
                }
            } catch (e) {
                // Try commitment1 seed if commitment0 fails
                try {
                    const [commitment1PDA] = PublicKey.findProgramAddressSync(
                        [Buffer.from("commitment1"), Buffer.from(commitmentBytes)],
                        PROGRAM_ID
                    );

                    const account1Info = await connection.getAccountInfo(commitment1PDA);
                    if (account1Info) {
                        // Parse the index from the account data according to CommitmentAccount structure
                        const encryptedOutputLength = account1Info.data.readUInt32LE(40);
                        const indexOffset = 44 + encryptedOutputLength;
                        const indexBytes = account1Info.data.slice(indexOffset, indexOffset + 8);
                        realIndex = new BN(indexBytes, 'le').toNumber();
                        logger.debug(`Found commitment1 account with index: ${realIndex}`);
                    }
                } catch (e2) {
                    logger.debug(`Could not find commitment account for ${commitment}, using encrypted index: ${res.utxo.index}`);
                }
            }

            // Update the UTXO with the real index if we found it
            if (realIndex !== null) {
                const oldIndex = res.utxo.index;
                res.utxo.index = realIndex;
            }

        } catch (error: any) {
            logger.debug(`Failed to get real index for UTXO: ${error.message}`);
        }
    } catch (error: any) {
        // this UTXO doesn't belong to the user
    }
    return res
}

async function decrypt_outputs(
    encryptedOutputs: string[],
    encryptionService: EncryptionService,
    utxoKeypair: UtxoKeypair,
    lightWasm: any,
): Promise<DecryptRes[]> {
    let results: DecryptRes[] = [];

    // decript all UTXO
    for (const encryptedOutput of encryptedOutputs) {
        if (!encryptedOutput) {
            results.push({ status: 'skipped' });
            continue;
        }
        try {
            const utxo = await encryptionService.decryptUtxo(
                encryptedOutput,
                lightWasm
            );
            results.push({ status: 'decrypted', utxo, encryptedOutput });
        } catch {
            results.push({ status: 'unDecrypted' });
        }
    }
    results = results.filter(r => r.status == 'decrypted')
    if (!results.length) {
        return []
    }

    // update utxo index
    if (results.length > 0) {
        let encrypted_outputs = results.map(r => r.encryptedOutput)

        let url = RELAYER_API_URL + `/utxos/indices`
        let res = await fetch(url, {
            method: 'POST', headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ encrypted_outputs, token: 'usdc' })
        })
        let j = await res.json()
        if (!j.indices || !Array.isArray(j.indices) || j.indices.length != encrypted_outputs.length) {
            throw new Error('failed fetching /utxos/indices')
        }
        for (let i = 0; i < results.length; i++) {
            let utxo = results[i].utxo
            if (utxo!.index !== j.indices[i] && typeof j.indices[i] == 'number') {
                logger.debug(`Updated UTXO index from ${utxo!.index} to ${j.indices[i]}`);
                utxo!.index = j.indices[i]
            }
        }
    }

    return results;
}