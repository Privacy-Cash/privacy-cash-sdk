import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, VersionedTransaction } from '@solana/web3.js';
import { deposit } from './deposit.js';
import { getBalanceFromUtxos, getUtxos, localstorageKey } from './getUtxos.js';

import { LSK_ENCRPTED_OUTPUTS, LSK_FETCH_OFFSET } from './utils/constants.js';
import { logger, type LoggerFn, setLogger } from './utils/logger.js';
import { EncryptionService } from './utils/encryption.js';
import { WasmFactory } from '@lightprotocol/hasher.rs';
import bs58 from 'bs58'
import { withdraw } from './withdraw.js';
import { LocalStorage } from "node-localstorage";
import path from 'node:path'

let storage = new LocalStorage(path.join(process.cwd(), "cache"));

export class PrivacyCash {
    private connection: Connection
    public publicKey: PublicKey
    private encryptionService: EncryptionService
    private keypair: Keypair
    constructor({ RPC_url, owner }: {
        RPC_url: string,
        owner: string | number[] | Uint8Array | Keypair,
    }) {
        let keypair = getSolanaKeypair(owner)
        if (!keypair) {
            throw new Error('param "owner" is not a valid Private Key or Keypair')
        }
        this.keypair = keypair
        this.connection = new Connection(RPC_url, 'confirmed')
        this.publicKey = keypair.publicKey
        this.encryptionService = new EncryptionService();
        this.encryptionService.deriveEncryptionKeyFromWallet(this.keypair);
    }

    setLogger(loger: LoggerFn) {
        setLogger(loger)
        return this
    }

    /**
     * Clears the cache of utxos.
     * 
     * By default, downloaded utxos will be cached in the local storage. Thus the next time when you makes another
     * deposit or withdraw or getPrivateBalance, the SDK only fetches the utxos that are not in the cache.
     * 
     * This method clears the cache of utxos.
     */
    async clearCache() {
        if (!this.publicKey) {
            return this
        }
        storage.removeItem(LSK_FETCH_OFFSET + localstorageKey(this.publicKey))
        storage.removeItem(LSK_ENCRPTED_OUTPUTS + localstorageKey(this.publicKey))
        return this
    }

    /**
     * Deposit SOL to the Privacy Cash.
     * 
     * Lamports is the amount of SOL in lamports. e.g. if you want to deposit 0.01 SOL (10000000 lamports), call deposit({ lamports: 10000000 })
     */
    async deposit({ lamports }: {
        lamports: number
    }) {
        let lightWasm = await WasmFactory.getInstance()
        return await deposit({
            lightWasm,
            amount_in_lamports: lamports,
            connection: this.connection,
            encryptionService: this.encryptionService,
            publicKey: this.publicKey,
            transactionSigner: async (tx: VersionedTransaction) => {
                tx.sign([this.keypair])
                return tx
            },
            keyBasePath: path.join(import.meta.dirname, '..', 'circuit2', 'transaction2'),
            storage
        })
    }

    /**
     * Withdraw SOL from the Privacy Cash.
     * 
     * Lamports is the amount of SOL in lamports. e.g. if you want to withdraw 0.01 SOL (10000000 lamports), call withdraw({ lamports: 10000000 })
     */
    async withdraw({ lamports, recipientAddress }: {
        lamports: number,
        recipientAddress?: string
    }) {
        let lightWasm = await WasmFactory.getInstance()
        return await withdraw({
            lightWasm,
            amount_in_lamports: lamports,
            connection: this.connection,
            encryptionService: this.encryptionService,
            publicKey: this.publicKey,
            recipient: recipientAddress ? new PublicKey(recipientAddress) : this.publicKey,
            keyBasePath: path.join(import.meta.dirname, '..', 'circuit2', 'transaction2'),
            storage
        })
    }

    /**
     * Returns the amount of lamports current wallet has in Privacy Cash.
     */
    async getPrivateBalance() {
        let utxos = await getUtxos({ publicKey: this.publicKey, connection: this.connection, encryptionService: this.encryptionService, storage })
        console.log('got utxos', utxos.length)
        return getBalanceFromUtxos(utxos)
    }

    /**
     * Returns true if the code is running in a browser.
     */
    isBrowser() {
        return typeof window !== "undefined"
    }
}

export { deposit, withdraw }

function getSolanaKeypair(
    secret: string | number[] | Uint8Array | Keypair
): Keypair | null {
    try {
        if (secret instanceof Keypair) {
            return secret;
        }

        let keyArray: Uint8Array;

        if (typeof secret === "string") {
            keyArray = bs58.decode(secret);
        } else if (secret instanceof Uint8Array) {
            keyArray = secret;
        } else {
            // number[]
            keyArray = Uint8Array.from(secret);
        }

        if (keyArray.length !== 32 && keyArray.length !== 64) {
            return null;
        }
        return Keypair.fromSecretKey(keyArray);
    } catch {
        return null;
    }
}