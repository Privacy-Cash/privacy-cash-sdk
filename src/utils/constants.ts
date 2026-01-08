import { PublicKey } from '@solana/web3.js';
import BN from 'bn.js';

export const FIELD_SIZE = new BN('21888242871839275222246405745257275088548364400416034343698204186575808495617')

export const PROGRAM_ID = process.env.NEXT_PUBLIC_PROGRAM_ID ? new PublicKey(process.env.NEXT_PUBLIC_PROGRAM_ID) : new PublicKey('9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD');

export const FEE_RECIPIENT = new PublicKey('AWexibGxNFKTa1b5R5MN4PJr9HWnWRwf8EW9g8cLx3dM')

export const FETCH_UTXOS_GROUP_SIZE = 20_000

export const TRANSACT_IX_DISCRIMINATOR = Buffer.from([217, 149, 130, 143, 221, 52, 252, 119]);

export const TRANSACT_SPL_IX_DISCRIMINATOR = Buffer.from([154, 66, 244, 204, 78, 225, 163, 151]);

export const MERKLE_TREE_DEPTH = 26;

export const ALT_ADDRESS = process.env.NEXT_PUBLIC_ALT_ADDRESS ? new PublicKey(process.env.NEXT_PUBLIC_ALT_ADDRESS) : new PublicKey('HEN49U2ySJ85Vc78qprSW9y6mFDhs1NczRxyppNHjofe');

export const RELAYER_API_URL = process.env.NEXT_PUBLIC_RELAYER_API_URL ?? 'https://api3.privacycash.org';

export const SIGN_MESSAGE = `Privacy Money account sign in`

// localStorage cache keys
export const LSK_FETCH_OFFSET = 'fetch_offset'
export const LSK_ENCRYPTED_OUTPUTS = 'encrypted_outputs'

export const USDC_MINT = process.env.NEXT_PUBLIC_USDC_MINT ? new PublicKey(process.env.NEXT_PUBLIC_USDC_MINT) : new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')

const tokenList = ['sol', 'usdc', 'usdt', 'zec', 'ore', 'store'] as const;
export type TokenList = typeof tokenList[number];
const splList = ['usdc', 'usdt', 'zec', 'ore', 'store'] as const;
export type SplList = typeof splList[number];
export type Token = {
    name: TokenList
    prefix: string
    units_per_token: number
    pubkey: PublicKey
}
export const tokens: Token[] = [
    {
        name: 'sol',
        pubkey: new PublicKey('So11111111111111111111111111111111111111112'),
        prefix: '',
        units_per_token: 1e9
    },
    {
        name: 'usdc',
        pubkey: process.env.NEXT_PUBLIC_USDC_MINT ? new PublicKey(process.env.NEXT_PUBLIC_USDC_MINT) : new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'),
        prefix: 'usdc_',
        units_per_token: 1e6
    },
    {
        name: 'usdt',
        pubkey: process.env.NEXT_PUBLIC_USDT_MINT ? new PublicKey(process.env.NEXT_PUBLIC_USDT_MINT) : new PublicKey('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB'),
        prefix: 'usdt_',
        units_per_token: 1e6
    },
    {
        name: 'zec',
        pubkey: process.env.NEXT_PUBLIC_ZEC_MINT ? new PublicKey(process.env.NEXT_PUBLIC_ZEC_MINT) : new PublicKey('A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS'),
        prefix: 'zec_',
        units_per_token: 1e8
    },
    {
        name: 'ore',
        pubkey: process.env.NEXT_PUBLIC_ORE_MINT ? new PublicKey(process.env.NEXT_PUBLIC_ORE_MINT) : new PublicKey('oreoU2P8bN6jkk3jbaiVxYnG1dCXcYxwhwyK9jSybcp'),
        prefix: 'ore_',
        units_per_token: 1e11
    },
    {
        name: 'store',
        pubkey: process.env.NEXT_PUBLIC_STORE_MINT ? new PublicKey(process.env.NEXT_PUBLIC_STORE_MINT) : new PublicKey('sTorERYB6xAZ1SSbwpK3zoK2EEwbBrc7TZAzg1uCGiH'),
        prefix: 'store_',
        units_per_token: 1e11
    },
]