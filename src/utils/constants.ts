import { PublicKey } from '@solana/web3.js';
import BN from 'bn.js';

export const FIELD_SIZE = new BN('21888242871839275222246405745257275088548364400416034343698204186575808495617')

export const PROGRAM_ID = new PublicKey('9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD');

export const DEPLOYER_ID = new PublicKey('AWexibGxNFKTa1b5R5MN4PJr9HWnWRwf8EW9g8cLx3dM')

export const FEE_RECIPIENT = new PublicKey('AWexibGxNFKTa1b5R5MN4PJr9HWnWRwf8EW9g8cLx3dM')

export const FETCH_UTXOS_GROUP_SIZE = 10_000

export const TRANSACT_IX_DISCRIMINATOR = Buffer.from([217, 149, 130, 143, 221, 52, 252, 119]);

export const MERKLE_TREE_DEPTH = 26;

export const ALT_ADDRESS = new PublicKey('72bpRay17JKp4k8H87p7ieU9C6aRDy5yCqwvtpTN2wuU');

export const INDEXER_API_URL = process.env.NEXT_PUBLIC_INDEXER_API_URL ?? 'https://api3.privacycash.org';

export const SIGN_MESSAGE = `Privacy Money account sign in`

// localStorage cache keys
export const LSK_FETCH_OFFSET = 'fetch_offset'
export const LSK_ENCRYPTED_OUTPUTS = 'encrypted_outputs'
