import { PublicKey } from '@solana/web3.js';
import { describe, expect, it } from 'vitest';
import { depositSPL } from '../src/depositSPL';
import {
    getRelayerTokenName,
    LEGACY_STORE_MINT,
    normalizeRelayerTokenMap,
    STORE_MINT,
    tokens,
} from '../src/utils/constants';

describe('stORE token aliases', () => {
    it('exports latest stORE as store and old stORE as legacyStore', () => {
        const tokenNames = tokens.map(token => token.name);

        expect(tokenNames).toContain('store');
        expect(tokenNames).toContain('legacyStore');
        expect(tokenNames).not.toContain('newstore' as any);

        expect(tokens.find(token => token.name === 'store')?.pubkey.toString()).toBe(STORE_MINT.toString());
        expect(tokens.find(token => token.name === 'legacyStore')?.pubkey.toString()).toBe(LEGACY_STORE_MINT.toString());
    });

    it('maps public stORE names to relayer token names', () => {
        expect(getRelayerTokenName('store')).toBe('newstore');
        expect(getRelayerTokenName('legacyStore')).toBe('store');
        expect(getRelayerTokenName('usdc')).toBe('usdc');
    });

    it('normalizes relayer config maps without exposing newstore', () => {
        expect(normalizeRelayerTokenMap({
            sol: 1,
            store: 2,
            newstore: 3,
        })).toEqual({
            sol: 1,
            store: 3,
            legacyStore: 2,
        });
    });

    it('rejects legacy stORE deposits before transaction work starts', async () => {
        await expect(depositSPL({
            mintAddress: new PublicKey(LEGACY_STORE_MINT),
            lightWasm: {} as any,
            storage: {} as any,
            keyBasePath: '',
            publicKey: PublicKey.default,
            connection: {} as any,
            base_units: 1,
            encryptionService: {} as any,
            transactionSigner: async tx => tx,
        })).rejects.toThrow('Legacy stORE deposit has been disabled. Please use the latest stORE.');
    });
});
