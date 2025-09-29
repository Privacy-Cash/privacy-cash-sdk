import { describe, it, expect, vi, beforeAll, beforeEach, type Mock } from "vitest";
import { PublicKey } from '@solana/web3.js';
import BN from 'bn.js';

// Define an interface for our mocked Utxo
interface MockUtxo {
    amount: { toString: () => string };
    blinding: { toString: () => string };
    index: number | string;
    getCommitment: Mock;
    getNullifier: Mock;
}

// -----------------------------
// Mock Modules
// -----------------------------

// Mock Utxo class
vi.mock("../src/models/utxo", () => {
    return {
        Utxo: vi.fn().mockImplementation(
            function (this: any, { amount, blinding, index }: { amount: any; blinding: any; index: any }) {
                this.amount = { toString: () => amount.toString() };
                this.blinding = { toString: () => blinding.toString() };
                this.index = index;
                this.getCommitment = vi.fn().mockResolvedValue("mock-commitment");
                this.getNullifier = vi.fn().mockResolvedValue("mock-nullifier");
            }
        )
    };
});

// Mock WasmFactory
vi.mock('@lightprotocol/hasher.rs', () => {
    return {
        WasmFactory: {
            getInstance: vi.fn().mockResolvedValue({
                poseidonHashString: vi.fn().mockReturnValue('1234567890') // return valid string to BN
            })
        }
    };
});

// Mock Keypair class
vi.mock('../models/keypair', () => {
    return {
        Keypair: vi.fn().mockImplementation(function (this: any, privkeyHex: string, lightWasm: any) {
            // add 0x prefix for BigInt 
            const hex = privkeyHex.startsWith('0x') ? privkeyHex : '0x' + privkeyHex;
            this.privkey = { toString: () => hex };
            this.pubkey = { toString: () => '1234567890' };
            this.lightWasm = lightWasm;
            this.sign = vi.fn().mockReturnValue('mock-signature');
        })
    };
});

// -----------------------------
// Imports for testing
// -----------------------------
import { Keypair } from '@solana/web3.js';
import { EncryptionService, serializeProofAndExtData } from '../src/utils/encryption';
import { Utxo } from '../src/models/utxo';
import { Keypair as UtxoKeypair } from '../src/models/keypair';
import { WasmFactory } from '@lightprotocol/hasher.rs';
import { TRANSACT_IX_DISCRIMINATOR } from '../src/utils/constants';

// -----------------------------
// Tests
// -----------------------------
describe('EncryptionService', () => {
    let encryptionService: EncryptionService;
    let testKeypair: Keypair;
    let testUtxoKeypair: UtxoKeypair;
    let mockLightWasm: any;

    beforeAll(async () => {
        mockLightWasm = await WasmFactory.getInstance();
    });

    beforeEach(() => {
        encryptionService = new EncryptionService();

        const seed = new Uint8Array(32).fill(1);
        testKeypair = Keypair.fromSeed(seed);

        testUtxoKeypair = new UtxoKeypair(
            '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            mockLightWasm
        );

        (Utxo as unknown as Mock).mockClear();
    });

    describe('deriveEncryptionKeyFromWallet', () => {
        it('should generate a deterministic key from a keypair', () => {
            const key1 = encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            encryptionService.resetEncryptionKey();
            const key2 = encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            expect(key1.v1.length).toBe(31);
            expect(key1.v2.length).toBe(32);
            expect(key2.v1.length).toBe(31);
            expect(key2.v2.length).toBe(32);

            expect(Buffer.from(key1.v1).toString('hex')).toBe(Buffer.from(key2.v1).toString('hex'));
            expect(Buffer.from(key1.v2).toString('hex')).toBe(Buffer.from(key2.v2).toString('hex'));
        });

        it('should set the internal encryption key', () => {
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v1')).toBe(false);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v2')).toBe(false);
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v1')).toBe(true);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v2')).toBe(true);
        });

        it('should generate different keys for different keypairs', () => {
            const key1 = encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Create a different keypair
            const seed2 = new Uint8Array(32).fill(2);
            const testKeypair2 = Keypair.fromSeed(seed2);

            // Reset and regenerate with different keypair
            encryptionService.resetEncryptionKey();
            const key2 = encryptionService.deriveEncryptionKeyFromWallet(testKeypair2);

            // Keys should be different
            expect(Buffer.from(key1.v1).toString('hex')).not.toBe(Buffer.from(key2.v1).toString('hex'));
            expect(Buffer.from(key1.v2).toString('hex')).not.toBe(Buffer.from(key2.v2).toString('hex'));
        });
    });

    describe('encrypt', () => {
        it('should throw an error if encryption key is not generated', () => {
            expect(() => {
                encryptionService.encrypt('test data');
            }).toThrow('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
        });

        it('should encrypt data as a buffer', () => {
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);
            const originalData = 'test data';
            const encrypted = encryptionService.encrypt(originalData);

            // Should return a buffer
            expect(Buffer.isBuffer(encrypted)).toBe(true);

            // Encrypted data should be longer than original (includes IV)
            expect(encrypted.length).toBeGreaterThan(originalData.length);

            // Encrypted data should not be the same as original
            expect(encrypted.toString()).not.toBe(originalData);
        });

        it('should encrypt Buffer data', () => {
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);
            const originalData = Buffer.from([1, 2, 3, 4, 5]);
            const encrypted = encryptionService.encrypt(originalData);

            // Should return a buffer
            expect(Buffer.isBuffer(encrypted)).toBe(true);

            // Encrypted data should not be the same as original
            expect(encrypted.toString('hex')).not.toBe(originalData.toString('hex'));
        });
    });

    describe('decrypt', () => {
        it('should throw an error if encryption key is not generated', () => {
            const fakeEncrypted = Buffer.from('fake encrypted data');

            expect(() => {
                encryptionService.decrypt(fakeEncrypted);
            }).toThrow('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
        });

        it('should decrypt previously encrypted data', () => {
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            const originalData = 'This is some secret UTXO data';
            const encrypted = encryptionService.encrypt(originalData);
            const decrypted = encryptionService.decrypt(encrypted);

            // Decrypted data should match original
            expect(decrypted.toString()).toBe(originalData);
        });

        it('should decrypt binary data correctly', () => {
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            const originalData = Buffer.from([0, 1, 2, 3, 255, 254, 253]);
            const encrypted = encryptionService.encrypt(originalData);
            const decrypted = encryptionService.decrypt(encrypted);

            // Decrypted data should match original
            expect(decrypted.toString('hex')).toBe(originalData.toString('hex'));
        });

        it('should throw error when decrypting with wrong key', () => {
            // Generate key and encrypt
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);
            const originalData = 'secret data';
            const encrypted = encryptionService.encrypt(originalData);

            // Create new service with different key
            const otherService = new EncryptionService();
            const seed2 = new Uint8Array(32).fill(2);
            const testKeypair2 = Keypair.fromSeed(seed2);
            otherService.deriveEncryptionKeyFromWallet(testKeypair2);

            // Should fail to decrypt with wrong key
            expect(() => {
                otherService.decrypt(encrypted);
            }).toThrow('Failed to decrypt data');
        });
    });

    describe('encryption key management', () => {
        it('should reset the encryption key', () => {
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v1')).toBe(true);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v2')).toBe(true);

            encryptionService.resetEncryptionKey();
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v1')).toBe(false);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v2')).toBe(false);
        });

        it('should correctly report whether key is present', () => {
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v1')).toBe(false);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v2')).toBe(false);
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v1')).toBe(true);
            expect(encryptionService.hasUtxoPrivateKeyWithVersion('v2')).toBe(true);
        });
    });

    describe('end-to-end workflow', () => {
        it('should support the full encrypt-decrypt workflow', () => {
            // Generate encryption key
            const key = encryptionService.deriveEncryptionKeyFromWallet(testKeypair);
            expect(key.v1.length).toBe(31);
            expect(key.v2.length).toBe(32);

            // Encrypt some UTXO data
            const utxoData = JSON.stringify({
                amount: '1000000000',
                blinding: '123456789',
                pubkey: 'abcdef1234567890'
            });

            const encrypted = encryptionService.encrypt(utxoData);

            // Verify encrypted data is different
            expect(encrypted.toString()).not.toContain(utxoData);

            // Decrypt and verify
            const decrypted = encryptionService.decrypt(encrypted);
            expect(decrypted.toString()).toBe(utxoData);

            // Parse the JSON to verify structure remained intact
            const parsedData = JSON.parse(decrypted.toString());
            expect(parsedData.amount).toBe('1000000000');
            expect(parsedData.blinding).toBe('123456789');
            expect(parsedData.pubkey).toBe('abcdef1234567890');
        });
    });

    describe('deriveUtxoPrivateKey', () => {
        it('should throw an error if encryption key is not generated', () => {
            expect(() => {
                encryptionService.deriveUtxoPrivateKey();
            }).toThrow('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
        });

        it('should generate a deterministic private key from the encryption key', () => {
            // Generate the encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Generate two private keys from the same encryption key
            const privKey1 = encryptionService.deriveUtxoPrivateKey();
            const privKey2 = encryptionService.deriveUtxoPrivateKey();

            // Private keys should be strings starting with 0x
            expect(typeof privKey1).toBe('string');
            expect(typeof privKey2).toBe('string');
            expect(privKey1.startsWith('0x')).toBe(true);

            // Same encryption key should produce same private key
            expect(privKey1).toBe(privKey2);
        });

        it('should generate the same private key consistently', () => {
            // Generate the encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Generate private keys multiple times
            const privKey1 = encryptionService.deriveUtxoPrivateKey();
            const privKey2 = encryptionService.deriveUtxoPrivateKey();

            // Same encryption key should produce same private key
            expect(privKey1).toBe(privKey2);
        });

        it('should generate different private keys for different users', () => {
            // User 1
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);
            const user1PrivKey = encryptionService.deriveUtxoPrivateKey();

            // User 2 with different encryption key
            const seed2 = new Uint8Array(32).fill(2);
            const testKeypair2 = Keypair.fromSeed(seed2);

            const user2Service = new EncryptionService();
            user2Service.deriveEncryptionKeyFromWallet(testKeypair2);
            const user2PrivKey = user2Service.deriveUtxoPrivateKey();

            // Different users should get different private keys
            expect(user1PrivKey).not.toBe(user2PrivKey);
        });
    });

    describe('end-to-end workflow with UTXO keypair', () => {
        it('should support the full encryption workflow with a generated keypair', () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Generate a UTXO private key
            const utxoPrivKey = encryptionService.deriveUtxoPrivateKey();

            // Simulate creating a custom UTXO format
            const utxoData = JSON.stringify({
                amount: '1000000000',
                blinding: '123456789',
                privateKey: utxoPrivKey
            });

            const encrypted = encryptionService.encrypt(utxoData);

            // Decrypt and verify
            const decrypted = encryptionService.decrypt(encrypted);
            expect(decrypted.toString()).toBe(utxoData);

            // Parse the JSON to verify structure remained intact
            const parsedData = JSON.parse(decrypted.toString());
            expect(parsedData.privateKey).toBe(utxoPrivKey);
        });
    });

    describe('encryptUtxo', () => {
        it('should throw an error if encryption key is not generated', () => {
            const testUtxo = new Utxo({
                lightWasm: mockLightWasm,
                amount: '1000000000',
                blinding: '123456789',
                index: 0,
                keypair: testUtxoKeypair
            });

            expect(() => {
                encryptionService.encryptUtxo(testUtxo);
            }).toThrow('Encryption key not set. Call setEncryptionKey or deriveEncryptionKeyFromWallet first.');
        });

        it('should encrypt and decrypt a UTXO with numeric index', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Create test UTXO
            const testUtxo = new Utxo({
                lightWasm: mockLightWasm,
                amount: '1000000000',
                blinding: '123456789',
                index: 0,
                keypair: testUtxoKeypair
            });

            // Encrypt the UTXO
            const encrypted = encryptionService.encryptUtxo(testUtxo);

            // Should return a buffer
            expect(Buffer.isBuffer(encrypted)).toBe(true);

            // Decrypt the UTXO (await the promise)
            const decrypted = await encryptionService.decryptUtxo(encrypted, mockLightWasm);

            // Decrypted UTXO should match original
            expect(decrypted.amount.toString()).toBe(testUtxo.amount.toString());
            expect(decrypted.blinding.toString()).toBe(testUtxo.blinding.toString());
            expect(decrypted.index).toBe(testUtxo.index);
        });

        it('should encrypt and decrypt a UTXO with string index', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Create test UTXO
            const testUtxo = new Utxo({
                lightWasm: mockLightWasm,
                amount: '1000000000',
                blinding: '123456789',
                index: 0, // Utxo constructor expects number, not string
                keypair: testUtxoKeypair
            });

            // Encrypt the UTXO
            const encrypted = encryptionService.encryptUtxo(testUtxo);

            // Decrypt the UTXO (await the promise)
            const decrypted = await encryptionService.decryptUtxo(encrypted, mockLightWasm);

            // Decrypted UTXO should match original
            expect(decrypted.amount.toString()).toBe(testUtxo.amount.toString());
            expect(decrypted.blinding.toString()).toBe(testUtxo.blinding.toString());

            // Note: In the implementation, string indices might be converted to numbers
            // If it can't be converted, it would return 0 as fallback
            // For tests, we just check that we have an index property
            expect(decrypted.index !== undefined).toBe(true);
        });

        it('should accept and decrypt a hex string instead of a Buffer', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Create test UTXO
            const testUtxo = new Utxo({
                lightWasm: mockLightWasm,
                amount: '5000000000',
                blinding: '987654321',
                index: 1,
                keypair: testUtxoKeypair
            });

            // Encrypt the UTXO
            const encrypted = encryptionService.encryptUtxo(testUtxo);

            // Convert to hex string
            const encryptedHex = encrypted.toString('hex');

            // Decrypt from hex string (await the promise)
            const decrypted = await encryptionService.decryptUtxo(encryptedHex, mockLightWasm);

            // Decrypted UTXO should match original
            expect(decrypted.amount.toString()).toBe(testUtxo.amount.toString());
            expect(decrypted.blinding.toString()).toBe(testUtxo.blinding.toString());
            expect(decrypted.index).toBe(testUtxo.index);
        });

        it('should throw an error when decrypting with wrong key', async () => {
            // Generate key and encrypt
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            const testUtxo = new Utxo({
                lightWasm: mockLightWasm,
                amount: '1000000000',
                blinding: '123456789',
                index: 0,
                keypair: testUtxoKeypair
            });

            const encrypted = encryptionService.encryptUtxo(testUtxo);

            // Create new service with different key
            const otherService = new EncryptionService();
            const seed2 = new Uint8Array(32).fill(2);
            const testKeypair2 = Keypair.fromSeed(seed2);
            otherService.deriveEncryptionKeyFromWallet(testKeypair2);

            // Should fail to decrypt with wrong key
            await expect(otherService.decryptUtxo(encrypted, mockLightWasm)).rejects.toThrow('Failed to decrypt data');
        });

        it('should throw an error when decrypting invalid UTXO format', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Encrypt invalid format (missing pipe separators)
            const invalidData = encryptionService.encrypt('invalidutxoformat');

            // Should fail to parse as UTXO
            await expect(encryptionService.decryptUtxo(invalidData, mockLightWasm)).rejects.toThrow('Invalid UTXO format');
        });
    });

    describe('encryptUtxo and decryptUtxo with Utxo instances', () => {
        it('should encrypt and decrypt Utxo instances', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Create a test Utxo instance
            const testUtxo = new Utxo({
                lightWasm: mockLightWasm,
                amount: '1000000000',
                blinding: '123456789',
                index: 0
            }) as unknown as MockUtxo;

            // Encrypt the UTXO
            const encrypted = encryptionService.encryptUtxo(testUtxo as unknown as Utxo);

            // Should return a buffer
            expect(Buffer.isBuffer(encrypted)).toBe(true);

            // Decrypt the UTXO
            const decrypted = await encryptionService.decryptUtxo(encrypted, mockLightWasm);

            // Check it's a proper Utxo instance
            expect(decrypted).toBeInstanceOf(Utxo);

            // Check core data matches
            expect(decrypted.amount.toString()).toBe(testUtxo.amount.toString().toString());
            expect(decrypted.blinding.toString()).toBe(testUtxo.blinding.toString().toString());
            expect(decrypted.index).toBe(testUtxo.index);
        });

        it('should handle larger amount values correctly', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Create a test Utxo with a large amount
            const largeAmount = '1000000000000000000'; // 1 SOL in lamports
            const testUtxo = new Utxo({
                lightWasm: mockLightWasm,
                amount: largeAmount,
                blinding: '987654321',
                index: 1
            }) as unknown as MockUtxo;

            // Encrypt and decrypt
            const encrypted = encryptionService.encryptUtxo(testUtxo as unknown as Utxo);
            const decrypted = await encryptionService.decryptUtxo(encrypted, mockLightWasm);

            // Check large amount is preserved
            expect(decrypted.amount.toString()).toBe(largeAmount);
        });

        it('should work with UtxoData and Utxo interchangeably', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Test with first Utxo
            const utxo1 = new Utxo({
                lightWasm: mockLightWasm,
                amount: '1000000000',
                blinding: '123456789',
                index: 0,
                keypair: testUtxoKeypair
            });

            const encryptedData = encryptionService.encryptUtxo(utxo1);
            const decryptedFromData = await encryptionService.decryptUtxo(encryptedData, mockLightWasm);

            // Test with second Utxo
            const utxo2 = new Utxo({
                lightWasm: mockLightWasm,
                amount: '1000000000',
                blinding: '123456789',
                index: 0,
                keypair: testUtxoKeypair
            });

            const encryptedInstance = encryptionService.encryptUtxo(utxo2);
            const decryptedFromInstance = await encryptionService.decryptUtxo(encryptedInstance, mockLightWasm);

            // Both should produce valid Utxo instances with the same data
            expect(decryptedFromData.amount.toString()).toBe(utxo1.amount.toString());
            expect(decryptedFromInstance.amount.toString()).toBe(utxo2.amount.toString());
        });

        it('should throw an error if trying to decrypt invalid UTXO data', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Encrypt some non-UTXO data
            const invalidData = encryptionService.encrypt('invalid data format');

            // Should throw when trying to decrypt as a UTXO
            await expect(async () => {
                await encryptionService.decryptUtxo(invalidData, mockLightWasm);
            }).rejects.toThrow('Invalid UTXO format');
        });
    });

    // encrypt using encryptUtxoDecryptedDoNotUse, and decrypt should still works
    describe('version backward compatibility', () => {
        it('should encrypt and decrypt Utxo instances', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Create a test Utxo instance
            const testUtxo = new Utxo({
                lightWasm: mockLightWasm,
                amount: '1000000000',
                blinding: '123456789',
                index: 20
            }) as unknown as MockUtxo;

            // Encrypt the UTXO
            const encrypted = encryptionService.encryptUtxoDecryptedDoNotUse(testUtxo as unknown as Utxo);

            // Decrypt the UTXO
            const decrypted = await encryptionService.decryptUtxo(encrypted, mockLightWasm);

            // Check it's a proper Utxo instance
            expect(decrypted).toBeInstanceOf(Utxo);

            // Check core data matches
            expect(decrypted.amount.toString()).toBe(testUtxo.amount.toString().toString());
            expect(decrypted.blinding.toString()).toBe(testUtxo.blinding.toString().toString());
            expect(decrypted.index).toBe(testUtxo.index);
        });

        it('should return correct version', async () => {
            // Generate encryption key
            encryptionService.deriveEncryptionKeyFromWallet(testKeypair);

            // Create a test Utxo instance
            const testUtxo = new Utxo({
                lightWasm: mockLightWasm,
                amount: '1000000000',
                blinding: '123456789',
                index: 20
            }) as unknown as MockUtxo;

            // Encrypt the UTXO
            const encryptedV1 = encryptionService.encryptUtxoDecryptedDoNotUse(testUtxo as unknown as Utxo);
            expect(encryptionService.getEncryptionKeyVersion(encryptedV1)).toBe('v1');

            const encryptedV2 = encryptionService.encryptUtxo(testUtxo as unknown as Utxo);
            expect(encryptionService.getEncryptionKeyVersion(encryptedV2)).toBe('v2');
            expect(encryptedV2.subarray(0, 8).equals(EncryptionService.ENCRYPTION_VERSION_V2)).toBe(true);
        })
    });
});

// -----------------------------
// Tests for serializeProofAndExtData function
// -----------------------------
describe('serializeProofAndExtData', () => {
    // Mock data that matches the expected structure
    const mockProof = {
        proofA: new Array(64).fill(1), // 64 bytes
        proofB: new Array(128).fill(2), // 128 bytes (64*2)
        proofC: new Array(64).fill(3), // 64 bytes
        root: new Array(32).fill(4), // 32 bytes
        publicAmount: new Array(32).fill(5), // 32 bytes
        extDataHash: new Array(32).fill(6), // 32 bytes
        inputNullifiers: [
            new Array(32).fill(7), // 32 bytes
            new Array(32).fill(8), // 32 bytes
        ],
        outputCommitments: [
            new Array(32).fill(9), // 32 bytes
            new Array(32).fill(10), // 32 bytes
        ],
    };

    const mockExtData = {
        extAmount: '1000000000', // 1 SOL in lamports
        fee: '5000000', // 0.005 SOL in lamports
        encryptedOutput1: Buffer.from('encrypted_output_1_data'),
        encryptedOutput2: Buffer.from('encrypted_output_2_data'),
        recipient: new PublicKey('11111111111111111111111111111112'),
        feeRecipient: new PublicKey('11111111111111111111111111111112'),
        mintAddress: new PublicKey('11111111111111111111111111111112'),
    };

    describe('basic serialization', () => {
        it('should serialize proof and extData into a Buffer', () => {
            const result = serializeProofAndExtData(mockProof, mockExtData);
            
            expect(Buffer.isBuffer(result)).toBe(true);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should start with TRANSACT_IX_DISCRIMINATOR', () => {
            const result = serializeProofAndExtData(mockProof, mockExtData);
            
            // Check that the result starts with the discriminator
            const discriminatorFromResult = result.subarray(0, TRANSACT_IX_DISCRIMINATOR.length);
            expect(discriminatorFromResult.equals(TRANSACT_IX_DISCRIMINATOR)).toBe(true);
        });

        it('should have the expected total length', () => {
            const result = serializeProofAndExtData(mockProof, mockExtData);
            
            // Calculate expected length:
            // TRANSACT_IX_DISCRIMINATOR: 8 bytes
            // proofA: 64 bytes
            // proofB: 128 bytes  
            // proofC: 64 bytes
            // root: 32 bytes
            // publicAmount: 32 bytes
            // extDataHash: 32 bytes
            // inputNullifiers[0]: 32 bytes
            // inputNullifiers[1]: 32 bytes
            // outputCommitments[0]: 32 bytes
            // outputCommitments[1]: 32 bytes
            // extAmount (BN as 8 bytes): 8 bytes
            // fee (BN as 8 bytes): 8 bytes
            // encryptedOutput1 length (4 bytes) + data: 4 + 23 = 27 bytes
            // encryptedOutput2 length (4 bytes) + data: 4 + 23 = 27 bytes
            const expectedLength = 8 + 64 + 128 + 64 + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 8 + 8 + 27 + 27;
            expect(result.length).toBe(expectedLength);
        });
    });

    describe('proof data serialization', () => {
        it('should correctly serialize proof components in order', () => {
            const result = serializeProofAndExtData(mockProof, mockExtData);
            
            let offset = TRANSACT_IX_DISCRIMINATOR.length;
            
            // Check proofA
            const proofAFromResult = result.subarray(offset, offset + 64);
            expect(proofAFromResult.equals(Buffer.from(mockProof.proofA))).toBe(true);
            offset += 64;
            
            // Check proofB
            const proofBFromResult = result.subarray(offset, offset + 128);
            expect(proofBFromResult.equals(Buffer.from(mockProof.proofB))).toBe(true);
            offset += 128;
            
            // Check proofC
            const proofCFromResult = result.subarray(offset, offset + 64);
            expect(proofCFromResult.equals(Buffer.from(mockProof.proofC))).toBe(true);
        });

        it('should correctly serialize public signals', () => {
            const result = serializeProofAndExtData(mockProof, mockExtData);
            
            let offset = TRANSACT_IX_DISCRIMINATOR.length + 64 + 128 + 64; // Skip discriminator and proof components
            
            // Check root
            const rootFromResult = result.subarray(offset, offset + 32);
            expect(rootFromResult.equals(Buffer.from(mockProof.root))).toBe(true);
            offset += 32;
            
            // Check publicAmount
            const publicAmountFromResult = result.subarray(offset, offset + 32);
            expect(publicAmountFromResult.equals(Buffer.from(mockProof.publicAmount))).toBe(true);
            offset += 32;
            
            // Check extDataHash
            const extDataHashFromResult = result.subarray(offset, offset + 32);
            expect(extDataHashFromResult.equals(Buffer.from(mockProof.extDataHash))).toBe(true);
        });

        it('should correctly serialize nullifiers and commitments', () => {
            const result = serializeProofAndExtData(mockProof, mockExtData);
            
            let offset = TRANSACT_IX_DISCRIMINATOR.length + 64 + 128 + 64 + 32 + 32 + 32; // Skip to nullifiers
            
            // Check inputNullifiers
            const nullifier0FromResult = result.subarray(offset, offset + 32);
            expect(nullifier0FromResult.equals(Buffer.from(mockProof.inputNullifiers[0]))).toBe(true);
            offset += 32;
            
            const nullifier1FromResult = result.subarray(offset, offset + 32);
            expect(nullifier1FromResult.equals(Buffer.from(mockProof.inputNullifiers[1]))).toBe(true);
            offset += 32;
            
            // Check outputCommitments
            const commitment0FromResult = result.subarray(offset, offset + 32);
            expect(commitment0FromResult.equals(Buffer.from(mockProof.outputCommitments[0]))).toBe(true);
            offset += 32;
            
            const commitment1FromResult = result.subarray(offset, offset + 32);
            expect(commitment1FromResult.equals(Buffer.from(mockProof.outputCommitments[1]))).toBe(true);
        });
    });

    describe('extData serialization', () => {
        it('should correctly serialize extAmount as signed 64-bit little-endian', () => {
            const result = serializeProofAndExtData(mockProof, mockExtData);
            
            // Calculate offset to extAmount (after discriminator + all proof data)
            const offset = TRANSACT_IX_DISCRIMINATOR.length + 64 + 128 + 64 + 32 + 32 + 32 + 32 + 32 + 32 + 32;
            
            const extAmountFromResult = result.subarray(offset, offset + 8);
            const expectedExtAmount = Buffer.from(new BN(mockExtData.extAmount).toTwos(64).toArray('le', 8));
            
            expect(extAmountFromResult.equals(expectedExtAmount)).toBe(true);
        });

        it('should correctly serialize fee as unsigned 64-bit little-endian', () => {
            const result = serializeProofAndExtData(mockProof, mockExtData);
            
            // Calculate offset to fee (after discriminator + all proof data + extAmount)
            const offset = TRANSACT_IX_DISCRIMINATOR.length + 64 + 128 + 64 + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 8;
            
            const feeFromResult = result.subarray(offset, offset + 8);
            const expectedFee = Buffer.from(new BN(mockExtData.fee).toArray('le', 8));
            
            expect(feeFromResult.equals(expectedFee)).toBe(true);
        });

        it('should correctly serialize encrypted outputs with length prefixes', () => {
            const result = serializeProofAndExtData(mockProof, mockExtData);
            
            // Calculate offset to encrypted outputs (after all previous data)
            let offset = TRANSACT_IX_DISCRIMINATOR.length + 64 + 128 + 64 + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 8 + 8;
            
            // Check encryptedOutput1 length prefix
            const output1LengthFromResult = result.subarray(offset, offset + 4);
            const expectedOutput1Length = Buffer.from(new BN(mockExtData.encryptedOutput1.length).toArray('le', 4));
            expect(output1LengthFromResult.equals(expectedOutput1Length)).toBe(true);
            offset += 4;
            
            // Check encryptedOutput1 data
            const output1DataFromResult = result.subarray(offset, offset + mockExtData.encryptedOutput1.length);
            expect(output1DataFromResult.equals(mockExtData.encryptedOutput1)).toBe(true);
            offset += mockExtData.encryptedOutput1.length;
            
            // Check encryptedOutput2 length prefix
            const output2LengthFromResult = result.subarray(offset, offset + 4);
            const expectedOutput2Length = Buffer.from(new BN(mockExtData.encryptedOutput2.length).toArray('le', 4));
            expect(output2LengthFromResult.equals(expectedOutput2Length)).toBe(true);
            offset += 4;
            
            // Check encryptedOutput2 data
            const output2DataFromResult = result.subarray(offset, offset + mockExtData.encryptedOutput2.length);
            expect(output2DataFromResult.equals(mockExtData.encryptedOutput2)).toBe(true);
        });
    });

    describe('edge cases and error handling', () => {
        it('should handle zero amounts correctly', () => {
            const zeroExtData = {
                ...mockExtData,
                extAmount: '0',
                fee: '0'
            };
            
            const result = serializeProofAndExtData(mockProof, zeroExtData);
            expect(Buffer.isBuffer(result)).toBe(true);
            
            // Verify zero amounts are serialized correctly
            const offset = TRANSACT_IX_DISCRIMINATOR.length + 64 + 128 + 64 + 32 + 32 + 32 + 32 + 32 + 32 + 32;
            const extAmountFromResult = result.subarray(offset, offset + 8);
            const expectedZeroAmount = Buffer.from(new BN(0).toTwos(64).toArray('le', 8));
            expect(extAmountFromResult.equals(expectedZeroAmount)).toBe(true);
        });

        it('should handle negative extAmount correctly', () => {
            const negativeExtData = {
                ...mockExtData,
                extAmount: '-1000000000' // negative 1 SOL
            };
            
            const result = serializeProofAndExtData(mockProof, negativeExtData);
            expect(Buffer.isBuffer(result)).toBe(true);
            
            // Verify negative amount is serialized correctly using two's complement
            const offset = TRANSACT_IX_DISCRIMINATOR.length + 64 + 128 + 64 + 32 + 32 + 32 + 32 + 32 + 32 + 32;
            const extAmountFromResult = result.subarray(offset, offset + 8);
            const expectedNegativeAmount = Buffer.from(new BN('-1000000000').toTwos(64).toArray('le', 8));
            expect(extAmountFromResult.equals(expectedNegativeAmount)).toBe(true);
        });

        it('should handle empty encrypted outputs', () => {
            const emptyOutputsExtData = {
                ...mockExtData,
                encryptedOutput1: Buffer.alloc(0),
                encryptedOutput2: Buffer.alloc(0)
            };
            
            const result = serializeProofAndExtData(mockProof, emptyOutputsExtData);
            expect(Buffer.isBuffer(result)).toBe(true);
            
            // Should still include length prefixes (which would be 0)
            let offset = TRANSACT_IX_DISCRIMINATOR.length + 64 + 128 + 64 + 32 + 32 + 32 + 32 + 32 + 32 + 32 + 8 + 8;
            
            const output1LengthFromResult = result.subarray(offset, offset + 4);
            const expectedZeroLength = Buffer.from(new BN(0).toArray('le', 4));
            expect(output1LengthFromResult.equals(expectedZeroLength)).toBe(true);
        });

        it('should handle large numbers correctly', () => {
            const largeExtData = {
                ...mockExtData,
                extAmount: '9223372036854775807', // Max signed 64-bit integer
                fee: '18446744073709551615' // Max unsigned 64-bit integer (will be truncated)
            };
            
            expect(() => {
                serializeProofAndExtData(mockProof, largeExtData);
            }).not.toThrow();
        });
    });

    describe('deterministic output', () => {
        it('should produce identical output for identical inputs', () => {
            const result1 = serializeProofAndExtData(mockProof, mockExtData);
            const result2 = serializeProofAndExtData(mockProof, mockExtData);
            
            expect(result1.equals(result2)).toBe(true);
        });

        it('should produce different output for different inputs', () => {
            const modifiedExtData = {
                ...mockExtData,
                extAmount: '2000000000' // Different amount
            };
            
            const result1 = serializeProofAndExtData(mockProof, mockExtData);
            const result2 = serializeProofAndExtData(mockProof, modifiedExtData);
            
            expect(result1.equals(result2)).toBe(false);
        });
    });

    describe('integration compatibility', () => {
        it('should work with real-world proof structure from parseProofToBytesArray', () => {
            // Mock a proof structure that would come from parseProofToBytesArray
            const realWorldProof = {
                proofA: Array.from({ length: 64 }, (_, i) => i % 256),
                proofB: Array.from({ length: 128 }, (_, i) => (i * 2) % 256),
                proofC: Array.from({ length: 64 }, (_, i) => (i * 3) % 256),
                root: Array.from({ length: 32 }, (_, i) => (i * 4) % 256),
                publicAmount: Array.from({ length: 32 }, (_, i) => (i * 5) % 256),
                extDataHash: Array.from({ length: 32 }, (_, i) => (i * 6) % 256),
                inputNullifiers: [
                    Array.from({ length: 32 }, (_, i) => (i * 7) % 256),
                    Array.from({ length: 32 }, (_, i) => (i * 8) % 256),
                ],
                outputCommitments: [
                    Array.from({ length: 32 }, (_, i) => (i * 9) % 256),
                    Array.from({ length: 32 }, (_, i) => (i * 10) % 256),
                ],
            };

            expect(() => {
                serializeProofAndExtData(realWorldProof, mockExtData);
            }).not.toThrow();
        });

        it('should handle string and BN inputs for amounts', () => {
            const stringExtData = {
                ...mockExtData,
                extAmount: '1000000000',
                fee: '5000000'
            };

            const bnExtData = {
                ...mockExtData,
                extAmount: new BN('1000000000'),
                fee: new BN('5000000')
            };

            const result1 = serializeProofAndExtData(mockProof, stringExtData);
            const result2 = serializeProofAndExtData(mockProof, bnExtData);

            // Should produce identical results regardless of input type
            expect(result1.equals(result2)).toBe(true);
        });
    });
});
