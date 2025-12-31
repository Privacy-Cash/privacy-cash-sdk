import { Connection, Keypair, PublicKey, TransactionInstruction, SystemProgram, ComputeBudgetProgram, VersionedTransaction, TransactionMessage, AddressLookupTableProgram } from '@solana/web3.js';
import BN from 'bn.js';
import { Utxo } from './models/utxo.js';
import { fetchMerkleProof, findNullifierPDAs, getProgramAccounts, queryRemoteTreeState, findCrossCheckNullifierPDAs, getExtDataHash, getMintAddressField } from './utils/utils.js';
import { prove, parseProofToBytesArray, parseToBytesArray } from './utils/prover.js';
import * as hasher from '@lightprotocol/hasher.rs';
import { MerkleTree } from './utils/merkle_tree.js';
import { EncryptionService, serializeProofAndExtData } from './utils/encryption.js';
import { Keypair as UtxoKeypair } from './models/keypair.js';
import { getUtxosSPL, isUtxoSpent } from './getUtxosSPL.js';
import { FIELD_SIZE, FEE_RECIPIENT, MERKLE_TREE_DEPTH, RELAYER_API_URL, PROGRAM_ID, ALT_ADDRESS, tokens, SplList, Token } from './utils/constants.js';
import { getProtocolAddressesWithMint, useExistingALT } from './utils/address_lookup_table.js';
import { logger } from './utils/logger.js';
import { getAssociatedTokenAddress, ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID, getAssociatedTokenAddressSync, getMint, getAccount } from '@solana/spl-token';


// Function to relay pre-signed deposit transaction to indexer backend
async function relayDepositToIndexer({ signedTransaction, publicKey, referrer, mintAddress }:
    {
        signedTransaction: string,
        publicKey: PublicKey,
        mintAddress: string,
        referrer?: string
    })
    : Promise<string> {
    try {
        logger.debug('Relaying pre-signed deposit transaction to indexer backend...');

        const params: any = {
            signedTransaction,
            senderAddress: publicKey.toString()
        };

        if (referrer) {
            params.referralWalletAddress = referrer
        }
        params.mintAddress = mintAddress

        const response = await fetch(`${RELAYER_API_URL}/deposit/spl`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params)
        });

        if (!response.ok) {
            logger.debug('res text:', await response.text())
            throw new Error('response not ok')
            // const errorData = await response.json() as { error?: string };
            // throw new Error(`Deposit relay failed: ${response.status} ${response.statusText} - ${errorData.error || 'Unknown error'}`);
        }
        let result: { signature: string, success: boolean }
        try {
            result = await response.json()
            logger.debug('Pre-signed deposit transaction relayed successfully!');
            logger.debug('Response:', result);
        } catch (e) {
            console.log('response.text', await response.text())
            throw new Error('failed to parse json')
        }
        return result.signature;
    } catch (error: any) {
        console.error('Failed to relay deposit transaction to indexer:', error.message);
        throw error;
    }
}

type DepositParams = {
    mintAddress: PublicKey | string,
    publicKey: PublicKey,
    connection: Connection,
    base_units?: number,
    amount?: number,
    storage: Storage,
    encryptionService: EncryptionService,
    keyBasePath: string,
    lightWasm: hasher.LightWasm,
    referrer?: string,
    transactionSigner: (tx: VersionedTransaction) => Promise<VersionedTransaction>
}
export async function depositSPL({ lightWasm, storage, keyBasePath, publicKey, connection, base_units, amount, encryptionService, transactionSigner, referrer, mintAddress }: DepositParams) {
    if (typeof mintAddress == 'string') {
        mintAddress = new PublicKey(mintAddress)
    }
    let token = tokens.find(t => t.pubkey.toString() == mintAddress.toString())
    if (!token) {
        throw new Error('token not found: ' + mintAddress.toString())
    }

    if (amount) {
        base_units = amount * token.units_per_token
    }

    if (!base_units) {
        throw new Error('You must input at least one of "base_units" or "amount"')
    }


    // let mintInfo = await getMint(connection, token.pubkey)
    // let units_per_token = 10 ** mintInfo.decimals

    let recipient = new PublicKey('AWexibGxNFKTa1b5R5MN4PJr9HWnWRwf8EW9g8cLx3dM')
    let recipient_ata = getAssociatedTokenAddressSync(
        token.pubkey,
        recipient,
        true
    );
    let feeRecipientTokenAccount = getAssociatedTokenAddressSync(
        token.pubkey,
        FEE_RECIPIENT,
        true
    );
    let signerTokenAccount = getAssociatedTokenAddressSync(
        token.pubkey,
        publicKey
    );

    // Derive tree account PDA with mint address for SPL
    const [treeAccount] = PublicKey.findProgramAddressSync(
        [Buffer.from('merkle_tree'), token.pubkey.toBuffer()],
        PROGRAM_ID
    );

    let limitAmount = await checkDepositLimit(connection, treeAccount, token)
    if (limitAmount && base_units > limitAmount * token.units_per_token) {
        throw new Error(`Don't deposit more than ${limitAmount} ${token.name.toUpperCase()}`)
    }

    // const base_units = amount_in_sol * units_per_token
    const fee_base_units = 0
    logger.debug('Encryption key generated from user keypair');
    logger.debug(`User wallet: ${publicKey.toString()}`);
    logger.debug(`Deposit amount: ${base_units} base_units (${base_units / token.units_per_token}  ${token.name.toUpperCase()})`);
    logger.debug(`Calculated fee: ${fee_base_units} base_units (${fee_base_units / token.units_per_token}  ${token.name.toUpperCase()})`);

    // Check SPL balance
    const accountInfo = await getAccount(connection, signerTokenAccount)
    let balance = Number(accountInfo.amount)
    logger.debug(`wallet balance: ${balance / token.units_per_token}  ${token.name.toUpperCase()}`);
    logger.debug('balance', balance)
    logger.debug('base_units + fee_base_units', base_units + fee_base_units)

    if (balance < (base_units + fee_base_units)) {
        throw new Error(`Insufficient balance. Need at least ${(base_units + fee_base_units) / token.units_per_token}  ${token.name.toUpperCase()}.`);
    }

    // Check SOL balance
    const solBalance = await connection.getBalance(publicKey);
    logger.debug(`SOL Wallet balance: ${solBalance / 1e9} SOL`);

    if (solBalance / 1e9 < 0.002) {
        throw new Error(`Need at least 0.002 SOL for Solana fees.`);
    }

    const { globalConfigAccount } = getProgramAccounts()

    // Create the merkle tree with the pre-initialized poseidon hash
    const tree = new MerkleTree(MERKLE_TREE_DEPTH, lightWasm);

    // Initialize root and nextIndex variables
    const { root, nextIndex: currentNextIndex } = await queryRemoteTreeState(token.name);

    logger.debug(`Using tree root: ${root}`);
    logger.debug(`New UTXOs will be inserted at indices: ${currentNextIndex} and ${currentNextIndex + 1}`);

    // Generate a deterministic private key derived from the wallet keypair
    // const utxoPrivateKey = encryptionService.deriveUtxoPrivateKey();
    const utxoPrivateKey = encryptionService.getUtxoPrivateKeyV2();

    // Create a UTXO keypair that will be used for all inputs and outputs
    const utxoKeypair = new UtxoKeypair(utxoPrivateKey, lightWasm);
    logger.debug('Using wallet-derived UTXO keypair for deposit');

    // Fetch existing UTXOs for this user
    logger.debug('\nFetching existing UTXOs...');
    const mintUtxos = await getUtxosSPL({ connection, publicKey, encryptionService, storage, mintAddress });

    // Calculate output amounts and external amount based on scenario
    let extAmount: number;
    let outputAmount: string;

    // Create inputs based on whether we have existing UTXOs
    let inputs: Utxo[];
    let inputMerklePathIndices: number[];
    let inputMerklePathElements: string[][];

    if (mintUtxos.length === 0) {
        // Scenario 1: Fresh deposit with dummy inputs - add new funds to the system
        extAmount = base_units;
        outputAmount = new BN(base_units).sub(new BN(fee_base_units)).toString();

        logger.debug(`Fresh deposit scenario (no existing UTXOs):`);
        logger.debug(`External amount (deposit): ${extAmount}`);
        logger.debug(`Fee amount: ${fee_base_units}`);
        logger.debug(`Output amount: ${outputAmount}`);

        // Use two dummy UTXOs as inputs
        inputs = [
            new Utxo({
                lightWasm,
                keypair: utxoKeypair,
                mintAddress: token.pubkey.toString()
            }),
            new Utxo({
                lightWasm,
                keypair: utxoKeypair,
                mintAddress: token.pubkey.toString()
            })
        ];

        // Both inputs are dummy, so use mock indices and zero-filled Merkle paths
        inputMerklePathIndices = inputs.map((input) => input.index || 0);
        inputMerklePathElements = inputs.map(() => {
            return [...new Array(tree.levels).fill("0")];
        });
    } else {
        // Scenario 2: Deposit that consolidates with existing UTXO(s)
        const firstUtxo = mintUtxos[0];
        const firstUtxoAmount = firstUtxo.amount;
        const secondUtxoAmount = mintUtxos.length > 1 ? mintUtxos[1].amount : new BN(0);
        extAmount = base_units; // Still depositing new funds

        // Output combines existing UTXO amounts + new deposit amount - fee
        outputAmount = firstUtxoAmount.add(secondUtxoAmount).add(new BN(base_units)).sub(new BN(fee_base_units)).toString();

        logger.debug(`Deposit with consolidation scenario:`);
        logger.debug(`First existing UTXO amount: ${firstUtxoAmount.toString()}`);
        if (secondUtxoAmount.gt(new BN(0))) {
            logger.debug(`Second existing UTXO amount: ${secondUtxoAmount.toString()}`);
        }
        logger.debug(`New deposit amount: ${base_units}`);
        logger.debug(`Fee amount: ${fee_base_units}`);
        logger.debug(`Output amount (existing UTXOs + deposit - fee): ${outputAmount}`);
        logger.debug(`External amount (deposit): ${extAmount}`);

        logger.debug('\nFirst UTXO to be consolidated:');

        // Use first existing UTXO as first input, and either second UTXO or dummy UTXO as second input
        const secondUtxo = mintUtxos.length > 1 ? mintUtxos[1] : new Utxo({
            lightWasm,
            keypair: utxoKeypair,
            amount: '0', // This UTXO will be inserted at currentNextIndex
            mintAddress: token.pubkey.toString()
        });

        inputs = [
            firstUtxo, // Use the first existing UTXO
            secondUtxo // Use second UTXO if available, otherwise dummy
        ];

        // Fetch Merkle proofs for real UTXOs
        const firstUtxoCommitment = await firstUtxo.getCommitment();
        const firstUtxoMerkleProof = await fetchMerkleProof(firstUtxoCommitment, token.name);

        let secondUtxoMerkleProof;
        if (secondUtxo.amount.gt(new BN(0))) {
            // Second UTXO is real, fetch its proof
            const secondUtxoCommitment = await secondUtxo.getCommitment();
            secondUtxoMerkleProof = await fetchMerkleProof(secondUtxoCommitment, token.name);
            logger.debug('\nSecond UTXO to be consolidated:');
            await secondUtxo.log();
        }

        // Use the real pathIndices from API for real inputs, mock index for dummy input
        inputMerklePathIndices = [
            firstUtxo.index || 0, // Use the real UTXO's index  
            secondUtxo.amount.gt(new BN(0)) ? (secondUtxo.index || 0) : 0 // Real UTXO index or dummy
        ];

        // Create Merkle path elements: real proof for real inputs, zeros for dummy input
        inputMerklePathElements = [
            firstUtxoMerkleProof.pathElements, // Real Merkle proof for first existing UTXO
            secondUtxo.amount.gt(new BN(0)) ? secondUtxoMerkleProof!.pathElements : [...new Array(tree.levels).fill("0")] // Real proof or zero-filled for dummy
        ];

        logger.debug(`Using first UTXO with amount: ${firstUtxo.amount.toString()} and index: ${firstUtxo.index}`);
        logger.debug(`Using second ${secondUtxo.amount.gt(new BN(0)) ? 'UTXO' : 'dummy UTXO'} with amount: ${secondUtxo.amount.toString()}${secondUtxo.amount.gt(new BN(0)) ? ` and index: ${secondUtxo.index}` : ''}`);
        logger.debug(`First UTXO Merkle proof path indices from API: [${firstUtxoMerkleProof.pathIndices.join(', ')}]`);
        if (secondUtxo.amount.gt(new BN(0))) {
            logger.debug(`Second UTXO Merkle proof path indices from API: [${secondUtxoMerkleProof!.pathIndices.join(', ')}]`);
        }
    }

    const publicAmountForCircuit = new BN(extAmount).sub(new BN(fee_base_units)).add(FIELD_SIZE).mod(FIELD_SIZE);
    logger.debug(`Public amount calculation: (${extAmount} - ${fee_base_units} + FIELD_SIZE) % FIELD_SIZE = ${publicAmountForCircuit.toString()}`);

    // Create outputs for the transaction with the same shared keypair
    const outputs = [
        new Utxo({
            lightWasm,
            amount: outputAmount,
            keypair: utxoKeypair,
            index: currentNextIndex, // This UTXO will be inserted at currentNextIndex
            mintAddress: token.pubkey.toString()
        }), // Output with value (either deposit amount minus fee, or input amount minus fee)
        new Utxo({
            lightWasm,
            amount: '0',
            keypair: utxoKeypair,
            index: currentNextIndex + 1, // This UTXO will be inserted at currentNextIndex
            mintAddress: token.pubkey.toString()
        }) // Empty UTXO
    ];

    // Verify this matches the circuit balance equation: sumIns + publicAmount = sumOuts
    const sumIns = inputs.reduce((sum, input) => sum.add(input.amount), new BN(0));
    const sumOuts = outputs.reduce((sum, output) => sum.add(output.amount), new BN(0));
    logger.debug(`Circuit balance check: sumIns(${sumIns.toString()}) + publicAmount(${publicAmountForCircuit.toString()}) should equal sumOuts(${sumOuts.toString()})`);

    // Convert to circuit-compatible format
    const publicAmountCircuitResult = sumIns.add(publicAmountForCircuit).mod(FIELD_SIZE);
    logger.debug(`Balance verification: ${sumIns.toString()} + ${publicAmountForCircuit.toString()} (mod FIELD_SIZE) = ${publicAmountCircuitResult.toString()}`);
    logger.debug(`Expected sum of outputs: ${sumOuts.toString()}`);
    logger.debug(`Balance equation satisfied: ${publicAmountCircuitResult.eq(sumOuts)}`);

    // Generate nullifiers and commitments
    const inputNullifiers = await Promise.all(inputs.map(x => x.getNullifier()));
    const outputCommitments = await Promise.all(outputs.map(x => x.getCommitment()));

    // Save original commitment and nullifier values for verification
    logger.debug('\n=== UTXO VALIDATION ===');
    logger.debug('Output 0 Commitment:', outputCommitments[0]);
    logger.debug('Output 1 Commitment:', outputCommitments[1]);

    // Encrypt the UTXO data using a compact format that includes the keypair
    logger.debug('\nEncrypting UTXOs with keypair data...');
    const encryptedOutput1 = encryptionService.encryptUtxo(outputs[0]);
    const encryptedOutput2 = encryptionService.encryptUtxo(outputs[1]);

    // logger.debug(`\nOutput[0] (with value):`);
    // await outputs[0].log();
    // logger.debug(`\nOutput[1] (empty):`);
    // await outputs[1].log();

    logger.debug(`\nEncrypted output 1 size: ${encryptedOutput1.length} bytes`);
    logger.debug(`Encrypted output 2 size: ${encryptedOutput2.length} bytes`);
    logger.debug(`Total encrypted outputs size: ${encryptedOutput1.length + encryptedOutput2.length} bytes`);

    // Test decryption to verify commitment values match
    logger.debug('\n=== TESTING DECRYPTION ===');
    logger.debug('Decrypting output 1 to verify commitment matches...');
    const decryptedUtxo1 = await encryptionService.decryptUtxo(encryptedOutput1, lightWasm);
    const decryptedCommitment1 = await decryptedUtxo1.getCommitment();
    logger.debug('Original commitment:', outputCommitments[0]);
    logger.debug('Decrypted commitment:', decryptedCommitment1);
    logger.debug('Commitment matches:', outputCommitments[0] === decryptedCommitment1);

    // Create the deposit ExtData with real encrypted outputs
    const extData = {
        // recipient - just a placeholder, not actually used for deposits. 
        recipient: recipient_ata,
        extAmount: new BN(extAmount),
        encryptedOutput1: encryptedOutput1,
        encryptedOutput2: encryptedOutput2,
        fee: new BN(fee_base_units),
        feeRecipient: feeRecipientTokenAccount,
        mintAddress: token.pubkey.toString()
    };
    // Calculate the extDataHash with the encrypted outputs (now includes mintAddress for security)
    const calculatedExtDataHash = getExtDataHash(extData);

    // Create the input for the proof generation (must match circuit input order exactly)
    const input = {
        // Common transaction data
        root: root,
        mintAddress: getMintAddressField(token.pubkey),// new mint address
        publicAmount: publicAmountForCircuit.toString(), // Use proper field arithmetic result
        extDataHash: calculatedExtDataHash,

        // Input UTXO data (UTXOs being spent) - ensure all values are in decimal format
        inAmount: inputs.map(x => x.amount.toString(10)),
        inPrivateKey: inputs.map(x => x.keypair.privkey),
        inBlinding: inputs.map(x => x.blinding.toString(10)),
        inPathIndices: inputMerklePathIndices,
        inPathElements: inputMerklePathElements,
        inputNullifier: inputNullifiers, // Use resolved values instead of Promise objects

        // Output UTXO data (UTXOs being created) - ensure all values are in decimal format
        outAmount: outputs.map(x => x.amount.toString(10)),
        outBlinding: outputs.map(x => x.blinding.toString(10)),
        outPubkey: outputs.map(x => x.keypair.pubkey),
        outputCommitment: outputCommitments,
    };

    logger.info('generating ZK proof...');

    // Generate the zero-knowledge proof
    const { proof, publicSignals } = await prove(input, keyBasePath);
    // Parse the proof and public signals into byte arrays
    const proofInBytes = parseProofToBytesArray(proof);
    const inputsInBytes = parseToBytesArray(publicSignals);

    // Create the proof object to submit to the program
    const proofToSubmit = {
        proofA: proofInBytes.proofA,
        proofB: proofInBytes.proofB.flat(),
        proofC: proofInBytes.proofC,
        root: inputsInBytes[0],
        publicAmount: inputsInBytes[1],
        extDataHash: inputsInBytes[2],
        inputNullifiers: [
            inputsInBytes[3],
            inputsInBytes[4]
        ],
        outputCommitments: [
            inputsInBytes[5],
            inputsInBytes[6]
        ],
    };

    // Find PDAs for nullifiers and commitments
    const { nullifier0PDA, nullifier1PDA } = findNullifierPDAs(proofToSubmit);
    const { nullifier2PDA, nullifier3PDA } = findCrossCheckNullifierPDAs(proofToSubmit);

    const [globalConfigPda, globalConfigPdaBump] = await PublicKey.findProgramAddressSync(
        [Buffer.from("global_config")],
        PROGRAM_ID
    );
    const treeAta = getAssociatedTokenAddressSync(token.pubkey, globalConfigPda, true);

    const lookupTableAccount = await useExistingALT(connection, ALT_ADDRESS);

    if (!lookupTableAccount?.value) {
        throw new Error(`ALT not found at address ${ALT_ADDRESS.toString()} `);
    }

    // Serialize the proof and extData with SPL discriminator
    const serializedProof = serializeProofAndExtData(proofToSubmit, extData, true);
    logger.debug(`Total instruction data size: ${serializedProof.length} bytes`);

    // Create the deposit instruction (user signs, not relayer)
    const depositInstruction = new TransactionInstruction({
        keys: [
            { pubkey: treeAccount, isSigner: false, isWritable: true },
            { pubkey: nullifier0PDA, isSigner: false, isWritable: true },
            { pubkey: nullifier1PDA, isSigner: false, isWritable: true },
            { pubkey: nullifier2PDA, isSigner: false, isWritable: false },
            { pubkey: nullifier3PDA, isSigner: false, isWritable: false },

            { pubkey: globalConfigAccount, isSigner: false, isWritable: false },
            // signer
            { pubkey: publicKey, isSigner: true, isWritable: true },
            // SPL token mint
            { pubkey: token.pubkey, isSigner: false, isWritable: false },
            // signer's token account
            { pubkey: signerTokenAccount, isSigner: false, isWritable: true },
            // recipient (placeholder)
            { pubkey: recipient, isSigner: false, isWritable: true },
            // recipient's token account (placeholder)
            { pubkey: recipient_ata, isSigner: false, isWritable: true },
            // tree ATA
            { pubkey: treeAta, isSigner: false, isWritable: true },
            // fee recipient token account
            { pubkey: feeRecipientTokenAccount, isSigner: false, isWritable: true },

            // token program id
            { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
            // ATA program
            { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
            // system protgram
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },

        ],
        programId: PROGRAM_ID,
        data: serializedProof,
    });

    // Set compute budget for the transaction
    const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_000_000
    });

    // Create versioned transaction with Address Lookup Table
    const recentBlockhash = await connection.getLatestBlockhash();

    const messageV0 = new TransactionMessage({
        payerKey: publicKey, // User pays for their own deposit
        recentBlockhash: recentBlockhash.blockhash,
        instructions: [modifyComputeUnits, depositInstruction],
    }).compileToV0Message([lookupTableAccount.value]);


    let versionedTransaction = new VersionedTransaction(messageV0);

    // sign tx
    versionedTransaction = await transactionSigner(versionedTransaction)

    logger.debug('Transaction signed by user');

    // Serialize the signed transaction for relay
    const serializedTransaction = Buffer.from(versionedTransaction.serialize()).toString('base64');

    logger.debug('Prepared signed transaction for relay to indexer backend');

    // Relay the pre-signed transaction to indexer backend
    logger.info('submitting transaction to relayer...')
    const signature = await relayDepositToIndexer({
        mintAddress: token.pubkey.toString(),
        publicKey,
        signedTransaction: serializedTransaction,
        referrer
    });
    logger.debug('Transaction signature:', signature);
    logger.debug(`Transaction link: https://explorer.solana.com/tx/${signature}`);

    logger.info('Waiting for transaction confirmation...')

    let retryTimes = 0
    let itv = 2
    const encryptedOutputStr = Buffer.from(encryptedOutput1).toString('hex')
    let start = Date.now()
    while (true) {
        logger.debug(`retryTimes: ${retryTimes}`)
        await new Promise(resolve => setTimeout(resolve, itv * 1000));
        logger.debug('Fetching updated tree state...');
        let url = RELAYER_API_URL + '/utxos/check/' + encryptedOutputStr + '?token=' + token.name
        let res = await fetch(url)
        let resJson = await res.json()
        if (resJson.exists) {
            logger.debug(`Top up successfully in ${((Date.now() - start) / 1000).toFixed(2)} seconds!`);
            return { tx: signature }
        }
        if (retryTimes >= 10) {
            throw new Error('Refresh the page to see latest balance.')
        }
        retryTimes++
    }

}


async function checkDepositLimit(connection: Connection, treeAccount: PublicKey, token: Token) {
    try {

        // Fetch the account data
        const accountInfo = await connection.getAccountInfo(treeAccount);

        if (!accountInfo) {
            console.error('❌ Tree account not found. Make sure the program is initialized.');
            return;
        }

        const authority = new PublicKey(accountInfo.data.slice(8, 40));
        const nextIndex = new BN(accountInfo.data.slice(40, 48), 'le');
        const rootIndex = new BN(accountInfo.data.slice(4112, 4120), 'le');
        const maxDepositAmount = new BN(accountInfo.data.slice(4120, 4128), 'le');
        const bump = accountInfo.data[4128];

        // Convert to SPL using BN division to handle large numbers
        const unitesPerToken = new BN(token.units_per_token);
        const maxDepositSpl = maxDepositAmount.div(unitesPerToken);
        const remainder = maxDepositAmount.mod(unitesPerToken);

        // Format the SPL amount with decimals
        let amountFormatted = '1';
        if (remainder.eq(new BN(0))) {
            amountFormatted = maxDepositSpl.toString();
        } else {
            // Handle fractional SPL by converting remainder to decimal
            const fractional = remainder.toNumber() / token.units_per_token;
            amountFormatted = `${maxDepositSpl.toString()}${fractional.toFixed(Math.log10(token.units_per_token)).substring(1)}`;
        }
        return Number(amountFormatted)

    } catch (error) {
        console.log('❌ Error reading deposit limit:', error);
        throw error
    }
}