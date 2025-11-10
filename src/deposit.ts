import { Connection, Keypair, PublicKey, TransactionInstruction, SystemProgram, ComputeBudgetProgram, VersionedTransaction, TransactionMessage, LAMPORTS_PER_SOL } from '@solana/web3.js';
import BN from 'bn.js';
import { Utxo } from './models/utxo.js';
import { fetchMerkleProof, findNullifierPDAs, getExtDataHash, getProgramAccounts, queryRemoteTreeState, findCrossCheckNullifierPDAs } from './utils/utils.js';
import { prove, parseProofToBytesArray, parseToBytesArray } from './utils/prover.js';
import * as hasher from '@lightprotocol/hasher.rs';
import { MerkleTree } from './utils/merkle_tree.js';
import { EncryptionService, serializeProofAndExtData } from './utils/encryption.js';
import { Keypair as UtxoKeypair } from './models/keypair.js';
import { getUtxos, isUtxoSpent } from './getUtxos.js';
import { FIELD_SIZE, FEE_RECIPIENT, MERKLE_TREE_DEPTH, INDEXER_API_URL, PROGRAM_ID } from './utils/constants.js';
import { useExistingALT } from './utils/address_lookup_table.js';
import { logger } from './utils/logger.js';


// Function to relay pre-signed deposit transaction to indexer backend
async function relayDepositToIndexer(signedTransaction: string, publicKey: PublicKey, referrer?: string): Promise<string> {
    try {
        logger.debug('Relaying pre-signed deposit transaction to indexer backend...');

        const params: any = {
            signedTransaction,
            senderAddress: publicKey.toString()
        };

        if (referrer) {
            params.referralWalletAddress = referrer
        }

        const response = await fetch(`${INDEXER_API_URL}/deposit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params)
        });

        if (!response.ok) {
            logger.error('res text:', await response.text())
            throw new Error('response not ok')
            // const errorData = await response.json() as { error?: string };
            // throw new Error(`Deposit relay failed: ${response.status} ${response.statusText} - ${errorData.error || 'Unknown error'}`);
        }

        const result = await response.json() as { signature: string, success: boolean };
        logger.debug('Pre-signed deposit transaction relayed successfully!');
        logger.debug('Response:', result);

        return result.signature;
    } catch (error) {
        console.error('Failed to relay deposit transaction to indexer:', error);
        throw error;
    }
}

type DepositParams = {
    publicKey: PublicKey,
    connection: Connection,
    amount_in_lamports: number,
    storage: Storage,
    encryptionService: EncryptionService,
    keyBasePath: string,
    lightWasm: hasher.LightWasm,
    referrer?: string,
    transactionSigner: (tx: VersionedTransaction) => Promise<VersionedTransaction>
}
export async function deposit({ lightWasm, storage, keyBasePath, publicKey, connection, amount_in_lamports, encryptionService, transactionSigner, referrer }: DepositParams) {
    // check limit
    let limitAmount = await checkDepositLimit(connection)
    if (limitAmount && amount_in_lamports > limitAmount * LAMPORTS_PER_SOL) {
        throw new Error(`Don't deposit more than ${limitAmount} SOL`)
    }

    // const amount_in_lamports = amount_in_sol * LAMPORTS_PER_SOL
    const fee_amount_in_lamports = 0
    logger.debug('Encryption key generated from user keypair');
    logger.debug(`User wallet: ${publicKey.toString()}`);
    logger.debug(`Deposit amount: ${amount_in_lamports} lamports (${amount_in_lamports / LAMPORTS_PER_SOL} SOL)`);
    logger.debug(`Calculated fee: ${fee_amount_in_lamports} lamports (${fee_amount_in_lamports / LAMPORTS_PER_SOL} SOL)`);

    // Check wallet balance
    const balance = await connection.getBalance(publicKey);
    logger.debug(`Wallet balance: ${balance / 1e9} SOL`);

    if (balance < amount_in_lamports + fee_amount_in_lamports) {
        new Error(`Insufficient balance: ${balance / 1e9} SOL. Need at least ${(amount_in_lamports + fee_amount_in_lamports) / LAMPORTS_PER_SOL} SOL.`);
    }

    const { treeAccount, treeTokenAccount, globalConfigAccount } = getProgramAccounts()

    // Create the merkle tree with the pre-initialized poseidon hash
    const tree = new MerkleTree(MERKLE_TREE_DEPTH, lightWasm);

    // Initialize root and nextIndex variables
    const { root, nextIndex: currentNextIndex } = await queryRemoteTreeState();

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
    const existingUnspentUtxos = await getUtxos({ connection, publicKey, encryptionService, storage });

    // Calculate output amounts and external amount based on scenario
    let extAmount: number;
    let outputAmount: string;

    // Create inputs based on whether we have existing UTXOs
    let inputs: Utxo[];
    let inputMerklePathIndices: number[];
    let inputMerklePathElements: string[][];

    if (existingUnspentUtxos.length === 0) {
        // Scenario 1: Fresh deposit with dummy inputs - add new funds to the system
        extAmount = amount_in_lamports;
        outputAmount = new BN(amount_in_lamports).sub(new BN(fee_amount_in_lamports)).toString();

        logger.debug(`Fresh deposit scenario (no existing UTXOs):`);
        logger.debug(`External amount (deposit): ${extAmount}`);
        logger.debug(`Fee amount: ${fee_amount_in_lamports}`);
        logger.debug(`Output amount: ${outputAmount}`);

        // Use two dummy UTXOs as inputs
        inputs = [
            new Utxo({
                lightWasm,
                keypair: utxoKeypair
            }),
            new Utxo({
                lightWasm,
                keypair: utxoKeypair
            })
        ];

        // Both inputs are dummy, so use mock indices and zero-filled Merkle paths
        inputMerklePathIndices = inputs.map((input) => input.index || 0);
        inputMerklePathElements = inputs.map(() => {
            return [...new Array(tree.levels).fill("0")];
        });
    } else {
        // Scenario 2: Deposit that consolidates with existing UTXO(s)
        const firstUtxo = existingUnspentUtxos[0];
        const firstUtxoAmount = firstUtxo.amount;
        const secondUtxoAmount = existingUnspentUtxos.length > 1 ? existingUnspentUtxos[1].amount : new BN(0);
        extAmount = amount_in_lamports; // Still depositing new funds

        // Output combines existing UTXO amounts + new deposit amount - fee
        outputAmount = firstUtxoAmount.add(secondUtxoAmount).add(new BN(amount_in_lamports)).sub(new BN(fee_amount_in_lamports)).toString();

        logger.debug(`Deposit with consolidation scenario:`);
        logger.debug(`First existing UTXO amount: ${firstUtxoAmount.toString()}`);
        if (secondUtxoAmount.gt(new BN(0))) {
            logger.debug(`Second existing UTXO amount: ${secondUtxoAmount.toString()}`);
        }
        logger.debug(`New deposit amount: ${amount_in_lamports}`);
        logger.debug(`Fee amount: ${fee_amount_in_lamports}`);
        logger.debug(`Output amount (existing UTXOs + deposit - fee): ${outputAmount}`);
        logger.debug(`External amount (deposit): ${extAmount}`);

        logger.debug('\nFirst UTXO to be consolidated:');
        await firstUtxo.log();

        // Use first existing UTXO as first input, and either second UTXO or dummy UTXO as second input
        const secondUtxo = existingUnspentUtxos.length > 1 ? existingUnspentUtxos[1] : new Utxo({
            lightWasm,
            keypair: utxoKeypair,
            amount: '0'
        });

        inputs = [
            firstUtxo, // Use the first existing UTXO
            secondUtxo // Use second UTXO if available, otherwise dummy
        ];

        // Fetch Merkle proofs for real UTXOs
        const firstUtxoCommitment = await firstUtxo.getCommitment();
        const firstUtxoMerkleProof = await fetchMerkleProof(firstUtxoCommitment);

        let secondUtxoMerkleProof;
        if (secondUtxo.amount.gt(new BN(0))) {
            // Second UTXO is real, fetch its proof
            const secondUtxoCommitment = await secondUtxo.getCommitment();
            secondUtxoMerkleProof = await fetchMerkleProof(secondUtxoCommitment);
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

    const publicAmountForCircuit = new BN(extAmount).sub(new BN(fee_amount_in_lamports)).add(FIELD_SIZE).mod(FIELD_SIZE);
    logger.debug(`Public amount calculation: (${extAmount} - ${fee_amount_in_lamports} + FIELD_SIZE) % FIELD_SIZE = ${publicAmountForCircuit.toString()}`);

    // Create outputs for the transaction with the same shared keypair
    const outputs = [
        new Utxo({
            lightWasm,
            amount: outputAmount,
            keypair: utxoKeypair,
            index: currentNextIndex // This UTXO will be inserted at currentNextIndex
        }), // Output with value (either deposit amount minus fee, or input amount minus fee)
        new Utxo({
            lightWasm,
            amount: '0',
            keypair: utxoKeypair,
            index: currentNextIndex + 1 // This UTXO will be inserted at currentNextIndex + 1
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

    logger.debug(`\nOutput[0] (with value):`);
    await outputs[0].log();
    logger.debug(`\nOutput[1] (empty):`);
    await outputs[1].log();

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
        recipient: new PublicKey('AWexibGxNFKTa1b5R5MN4PJr9HWnWRwf8EW9g8cLx3dM'),
        extAmount: new BN(extAmount),
        encryptedOutput1: encryptedOutput1,
        encryptedOutput2: encryptedOutput2,
        fee: new BN(fee_amount_in_lamports),
        feeRecipient: FEE_RECIPIENT,
        mintAddress: inputs[0].mintAddress
    };

    // Calculate the extDataHash with the encrypted outputs (now includes mintAddress for security)
    const calculatedExtDataHash = getExtDataHash(extData);

    // Create the input for the proof generation (must match circuit input order exactly)
    const input = {
        // Common transaction data
        root: root,
        inputNullifier: inputNullifiers, // Use resolved values instead of Promise objects
        outputCommitment: outputCommitments, // Use resolved values instead of Promise objects
        publicAmount: publicAmountForCircuit.toString(), // Use proper field arithmetic result
        extDataHash: calculatedExtDataHash,

        // Input UTXO data (UTXOs being spent) - ensure all values are in decimal format
        inAmount: inputs.map(x => x.amount.toString(10)),
        inPrivateKey: inputs.map(x => x.keypair.privkey),
        inBlinding: inputs.map(x => x.blinding.toString(10)),
        inPathIndices: inputMerklePathIndices,
        inPathElements: inputMerklePathElements,

        // Output UTXO data (UTXOs being created) - ensure all values are in decimal format
        outAmount: outputs.map(x => x.amount.toString(10)),
        outBlinding: outputs.map(x => x.blinding.toString(10)),
        outPubkey: outputs.map(x => x.keypair.pubkey),

        // new mint address
        mintAddress: inputs[0].mintAddress
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

    // Address Lookup Table for transaction size optimization
    logger.debug('Setting up Address Lookup Table...');

    const ALT_ADDRESS = new PublicKey('72bpRay17JKp4k8H87p7ieU9C6aRDy5yCqwvtpTN2wuU');
    const lookupTableAccount = await useExistingALT(connection, ALT_ADDRESS);

    if (!lookupTableAccount?.value) {
        throw new Error(`ALT not found at address ${ALT_ADDRESS.toString()} `);
    }

    // Serialize the proof and extData
    const serializedProof = serializeProofAndExtData(proofToSubmit, extData);
    logger.debug(`Total instruction data size: ${serializedProof.length} bytes`);

    // Create the deposit instruction (user signs, not relayer)
    const depositInstruction = new TransactionInstruction({
        keys: [
            { pubkey: treeAccount, isSigner: false, isWritable: true },
            { pubkey: nullifier0PDA, isSigner: false, isWritable: true },
            { pubkey: nullifier1PDA, isSigner: false, isWritable: true },
            { pubkey: nullifier2PDA, isSigner: false, isWritable: false },
            { pubkey: nullifier3PDA, isSigner: false, isWritable: false },
            { pubkey: treeTokenAccount, isSigner: false, isWritable: true },
            { pubkey: globalConfigAccount, isSigner: false, isWritable: false },
            // recipient - just a placeholder, not actually used for deposits. using an ALT address to save bytes
            { pubkey: new PublicKey('AWexibGxNFKTa1b5R5MN4PJr9HWnWRwf8EW9g8cLx3dM'), isSigner: false, isWritable: true },
            // fee recipient
            { pubkey: FEE_RECIPIENT, isSigner: false, isWritable: true },
            // signer
            { pubkey: publicKey, isSigner: true, isWritable: true },
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
    const signature = await relayDepositToIndexer(serializedTransaction, publicKey, referrer);
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
        let res = await fetch(INDEXER_API_URL + '/utxos/check/' + encryptedOutputStr)
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


async function checkDepositLimit(connection: Connection) {
    try {

        // Derive the tree account PDA
        const [treeAccount] = PublicKey.findProgramAddressSync(
            [Buffer.from('merkle_tree')],
            PROGRAM_ID
        );


        // Fetch the account data
        const accountInfo = await connection.getAccountInfo(treeAccount);

        if (!accountInfo) {
            console.error('❌ Tree account not found. Make sure the program is initialized.');
            return;
        }

        console.log(`Account data size: ${accountInfo.data.length} bytes`);
        const authority = new PublicKey(accountInfo.data.slice(8, 40));
        const nextIndex = new BN(accountInfo.data.slice(40, 48), 'le');
        const rootIndex = new BN(accountInfo.data.slice(4112, 4120), 'le');
        const maxDepositAmount = new BN(accountInfo.data.slice(4120, 4128), 'le');
        const bump = accountInfo.data[4128];

        console.log('\n📋 MerkleTreeAccount Details:');
        console.log(`┌─ Authority: ${authority.toString()}`);
        console.log(`├─ Next Index: ${nextIndex.toString()}`);
        console.log(`├─ Root Index: ${rootIndex.toString()}`);
        console.log(`├─ Max Deposit Amount: ${maxDepositAmount.toString()} lamports`);

        // Convert to SOL using BN division to handle large numbers
        const lamportsPerSol = new BN(1_000_000_000);
        const maxDepositSol = maxDepositAmount.div(lamportsPerSol);
        const remainder = maxDepositAmount.mod(lamportsPerSol);

        // Format the SOL amount with decimals
        let solFormatted = '1';
        if (remainder.eq(new BN(0))) {
            solFormatted = maxDepositSol.toString();
        } else {
            // Handle fractional SOL by converting remainder to decimal
            const fractional = remainder.toNumber() / 1e9;
            solFormatted = `${maxDepositSol.toString()}${fractional.toFixed(9).substring(1)}`;
        }
        console.log('solFormatted', solFormatted)
        return Number(solFormatted)

    } catch (error) {
        console.log('❌ Error reading deposit limit:', error);
        throw error
    }
}