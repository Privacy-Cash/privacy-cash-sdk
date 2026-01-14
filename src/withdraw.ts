import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, Transaction, TransactionInstruction, VersionedTransaction } from '@solana/web3.js';
import BN from 'bn.js';
import { Buffer } from 'buffer';
import { Keypair as UtxoKeypair } from './models/keypair.js';
import * as hasher from '@lightprotocol/hasher.rs';
import { Utxo } from './models/utxo.js';
import { parseProofToBytesArray, parseToBytesArray, prove } from './utils/prover.js';

import { ALT_ADDRESS, FEE_RECIPIENT, FIELD_SIZE, RELAYER_API_URL, MERKLE_TREE_DEPTH, PROGRAM_ID } from './utils/constants.js';
import { EncryptionService, serializeProofAndExtData } from './utils/encryption.js';
import { fetchMerkleProof, findNullifierPDAs, getExtDataHash, getProgramAccounts, queryRemoteTreeState, findCrossCheckNullifierPDAs } from './utils/utils.js';

import { getUtxos } from './getUtxos.js';
import { logger } from './utils/logger.js';
import { getConfig } from './config.js';
// Indexer API endpoint


// Function to submit withdraw request to indexer backend
async function submitWithdrawToIndexer(params: any): Promise<string> {
    try {

        const response = await fetch(`${RELAYER_API_URL}/withdraw`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params)
        });

        if (!response.ok) {
            const errorData = await response.json() as { error?: string };
            throw new Error(errorData.error)
        }

        const result = await response.json() as { signature: string, success: boolean };
        logger.debug('Withdraw request submitted successfully!');
        logger.debug('Response:', result);

        return result.signature;
    } catch (error) {
        logger.debug('Failed to submit withdraw request to indexer:', typeof error, error);
        throw error;
    }
}

type WithdrawParams = {
    publicKey: PublicKey,
    connection: Connection,
    amount_in_lamports: number,
    keyBasePath: string,
    encryptionService: EncryptionService,
    lightWasm: hasher.LightWasm,
    recipient: PublicKey,
    storage: Storage,
    referrer?: string,
}

export async function withdraw({ recipient, lightWasm, storage, publicKey, connection, amount_in_lamports, encryptionService, keyBasePath, referrer }: WithdrawParams) {
    let fee_in_lamports = Math.floor(amount_in_lamports * (await getConfig('withdraw_fee_rate')) + LAMPORTS_PER_SOL * (await getConfig('withdraw_rent_fee')))
    amount_in_lamports = Math.floor(amount_in_lamports - fee_in_lamports)
    let isPartial = false

    logger.debug('Encryption key generated from user keypair');

    const { treeAccount, treeTokenAccount, globalConfigAccount } = getProgramAccounts()

    // Get current tree state
    const { root, nextIndex: currentNextIndex } = await queryRemoteTreeState();
    logger.debug(`Using tree root: ${root}`);
    logger.debug(`New UTXOs will be inserted at indices: ${currentNextIndex} and ${currentNextIndex + 1}`);

    // Generate a deterministic private key derived from the wallet keypair
    const utxoPrivateKey = encryptionService.deriveUtxoPrivateKey();

    // Create a UTXO keypair that will be used for all inputs and outputs
    const utxoKeypair = new UtxoKeypair(utxoPrivateKey, lightWasm);
    logger.debug('Using wallet-derived UTXO keypair for withdrawal');

    // Generate a deterministic private key derived from the wallet keypair (V2)
    const utxoPrivateKeyV2 = encryptionService.getUtxoPrivateKeyV2();
    const utxoKeypairV2 = new UtxoKeypair(utxoPrivateKeyV2, lightWasm);

    // Fetch existing UTXOs for this user
    logger.debug('\nFetching existing UTXOs...');
    const unspentUtxos = await getUtxos({ connection, publicKey, encryptionService, storage });
    logger.debug(`Found ${unspentUtxos.length} total UTXOs`);

    // Calculate and log total unspent UTXO balance
    const totalUnspentBalance = unspentUtxos.reduce((sum, utxo) => sum.add(utxo.amount), new BN(0));
    logger.debug(`Total unspent UTXO balance before: ${totalUnspentBalance.toString()} lamports (${totalUnspentBalance.toNumber() / 1e9} SOL)`);

    if (unspentUtxos.length < 1) {
        throw new Error('Need at least 1 unspent UTXO to perform a withdrawal');
    }

    // Sort UTXOs by amount in descending order to use the largest ones first
    unspentUtxos.sort((a, b) => b.amount.cmp(a.amount));

    // Use the largest UTXO as first input, and either second largest UTXO or dummy UTXO as second input
    const firstInput = unspentUtxos[0];
    const secondInput = unspentUtxos.length > 1 ? unspentUtxos[1] : new Utxo({
        lightWasm,
        keypair: utxoKeypair,
        amount: '0'
    });

    const inputs = [firstInput, secondInput];
    logger.debug(`firstInput index: ${firstInput.index}, commitment: ${firstInput.getCommitment()}`)
    logger.debug(`secondInput index: ${secondInput.index}, commitment: ${secondInput.getCommitment()}`)
    const totalInputAmount = firstInput.amount.add(secondInput.amount);
    logger.debug(`Using UTXO with amount: ${firstInput.amount.toString()} and ${secondInput.amount.gt(new BN(0)) ? 'second UTXO with amount: ' + secondInput.amount.toString() : 'dummy UTXO'}`);
    if (totalInputAmount.toNumber() === 0) {
        throw new Error('no balance')
    }
    if (totalInputAmount.lt(new BN(amount_in_lamports + fee_in_lamports))) {
        isPartial = true
        amount_in_lamports = totalInputAmount.toNumber()
        amount_in_lamports -= fee_in_lamports
    }

    // Calculate the change amount (what's left after withdrawal and fee)
    const changeAmount = totalInputAmount.sub(new BN(amount_in_lamports)).sub(new BN(fee_in_lamports));
    logger.debug(`Withdrawing ${amount_in_lamports} lamports with ${fee_in_lamports} fee, ${changeAmount.toString()} as change`);

    // Get Merkle proofs for both input UTXOs
    const inputMerkleProofs = await Promise.all(
        inputs.map(async (utxo, index) => {
            // For dummy UTXO (amount is 0), use a zero-filled proof
            if (utxo.amount.eq(new BN(0))) {
                return {
                    pathElements: [...new Array(MERKLE_TREE_DEPTH).fill("0")],
                    pathIndices: Array(MERKLE_TREE_DEPTH).fill(0)
                };
            }
            // For real UTXOs, fetch the proof from API
            const commitment = await utxo.getCommitment();
            return fetchMerkleProof(commitment);
        })
    );

    // Extract path elements and indices
    const inputMerklePathElements = inputMerkleProofs.map(proof => proof.pathElements);
    const inputMerklePathIndices = inputs.map(utxo => utxo.index || 0);

    // Create outputs: first output is change, second is dummy (required by protocol)
    const outputs = [
        new Utxo({
            lightWasm,
            amount: changeAmount.toString(),
            keypair: utxoKeypairV2,
            index: currentNextIndex
        }), // Change output
        new Utxo({
            lightWasm,
            amount: '0',
            keypair: utxoKeypairV2,
            index: currentNextIndex + 1
        }) // Empty UTXO
    ];

    // For withdrawals, extAmount is negative (funds leaving the system)
    const extAmount = -amount_in_lamports;
    const publicAmountForCircuit = new BN(extAmount).sub(new BN(fee_in_lamports)).add(FIELD_SIZE).mod(FIELD_SIZE);
    logger.debug(`Public amount calculation: (${extAmount} - ${fee_in_lamports} + FIELD_SIZE) % FIELD_SIZE = ${publicAmountForCircuit.toString()}`);

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

    logger.debug(`\nOutput[0] (change):`);
    await outputs[0].log();
    logger.debug(`\nOutput[1] (empty):`);
    await outputs[1].log();
    logger.debug(`Encrypted output 1: ${encryptedOutput1.toString('hex')}`)
    logger.debug(`Encrypted output 2: ${encryptedOutput2.toString('hex')}`)
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

    // Create the withdrawal ExtData with real encrypted outputs
    const extData = {
        // it can be any address
        recipient,
        extAmount: new BN(extAmount),
        encryptedOutput1: encryptedOutput1,
        encryptedOutput2: encryptedOutput2,
        fee: new BN(fee_in_lamports),
        feeRecipient: FEE_RECIPIENT,
        mintAddress: inputs[0].mintAddress
    };

    // Calculate the extDataHash with the encrypted outputs
    const calculatedExtDataHash = getExtDataHash(extData);

    // Create the input for the proof generation
    const input = {
        // Common transaction data
        root: root,
        inputNullifier: inputNullifiers,
        outputCommitment: outputCommitments,
        publicAmount: publicAmountForCircuit.toString(),
        extDataHash: calculatedExtDataHash,

        // Input UTXO data (UTXOs being spent)
        inAmount: inputs.map(x => x.amount.toString(10)),
        inPrivateKey: inputs.map(x => x.keypair.privkey),
        inBlinding: inputs.map(x => x.blinding.toString(10)),
        inPathIndices: inputMerklePathIndices,
        inPathElements: inputMerklePathElements,

        // Output UTXO data (UTXOs being created)
        outAmount: outputs.map(x => x.amount.toString(10)),
        outBlinding: outputs.map(x => x.blinding.toString(10)),
        outPubkey: outputs.map(x => x.keypair.pubkey),

        // new mint address
        mintAddress: inputs[0].mintAddress
    };
    logger.info('generating ZK proof...')

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

    // Serialize the proof and extData
    const serializedProof = serializeProofAndExtData(proofToSubmit, extData);
    logger.debug(`Total instruction data size: ${serializedProof.length} bytes`);

    // Prepare withdraw parameters for indexer backend
    const withdrawParams = {
        serializedProof: serializedProof.toString('base64'),
        treeAccount: treeAccount.toString(),
        nullifier0PDA: nullifier0PDA.toString(),
        nullifier1PDA: nullifier1PDA.toString(),
        nullifier2PDA: nullifier2PDA.toString(),
        nullifier3PDA: nullifier3PDA.toString(),
        treeTokenAccount: treeTokenAccount.toString(),
        globalConfigAccount: globalConfigAccount.toString(),
        recipient: recipient.toString(),
        feeRecipientAccount: FEE_RECIPIENT.toString(),
        extAmount: extAmount,
        encryptedOutput1: encryptedOutput1.toString('base64'),
        encryptedOutput2: encryptedOutput2.toString('base64'),
        fee: fee_in_lamports,
        lookupTableAddress: ALT_ADDRESS.toString(),
        senderAddress: publicKey.toString(),
        referralWalletAddress: referrer
    };


    logger.debug('Prepared withdraw parameters for indexer backend');

    // Submit to indexer backend instead of directly to Solana
    logger.info('submitting transaction to relayer...')
    const signature = await submitWithdrawToIndexer(withdrawParams);
    // Wait a moment for the transaction to be confirmed
    logger.info('waiting for transaction confirmation...')
    let retryTimes = 0
    let itv = 2
    const encryptedOutputStr = Buffer.from(encryptedOutput1).toString('hex')
    let start = Date.now()
    while (true) {
        logger.info('Confirming transaction..')
        logger.debug(`retryTimes: ${retryTimes}`)
        await new Promise(resolve => setTimeout(resolve, itv * 1000));
        logger.info('Fetching updated tree state...');
        let res = await fetch(RELAYER_API_URL + '/utxos/check/' + encryptedOutputStr)
        let resJson = await res.json()
        logger.debug('resJson:', resJson)
        if (resJson.exists) {
            return { isPartial, tx: signature, recipient: recipient.toString(), amount_in_lamports, fee_in_lamports }
        }
        if (retryTimes >= 10) {
            throw new Error('Refresh the page to see latest balance.')
        }
        retryTimes++
    }

}