import { describe, it, expect, vi, beforeAll, beforeEach, type Mock } from "vitest";
import dotenv from 'dotenv';
import { PrivacyCash } from "../src";
import { getAccount, getAssociatedTokenAddress } from "@solana/spl-token";
import { FEE_RECIPIENT, USDC_MINT } from "../src/utils/constants";
import { Connection } from "@solana/web3.js";
dotenv.config();
const TEST_AMOUNT = 2
const units_per_token = 1_000_000
describe('e2e test', async () => {
    if (!process.env.PRIVATE_KEY) {
        throw new Error('missing PRIVATE_KEY in .env')
    }
    if (!process.env.RPC_URL) {
        throw new Error('missing RPC_URL in .env')
    }

    const connection = new Connection(process.env.RPC_URL)
    let fee_recipient_ata = await getAssociatedTokenAddress(USDC_MINT, FEE_RECIPIENT, true)
    let feeRecipientAccount = await getAccount(connection, fee_recipient_ata)
    let feeRecipientBalance_before = feeRecipientAccount.amount

    let client = new PrivacyCash({
        RPC_url: process.env.RPC_URL,
        owner: process.env.PRIVATE_KEY
    })
    let balance_original = await client.getPrivateBalanceUSDC()

    // deposit
    await client.depositUSDC({
        base_units: TEST_AMOUNT * units_per_token
    })
    let balance_after_deposit = await client.getPrivateBalanceUSDC()

    // withdraw wrong amount
    it(`show throw error if withdraw amount less than 1`, async () => {
        await expect(client.withdrawUSDC({
            base_units: 0.9 * units_per_token
        })).rejects.toThrow()
    })

    // withdraw
    let withdrawRes = await client.withdrawUSDC({
        base_units: TEST_AMOUNT * units_per_token
    })

    await new Promise(r => setTimeout(r, 10_000));

    feeRecipientAccount = await getAccount(connection, fee_recipient_ata)
    let feeRecipientBalance_after = feeRecipientAccount.amount

    let balance_after_withdraw = await client.getPrivateBalanceUSDC()

    it('balance is a number', () => {
        expect(balance_original.base_units).to.be.a('number')
    })

    it(`balance should be increased ${TEST_AMOUNT} USDC`, () => {
        expect(balance_after_deposit.base_units).equal(balance_after_withdraw.base_units + TEST_AMOUNT * units_per_token)
    })

    it('should keep balance unchanged after depositing and withdrawing the same amount', () => {
        expect(balance_original.base_units).equal(balance_after_withdraw.base_units)
    })

    it(`withdraw real amount plus fee should  be ${TEST_AMOUNT * units_per_token}`, () => {
        expect(withdrawRes.base_units + withdrawRes.fee_base_units).equal(TEST_AMOUNT * units_per_token)
    })

    it('fee recipient amount should be inceased by the withdraw fee', () => {
        expect(withdrawRes.fee_base_units).equal(Number(feeRecipientBalance_after - feeRecipientBalance_before))
    })
})