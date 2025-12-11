import { describe, it, expect, vi, beforeAll, beforeEach, type Mock } from "vitest";
import dotenv from 'dotenv';
import { PrivacyCash } from "../src";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";
dotenv.config();
const TEST_AMOUNT = 0.01

describe('e2e test', async () => {
    if (!process.env.PRIVATE_KEY) {
        throw new Error('missing PRIVATE_KEY in .env')
    }
    if (!process.env.RPC_URL) {
        throw new Error('missing RPC_URL in .env')
    }

    let client = new PrivacyCash({
        RPC_url: process.env.RPC_URL,
        owner: process.env.PRIVATE_KEY
    })
    let balance_original = await client.getPrivateBalance()

    // deposit
    await client.deposit({
        lamports: TEST_AMOUNT * LAMPORTS_PER_SOL
    })
    let balance_after_deposit = await client.getPrivateBalance()

    // withdraw wrong amount
    it(`show throw error if withdraw amount less than 0.01`, async () => {
        await expect(client.withdraw({
            lamports: 0.005 * LAMPORTS_PER_SOL
        })).rejects.toThrow()
    })

    // withdraw
    let withdrawRes = await client.withdraw({
        lamports: TEST_AMOUNT * LAMPORTS_PER_SOL
    })
    let balance_after_withdraw = await client.getPrivateBalance()

    it('balance is a number', () => {
        expect(balance_original.lamports).to.be.a('number')
    })

    it(`balance should be increased ${TEST_AMOUNT} sol`, () => {
        expect(balance_after_deposit.lamports).equal(balance_after_withdraw.lamports + TEST_AMOUNT * LAMPORTS_PER_SOL)
    })

    it('should keep balance unchanged after depositing and withdrawing the same amount', () => {
        expect(balance_original.lamports).equal(balance_after_withdraw.lamports)
    })

    it(`withdraw real amount plus fee should  be ${TEST_AMOUNT * LAMPORTS_PER_SOL}`, () => {
        expect(withdrawRes.amount_in_lamports + withdrawRes.fee_in_lamports).equal(TEST_AMOUNT * LAMPORTS_PER_SOL)
    })
})