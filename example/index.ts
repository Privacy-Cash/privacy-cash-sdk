import { PublicKey } from '@solana/web3.js'
import { PrivacyCash } from 'privacycash'

async function solExample(client: PrivacyCash, recipientAddress: string) {
    // deposit SOL
    let depositRes = await client.deposit({
        lamports: 0.01 * 1_000_000_000
    })
    console.log(depositRes)

    let privateBalance = await client.getPrivateBalance()
    console.log('balance after deposit:', privateBalance, privateBalance.lamports / 1_000_000_000)

    // withdraw SOL
    let withdrawRes = await client.withdraw({
        lamports: 0.01 * 1_000_000_000,
        recipientAddress
    })
    console.log(withdrawRes)

    privateBalance = await client.getPrivateBalance()
    console.log('balance after withdraw:', privateBalance, privateBalance.lamports / 1_000_000_000)
}

async function usdcExample(client: PrivacyCash, recipientAddress: string) {
    // USDC mint address
    let mintAddress = new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')

    // get balance
    let privateBalance = await client.getPrivateBalanceSpl(mintAddress)
    console.log('USDC balance:', privateBalance, privateBalance.amount)

    // deposit USDC
    let depositUSDCRes = await client.depositSPL({
        amount: 2,
        mintAddress
    })
    console.log(depositUSDCRes)
    console.log('USDC balance after deposit:', privateBalance, privateBalance.amount)

    // withdraw USDC
    let withdrawUSDCRes = await client.withdrawSPL({
        mintAddress,
        amount: 2,
        recipientAddress
    })
    console.log(withdrawUSDCRes)
    console.log('USDC balance after withdraw:', privateBalance, privateBalance.amount)
}

async function usdtExample(client: PrivacyCash, recipientAddress: string) {
    // USDT mint address
    let mintAddress = new PublicKey('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB')

    // get balance
    let privateBalance = await client.getPrivateBalanceSpl(mintAddress)
    console.log('USDT balance:', privateBalance, privateBalance.amount)

    // deposit USDT
    let depositUSDCRes = await client.depositSPL({
        amount: 2,
        mintAddress
    })
    console.log(depositUSDCRes)
    console.log('USDT balance after deposit:', privateBalance, privateBalance.amount)

    // withdraw USDT
    let withdrawUSDCRes = await client.withdrawSPL({
        mintAddress,
        amount: 2,
        recipientAddress
    })
    console.log(withdrawUSDCRes)
    console.log('USDT balance after withdraw:', privateBalance, privateBalance.amount)
}

async function main() {
    let client = new PrivacyCash({
        RPC_url: '[YOUR_SOLANA_MAINNET_RPC_URL]',
        owner: '[YOUR_PRIVATE_KEY]'
    })
    // the recipient address used in withdrawal
    let recipientAddress = '[RECIPIENT_ADDRESS]'


    // historical utxos will be cached locally for faster performance.
    // you don't need to call clearCache() unless you encountered some issues and want to do a full refresh.
    // client.clearCache()

    // SOL example
    await solExample(client, recipientAddress)

    // USDC example
    await usdcExample(client, recipientAddress)

    // USDT example
    await usdtExample(client, recipientAddress)

    process.exit(1)
}

main()