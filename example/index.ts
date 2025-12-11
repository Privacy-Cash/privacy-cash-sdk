import { PrivacyCash } from 'privacycash'

async function main() {
    let client = new PrivacyCash({
        RPC_url: '[YOUR_SOLANA_MAINNET_RPC_URL]',
        owner: '[YOUR_PRIVATE_KEY]'
    })

    // historical utxos will be cached locally for faster performance.
    // you don't need to call clearCache() unless you encountered some issues and want to do a full refresh.
    // client.clearCache()

    // deposit
    let depositRes = await client.deposit({
        lamports: 0.02 * 1_000_000_000
    })
    console.log(depositRes)

    let balance = await client.getPrivateBalance()
    console.log('balance after deposit:', balance, balance.lamports / 1_000_000_000)

    // withdraw
    let withdrawRes = await client.withdraw({
        lamports: 0.01 * 1_000_000_000,
        recipientAddress: '[RECIPIENT_ADDRESS]'
    })
    console.log(withdrawRes)

    balance = await client.getPrivateBalance()
    console.log('balance after withdraw:', balance, balance.lamports / 1_000_000_000)

    // get USDC balance
    let usdcBalance = await client.getPrivateBalanceUSDC()
    console.log('USDC balance:', usdcBalance, usdcBalance.base_units / 1e6)

    // deposit USDC
    let depositUSDCRes = await client.depositUSDC({
        base_units: 2 * 1e6
    })
    console.log(depositUSDCRes)
    console.log('USDC balance after deposit:', usdcBalance, usdcBalance.base_units / 1e6)

    // withdraw USDC
    let withdrawUSDCRes = await client.withdrawUSDC({
        base_units: 2 * 1e6,
        recipientAddress: '[RECIPIENT_ADDRESS]'
    })
    console.log(withdrawUSDCRes)
    console.log('USDC balance after withdraw:', usdcBalance, usdcBalance.base_units / 1e6)

    process.exit(1)
}

main()