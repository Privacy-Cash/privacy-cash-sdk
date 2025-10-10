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

    process.exit(1)
}

main()