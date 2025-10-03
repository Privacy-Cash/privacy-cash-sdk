import { INDEXER_API_URL } from "./utils/constants.js";

type Config = {
    withdraw_fee_rate: number
    withdraw_rent_fee: number
    deposit_fee_rate: number
}

let config: Config | undefined

export async function getConfig<K extends keyof Config>(key: K): Promise<Config[K]> {
    if (!config) {
        const res = await fetch(INDEXER_API_URL + '/config')
        const data = await res.json()

        // check types
        if (
            typeof data.withdraw_fee_rate !== 'number' ||
            typeof data.withdraw_rent_fee !== 'number' ||
            typeof data.deposit_fee_rate !== 'number'
        ) {
            throw new Error("Invalid config received from server")
        }

        config = data
    }
    return config![key]
}