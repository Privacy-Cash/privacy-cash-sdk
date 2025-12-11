import { RELAYER_API_URL } from "./utils/constants.js";

type Config = {
    withdraw_fee_rate: number
    withdraw_rent_fee: number
    deposit_fee_rate: number
    usdc_withdraw_rent_fee: number
}

let config: Config | undefined

export async function getConfig<K extends keyof Config>(key: K): Promise<Config[K]> {
    if (!config) {
        const res = await fetch(RELAYER_API_URL + '/config')
        config = await res.json()
    }
    if (typeof config![key] != 'number') {
        throw new Error(`can not get ${key} from ${RELAYER_API_URL}/config`)
    }
    return config![key]
}