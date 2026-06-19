import { normalizeRelayerTokenMap, RELAYER_API_URL } from "./utils/constants.js";

type Config = {
    withdraw_fee_rate: number
    withdraw_rent_fee: number
    deposit_fee_rate: number
    usdc_withdraw_rent_fee: number
    rent_fees: Record<string, number>
    minimum_withdrawal: Record<string, number>
    prices: Record<string, number>
}

let config: Config | undefined

export async function getConfig<K extends keyof Config>(key: K): Promise<Config[K]> {
    if (!config) {
        const res = await fetch(RELAYER_API_URL + '/config')
        config = normalizeConfig(await res.json())
    }
    if (typeof config![key] == 'undefined') {
        throw new Error(`can not get ${key} from ${RELAYER_API_URL}/config`)
    }
    return config![key]
}

function normalizeConfig(raw: Config): Config {
    return {
        ...raw,
        rent_fees: normalizeRelayerTokenMap(raw.rent_fees) ?? {},
        minimum_withdrawal: normalizeRelayerTokenMap(raw.minimum_withdrawal) ?? {},
        prices: normalizeRelayerTokenMap(raw.prices) ?? {},
    }
}
