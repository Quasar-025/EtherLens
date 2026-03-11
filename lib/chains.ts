export const DEFAULT_RPC_URLS = {
    ethereum: "https://eth.llamarpc.com",
    polygon: "https://polygon-rpc.com",
    base: "https://mainnet.base.org",
    arbitrum: "https://arb1.arbitrum.io/rpc"
} as const;

export type SupportedChain = keyof typeof DEFAULT_RPC_URLS;

const RPC_ENV_VARS: Record<SupportedChain, string> = {
    ethereum: "ETHEREUM_RPC_URL",
    polygon: "POLYGON_RPC_URL",
    base: "BASE_RPC_URL",
    arbitrum: "ARBITRUM_RPC_URL"
};

const SUPPORTED_CHAINS = Object.keys(DEFAULT_RPC_URLS) as SupportedChain[];

function readConfiguredRpcUrl(chain: SupportedChain): string {
    const envVar = RPC_ENV_VARS[chain];
    const value = process.env[envVar];

    if (typeof value !== "string") {
        return DEFAULT_RPC_URLS[chain];
    }

    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : DEFAULT_RPC_URLS[chain];
}

export function getConfiguredRpcUrls(): Record<SupportedChain, string> {
    return {
        ethereum: readConfiguredRpcUrl("ethereum"),
        polygon: readConfiguredRpcUrl("polygon"),
        base: readConfiguredRpcUrl("base"),
        arbitrum: readConfiguredRpcUrl("arbitrum")
    };
}

export function getSupportedChains(): SupportedChain[] {
    return [...SUPPORTED_CHAINS];
}

export function isSupportedChain(chain: string): chain is SupportedChain {
    return SUPPORTED_CHAINS.includes(chain as SupportedChain);
}

export function resolveRpcUrl(chainInput: string): { chain: SupportedChain; rpcUrl: string } | null {
    const normalizedChain = chainInput.trim().toLowerCase();
    if (!isSupportedChain(normalizedChain)) {
        return null;
    }

    const rpcUrls = getConfiguredRpcUrls();
    return {
        chain: normalizedChain,
        rpcUrl: rpcUrls[normalizedChain]
    };
}
