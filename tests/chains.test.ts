import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_RPC_URLS, getConfiguredRpcUrls, getSupportedChains, resolveRpcUrl } from "../lib/chains";

const RPC_ENV_KEYS = [
    "ETHEREUM_RPC_URL",
    "POLYGON_RPC_URL",
    "BASE_RPC_URL",
    "ARBITRUM_RPC_URL"
] as const;

const originalEnvValues: Record<string, string | undefined> = {};

beforeEach(() => {
    for (const envKey of RPC_ENV_KEYS) {
        originalEnvValues[envKey] = process.env[envKey];
        delete process.env[envKey];
    }
});

afterEach(() => {
    for (const envKey of RPC_ENV_KEYS) {
        const previousValue = originalEnvValues[envKey];
        if (previousValue === undefined) {
            delete process.env[envKey];
        } else {
            process.env[envKey] = previousValue;
        }
    }
});

describe("Chain RPC configuration", () => {
    it("should expose supported chains", () => {
        expect(getSupportedChains()).toEqual(["ethereum", "polygon", "base", "arbitrum"]);
    });

    it("should use default URLs when no env overrides are set", () => {
        expect(getConfiguredRpcUrls()).toEqual(DEFAULT_RPC_URLS);
    });

    it("should apply RPC URL environment overrides", () => {
        process.env.ETHEREUM_RPC_URL = "https://rpc.internal/eth";
        process.env.BASE_RPC_URL = "https://rpc.internal/base";

        const urls = getConfiguredRpcUrls();

        expect(urls.ethereum).toBe("https://rpc.internal/eth");
        expect(urls.base).toBe("https://rpc.internal/base");
        expect(urls.polygon).toBe(DEFAULT_RPC_URLS.polygon);
        expect(urls.arbitrum).toBe(DEFAULT_RPC_URLS.arbitrum);
    });

    it("should ignore blank environment overrides", () => {
        process.env.POLYGON_RPC_URL = "   ";

        const urls = getConfiguredRpcUrls();

        expect(urls.polygon).toBe(DEFAULT_RPC_URLS.polygon);
    });

    it("should resolve a supported chain case-insensitively", () => {
        process.env.ARBITRUM_RPC_URL = "https://custom.arbitrum";

        const resolved = resolveRpcUrl("ArBiTrUm");

        expect(resolved).not.toBeNull();
        expect(resolved?.chain).toBe("arbitrum");
        expect(resolved?.rpcUrl).toBe("https://custom.arbitrum");
    });

    it("should trim surrounding whitespace before chain resolution", () => {
        const resolved = resolveRpcUrl("  base  ");

        expect(resolved).not.toBeNull();
        expect(resolved?.chain).toBe("base");
        expect(resolved?.rpcUrl).toBe(DEFAULT_RPC_URLS.base);
    });

    it("should reject unsupported chains", () => {
        expect(resolveRpcUrl("optimism")).toBeNull();
    });
});
