import * as fs from "fs";
import { JsonRpcProvider } from "ethers";
import { resolveRpcUrl } from "../lib/chains";
import { disassembleBytecode } from "../lib/disassembler";
import { extractAndResolveSelectors } from "../lib/extractor";
import { CFGBuilder } from "../lib/graph";
import { SecurityAnalyzer } from "../lib/security";
import { fetchWithBackoff } from "../lib/rpc";

interface ContractTarget {
    name: string;
    address: string;
    category: "simple-token" | "defi" | "proxy" | "unverified" | "vyper-defi";
    notes?: string;
}

interface VerificationStatus {
    status: "verified" | "unverified" | "unknown";
    evidence: string;
    languageHint: "solidity" | "vyper" | "unknown";
}

interface ContractResearchResult {
    name: string;
    address: string;
    category: string;
    notes: string;
    verificationStatus: VerificationStatus["status"];
    verificationEvidence: string;
    languageHint: VerificationStatus["languageHint"];
    totalInstructions: number;
    functionsFound: number;
    dispatchEntries: number;
    cfgBlocks: number;
    cfgEdges: number;
    staticJumps: number;
    dynamicJumps: number;
    staticJumpPct: number;
    dynamicJumpPct: number;
    securityPatternsDetected: string[];
    metadataDetected: boolean;
    metadataLength: number;
    compilerVersion: string | null;
    cborValid: boolean;
}

const TARGETS: ContractTarget[] = [
    {
        name: "WETH",
        address: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        category: "simple-token",
        notes: "Canonical wrapped ETH token"
    },
    {
        name: "LINK",
        address: "0x514910771af9ca656af840dff83e8264ecf986ca",
        category: "simple-token",
        notes: "ERC-20 token"
    },
    {
        name: "DAI",
        address: "0x6b175474e89094c44da98b954eedeac495271d0f",
        category: "simple-token",
        notes: "Stablecoin token"
    },
    {
        name: "USDC",
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        category: "proxy",
        notes: "FiatToken proxy"
    },
    {
        name: "USDT",
        address: "0xdac17f958d2ee523a2206206994597c13d831ec7",
        category: "proxy",
        notes: "Legacy token contract with proxy-style behavior"
    },
    {
        name: "Aave v3 Pool",
        address: "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
        category: "proxy",
        notes: "Aave pool proxy endpoint"
    },
    {
        name: "Uniswap V2 Router02",
        address: "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
        category: "defi",
        notes: "DEX router"
    },
    {
        name: "Uniswap V3 SwapRouter",
        address: "0xe592427a0aece92de3edee1f18e0157c05861564",
        category: "defi",
        notes: "DEX router"
    },
    {
        name: "Curve 3Pool",
        address: "0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7",
        category: "vyper-defi",
        notes: "Known Vyper DeFi contract"
    },
    {
        name: "MEV Bot Candidate",
        address: "0xaf682de1f2e6f710731121a05a44cb3c1b511f7d",
        category: "unverified",
        notes: "Candidate discovered from Etherscan internal transactions"
    }
];

function buildNoopFetch() {
    return async (_url: string) => ({
        ok: true,
        status: 200,
        json: async () => ({ count: 0, results: [] })
    });
}

function collectSecurityAlerts(logs: string[]): string[] {
    const alerts = new Set<string>();

    for (const line of logs) {
        if (!line.includes("[!] Pattern")) {
            continue;
        }

        const match = line.match(/Pattern\s+\d+\s+\(([^)]+)\)/);
        if (match && match[1]) {
            alerts.add(match[1].trim());
        } else {
            alerts.add(line.trim());
        }
    }

    return Array.from(alerts.values());
}

async function getVerificationStatus(address: string): Promise<VerificationStatus> {
    const url = `https://etherscan.io/address/${address}`;
    const response = await fetch(url);
    if (!response.ok) {
        return {
            status: "unknown",
            evidence: `Failed to fetch Etherscan page (HTTP ${response.status}).`,
            languageHint: "unknown"
        };
    }

    const html = await response.text();
    const lower = html.toLowerCase();

    const hasVerifiedMarker = lower.includes("contract source code verified")
        || lower.includes("verified (exact match)")
        || lower.includes("verified (similar match)");

    const hasUnverifiedMarker = lower.includes("verify and publish")
        && lower.includes("your contract source code today");

    const compilerMatch = html.match(/Compiler Version<\/div>[\s\S]{0,400}?<span[^>]*>([^<]+)<\/span>/i);
    const compilerLabel = compilerMatch?.[1]?.trim().toLowerCase() ?? "";

    const languageHint: VerificationStatus["languageHint"] = compilerLabel.includes("vyper")
        ? "vyper"
        : compilerLabel.length > 0
            ? "solidity"
            : "unknown";

    if (hasVerifiedMarker) {
        return {
            status: "verified",
            evidence: "Etherscan page includes Contract Source Code Verified marker.",
            languageHint
        };
    }

    if (hasUnverifiedMarker) {
        return {
            status: "unverified",
            evidence: "Etherscan page prompts Verify and Publish your contract source code today.",
            languageHint
        };
    }

    return {
        status: "unknown",
        evidence: "Etherscan page did not expose a definitive verification marker under current scraping method.",
        languageHint
    };
}

async function analyzeContract(provider: JsonRpcProvider, target: ContractTarget): Promise<ContractResearchResult> {
    const bytecode = await fetchWithBackoff(() => provider.getCode(target.address));
    if (bytecode === "0x") {
        throw new Error(`No bytecode at ${target.address}`);
    }

    const disassembly = disassembleBytecode(bytecode);
    const instructions = disassembly.instructions;

    const selectorAnalysis = await extractAndResolveSelectors(instructions, {
        fetchFn: buildNoopFetch()
    });

    const cfg = new CFGBuilder(instructions);
    const blocks = cfg.build({ silent: true });
    const jumpStats = cfg.getJumpResolutionStats();

    const adjacency = JSON.parse(cfg.getJsonAdjacencyList(true)) as Record<string, Array<number | string>>;
    const cfgEdges = Object.values(adjacency).reduce((sum, successors) => {
        return sum + successors.filter((value) => typeof value === "number").length;
    }, 0);

    const logs: string[] = [];
    const originalConsoleLog = console.log;
    console.log = (...args: unknown[]) => {
        logs.push(args.map((arg) => String(arg)).join(" "));
    };

    try {
        const analyzer = new SecurityAnalyzer(instructions, blocks, provider, target.address);
        await analyzer.analyze();
    } finally {
        console.log = originalConsoleLog;
    }

    const verification = await getVerificationStatus(target.address);

    return {
        name: target.name,
        address: target.address,
        category: target.category,
        notes: target.notes ?? "",
        verificationStatus: verification.status,
        verificationEvidence: verification.evidence,
        languageHint: verification.languageHint,
        totalInstructions: instructions.length,
        functionsFound: selectorAnalysis.uniqueSelectors.length,
        dispatchEntries: selectorAnalysis.dispatchEntries.length,
        cfgBlocks: blocks.length,
        cfgEdges,
        staticJumps: jumpStats.staticJumps,
        dynamicJumps: jumpStats.dynamicJumps,
        staticJumpPct: jumpStats.staticPercentage,
        dynamicJumpPct: jumpStats.dynamicPercentage,
        securityPatternsDetected: collectSecurityAlerts(logs),
        metadataDetected: disassembly.metadata.detected,
        metadataLength: disassembly.metadata.metadataLength,
        compilerVersion: disassembly.metadata.solidityVersion,
        cborValid: disassembly.metadata.cborValid
    };
}

async function main() {
    const resolved = resolveRpcUrl("ethereum");
    if (!resolved) {
        throw new Error("Unable to resolve ethereum RPC URL.");
    }

    const provider = new JsonRpcProvider(resolved.rpcUrl);
    const results: ContractResearchResult[] = [];

    for (const target of TARGETS) {
        process.stdout.write(`Analyzing ${target.name} (${target.address})... `);
        try {
            const result = await analyzeContract(provider, target);
            results.push(result);
            process.stdout.write("done\n");
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : String(error);
            process.stdout.write(`failed (${message})\n`);
        }
    }

    const output = {
        generatedAt: new Date().toISOString(),
        rpcUrl: resolved.rpcUrl,
        chain: "ethereum",
        contractCount: results.length,
        contracts: results
    };

    fs.writeFileSync("research_results.json", JSON.stringify(output, null, 2), "utf8");
    console.log(`Saved research results to research_results.json (${results.length} contracts analyzed).`);
}

main().catch((error) => {
    console.error("Research run failed:", error);
    process.exitCode = 1;
});
