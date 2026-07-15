// api.ts
import express, { Request, Response } from 'express';
import { JsonRpcProvider, isAddress } from 'ethers';
import { disassembleBytecode } from './lib/disassembler';
import { extractAndResolveSelectors } from './lib/extractor';
import { CFGBuilder } from './lib/graph';
import { getSupportedChains, resolveRpcUrl } from './lib/chains';
import { SecurityAnalyzer } from './lib/security';
import { fetchWithBackoff } from './lib/rpc';

const app = express();
app.use(express.json());

app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({
        status: "ok",
        service: "etherlens-api",
        timestamp: new Date().toISOString()
    });
});

app.post('/analyze', async (req: Request, res: Response) => {
    // SECURITY FIX: Ensure req.body actually exists before trying to destructure it
    if (!req.body || Object.keys(req.body).length === 0) {
        res.status(400).json({ error: "Request body is empty. Please provide a JSON payload with an 'address'." });
        return;
    }

    const { address, chain = "ethereum" } = req.body;

    if (!address || typeof address !== "string" || !isAddress(address)) {
        res.status(400).json({ error: "Invalid Ethereum contract address." });
        return;
    }

    if (typeof chain !== "string" || chain.trim().length === 0) {
        res.status(400).json({ error: "Invalid chain value. Chain must be a non-empty string." });
        return;
    }

    const resolvedChain = resolveRpcUrl(chain);
    if (!resolvedChain) {
        res.status(400).json({ error: `Unsupported chain. Supported: ${getSupportedChains().join(", ")}` });
        return;
    }

    const { chain: normalizedChain, rpcUrl } = resolvedChain;

    try {
        console.log(`[API] Fetching bytecode for ${address} on ${normalizedChain}...`);
        const provider = new JsonRpcProvider(rpcUrl);
        
        // Use our robust exponential backoff wrapper!
        const rawBytecode = await fetchWithBackoff(() => provider.getCode(address));
        
        if (rawBytecode === "0x") {
            res.status(404).json({ error: "No bytecode found (address is empty or an EOA)." });
            return;
        }

        // --- Core Engine Execution ---
        const disassembly = disassembleBytecode(rawBytecode);
        const instructions = disassembly.instructions;
        const selectorAnalysis = await extractAndResolveSelectors(instructions);
        
        const cfgBuilder = new CFGBuilder(instructions);
        const basicBlocks = cfgBuilder.build();
        const adjacencyList = JSON.parse(cfgBuilder.getJsonAdjacencyList(true));
        const jumpResolution = cfgBuilder.getJumpResolutionStats();

        // Capture security logs for the API response without leaking global logger state.
        const securityLogs: string[] = [];
        const originalLog = console.log;
        console.log = (...args: unknown[]) => securityLogs.push(args.map(arg => String(arg)).join(" "));

        try {
            const security = new SecurityAnalyzer(instructions, basicBlocks, provider, address);
            await security.analyze();
        } finally {
            console.log = originalLog;
        }

        // --- Structured JSON Report ---
        res.json({
            success: true,
            metadata: {
                address: address,
                chain: normalizedChain,
                totalInstructions: instructions.length,
                totalBlocks: basicBlocks.length,
                jumpResolution: {
                    static: jumpResolution.staticJumps,
                    dynamic: jumpResolution.dynamicJumps,
                    total: jumpResolution.totalJumps,
                    staticPercentage: jumpResolution.staticPercentage,
                    dynamicPercentage: jumpResolution.dynamicPercentage
                },
                disassembly: {
                    metadataDetected: disassembly.metadata.detected,
                    metadataLength: disassembly.metadata.metadataLength,
                    cborValid: disassembly.metadata.cborValid,
                    solidityVersion: disassembly.metadata.solidityVersion
                }
            },
            securityAnalysis: securityLogs.filter(log => log.includes('[!]') || log.includes('[✓]')),
            cfgAdjacencyList: adjacencyList,
            selectorAnalysis,
            // Only return the first 50 instructions to keep the JSON payload lightweight
            disassemblyPreview: instructions.slice(0, 50) 
        });

    } catch (error: any) {
        console.error("[API] Fatal Error:", error);
        res.status(500).json({ error: "Internal Server Error", details: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`EVM Analyzer API running securely on http://localhost:${PORT}`);
});