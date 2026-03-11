import { JsonRpcProvider, isAddress } from "ethers";
import { disassembleBytecode } from "./lib/disassembler";
import { extractAndResolveSelectors, formatSelectorAnalysis, SelectorAnalysisResult } from "./lib/extractor";
import { BasicBlock, CFGBuilder } from "./lib/graph";
import { getSupportedChains, resolveRpcUrl } from "./lib/chains";
import { SecurityAnalyzer } from "./lib/security";
import { fetchWithBackoff } from "./lib/rpc";

const DEFAULT_DISASSEMBLY_PREVIEW_LIMIT = 20;
const VALID_OUTPUT_FORMATS = new Set(["json", "text", "dot"]);

function getOptionValue(args: string[], flag: string): string | null {
    const index = args.indexOf(flag);
    if (index === -1) {
        return null;
    }

    const value = args[index + 1];
    if (!value || value.startsWith("--")) {
        throw new Error(`Missing value for ${flag}.`);
    }

    return value;
}

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args.includes("--help")) {
        console.log("Usage: analyzer <address> --chain <chain> --output <json|text|dot> [flags]");
        console.log("Flags: --disasm, --selectors, --cfg, --security, --svg");
        console.log(`Supported chains: ${getSupportedChains().join(", ")}`);
        console.log("RPC URLs can be configured with ETHEREUM_RPC_URL, POLYGON_RPC_URL, BASE_RPC_URL, ARBITRUM_RPC_URL.");
        console.log(`Default disassembly output is preview mode (${DEFAULT_DISASSEMBLY_PREVIEW_LIMIT} rows). Use --disasm for full output.`);
        console.log("Use --svg with --output dot to generate an SVG if Graphviz is installed.");
        return;
    }

    // Parse Arguments
    const address = args.find(a => isAddress(a));
    if (!address) return console.error("Error: Please provide a valid Ethereum contract address.");

    let chainInput = "ethereum";
    let outputFormat = "text";
    try {
        const chainValue = getOptionValue(args, "--chain");
        const outputValue = getOptionValue(args, "--output");

        if (chainValue) {
            chainInput = chainValue;
        }

        if (outputValue) {
            outputFormat = outputValue.toLowerCase();
            if (!VALID_OUTPUT_FORMATS.has(outputFormat)) {
                return console.error(`Error: Unsupported output format '${outputValue}'. Supported: json, text, dot`);
            }
        }
    } catch (error: any) {
        return console.error(`Error: ${error.message}`);
    }

    const runDisasm = args.includes("--disasm");
    const runSelectors = args.includes("--selectors");
    const runCfg = args.includes("--cfg");
    const runSecurity = args.includes("--security");
    const generateSvg = args.includes("--svg");
    
    // If no specific flags are provided, run everything
    const runAll = !runDisasm && !runSelectors && !runCfg && !runSecurity;

    const resolvedChain = resolveRpcUrl(chainInput);
    if (!resolvedChain) {
        return console.error(`Error: Unsupported chain '${chainInput}'. Supported: ${getSupportedChains().join(", ")}`);
    }
    const { chain, rpcUrl } = resolvedChain;
    
    const provider = new JsonRpcProvider(rpcUrl);

    try {
        if (outputFormat === "text") console.log(`\n[CLI] Fetching bytecode for ${address} on ${chain}...`);
        
        // Use the Exponential Backoff wrapper!
        const rawBytecode = await fetchWithBackoff(() => provider.getCode(address));
        if (rawBytecode === "0x") return console.error("No bytecode found at this address.");

        // --- CORE ENGINE ---
        const disassembly = disassembleBytecode(rawBytecode);
        const instructions = disassembly.instructions;

        let cfgBuilder: CFGBuilder | null = null;
        let basicBlocks: BasicBlock[] = [];
        let selectorAnalysis: SelectorAnalysisResult | null = null;

        const cfgSilentMode = outputFormat === "json";

        const ensureCfg = () => {
            if (!cfgBuilder) {
                cfgBuilder = new CFGBuilder(instructions);
                basicBlocks = cfgBuilder.build({ silent: cfgSilentMode });
            }
        };

        const ensureSelectorAnalysis = async () => {
            if (!selectorAnalysis) {
                selectorAnalysis = await extractAndResolveSelectors(instructions);
            }
        };

        // --- OUTPUT: JSON ---
        if (outputFormat === "json") {
            const report: any = { metadata: { address, chain } };
            if (runDisasm || runAll) {
                if (runDisasm) {
                    report.disassembly = instructions;
                } else {
                    report.disassembly = instructions.slice(0, DEFAULT_DISASSEMBLY_PREVIEW_LIMIT);
                    report.disassemblyPreview = true;
                    report.disassemblyPreviewLimit = DEFAULT_DISASSEMBLY_PREVIEW_LIMIT;
                    report.totalInstructions = instructions.length;
                }
            }
            if (runCfg || runAll) {
                ensureCfg();
                report.cfg = JSON.parse(cfgBuilder!.getJsonAdjacencyList(true));
                report.cfgJumpResolution = cfgBuilder!.getJumpResolutionStats();
                cfgBuilder!.exportToJson("cli_output.json");
            }
            if (runSelectors || runAll) {
                await ensureSelectorAnalysis();
                report.selectorAnalysis = selectorAnalysis;
            }
            console.log(JSON.stringify(report, null, 2));
            return; 
        }

        // --- OUTPUT: DOT ---
        if (outputFormat === "dot") {
            ensureCfg();
            cfgBuilder!.exportToDot("cli_output.dot", generateSvg);
            console.log("Saved CFG to cli_output.dot");
            return;
        }

        // --- OUTPUT: TEXT (Default) ---
        if (runDisasm || runAll) {
            const previewMode = runAll && !runDisasm;
            const disassemblyRows = previewMode
                ? instructions.slice(0, DEFAULT_DISASSEMBLY_PREVIEW_LIMIT)
                : instructions;

            console.log(`\n--- DISASSEMBLY ${previewMode ? `(First ${DEFAULT_DISASSEMBLY_PREVIEW_LIMIT} Rows)` : "(Full)"} ---`);
            if (disassembly.metadata.detected) {
                console.log(`[+] CBOR metadata trailer detected (${disassembly.metadata.metadataLength} bytes).`);
                console.log(`[+] Solidity compiler: ${disassembly.metadata.solidityVersion || "Unknown"}`);
            } else {
                console.log(`[+] CBOR metadata trailer not detected.`);
            }

            if (previewMode && instructions.length > DEFAULT_DISASSEMBLY_PREVIEW_LIMIT) {
                console.log(`[+] Showing ${DEFAULT_DISASSEMBLY_PREVIEW_LIMIT} of ${instructions.length} rows. Use --disasm for full output.`);
            }

            for (let i = 0; i < disassemblyRows.length; i++) {
                const inst = disassemblyRows[i];
                console.log(`0x${inst.offset.toString(16).padStart(4,'0')}: ${inst.opcode.toString(16).padStart(2,'0')} ${inst.mnemonic} ${inst.operand || ''}`);
            }
        }

        if (runSelectors || runAll) {
            console.log(`\n--- FUNCTION SELECTORS ---`);
            await ensureSelectorAnalysis();
            for (const line of formatSelectorAnalysis(selectorAnalysis!)) {
                console.log(line);
            }
        }

        if (runCfg || runAll) {
            ensureCfg();
            const stats = cfgBuilder!.getJumpResolutionStats();
            console.log(`\n--- CONTROL FLOW GRAPH ---`);
            console.log(`Blocks Generated: ${basicBlocks.length}`);
            console.log(`Jump Resolution: ${stats.staticJumps} Static, ${stats.dynamicJumps} Dynamic.`);
            console.log(`Static Resolution: ${stats.staticPercentage.toFixed(2)}%`);
        }

        if (runSecurity || runAll) {
            ensureCfg();
            console.log(`\n--- SECURITY ANALYSIS ---`);
            const security = new SecurityAnalyzer(instructions, basicBlocks, provider, address);
            await security.analyze();
        }

    } catch (error: any) {
        console.error("CLI Error:", error.message);
    }
}

main();