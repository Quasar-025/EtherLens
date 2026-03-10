import { JsonRpcProvider, isAddress } from "ethers";
import { disassembleBytecode } from "./lib/disassembler";
import { extractAndResolveSelectors, formatSelectorAnalysis, SelectorAnalysisResult } from "./lib/extractor";
import { BasicBlock, CFGBuilder } from "./lib/graph";
import { SecurityAnalyzer } from "./lib/security";
import { fetchWithBackoff } from "./lib/rpc";

const RPC_URLS: Record<string, string> = {
    ethereum: "https://eth.llamarpc.com",
    polygon: "https://polygon-rpc.com",
    base: "https://mainnet.base.org",
    arbitrum: "https://arb1.arbitrum.io/rpc"
};

const DEFAULT_DISASSEMBLY_PREVIEW_LIMIT = 20;

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args.includes("--help")) {
        console.log("Usage: analyzer <address> --chain <chain> --output <json|text|dot> [flags]");
        console.log("Flags: --disasm, --selectors, --cfg, --security");
        console.log(`Default disassembly output is preview mode (${DEFAULT_DISASSEMBLY_PREVIEW_LIMIT} rows). Use --disasm for full output.`);
        return;
    }

    // Parse Arguments
    const address = args.find(a => isAddress(a));
    if (!address) return console.error("Error: Please provide a valid Ethereum contract address.");

    const chainIndex = args.indexOf("--chain");
    const chain = chainIndex !== -1 ? args[chainIndex + 1].toLowerCase() : "ethereum";
    
    const outputIndex = args.indexOf("--output");
    const outputFormat = outputIndex !== -1 ? args[outputIndex + 1].toLowerCase() : "text";

    const runDisasm = args.includes("--disasm");
    const runSelectors = args.includes("--selectors");
    const runCfg = args.includes("--cfg");
    const runSecurity = args.includes("--security");
    
    // If no specific flags are provided, run everything
    const runAll = !runDisasm && !runSelectors && !runCfg && !runSecurity;

    const rpcUrl = RPC_URLS[chain];
    if (!rpcUrl) return console.error(`Error: Unsupported chain '${chain}'. Supported: ${Object.keys(RPC_URLS).join(", ")}`);
    
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

        const ensureCfg = () => {
            if (!cfgBuilder) {
                cfgBuilder = new CFGBuilder(instructions);
                basicBlocks = cfgBuilder.build();
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
                report.cfg = JSON.parse(cfgBuilder!.getJsonAdjacencyList());
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
            cfgBuilder!.exportToDot("cli_output.dot", false);
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
            console.log(`\n--- CONTROL FLOW GRAPH ---`);
            console.log(`Blocks Generated: ${basicBlocks.length}`);
            console.log(`Jump Resolution: ${cfgBuilder!.staticJumps} Static, ${cfgBuilder!.dynamicJumps} Dynamic.`);
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