// cli.ts
import { JsonRpcProvider } from "ethers";
import { disassembleBytecode } from "./lib/disassembler";
import { extractAndResolveSelectors } from "./lib/extractor";
import { CFGBuilder } from "./lib/graph";
import { SecurityAnalyzer } from "./lib/security";
import { fetchWithBackoff } from "./lib/rpc";

const RPC_URLS: Record<string, string> = {
    ethereum: "https://eth.llamarpc.com",
    polygon: "https://polygon-rpc.com",
    base: "https://mainnet.base.org",
    arbitrum: "https://arb1.arbitrum.io/rpc"
};

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args.includes("--help")) {
        console.log("Usage: analyzer <address> --chain <chain> --output <json|text|dot> [flags]");
        console.log("Flags: --disasm, --selectors, --cfg, --security");
        return;
    }

    // Parse Arguments
    const address = args.find(a => a.startsWith("0x") && a.length === 42);
    if (!address) return console.error("Error: Please provide a valid 42-character 0x contract address.");

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
        const instructions = disassembleBytecode(rawBytecode);
        const cfgBuilder = new CFGBuilder(instructions);
        const basicBlocks = cfgBuilder.build();

        // --- OUTPUT: JSON ---
        if (outputFormat === "json") {
            const report: any = { metadata: { address, chain } };
            if (runDisasm || runAll) report.disassembly = instructions.slice(0, 100); 
            if (runCfg || runAll) report.cfg = JSON.parse(cfgBuilder.getJsonAdjacencyList());
            console.log(JSON.stringify(report, null, 2));
            return; 
        }

        // --- OUTPUT: DOT ---
        if (outputFormat === "dot") {
            cfgBuilder.exportToDot("cli_output.dot", false);
            console.log("Saved CFG to cli_output.dot");
            return;
        }

        // --- OUTPUT: TEXT (Default) ---
        if (runDisasm || runAll) {
            console.log(`\n--- DISASSEMBLY (First 15 Opcodes) ---`);
            for (let i = 0; i < Math.min(15, instructions.length); i++) {
                const inst = instructions[i];
                console.log(`0x${inst.offset.toString(16).padStart(4,'0')}: ${inst.opcode.toString(16).padStart(2,'0')} ${inst.mnemonic} ${inst.operand || ''}`);
            }
        }

        if (runSelectors || runAll) {
            console.log(`\n--- FUNCTION SELECTORS ---`);
            await extractAndResolveSelectors(instructions);
        }

        if (runCfg || runAll) {
            console.log(`\n--- CONTROL FLOW GRAPH ---`);
            console.log(`Blocks Generated: ${basicBlocks.length}`);
            console.log(`Jump Resolution: ${cfgBuilder.staticJumps} Static, ${cfgBuilder.dynamicJumps} Dynamic.`);
        }

        if (runSecurity || runAll) {
            console.log(`\n--- SECURITY ANALYSIS ---`);
            const security = new SecurityAnalyzer(instructions, basicBlocks, provider, address);
            await security.analyze();
        }

    } catch (error: any) {
        console.error("CLI Error:", error.message);
    }
}

main();