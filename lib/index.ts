import { JsonRpcProvider } from "ethers";
import { disassembleBytecode } from "./disassembler";
import { extractAndResolveSelectors } from "./extractor";
import { CFGBuilder } from "./graph";
import * as fs from "fs";
import { SecurityAnalyzer } from "./security";
import { fetchWithBackoff } from "./rpc";

async function main() {
    // Basic CLI Argument Parsing
    const args = process.argv.slice(2);
    const generateSvg = args.includes("--svg");
    // Connect to a free public RPC (Ethereum Mainnet)
    const provider = new JsonRpcProvider("https://eth.llamarpc.com", 1);    // Example: Wrapped Ether (WETH) Contract
    // Search the CLI arguments for anything that looks like an Ethereum address (starts with 0x)
    const cliAddress = args.find(arg => arg.startsWith("0x") && arg.length === 42);
    // Use the CLI address if provided, otherwise fallback to the Uniswap Address for testing
    // for testing

    //WETH Address
    // const targetAddress = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    // Uniswap Address
    const targetAddress = cliAddress || "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984";
    console.log(`Fetching bytecode for: ${targetAddress}...`);

    try {
        const rawBytecode = await fetchWithBackoff(() => provider.getCode(targetAddress));
        
        if (rawBytecode === "0x") {
            console.log("No bytecode found.");
            return;
        }
        // console.log("Raw Bytecode:", rawBytecode);
        console.log("Disassembling...");
        const disassembly = disassembleBytecode(rawBytecode);
        const instructions = disassembly.instructions;

        if (disassembly.metadata.detected) {
            console.log(`[+] CBOR metadata trailer detected (${disassembly.metadata.metadataLength} bytes).`);
            console.log(`[+] Solidity compiler: ${disassembly.metadata.solidityVersion || "Unknown"}`);
        } else {
            console.log("[+] CBOR metadata trailer not detected.");
        }

        console.log("OFFSET | HEX | MNEMONIC | OPERAND");
        console.log("-".repeat(40));
        
        // FIX: Use slice and for...of to satisfy TypeScript's strict null checks
        const subset = instructions.slice(0, 15);
        for (const inst of subset) {
            const offsetHex = `0x${inst.offset.toString(16).padStart(4, '0')}`;
            const opcodeHex = inst.opcode.toString(16).padStart(2, '0');
            const operandStr = inst.operand ? inst.operand : "";
            
            console.log(`${offsetHex} |  ${opcodeHex} | ${inst.mnemonic.padEnd(8)} | ${operandStr}`);
        }
        await extractAndResolveSelectors(instructions);

        const cfg = new CFGBuilder(instructions);
        const basicBlocks = cfg.build();
        // Export JSON Adjacency List
        const jsonGraph = cfg.getJsonAdjacencyList();
        fs.writeFileSync("cfg.json", jsonGraph);
        console.log(`[+] JSON Adjacency list saved to cfg.json`);

        // Export DOT (and SVG if --svg flag is passed)
        cfg.exportToDot("cfg.dot", generateSvg);

        // Security Analysis
        const securityAnalyzer = new SecurityAnalyzer(instructions, basicBlocks, provider, targetAddress);
        await securityAnalyzer.analyze();
    } catch (error) {
        console.error("Error fetching or parsing bytecode:", error);
    }
}

main();