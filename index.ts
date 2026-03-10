import { JsonRpcProvider } from "ethers";
import { disassembleBytecode } from "./disassembler";
import { extractAndResolveSelectors } from "./extractor";

async function main() {
    // Connect to a free public RPC (Ethereum Mainnet)
    const provider = new JsonRpcProvider("https://eth.llamarpc.com", 1);    // Example: Wrapped Ether (WETH) Contract
    
    // for testing

    //WETH Address
    // const targetAddress = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    // Uniswap Address
    const targetAddress = "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984";
    console.log(`Fetching bytecode for: ${targetAddress}...`);

    try {
        const rawBytecode = await provider.getCode(targetAddress);
        
        if (rawBytecode === "0x") {
            console.log("No bytecode found. Is it an Externally Owned Account?");
            return;
        }
        console.log("Raw Bytecode:", rawBytecode);
        console.log("Disassembling...");
        const instructions = disassembleBytecode(rawBytecode);

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
    } catch (error) {
        console.error("Error fetching or parsing bytecode:", error);
    }
}

main();