import { Instruction } from "./disassembler";

export async function extractAndResolveSelectors(instructions: Instruction[]) {
    console.log("\nScanning Dispatch Table for Function Selectors...");
    
    // Use a Set to avoid duplicates (sometimes contracts check the same selector twice)
    const selectors = new Set<string>();

    let maxCallDataOffset = 0;

    for (let i = 0; i < instructions.length - 1; i++) {
        const current = instructions[i];
        const next = instructions[i + 1];

        // 1. Extract Selectors
        if (current.opcode === 0x63 && next.opcode === 0x14) {
            if (current.operand) selectors.add(current.operand);
        }

        // 2. ABI Parameter Heuristic (Look for PUSH1 <offset> followed by CALLDATALOAD)
        if (current.opcode === 0x60 && next.opcode === 0x35 && current.operand) {
            const offset = parseInt(current.operand, 16);
            if (offset > maxCallDataOffset) {
                maxCallDataOffset = offset;
            }
        }
    }

    // Calculate parameter count based on highest calldata offset accessed
    // Formula: (Highest Offset - 4 byte selector) / 32 byte slot size + 1
    let estimatedParams = 0;
    if (maxCallDataOffset >= 4) {
         estimatedParams = Math.floor((maxCallDataOffset - 4) / 32) + 1;
    }

    console.log(`\n[Heuristic] ABI Scanning detected CALLDATALOAD offsets up to 0x${maxCallDataOffset.toString(16)}.`);
    console.log(`[Heuristic] This contract accepts functions with at least ${estimatedParams} parameter(s).`);
    console.log(`\nFound ${selectors.size} unique functions! Resolving signatures...\n`);

    // Scan for the pattern: PUSH4 <selector> followed by EQ
    for (let i = 0; i < instructions.length - 1; i++) {
        const current = instructions[i];
        const next = instructions[i + 1];

        // 0x63 is PUSH4, 0x14 is EQ
        if (current.opcode === 0x63 && next.opcode === 0x14) {
            if (current.operand) {
                selectors.add(current.operand);
            }
        }
    }

    console.log(`Found ${selectors.size} unique functions! Resolving signatures...\n`);

    // Query the 4byte.directory API to crack the hashes back into readable text
    for (const selector of selectors) {
        try {
            // We use native Node fetch (Requires Node.js 18+)
            const response = await fetch(`https://www.4byte.directory/api/v1/signatures/?hex_signature=${selector}`);
            const data = await response.json();
            
            if (data.count > 0) {
                // Usually the oldest/shortest result is the correct standard one
                const signature = data.results[data.results.length - 1].text_signature;
                console.log(`[+] ${selector} -> ${signature}`);
            } else {
                console.log(`[?] ${selector} -> [Unknown Custom Function]`);
            }
        } catch (error) {
            console.log(`[!] ${selector} -> [API Request Failed]`);
        }
    }
}