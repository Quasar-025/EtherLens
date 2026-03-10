import { OPCODES } from "./opcodes";

export interface Instruction {
    offset: number;
    opcode: number;
    mnemonic: string;
    operand: string | null;
}

export function disassembleBytecode(hexString: string): Instruction[] {
    // 1. Clean the input
    let bytecodeStr = hexString.startsWith("0x") ? hexString.slice(2) : hexString;
    const bytecode = Buffer.from(bytecodeStr, "hex");

    // 2. Strip the CBOR Metadata & Extract Solidity Version
    let executableBytecode = bytecode;
    let solidityVersion = "Unknown";

    if (bytecode.length > 2) {
        const metadataLength = (bytecode[bytecode.length - 2] << 8) | bytecode[bytecode.length - 1];
        
        if (metadataLength <= bytecode.length - 2) {
            // Extract the metadata block
            const metadataBuffer = bytecode.subarray(bytecode.length - metadataLength - 2, bytecode.length - 2);
            executableBytecode = bytecode.subarray(0, bytecode.length - metadataLength - 2);

            // HEURISTIC: Search for the hex representation of the string "solc" (0x736f6c63)
            const solcStringHex = "736f6c63";
            const metadataHex = metadataBuffer.toString("hex");
            const solcIndex = metadataHex.indexOf(solcStringHex);

            if (solcIndex !== -1) {
                // In CBOR, the 3-byte version array usually follows "solc" + 1 byte marker
                // We jump 8 hex chars ("solc") + 2 hex chars (CBOR marker, usually '43')
                const versionHex = metadataHex.slice(solcIndex + 10, solcIndex + 16);
                if (versionHex.length === 6) {
                    const major = parseInt(versionHex.slice(0, 2), 16);
                    const minor = parseInt(versionHex.slice(2, 4), 16);
                    const patch = parseInt(versionHex.slice(4, 6), 16);
                    solidityVersion = `${major}.${minor}.${patch}`;
                    console.log(`\n[+] Extracted Solidity Compiler Version: ${solidityVersion}`);
                }
            }
        }
    }

    // 3. The Disassembly Loop
    const instructions: Instruction[] = [];
    let pc = 0; // Program Counter

    while (pc < executableBytecode.length) {
        const opcode = executableBytecode[pc];
        const mnemonic = OPCODES[opcode] || `UNKNOWN_0x${opcode.toString(16)}`;
        
        let operand: string | null = null;
        let instructionLength = 1;

        // THE TRAP: If it's a PUSH instruction (0x60 to 0x7f), we MUST skip the next N bytes.
        // If we don't, the analyzer will read hardcoded data as if it were executable code.
        if (opcode >= 0x60 && opcode <= 0x7f) {
            const pushBytesCount = opcode - 0x5f;
            
            // Extract the hex data that follows the PUSH instruction
            const operandBuffer = executableBytecode.subarray(pc + 1, pc + 1 + pushBytesCount);
            operand = "0x" + operandBuffer.toString("hex");
            
            // Advance the instruction length by the amount of data bytes we just read
            instructionLength += pushBytesCount;
        }

        instructions.push({
            offset: pc,
            opcode: opcode,
            mnemonic: mnemonic,
            operand: operand
        });

        // Advance the program counter to the next actual instruction
        pc += instructionLength;
    }

    return instructions;
}