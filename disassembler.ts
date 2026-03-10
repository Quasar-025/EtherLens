// disassembler.ts
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

    // 2. Strip the CBOR Metadata (Solidity appends this at the very end)
    // The last 2 bytes dictate the length of the metadata
    let executableBytecode = bytecode;
    if (bytecode.length > 2) {
        const metadataLength = (bytecode[bytecode.length - 2] << 8) | bytecode[bytecode.length - 1];
        // Sanity check: ensure the length makes sense and isn't just random code
        if (metadataLength <= bytecode.length - 2) {
             // Slice off the metadata and the 2 bytes denoting the length
            executableBytecode = bytecode.subarray(0, bytecode.length - metadataLength - 2);
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