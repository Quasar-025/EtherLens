// lib/disassembler.ts
import { OPCODES } from "./opcodes";

export interface Instruction {
    offset: number;
    opcode: number;
    mnemonic: string;
    operand: string | null;
}

export interface DisassemblyMetadata {
    detected: boolean;
    cborValid: boolean;
    metadataLength: number;
    solidityVersion: string | null;
}

export interface DisassemblyResult {
    instructions: Instruction[];
    executableBytecodeHex: string;
    metadata: DisassemblyMetadata;
}

interface CborLengthResult {
    ok: boolean;
    length: number;
    nextOffset: number;
}

interface CborParseResult {
    ok: boolean;
    value: unknown;
    nextOffset: number;
}

function readCborLength(buffer: Buffer, offset: number, additionalInfo: number): CborLengthResult {
    if (additionalInfo < 24) {
        return { ok: true, length: additionalInfo, nextOffset: offset };
    }

    if (additionalInfo === 24) {
        if (offset + 1 > buffer.length) {
            return { ok: false, length: 0, nextOffset: offset };
        }
        return { ok: true, length: buffer[offset], nextOffset: offset + 1 };
    }

    if (additionalInfo === 25) {
        if (offset + 2 > buffer.length) {
            return { ok: false, length: 0, nextOffset: offset };
        }
        return { ok: true, length: buffer.readUInt16BE(offset), nextOffset: offset + 2 };
    }

    if (additionalInfo === 26) {
        if (offset + 4 > buffer.length) {
            return { ok: false, length: 0, nextOffset: offset };
        }
        return { ok: true, length: buffer.readUInt32BE(offset), nextOffset: offset + 4 };
    }

    if (additionalInfo === 27) {
        if (offset + 8 > buffer.length) {
            return { ok: false, length: 0, nextOffset: offset };
        }

        const bigLength = buffer.readBigUInt64BE(offset);
        if (bigLength > BigInt(Number.MAX_SAFE_INTEGER)) {
            return { ok: false, length: 0, nextOffset: offset };
        }

        return { ok: true, length: Number(bigLength), nextOffset: offset + 8 };
    }

    return { ok: false, length: 0, nextOffset: offset };
}

function decodeHalfFloat(raw: number): number {
    const sign = (raw & 0x8000) === 0 ? 1 : -1;
    const exponent = (raw >> 10) & 0x1f;
    const fraction = raw & 0x03ff;

    if (exponent === 0) {
        return sign * Math.pow(2, -14) * (fraction / 1024);
    }

    if (exponent === 0x1f) {
        if (fraction === 0) {
            return sign * Infinity;
        }
        return Number.NaN;
    }

    return sign * Math.pow(2, exponent - 15) * (1 + fraction / 1024);
}

function parseCborItem(buffer: Buffer, startOffset: number, depth: number): CborParseResult {
    if (startOffset >= buffer.length || depth > 64) {
        return { ok: false, value: null, nextOffset: startOffset };
    }

    const initialByte = buffer[startOffset];
    const majorType = initialByte >> 5;
    const additionalInfo = initialByte & 0x1f;

    if (additionalInfo === 31) {
        return { ok: false, value: null, nextOffset: startOffset };
    }

    const lengthResult = readCborLength(buffer, startOffset + 1, additionalInfo);
    if (!lengthResult.ok) {
        return { ok: false, value: null, nextOffset: startOffset };
    }

    const { length } = lengthResult;
    let cursor = lengthResult.nextOffset;

    if (majorType === 0) {
        return { ok: true, value: length, nextOffset: cursor };
    }

    if (majorType === 1) {
        return { ok: true, value: -1 - length, nextOffset: cursor };
    }

    if (majorType === 2) {
        if (cursor + length > buffer.length) {
            return { ok: false, value: null, nextOffset: startOffset };
        }
        const bytesValue = buffer.subarray(cursor, cursor + length);
        return { ok: true, value: bytesValue, nextOffset: cursor + length };
    }

    if (majorType === 3) {
        if (cursor + length > buffer.length) {
            return { ok: false, value: null, nextOffset: startOffset };
        }
        const textValue = buffer.subarray(cursor, cursor + length).toString("utf8");
        return { ok: true, value: textValue, nextOffset: cursor + length };
    }

    if (majorType === 4) {
        const arrayValue: unknown[] = [];
        for (let i = 0; i < length; i++) {
            const item = parseCborItem(buffer, cursor, depth + 1);
            if (!item.ok) {
                return { ok: false, value: null, nextOffset: startOffset };
            }
            arrayValue.push(item.value);
            cursor = item.nextOffset;
        }
        return { ok: true, value: arrayValue, nextOffset: cursor };
    }

    if (majorType === 5) {
        const mapValue = new Map<unknown, unknown>();
        for (let i = 0; i < length; i++) {
            const key = parseCborItem(buffer, cursor, depth + 1);
            if (!key.ok) {
                return { ok: false, value: null, nextOffset: startOffset };
            }
            cursor = key.nextOffset;

            const value = parseCborItem(buffer, cursor, depth + 1);
            if (!value.ok) {
                return { ok: false, value: null, nextOffset: startOffset };
            }
            cursor = value.nextOffset;

            mapValue.set(key.value, value.value);
        }
        return { ok: true, value: mapValue, nextOffset: cursor };
    }

    if (majorType === 6) {
        const taggedItem = parseCborItem(buffer, cursor, depth + 1);
        if (!taggedItem.ok) {
            return { ok: false, value: null, nextOffset: startOffset };
        }
        return {
            ok: true,
            value: { tag: length, value: taggedItem.value },
            nextOffset: taggedItem.nextOffset
        };
    }

    if (majorType === 7) {
        if (additionalInfo < 20) {
            return { ok: true, value: additionalInfo, nextOffset: cursor };
        }
        if (additionalInfo === 20) {
            return { ok: true, value: false, nextOffset: cursor };
        }
        if (additionalInfo === 21) {
            return { ok: true, value: true, nextOffset: cursor };
        }
        if (additionalInfo === 22) {
            return { ok: true, value: null, nextOffset: cursor };
        }
        if (additionalInfo === 23) {
            return { ok: true, value: undefined, nextOffset: cursor };
        }
        if (additionalInfo === 24) {
            if (cursor > buffer.length) {
                return { ok: false, value: null, nextOffset: startOffset };
            }
            return { ok: true, value: buffer[cursor - 1], nextOffset: cursor };
        }
        if (additionalInfo === 25) {
            if (cursor > buffer.length) {
                return { ok: false, value: null, nextOffset: startOffset };
            }
            const half = buffer.readUInt16BE(cursor - 2);
            return { ok: true, value: decodeHalfFloat(half), nextOffset: cursor };
        }
        if (additionalInfo === 26) {
            if (cursor > buffer.length) {
                return { ok: false, value: null, nextOffset: startOffset };
            }
            const floatValue = buffer.readFloatBE(cursor - 4);
            return { ok: true, value: floatValue, nextOffset: cursor };
        }
        if (additionalInfo === 27) {
            if (cursor > buffer.length) {
                return { ok: false, value: null, nextOffset: startOffset };
            }
            const doubleValue = buffer.readDoubleBE(cursor - 8);
            return { ok: true, value: doubleValue, nextOffset: cursor };
        }
    }

    return { ok: false, value: null, nextOffset: startOffset };
}

function extractSolidityVersion(metadataBuffer: Buffer): { cborValid: boolean; solidityVersion: string | null } {
    const parsed = parseCborItem(metadataBuffer, 0, 0);
    if (!parsed.ok || parsed.nextOffset !== metadataBuffer.length) {
        return { cborValid: false, solidityVersion: null };
    }

    const metadataMap = parsed.value;
    if (!(metadataMap instanceof Map)) {
        return { cborValid: true, solidityVersion: null };
    }

    const solcValue = metadataMap.get("solc");
    if (solcValue == null) {
        return { cborValid: true, solidityVersion: null };
    }

    if (Buffer.isBuffer(solcValue)) {
        if (solcValue.length >= 3) {
            return {
                cborValid: true,
                solidityVersion: `${solcValue[0]}.${solcValue[1]}.${solcValue[2]}`
            };
        }
        return { cborValid: true, solidityVersion: null };
    }

    if (typeof solcValue === "string") {
        const normalized = solcValue.trim();
        return { cborValid: true, solidityVersion: normalized.length > 0 ? normalized : null };
    }

    if (Array.isArray(solcValue) && solcValue.length >= 3) {
        const [major, minor, patch] = solcValue;
        if (
            typeof major === "number" &&
            typeof minor === "number" &&
            typeof patch === "number"
        ) {
            return {
                cborValid: true,
                solidityVersion: `${major}.${minor}.${patch}`
            };
        }
    }

    return { cborValid: true, solidityVersion: null };
}

function splitExecutableAndMetadata(bytecode: Buffer): { executableBytecode: Buffer; metadata: DisassemblyMetadata } {
    const emptyMetadata: DisassemblyMetadata = {
        detected: false,
        cborValid: false,
        metadataLength: 0,
        solidityVersion: null
    };

    if (bytecode.length <= 2) {
        return { executableBytecode: bytecode, metadata: emptyMetadata };
    }

    const metadataLength = (bytecode[bytecode.length - 2] << 8) | bytecode[bytecode.length - 1];
    if (metadataLength === 0) {
        return { executableBytecode: bytecode, metadata: emptyMetadata };
    }

    const metadataStart = bytecode.length - metadataLength - 2;
    if (metadataStart < 0) {
        return { executableBytecode: bytecode, metadata: emptyMetadata };
    }

    const metadataBuffer = bytecode.subarray(metadataStart, bytecode.length - 2);
    if (metadataBuffer.length !== metadataLength) {
        return { executableBytecode: bytecode, metadata: emptyMetadata };
    }

    const parsedMetadata = extractSolidityVersion(metadataBuffer);
    if (!parsedMetadata.cborValid) {
        return { executableBytecode: bytecode, metadata: emptyMetadata };
    }

    return {
        executableBytecode: bytecode.subarray(0, metadataStart),
        metadata: {
            detected: true,
            cborValid: true,
            metadataLength,
            solidityVersion: parsedMetadata.solidityVersion
        }
    };
}

export function disassembleBytecode(hexString: string): DisassemblyResult {
    const bytecodeStr = hexString.startsWith("0x") ? hexString.slice(2) : hexString;
    const bytecode = Buffer.from(bytecodeStr, "hex");

    const { executableBytecode, metadata } = splitExecutableAndMetadata(bytecode);

    // Disassembly loop is robust against truncated PUSH payloads by relying on Buffer.subarray.
    const instructions: Instruction[] = [];
    let pc = 0;

    while (pc < executableBytecode.length) {
        const opcode = executableBytecode[pc];
        const mnemonic = OPCODES[opcode] || `UNKNOWN_0x${opcode.toString(16).padStart(2, "0")}`;

        let operand: string | null = null;
        let instructionLength = 1;

        if (opcode >= 0x5f && opcode <= 0x7f) {
            const pushBytesCount = opcode === 0x5f ? 0 : opcode - 0x5f;
            const operandBuffer = executableBytecode.subarray(pc + 1, pc + 1 + pushBytesCount);

            if (operandBuffer.length > 0) {
                operand = "0x" + operandBuffer.toString("hex");
            }

            instructionLength += pushBytesCount;
        }

        instructions.push({
            offset: pc,
            opcode,
            mnemonic,
            operand
        });

        pc += instructionLength;
    }

    return {
        instructions,
        executableBytecodeHex: executableBytecode.toString("hex"),
        metadata
    };
}