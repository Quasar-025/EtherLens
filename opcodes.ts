// opcodes.ts
export const OPCODES: Record<number, string> = {
    0x00: "STOP",
    0x01: "ADD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x5b: "JUMPDEST",
    0xf3: "RETURN",
    0xfd: "REVERT",
    0xfe: "INVALID",
    0xff: "SELFDESTRUCT",
    0x04: "DIV",
    0x10: "LT",
    0x14: "EQ",
    0x16: "AND",
    0x35: "CALLDATALOAD",
    0x63: "PUSH4",
};

// Programmatically add PUSH1 (0x60) through PUSH32 (0x7f)
for (let i = 0x60; i <= 0x7f; i++) {
    OPCODES[i] = `PUSH${i - 0x5f}`;
}

// Programmatically add DUP1 (0x80) through DUP16 (0x8f)
for (let i = 0x80; i <= 0x8f; i++) {
    OPCODES[i] = `DUP${i - 0x7f}`;
}

// Programmatically add SWAP1 (0x90) through SWAP16 (0x9f)
for (let i = 0x90; i <= 0x9f; i++) {
    OPCODES[i] = `SWAP${i - 0x8f}`;
}