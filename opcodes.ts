// opcodes.ts
export const OPCODES: Record<number, string> = {
    // 0x00 range - Stop and Arithmetic Operations
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD", 0x0a: "EXP", 0x0b: "SIGNEXTEND",
    // 0x10 range - Comparison & Bitwise Logic
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1a: "BYTE", 0x1b: "SHL", 0x1c: "SHR", 0x1d: "SAR",
    // 0x20 range - SHA3
    0x20: "SHA3",
    // 0x30 range - Environmental Information
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY", 0x3a: "GASPRICE", 0x3b: "EXTCODESIZE", 0x3c: "EXTCODECOPY", 0x3d: "RETURNDATASIZE", 0x3e: "RETURNDATACOPY", 0x3f: "EXTCODEHASH",
    // 0x40 range - Block Information
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x49: "BLOBHASH", 0x4a: "BLOBBASEFEE",
    // 0x50 range - Stack, Memory, Storage and Flow Operations
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5a: "GAS", 0x5b: "JUMPDEST", 0x5c: "TLOAD", 0x5d: "TSTORE", 0x5e: "MCOPY", 0x5f: "PUSH0",
    // 0xf0 range - System operations
    0xf0: "CREATE", 0xf1: "CALL", 0xf2: "CALLCODE", 0xf3: "RETURN", 0xf4: "DELEGATECALL", 0xf5: "CREATE2", 0xfa: "STATICCALL", 0xfd: "REVERT", 0xfe: "INVALID", 0xff: "SELFDESTRUCT",
};

// Programmatically add PUSH1 (0x60) through PUSH32 (0x7f)
for (let i = 0x60; i <= 0x7f; i++) { OPCODES[i] = `PUSH${i - 0x5f}`; }
// Programmatically add DUP1 (0x80) through DUP16 (0x8f)
for (let i = 0x80; i <= 0x8f; i++) { OPCODES[i] = `DUP${i - 0x7f}`; }
// Programmatically add SWAP1 (0x90) through SWAP16 (0x9f)
for (let i = 0x90; i <= 0x9f; i++) { OPCODES[i] = `SWAP${i - 0x8f}`; }
// Programmatically add LOG0 (0xa0) through LOG4 (0xa4)
for (let i = 0xa0; i <= 0xa4; i++) { OPCODES[i] = `LOG${i - 0xa0}`; }