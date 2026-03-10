// security.ts
import { Instruction } from "./disassembler";
import { BasicBlock } from "./graph";
import { JsonRpcProvider } from "ethers";

export class SecurityAnalyzer {
    private instructions: Instruction[];
    private blocks: BasicBlock[];
    private provider: JsonRpcProvider;
    private address: string;

    constructor(instructions: Instruction[], blocks: BasicBlock[], provider: JsonRpcProvider, address: string) {
        this.instructions = instructions;
        this.blocks = blocks;
        this.provider = provider;
        this.address = address;
    }

    public async analyze() {
        console.log("\nRunning All Security Heuristics...");
        
        await this.detectProxyPattern();          // 1
        this.detectUncheckedCalls();              // 2
        this.detectPayableFunctions();            // 3
        this.detectSelfDestructAndTrace();        // 4 (Upgraded with CFG Trace)
        this.detectAccessControl();               // 5 (New)
        this.detectReentrancyGuard();             // 6 (New)
        
        console.log("\n[+] Security Analysis Complete.\n");
    }

    // --- 1. PROXY PATTERN ---
    private async detectProxyPattern() {
        const hasDelegateCall = this.instructions.some(inst => inst.opcode === 0xf4); // DELEGATECALL
        if (hasDelegateCall) {
            const eip1967Slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
            const legacySlot = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";
            try {
                const val1967 = await this.provider.getStorage(this.address, eip1967Slot);
                const valLegacy = await this.provider.getStorage(this.address, legacySlot);
                const isEmpty = (val: string) => val === "0x" || val === "0x0000000000000000000000000000000000000000000000000000000000000000";

                if (!isEmpty(val1967)) {
                    console.log(`[!] Pattern 1 (Proxy): EIP-1967 Proxy Detected! Implementation: 0x${val1967.substring(26)}`);
                } else if (!isEmpty(valLegacy)) {
                    console.log(`[!] Pattern 1 (Proxy): Legacy Proxy Detected! Implementation: 0x${valLegacy.substring(26)}`);
                } else {
                    console.log("[✓] Pattern 1 (Proxy): DELEGATECALL present, but proxy storage slots are empty.");
                }
            } catch (error) {
                console.log("[-] Pattern 1 (Proxy): Failed to query live storage slots.");
            }
        } else {
             console.log("[✓] Pattern 1 (Proxy): No DELEGATECALL found. Not a proxy.");
        }
    }

    // --- 2. UNCHECKED EXTERNAL CALLS ---
    private detectUncheckedCalls() {
        let uncheckedCount = 0;
        for (let i = 0; i < this.instructions.length - 2; i++) {
            const current = this.instructions[i];
            const isCall = [0xf1, 0xf2, 0xf4, 0xfa].includes(current.opcode); // CALL, CALLCODE, DELEGATECALL, STATICCALL
            if (isCall) {
                const next1 = this.instructions[i + 1];
                const next2 = this.instructions[i + 2];
                // Prompt specifically asks to detect missing (ISZERO + JUMPI)
                if (!(next1.opcode === 0x15 && next2.opcode === 0x57)) {
                    uncheckedCount++;
                }
            }
        }
        if (uncheckedCount > 0) {
            console.log(`[!] Pattern 2 (Unchecked Calls): Detected ${uncheckedCount} potentially unverified external calls.`);
        } else {
            console.log("[✓] Pattern 2 (Unchecked Calls): All external calls appear to check their return values.");
        }
    }

    // --- 3. PAYABLE FUNCTIONS ---
    private detectPayableFunctions() {
        let hasPayableGuard = false;
        for (let i = 0; i < Math.min(100, this.instructions.length - 3); i++) {
            const op1 = this.instructions[i];
            const op2 = this.instructions[i+1];
            const op3 = this.instructions[i+2];
            // Prompt specifically asks for CALLVALUE + ISZERO (+ REVERT implicitly handled by the JUMPI redirect)
            if ((op1.opcode === 0x34 && op2.opcode === 0x15) || (op1.opcode === 0x34 && op2.opcode === 0x80 && op3.opcode === 0x15)) {
                hasPayableGuard = true; break;
            }
        }
        if (hasPayableGuard) {
            console.log("[✓] Pattern 3 (Payable): Found non-payable guards (CALLVALUE + ISZERO). Contract differentiates ETH acceptance.");
        } else {
            console.log("[!] Pattern 3 (Payable): No global non-payable guard detected. All functions might be payable.");
        }
    }

    // --- 4. SELFDESTRUCT WITH CFG TRACE ---
    private detectSelfDestructAndTrace() {
        // Find the specific block that contains the 0xff opcode
        const targetBlock = this.blocks.find(b => b.instructions.some(inst => inst.opcode === 0xff));
        
        if (!targetBlock) {
            console.log("[✓] Pattern 4 (Selfdestruct): No SELFDESTRUCT opcode found.");
            return;
        }

        console.log(`[!] Pattern 4 (Selfdestruct): HIGH RISK. SELFDESTRUCT found in Block ${targetBlock.id}. Tracing path...`);
        
        // DFS Pathfinding algorithm to trace from Block 0 to the target block
        const path = this.tracePathDFS(0, targetBlock.id, new Set<number>());
        if (path) {
            const pathStr = path.map(id => `Block ${id}`).join(" -> ");
            console.log(`    ↳ Execution Path to destruction: ${pathStr}`);
        } else {
            console.log(`    ↳ Could not statically trace a continuous path from Entry to Block ${targetBlock.id} (likely obscured by dynamic jumps).`);
        }
    }

    // Helper method for the CFG trace
    private tracePathDFS(currentId: number, targetId: number, visited: Set<number>): number[] | null {
        if (currentId === targetId) return [currentId];
        visited.add(currentId);

        const currentBlock = this.blocks[currentId];
        if (!currentBlock) return null;

        for (const successorId of currentBlock.successors) {
            if (!visited.has(successorId)) {
                const path = this.tracePathDFS(successorId, targetId, visited);
                if (path) return [currentId, ...path]; // Prepend current node to the successful path
            }
        }
        return null;
    }

    // --- 5. ACCESS CONTROL (onlyOwner) ---
    private detectAccessControl() {
        let hasOwnerCheck = false;
        
        // Broaden the search window significantly. Compilers often push variables, 
        // perform other checks, or jump to a modifier block before doing the EQ check.
        // We look for a block that contains CALLER (msg.sender) and an SLOAD (storage read)
        // followed eventually by an EQ or REVERT within the same general execution flow.
        
        for (const block of this.blocks) {
            const opcodes = block.instructions.map(inst => inst.opcode);
            
            // Check if this single block loads the caller AND reads from storage
            const hasCaller = opcodes.includes(0x33); // CALLER
            const hasSload = opcodes.includes(0x54);  // SLOAD
            
            if (hasCaller && hasSload) {
                 // Check if it performs an equality check or branches to a revert
                 const hasEq = opcodes.includes(0x14); // EQ
                 const hasRevert = opcodes.includes(0xfd); // REVERT
                 const hasJumpI = opcodes.includes(0x57); // JUMPI (checking the result)

                 if (hasEq || (hasRevert && hasJumpI)) {
                     hasOwnerCheck = true;
                     break;
                 }
            }
        }

        if (hasOwnerCheck) {
            console.log("[✓] Pattern 5 (Access Control): Detected CALLER compared to SLOAD logic. Likely uses role-based access modifiers.");
        } else {
            console.log("[!] Pattern 5 (Access Control): No standard onlyOwner pattern detected statically. Ensure access is restricted where necessary.");
        }
    }

    // --- 6. REENTRANCY GUARDS - UPGRADED ---
    private detectReentrancyGuard() {
        let hasReentrancyGuard = false;
        
        // A standard mutex involves writing to storage (SSTORE), making an external call, 
        // and writing to storage again to unlock. We will scan across block boundaries
        // to find this general sequence, as it often spans multiple basic blocks.

        for (let i = 0; i < this.instructions.length - 20; i++) {
            if (this.instructions[i].opcode === 0x55) { // First SSTORE (Lock)
                let foundCall = false;
                
                // Scan ahead up to 100 instructions (spanning multiple blocks)
                for (let j = i + 1; j < Math.min(i + 100, this.instructions.length); j++) {
                    const lookAheadOp = this.instructions[j].opcode;
                    
                    if ([0xf1, 0xf2, 0xf4, 0xfa].includes(lookAheadOp)) {
                        foundCall = true; // Found the external call
                    }
                    
                    // If we found a call, and now we see another SSTORE, it's a mutex pattern
                    if (foundCall && lookAheadOp === 0x55) {
                        hasReentrancyGuard = true;
                        break;
                    }
                    
                    // Optimization: If we hit a halting instruction before the unlock, break early
                    if ([0x00, 0xf3, 0xfd, 0xfe, 0xff].includes(lookAheadOp)) {
                        break;
                    }
                }
                if (hasReentrancyGuard) break;
            }
        }

        if (hasReentrancyGuard) {
            console.log("[✓] Pattern 6 (Reentrancy Guard): Detected SSTORE -> CALL -> SSTORE sequence. Contract likely implements mutex guards.");
        } else {
            console.log("[!] Pattern 6 (Reentrancy Guard): No standard locking mechanism found spanning external calls.");
        }
    }
}