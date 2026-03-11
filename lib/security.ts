// security.ts
import { Instruction } from "./disassembler";
import { BasicBlock } from "./graph";
import { JsonRpcProvider } from "ethers";
import { fetchWithBackoff } from "./rpc";

const EXTERNAL_CALL_OPCODES = new Set<number>([0xf1, 0xf4, 0xfa]); // CALL, DELEGATECALL, STATICCALL
const HALTING_OPCODES = new Set<number>([0x00, 0xf3, 0xfd, 0xfe, 0xff]);

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
        const delegateCallIndexes = this.instructions
            .map((inst, index) => (inst.opcode === 0xf4 ? index : -1))
            .filter(index => index !== -1);

        if (delegateCallIndexes.length === 0) {
            console.log("[✓] Pattern 1 (Proxy): No DELEGATECALL found. Not a proxy.");
            return;
        }

        const hasStorageBackedDelegateCall = delegateCallIndexes.some(index => this.findPreviousOpcode(index, 0x54, 24) !== -1);
        if (!hasStorageBackedDelegateCall) {
            console.log("[!] Pattern 1 (Proxy): DELEGATECALL detected, but target does not appear to be storage-backed.");
            return;
        }

        const eip1967Slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
        const legacySlot = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";

        try {
            const val1967 = await fetchWithBackoff(() => this.provider.getStorage(this.address, eip1967Slot));
            const valLegacy = await fetchWithBackoff(() => this.provider.getStorage(this.address, legacySlot));

            const impl1967 = this.extractAddressFromStorageWord(val1967);
            const implLegacy = this.extractAddressFromStorageWord(valLegacy);

            if (impl1967) {
                console.log(`[!] Pattern 1 (Proxy): EIP-1967 proxy detected (target sourced from storage). Implementation: ${impl1967}`);
            } else if (implLegacy) {
                console.log(`[!] Pattern 1 (Proxy): Legacy proxy detected (target sourced from storage). Implementation: ${implLegacy}`);
            } else {
                console.log("[!] Pattern 1 (Proxy): Storage-backed DELEGATECALL detected, but implementation slot values are empty.");
            }
        } catch (error) {
            console.log("[-] Pattern 1 (Proxy): Failed to query live storage slots.");
        }
    }

    // --- 2. UNCHECKED EXTERNAL CALLS ---
    private detectUncheckedCalls() {
        const uncheckedOffsets: string[] = [];

        for (let i = 0; i < this.instructions.length; i++) {
            const current = this.instructions[i];
            if (!this.isExternalCallOpcode(current.opcode)) {
                continue;
            }

            if (!this.isCallReturnChecked(i)) {
                uncheckedOffsets.push(`0x${current.offset.toString(16)}`);
            }
        }

        if (uncheckedOffsets.length > 0) {
            const preview = uncheckedOffsets.slice(0, 5).join(", ");
            const suffix = uncheckedOffsets.length > 5 ? ", ..." : "";
            console.log(`[!] Pattern 2 (Unchecked Calls): Detected ${uncheckedOffsets.length} potentially unverified external calls (missing ISZERO + JUMPI) at offsets: ${preview}${suffix}`);
        } else {
            console.log("[✓] Pattern 2 (Unchecked Calls): All external calls appear to check their return values.");
        }
    }

    // --- 3. PAYABLE FUNCTIONS ---
    private detectPayableFunctions() {
        const guardedCallValueOffsets: string[] = [];
        const unguardedCallValueOffsets: string[] = [];

        for (let i = 0; i < this.instructions.length; i++) {
            if (this.instructions[i].opcode !== 0x34) {
                continue;
            }

            if (this.hasNonPayableGuardFrom(i)) {
                guardedCallValueOffsets.push(`0x${this.instructions[i].offset.toString(16)}`);
            } else {
                unguardedCallValueOffsets.push(`0x${this.instructions[i].offset.toString(16)}`);
            }
        }

        if (guardedCallValueOffsets.length > 0 && unguardedCallValueOffsets.length > 0) {
            console.log(`[!] Pattern 3 (Payable): Found ${guardedCallValueOffsets.length} non-payable guard(s) and ${unguardedCallValueOffsets.length} unguarded CALLVALUE site(s). Contract likely has both non-payable and payable entrypoints.`);
            return;
        }

        if (guardedCallValueOffsets.length > 0) {
            console.log(`[✓] Pattern 3 (Payable): Found ${guardedCallValueOffsets.length} non-payable guard(s) using CALLVALUE + ISZERO + JUMPI + REVERT.`);
            return;
        }

        if (unguardedCallValueOffsets.length > 0) {
            const preview = unguardedCallValueOffsets.slice(0, 5).join(", ");
            const suffix = unguardedCallValueOffsets.length > 5 ? ", ..." : "";
            console.log(`[!] Pattern 3 (Payable): Detected CALLVALUE usage without non-payable guards at offsets: ${preview}${suffix}. ETH-accepting (payable) paths are likely.`);
            return;
        }

        console.log("[✓] Pattern 3 (Payable): No CALLVALUE opcode observed in executable paths.");
    }

    // --- 4. SELFDESTRUCT WITH CFG TRACE ---
    private detectSelfDestructAndTrace() {
        const targetBlocks = this.blocks.filter(block => block.instructions.some(inst => inst.opcode === 0xff));

        if (targetBlocks.length === 0) {
            console.log("[✓] Pattern 4 (Selfdestruct): No SELFDESTRUCT opcode found.");
            return;
        }

        console.log(`[!] Pattern 4 (Selfdestruct): HIGH RISK. SELFDESTRUCT found in ${targetBlocks.length} block(s). Tracing CFG paths...`);

        for (const targetBlock of targetBlocks) {
            const path = this.tracePathDFS(0, targetBlock.id, new Set<number>());
            if (path) {
                const pathStr = path.map(id => `Block ${id}`).join(" -> ");
                console.log(`    -> Execution Path to destruction (Block ${targetBlock.id}): ${pathStr}`);
            } else {
                console.log(`    -> Could not statically trace a continuous path from Entry to Block ${targetBlock.id} (likely obscured by dynamic jumps).`);
            }
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
        const ownerCheckOffsets: string[] = [];

        for (let i = 0; i < this.instructions.length; i++) {
            if (this.instructions[i].opcode !== 0x14) { // EQ
                continue;
            }

            const lookbackStart = Math.max(0, i - 12);
            let hasCaller = false;
            let hasSload = false;
            for (let j = lookbackStart; j < i; j++) {
                if (this.instructions[j].opcode === 0x33) {
                    hasCaller = true;
                }
                if (this.instructions[j].opcode === 0x54) {
                    hasSload = true;
                }
            }

            if (!hasCaller || !hasSload) {
                continue;
            }

            let hasBranchOrRevert = false;
            for (let j = i + 1; j < Math.min(i + 8, this.instructions.length); j++) {
                const opcode = this.instructions[j].opcode;
                if (opcode === 0x57 || opcode === 0xfd) {
                    hasBranchOrRevert = true;
                    break;
                }
                if (HALTING_OPCODES.has(opcode)) {
                    break;
                }
            }

            if (hasBranchOrRevert) {
                ownerCheckOffsets.push(`0x${this.instructions[i].offset.toString(16)}`);
            }
        }

        if (ownerCheckOffsets.length > 0) {
            const preview = ownerCheckOffsets.slice(0, 5).join(", ");
            const suffix = ownerCheckOffsets.length > 5 ? ", ..." : "";
            console.log(`[✓] Pattern 5 (Access Control): Detected CALLER-vs-SLOAD owner checks around EQ at offsets: ${preview}${suffix}.`);
        } else {
            console.log("[!] Pattern 5 (Access Control): No standard onlyOwner pattern detected statically. Ensure access is restricted where necessary.");
        }
    }

    // --- 6. REENTRANCY GUARDS - UPGRADED ---
    private detectReentrancyGuard() {
        const findings: string[] = [];

        for (let i = 0; i < this.instructions.length; i++) {
            if (!this.isExternalCallOpcode(this.instructions[i].opcode)) {
                continue;
            }

            const lockStoreIndex = this.findPreviousOpcode(i, 0x55, 40);
            const lockLoadIndex = lockStoreIndex !== -1 ? this.findPreviousOpcode(lockStoreIndex, 0x54, 24) : -1;
            const unlockStoreIndex = this.findNextOpcode(i + 1, 0x55, 60);

            if (lockLoadIndex !== -1 && lockStoreIndex !== -1 && unlockStoreIndex !== -1) {
                const lockOffset = `0x${this.instructions[lockStoreIndex].offset.toString(16)}`;
                const callOffset = `0x${this.instructions[i].offset.toString(16)}`;
                const unlockOffset = `0x${this.instructions[unlockStoreIndex].offset.toString(16)}`;
                const sameSlot = this.hasMatchingSstoreSlot(lockStoreIndex, unlockStoreIndex);
                const slotHint = sameSlot ? " (matching storage slot)" : "";
                findings.push(`mutex pattern SLOAD->SSTORE->CALL->SSTORE${slotHint} at ${lockOffset} -> ${callOffset} -> ${unlockOffset}`);
                continue;
            }

            // Fallback CEI heuristic: check branch before state write before external interaction.
            const effectsStoreIndex = this.findPreviousOpcode(i, 0x55, 24);
            const checksJumpIndex = effectsStoreIndex !== -1 ? this.findPreviousOpcode(effectsStoreIndex, 0x57, 20) : -1;
            if (checksJumpIndex !== -1) {
                const jumpOffset = `0x${this.instructions[checksJumpIndex].offset.toString(16)}`;
                const storeOffset = `0x${this.instructions[effectsStoreIndex].offset.toString(16)}`;
                const callOffset = `0x${this.instructions[i].offset.toString(16)}`;
                findings.push(`checks-effects-interactions pattern at ${jumpOffset} -> ${storeOffset} -> ${callOffset}`);
                continue;
            }
        }

        if (findings.length > 0) {
            const preview = findings[0];
            console.log(`[✓] Pattern 6 (Reentrancy Guard): Detected ${findings.length} guarded interaction path(s). Example: ${preview}.`);
        } else {
            console.log("[!] Pattern 6 (Reentrancy Guard): No standard locking mechanism found spanning external calls.");
        }
    }

    private isExternalCallOpcode(opcode: number): boolean {
        return EXTERNAL_CALL_OPCODES.has(opcode);
    }

    private isPushOpcode(opcode: number): boolean {
        return opcode >= 0x5f && opcode <= 0x7f;
    }

    private isStackShapingOpcode(opcode: number): boolean {
        return opcode >= 0x80 && opcode <= 0x9f;
    }

    private findPreviousOpcode(fromIndexExclusive: number, targetOpcode: number, maxLookback: number): number {
        const start = Math.max(0, fromIndexExclusive - maxLookback);
        for (let i = fromIndexExclusive - 1; i >= start; i--) {
            if (this.instructions[i].opcode === targetOpcode) {
                return i;
            }

            // A hard halt means we do not cross into a previous execution path.
            if (HALTING_OPCODES.has(this.instructions[i].opcode)) {
                break;
            }
        }
        return -1;
    }

    private findNextOpcode(fromIndexInclusive: number, targetOpcode: number, maxLookahead: number): number {
        const end = Math.min(this.instructions.length, fromIndexInclusive + maxLookahead);
        for (let i = fromIndexInclusive; i < end; i++) {
            if (this.instructions[i].opcode === targetOpcode) {
                return i;
            }

            if (HALTING_OPCODES.has(this.instructions[i].opcode)) {
                break;
            }
        }
        return -1;
    }

    private isCallReturnChecked(callIndex: number): boolean {
        let isZeroIndex = -1;
        const isZeroWindowEnd = Math.min(this.instructions.length, callIndex + 12);

        for (let i = callIndex + 1; i < isZeroWindowEnd; i++) {
            const opcode = this.instructions[i].opcode;

            if (opcode === 0x15) {
                isZeroIndex = i;
                break;
            }

            if (opcode === 0x50 || HALTING_OPCODES.has(opcode) || this.isExternalCallOpcode(opcode)) {
                return false;
            }

            if (this.isPushOpcode(opcode) || this.isStackShapingOpcode(opcode)) {
                continue;
            }

            return false;
        }

        if (isZeroIndex === -1) {
            return false;
        }

        const jumpWindowEnd = Math.min(this.instructions.length, isZeroIndex + 8);
        for (let i = isZeroIndex + 1; i < jumpWindowEnd; i++) {
            const opcode = this.instructions[i].opcode;

            if (opcode === 0x57) {
                return true;
            }

            if (opcode === 0x50 || HALTING_OPCODES.has(opcode) || this.isExternalCallOpcode(opcode)) {
                return false;
            }

            if (this.isPushOpcode(opcode) || this.isStackShapingOpcode(opcode)) {
                continue;
            }

            return false;
        }

        return false;
    }

    private hasNonPayableGuardFrom(callValueIndex: number): boolean {
        let isZeroIndex = -1;
        const isZeroWindowEnd = Math.min(this.instructions.length, callValueIndex + 5);

        for (let i = callValueIndex + 1; i < isZeroWindowEnd; i++) {
            const opcode = this.instructions[i].opcode;
            if (opcode === 0x15) {
                isZeroIndex = i;
                break;
            }

            if (this.isStackShapingOpcode(opcode) || this.isPushOpcode(opcode)) {
                continue;
            }

            if (HALTING_OPCODES.has(opcode)) {
                return false;
            }

            return false;
        }

        if (isZeroIndex === -1) {
            return false;
        }

        let jumpiIndex = -1;
        const jumpWindowEnd = Math.min(this.instructions.length, isZeroIndex + 8);
        for (let i = isZeroIndex + 1; i < jumpWindowEnd; i++) {
            const opcode = this.instructions[i].opcode;
            if (opcode === 0x57) {
                jumpiIndex = i;
                break;
            }

            if (this.isPushOpcode(opcode) || this.isStackShapingOpcode(opcode)) {
                continue;
            }

            if (HALTING_OPCODES.has(opcode)) {
                return false;
            }

            return false;
        }

        if (jumpiIndex === -1) {
            return false;
        }

        const revertWindowEnd = Math.min(this.instructions.length, jumpiIndex + 12);
        for (let i = callValueIndex + 1; i < revertWindowEnd; i++) {
            if (this.instructions[i].opcode === 0xfd) {
                return true;
            }
        }

        return false;
    }

    private extractAddressFromStorageWord(value: string): string | null {
        if (!value || value === "0x") {
            return null;
        }

        const rawHex = value.startsWith("0x") ? value.slice(2) : value;
        if (!/^[0-9a-fA-F]+$/.test(rawHex) || rawHex.length < 40) {
            return null;
        }

        const addressHex = rawHex.slice(-40);
        if (/^0+$/.test(addressHex)) {
            return null;
        }

        return `0x${addressHex}`;
    }

    private hasMatchingSstoreSlot(lockStoreIndex: number, unlockStoreIndex: number): boolean {
        const lockSlot = this.extractStorageSlotNearSstore(lockStoreIndex);
        const unlockSlot = this.extractStorageSlotNearSstore(unlockStoreIndex);
        return lockSlot !== null && unlockSlot !== null && lockSlot === unlockSlot;
    }

    private extractStorageSlotNearSstore(sstoreIndex: number): string | null {
        const start = Math.max(0, sstoreIndex - 4);
        for (let i = sstoreIndex - 1; i >= start; i--) {
            const inst = this.instructions[i];
            if (this.isPushOpcode(inst.opcode) && inst.operand) {
                const normalized = inst.operand.replace(/^0+/, "").toLowerCase();
                return normalized.length === 0 ? "0" : normalized;
            }
        }
        return null;
    }
}