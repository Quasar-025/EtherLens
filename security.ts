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
        console.log("\n[Phase 4] Running Security Heuristics...");
        
        this.detectSelfDestruct();
        this.detectUncheckedCalls();
        await this.detectProxyPattern();
        this.detectPayableFunctions();
        
        console.log("\n[+] Security Analysis Complete.\n");
    }

    // Pattern 1: Selfdestruct Presence
    private detectSelfDestruct() {
        const hasSelfDestruct = this.instructions.some(inst => inst.opcode === 0xff); // 0xff is SELFDESTRUCT
        if (hasSelfDestruct) {
            console.log("[!] HIGH RISK: SELFDESTRUCT opcode detected. Contract can be destroyed.");
        } else {
            console.log("[✓] Pattern 1: No SELFDESTRUCT opcode found.");
        }
    }

    // Pattern 2: Unchecked External Calls
    private detectUncheckedCalls() {
        let uncheckedCallsCount = 0;

        for (let i = 0; i < this.instructions.length - 2; i++) {
            const current = this.instructions[i];
            // 0xf1 (CALL), 0xf2 (CALLCODE), 0xf4 (DELEGATECALL), 0xfa (STATICCALL)
            const isCall = [0xf1, 0xf2, 0xf4, 0xfa].includes(current.opcode);

            if (isCall) {
                const next1 = this.instructions[i + 1];
                const next2 = this.instructions[i + 2];

                // If the very next instruction isn't ISZERO (0x15), the return value (success/fail) might be ignored
                if (!(next1.opcode === 0x15 && next2.opcode === 0x57)) {
                    uncheckedCallsCount++;
                }
            }
        }

        if (uncheckedCallsCount > 0) {
            console.log(`[!] WARNING: Detected ${uncheckedCallsCount} potentially unchecked external call(s).`);
        } else {
            console.log("[✓] Pattern 2: All external calls appear to check their return values.");
        }
    }

    // Pattern 3: Proxy Contract (EIP-1967)
    private async detectProxyPattern() {
        const hasDelegateCall = this.instructions.some(inst => inst.opcode === 0xf4); // 0xf4 is DELEGATECALL

        if (hasDelegateCall) {
            // Standard EIP-1967 Implementation Slot
            const implementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
            
            try {
                // Fetch the live storage state of this specific slot
                const slotValue = await this.provider.getStorage(this.address, implementationSlot);
                
                // If it's not empty, it holds an address
                if (slotValue !== "0x" && slotValue !== "0x0000000000000000000000000000000000000000000000000000000000000000") {
                    const implAddress = "0x" + slotValue.substring(26);
                    console.log(`[!] Pattern 3: PROXY DETECTED. Logic delegated to: ${implAddress}`);
                } else {
                    console.log("[✓] Pattern 3: DELEGATECALL used, but EIP-1967 slots are empty (Not a standard proxy).");
                }
            } catch (error) {
                console.log("[-] Pattern 3: Failed to query storage slots for Proxy detection.");
            }
        } else {
             console.log("[✓] Pattern 3: No DELEGATECALL opcode found. Not a proxy contract.");
        }
    }

    // Pattern 4: Payable Functions
    private detectPayableFunctions() {
        let hasPayableModifier = false;
        
        // Scan early blocks for the CALLVALUE -> ISZERO -> REVERT pattern
        // If a contract is entirely non-payable, it usually checks CALLVALUE near the top of the dispatch table.
        for (let i = 0; i < Math.min(50, this.instructions.length - 2); i++) {
            const op1 = this.instructions[i];
            const op2 = this.instructions[i+1];
            
            // 0x34 is CALLVALUE, 0x15 is ISZERO
            if (op1.opcode === 0x34 && op2.opcode === 0x15) {
                hasPayableModifier = true;
                break;
            }
        }

        if (hasPayableModifier) {
            console.log("[✓] Pattern 4: Non-payable guards detected (Contract likely rejects accidental ETH).");
        } else {
            console.log("[!] WARNING: No global non-payable guard detected. Contract may accept ETH unexpectedly.");
        }
    }
}