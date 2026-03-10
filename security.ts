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
        console.log("\nRunning Security Heuristics...");
        
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
    // Pattern 3: Proxy Contract (EIP-1967 & Legacy)
    private async detectProxyPattern() {
        const hasDelegateCall = this.instructions.some(inst => inst.opcode === 0xf4); // 0xf4 is DELEGATECALL

        if (hasDelegateCall) {
            console.log("[?] DELEGATECALL detected. Checking common Proxy storage slots...");
            
            // Standard EIP-1967 Implementation Slot
            const eip1967Slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
            
            // Legacy Zeppelinos Proxy Slot (Used by USDC and older contracts)
            // It is the keccak256 hash of "org.zeppelinos.proxy.implementation"
            const legacySlot = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";
            
            try {
                const val1967 = await this.provider.getStorage(this.address, eip1967Slot);
                const valLegacy = await this.provider.getStorage(this.address, legacySlot);
                
                const isEmpty = (val: string) => val === "0x" || val === "0x0000000000000000000000000000000000000000000000000000000000000000";

                if (!isEmpty(val1967)) {
                    const implAddress = "0x" + val1967.substring(26);
                    console.log(`[!] PROXY DETECTED (EIP-1967). Logic delegated to: ${implAddress}`);
                } else if (!isEmpty(valLegacy)) {
                    const implAddress = "0x" + valLegacy.substring(26);
                    console.log(`[!] PROXY DETECTED (Legacy Zeppelinos). Logic delegated to: ${implAddress}`);
                } else {
                    console.log("[✓] DELEGATECALL is used, but standard proxy slots are empty. Might be a custom proxy.");
                }
            } catch (error) {
                console.log("[-] Failed to query storage slots for Proxy detection.");
            }
        } else {
             console.log("[✓] Pattern 3: No DELEGATECALL opcode found. Not a proxy contract.");
        }
    }

    // Pattern 4: Payable Functions
    private detectPayableFunctions() {
        let hasPayableModifier = false;
        
        for (let i = 0; i < Math.min(50, this.instructions.length - 3); i++) {
            const op1 = this.instructions[i];
            const op2 = this.instructions[i+1];
            const op3 = this.instructions[i+2];
            
            // Check for CALLVALUE -> ISZERO or CALLVALUE -> DUP1 -> ISZERO
            if (op1.opcode === 0x34 && op2.opcode === 0x15) {
                hasPayableModifier = true; break;
            } else if (op1.opcode === 0x34 && op2.opcode === 0x80 && op3.opcode === 0x15) {
                hasPayableModifier = true; break;
            }
        }

        if (hasPayableModifier) {
            console.log("[✓] Pattern 4: Non-payable guards detected (Contract likely rejects accidental ETH).");
        } else {
            console.log("[!] WARNING: No global non-payable guard detected. Contract may accept ETH unexpectedly.");
        }
    }
}