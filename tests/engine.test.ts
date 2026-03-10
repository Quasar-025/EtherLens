// tests/engine.test.ts
import { describe, it, expect, vi } from 'vitest';
import { disassembleBytecode } from '../lib/disassembler';
import { CFGBuilder } from '../lib/graph';
import { SecurityAnalyzer } from '../lib/security';
import { fetchWithBackoff } from '../lib/rpc';

describe('EVM Reverse Engineering Engine - Edge Cases', () => {

    describe('1. Disassembler Robustness (Malformed Bytecode)', () => {
        it('should handle EOF during a PUSH instruction without crashing', () => {
            // 0x61 is PUSH2 (expects 2 bytes of data). But we only give it 1 byte (0xff).
            // A naive loop will throw an OutOfBounds error here.
            const malformedBytecode = "0x61ff"; 
            const instructions = disassembleBytecode(malformedBytecode);
            
            expect(instructions.length).toBe(1);
            expect(instructions[0].mnemonic).toBe("PUSH2");
            // It should gracefully capture what it can, or leave it blank, but NOT crash.
            expect(instructions[0].operand).toBeDefined(); 
        });

        it('should correctly skip bytes for PUSH32 to avoid false opcode detection', () => {
            // 0x7f (PUSH32) followed by 32 bytes of 0xff (which is SELFDESTRUCT).
            // If the disassembler doesn't skip the data payload, it will falsely flag a self-destruct.
            const bytecode = "0x7f" + "ff".repeat(32) + "00";
            const instructions = disassembleBytecode(bytecode);
            
            expect(instructions.length).toBe(2);
            expect(instructions[0].mnemonic).toBe("PUSH32");
            expect(instructions[1].opcode).toBe(0x00); // STOP
            
            // Prove no SELFDESTRUCT was accidentally parsed from the data
            const hasSelfDestruct = instructions.some(i => i.opcode === 0xff);
            expect(hasSelfDestruct).toBe(false);
        });
    });

    describe('2. Control Flow Graph & DFS Pathfinding', () => {
        it('should correctly partition blocks and trace a path to SELFDESTRUCT', async () => {
            // Hand-crafted bytecode: 
            // Block 0: PUSH1 0x80, PUSH1 0x40, JUMPI (to Block 2)
            // Block 1: STOP (0x00)
            // Block 2: JUMPDEST (0x5b), SELFDESTRUCT (0xff)
            const simulatedHackerContract = "0x6080600657005bff";
            const instructions = disassembleBytecode(simulatedHackerContract);
            
            const cfg = new CFGBuilder(instructions);
            const blocks = cfg.build();

            expect(blocks.length).toBe(3); // Should split into 3 distinct blocks
            
            // Mock the provider since we aren't testing live storage here
            const mockProvider = {} as any; 
            const analyzer = new SecurityAnalyzer(instructions, blocks, mockProvider, "0x0");
            
            // Spy on console.log to capture the DFS output
            const consoleSpy = vi.spyOn(console, 'log');
            await analyzer.analyze();

            // Verify the DFS trace correctly mapped the path skipping Block 1
            const dfsOutput = consoleSpy.mock.calls.find(call => 
                call[0] && call[0].includes("Execution Path to destruction")
            );
            
            expect(dfsOutput).toBeDefined();
            // The path must go from Block 0 straight to Block 2, bypassing Block 1
            expect(dfsOutput![0]).toContain("Block 0 -> Block 2");
            
            consoleSpy.mockRestore();
        });
    });

    describe('3. Network Reliability (Exponential Backoff)', () => {
        it('should successfully retry a failing RPC call and eventually resolve', async () => {
            let attempts = 0;
            const mockFlakyRPC = async () => {
                attempts++;
                if (attempts < 3) throw new Error("Rate limit exceeded (429)");
                return "0x60806040"; // Succeeds on the 3rd attempt
            };

            // baseDelay 10ms for fast testing
            const result = await fetchWithBackoff(mockFlakyRPC, 3, 10); 
            
            expect(attempts).toBe(3);
            expect(result).toBe("0x60806040");
        });

        it('should throw an error if max retries are exceeded', async () => {
            const mockDeadRPC = async () => {
                throw new Error("RPC is down (500)");
            };

            // Should fail after 2 attempts
            await expect(fetchWithBackoff(mockDeadRPC, 2, 10)).rejects.toThrow(/RPC Operation failed/);
        });
    });
});