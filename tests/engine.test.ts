// tests/engine.test.ts
import { describe, it, expect, vi } from 'vitest';
import { disassembleBytecode } from '../lib/disassembler';
import { extractAndResolveSelectors } from '../lib/extractor';
import { CFGBuilder } from '../lib/graph';
import { SecurityAnalyzer } from '../lib/security';
import { fetchWithBackoff } from '../lib/rpc';

describe('EVM Reverse Engineering Engine - Edge Cases', () => {

    describe('1. Disassembler Robustness (Malformed Bytecode)', () => {
        it('should handle EOF during a PUSH instruction without crashing', () => {
            // 0x61 is PUSH2 (expects 2 bytes of data). But we only give it 1 byte (0xff).
            // A naive loop will throw an OutOfBounds error here.
            const malformedBytecode = "0x61ff"; 
            const result = disassembleBytecode(malformedBytecode);
            const instructions = result.instructions;
            
            expect(instructions.length).toBe(1);
            expect(instructions[0].mnemonic).toBe("PUSH2");
            // It should gracefully capture what it can, or leave it blank, but NOT crash.
            expect(instructions[0].operand).toBeDefined(); 
        });

        it('should correctly skip bytes for PUSH32 to avoid false opcode detection', () => {
            // 0x7f (PUSH32) followed by 32 bytes of 0xff (which is SELFDESTRUCT).
            // If the disassembler doesn't skip the data payload, it will falsely flag a self-destruct.
            const bytecode = "0x7f" + "ff".repeat(32) + "00";
            const result = disassembleBytecode(bytecode);
            const instructions = result.instructions;
            
            expect(instructions.length).toBe(2);
            expect(instructions[0].mnemonic).toBe("PUSH32");
            expect(instructions[1].opcode).toBe(0x00); // STOP
            
            // Prove no SELFDESTRUCT was accidentally parsed from the data
            const hasSelfDestruct = instructions.some(i => i.opcode === 0xff);
            expect(hasSelfDestruct).toBe(false);
        });

        it('should parse PUSH0 as a zero-operand instruction', () => {
            const bytecode = "0x5f00";
            const result = disassembleBytecode(bytecode);
            const instructions = result.instructions;

            expect(instructions.length).toBe(2);
            expect(instructions[0].mnemonic).toBe("PUSH0");
            expect(instructions[0].operand).toBeNull();
            expect(instructions[1].mnemonic).toBe("STOP");
        });
    });

    describe('1b. CBOR Metadata Handling', () => {
        it('should detect and strip valid Solidity CBOR metadata', () => {
            // Executable: PUSH1 0x00, PUSH1 0x00, JUMP
            // Metadata: a1 64 736f6c63 43 000813  ( { "solc": h'000813' } )
            const bytecodeWithMetadata = "0x6000600056a164736f6c6343000813000a";
            const result = disassembleBytecode(bytecodeWithMetadata);

            expect(result.metadata.detected).toBe(true);
            expect(result.metadata.cborValid).toBe(true);
            expect(result.metadata.metadataLength).toBe(10);
            expect(result.metadata.solidityVersion).toBe("0.8.19");
            expect(result.executableBytecodeHex).toBe("6000600056");

            const instructions = result.instructions;
            expect(instructions.length).toBe(3);
            expect(instructions[0].mnemonic).toBe("PUSH1");
            expect(instructions[1].mnemonic).toBe("PUSH1");
            expect(instructions[2].mnemonic).toBe("JUMP");
        });

        it('should keep full bytecode when trailer length points to invalid CBOR', () => {
            // Last 2 bytes claim 2-byte metadata trailer (0x0002), but bytes are invalid CBOR payload.
            const malformedTrailer = "0x60016002abcf0002";
            const result = disassembleBytecode(malformedTrailer);

            expect(result.metadata.detected).toBe(false);
            expect(result.metadata.cborValid).toBe(false);
            expect(result.metadata.solidityVersion).toBeNull();
            expect(result.executableBytecodeHex).toBe("60016002abcf0002");
        });
    });

    describe('2. Control Flow Graph & DFS Pathfinding', () => {
        it('should correctly partition blocks and trace a path to SELFDESTRUCT', async () => {
            // Hand-crafted bytecode: 
            // Block 0: PUSH1 0x80, PUSH1 0x40, JUMPI (to Block 2)
            // Block 1: STOP (0x00)
            // Block 2: JUMPDEST (0x5b), SELFDESTRUCT (0xff)
            const simulatedHackerContract = "0x6080600657005bff";
            const result = disassembleBytecode(simulatedHackerContract);
            const instructions = result.instructions;
            
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

    describe('4. Selector Extraction & Resolution', () => {
        it('should parse strict dispatch entries and resolve collisions deterministically', async () => {
            const bytecode =
                '0x' +
                '63a9059cbb1461001057' + // transfer selector check
                '63095ea7b31461002057' + // approve selector check
                '600435' +               // CALLDATALOAD at offset 0x04
                '602435' +               // CALLDATALOAD at offset 0x24
                '00';

            const result = disassembleBytecode(bytecode);
            const instructions = result.instructions;

            const mockFetch = vi.fn(async (url: string) => {
                if (url.includes('a9059cbb')) {
                    return {
                        ok: true,
                        json: async () => ({
                            count: 2,
                            results: [
                                { text_signature: 'many_msg_babbage(bytes1)' },
                                { text_signature: 'transfer(address,uint256)' }
                            ]
                        })
                    };
                }

                return {
                    ok: true,
                    json: async () => ({
                        count: 2,
                        results: [
                            { text_signature: 'approve(bytes,uint256)' },
                            { text_signature: 'approve(address,uint256)' }
                        ]
                    })
                };
            });

            const analysis = await extractAndResolveSelectors(instructions, { fetchFn: mockFetch as any });

            expect(analysis.dispatchEntries).toHaveLength(2);
            expect(analysis.dispatchEntries[0].selector).toBe('0xa9059cbb');
            expect(analysis.dispatchEntries[0].jumpDestination).toBe(0x10);
            expect(analysis.dispatchEntries[1].selector).toBe('0x095ea7b3');
            expect(analysis.dispatchEntries[1].jumpDestination).toBe(0x20);

            expect(analysis.uniqueSelectors).toEqual(['0x095ea7b3', '0xa9059cbb']);

            const transferResolution = analysis.resolutions.find(r => r.selector === '0xa9059cbb');
            expect(transferResolution?.status).toBe('resolved');
            expect(transferResolution?.selectedSignature).toBe('transfer(address,uint256)');
            expect(transferResolution?.collision).toBe(true);

            const approveResolution = analysis.resolutions.find(r => r.selector === '0x095ea7b3');
            expect(approveResolution?.status).toBe('resolved');
            expect(approveResolution?.selectedSignature).toBe('approve(address,uint256)');
            expect(approveResolution?.collision).toBe(true);
            expect(approveResolution?.candidateSignatures).toHaveLength(2);

            expect(analysis.abiHeuristics.maxCallDataOffset).toBe(0x24);
            expect(analysis.abiHeuristics.minimumParameterCount).toBe(2);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it('should mark selectors unresolved when 4byte returns no results', async () => {
            const bytecode = '0x63deadbeef146100105700';
            const instructions = disassembleBytecode(bytecode).instructions;

            const mockFetch = vi.fn(async () => ({
                ok: true,
                json: async () => ({ count: 0, results: [] })
            }));

            const analysis = await extractAndResolveSelectors(instructions, { fetchFn: mockFetch as any });

            expect(analysis.dispatchEntries).toHaveLength(1);
            expect(analysis.resolutions).toHaveLength(1);
            expect(analysis.resolutions[0].status).toBe('unresolved');
            expect(analysis.resolutions[0].selectedSignature).toBeNull();
            expect(analysis.resolutions[0].collision).toBe(false);
        });

        it('should mark selector resolution as error when API call fails', async () => {
            const bytecode = '0x63ffffffff146100105700';
            const instructions = disassembleBytecode(bytecode).instructions;

            const mockFetch = vi.fn(async () => {
                throw new Error('network down');
            });

            const analysis = await extractAndResolveSelectors(instructions, { fetchFn: mockFetch as any });

            expect(analysis.dispatchEntries).toHaveLength(1);
            expect(analysis.resolutions).toHaveLength(1);
            expect(analysis.resolutions[0].status).toBe('error');
            expect(analysis.resolutions[0].error).toContain('network down');
        });
    });
});