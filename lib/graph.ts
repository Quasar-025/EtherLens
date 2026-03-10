// graph.ts
import { Instruction } from "./disassembler";
import { execSync } from "child_process";
import * as fs from "fs";

export interface BasicBlock {
    id: number;
    startOffset: number;
    instructions: Instruction[];
    successors: number[]; // Block IDs this block jumps or falls through to
    hasDynamicJump: boolean; // Flag if we couldn't resolve the jump target
}

export interface JumpResolutionStats {
    staticJumps: number;
    dynamicJumps: number;
    totalJumps: number;
    staticPercentage: number;
    dynamicPercentage: number;
}

export class CFGBuilder {
    private instructions: Instruction[];
    private blocks: BasicBlock[] = [];
    private offsetToBlockId: Map<number, number> = new Map();
    
    // Metrics for the prompt requirement
    public staticJumps = 0;
    public dynamicJumps = 0;

    constructor(instructions: Instruction[]) {
        this.instructions = instructions;
    }

    public build(options?: { silent?: boolean }): BasicBlock[] {
        const silent = options?.silent ?? false;
        if (!silent) {
            console.log("\nBuilding Control Flow Graph...");
        }

        this.partitionBlocks();
        this.resolveEdges();

        if (!silent) {
            this.printMetrics();
        }

        return this.blocks;
    }

    // --- REQUIREMENT 1: Partition into Basic Blocks ---
    private partitionBlocks() {
        let currentBlock: BasicBlock | null = null;

        const terminalOpcodes = new Set([
            0x56, // JUMP
            0x57, // JUMPI
            0x00, // STOP
            0xf3, // RETURN
            0xfd, // REVERT
            0xfe, // INVALID
            0xff  // SELFDESTRUCT
        ]);

        for (const inst of this.instructions) {
            // Start a new block if we don't have one, OR if we hit a JUMPDEST (0x5b)
            if (!currentBlock || inst.opcode === 0x5b) {
                currentBlock = {
                    id: this.blocks.length,
                    startOffset: inst.offset,
                    instructions: [],
                    successors: [],
                    hasDynamicJump: false
                };
                this.blocks.push(currentBlock);
                this.offsetToBlockId.set(inst.offset, currentBlock.id);
            }

            currentBlock.instructions.push(inst);

            // If this instruction is a terminator, force the NEXT instruction to start a new block
            if (terminalOpcodes.has(inst.opcode)) {
                currentBlock = null; 
            }
        }
    }

    // --- REQUIREMENT 2 & 3: Resolve Edges & Jump Targets ---
    private resolveEdges() {
        const haltingOpcodes = new Set([0x00, 0xf3, 0xfd, 0xfe, 0xff]);

        for (let i = 0; i < this.blocks.length; i++) {
            const block = this.blocks[i];
            const lastInst = block.instructions[block.instructions.length - 1];

            // 1. Fall-through Edges
            // If the block doesn't halt, and it isn't a hard JUMP, it flows to the next sequential block
            if (!haltingOpcodes.has(lastInst.opcode) && lastInst.opcode !== 0x56) {
                if (i + 1 < this.blocks.length) {
                    block.successors.push(this.blocks[i + 1].id);
                }
            }

            // 2. Jump Edges (JUMP = 0x56, JUMPI = 0x57)
            if (lastInst.opcode === 0x56 || lastInst.opcode === 0x57) {
                const targetOffset = this.findStaticJumpTarget(block);

                if (targetOffset !== null && this.offsetToBlockId.has(targetOffset)) {
                    // We successfully resolved it statically!
                    block.successors.push(this.offsetToBlockId.get(targetOffset)!);
                    this.staticJumps++;
                } else {
                    // The jump destination is calculated dynamically on the stack (e.g., loaded from memory)
                    block.hasDynamicJump = true;
                    this.dynamicJumps++;
                }
            }
        }
    }

    // Heuristic: Look backwards in the block to find the PUSH instruction that provides the jump address
    private findStaticJumpTarget(block: BasicBlock): number | null {
        // Scan the last few instructions of the block
        for (let j = block.instructions.length - 2; j >= 0; j--) {
            const prevInst = block.instructions[j];
            
            // If it's a PUSH instruction, this is highly likely the jump destination
            if (prevInst.opcode >= 0x60 && prevInst.opcode <= 0x7f && prevInst.operand) {
                return parseInt(prevInst.operand, 16);
            }
        }
        return null;
    }

    private printMetrics() {
        const stats = this.getJumpResolutionStats();
        console.log(`[CFG] Generated ${this.blocks.length} basic blocks.`);
        console.log(`[CFG] Jump Resolution: ${stats.staticJumps} Static, ${stats.dynamicJumps} Dynamic.`);
        console.log(`[CFG] Statically resolved jump percentage: ${stats.staticPercentage.toFixed(2)}%`);
    }

    public getJumpResolutionStats(): JumpResolutionStats {
        const totalJumps = this.staticJumps + this.dynamicJumps;
        const staticPercentage = totalJumps === 0
            ? 0
            : Number(((this.staticJumps / totalJumps) * 100).toFixed(2));
        const dynamicPercentage = totalJumps === 0
            ? 0
            : Number(((this.dynamicJumps / totalJumps) * 100).toFixed(2));

        return {
            staticJumps: this.staticJumps,
            dynamicJumps: this.dynamicJumps,
            totalJumps,
            staticPercentage,
            dynamicPercentage
        };
    }

    // --- REQUIREMENT 4: Export Formats ---
    
    public getJsonAdjacencyList(includeDynamicMarker: boolean = false): string {
        const adjacencyList: Record<number, Array<number | "dynamic">> = {};
        for (const block of this.blocks) {
            const successors: Array<number | "dynamic"> = [...block.successors];
            if (includeDynamicMarker && block.hasDynamicJump) {
                successors.push("dynamic");
            }
            adjacencyList[block.id] = successors;
        }
        return JSON.stringify(adjacencyList, null, 2);
    }

    public exportToJson(filename: string) {
        const cfgData = {
            metadata: {
                totalBlocks: this.blocks.length,
                jumpResolution: this.getJumpResolutionStats()
            },
            adjacencyList: JSON.parse(this.getJsonAdjacencyList(true)),
            blocks: this.blocks.map(block => ({
                id: block.id,
                startOffset: `0x${block.startOffset.toString(16)}`,
                successors: block.successors,
                hasDynamicJump: block.hasDynamicJump,
                instructionCount: block.instructions.length,
                instructions: block.instructions.map(inst => ({
                    offset: `0x${inst.offset.toString(16)}`,
                    opcode: `0x${inst.opcode.toString(16).padStart(2, '0')}`,
                    mnemonic: inst.mnemonic,
                    operand: inst.operand || null
                }))
            }))
        };

        fs.writeFileSync(filename, JSON.stringify(cfgData, null, 2));
        console.log(`[+] CFG JSON file saved to ${filename}`);
    }

    public exportToDot(filename: string, generateSvg: boolean = false) {
        let dot = "digraph EVM_CFG {\n  node [shape=box, fontname=\"Courier\"];\n";

        for (const block of this.blocks) {
            let label = `Block ${block.id} (0x${block.startOffset.toString(16)})\\l`;
            label += "-------------------\\l";
            
            // Print up to 4 instructions so the graph is readable
            const limit = Math.min(4, block.instructions.length);
            for (let i = 0; i < limit; i++) {
                const inst = block.instructions[i];
                label += `${inst.mnemonic} ${inst.operand || ''}\\l`;
            }
            if (block.instructions.length > 4) label += `...\\l`;

            dot += `  B${block.id} [label="${label}"];\n`;

            for (const succ of block.successors) {
                dot += `  B${block.id} -> B${succ};\n`;
            }

            if (block.hasDynamicJump) {
                dot += `  B${block.id} -> DYNAMIC_TARGET [color=red, style=dashed];\n`;
            }
        }
        dot += "}\n";

        fs.writeFileSync(filename, dot);
        console.log(`[+] DOT file saved to ${filename}`);

        // Handle SVG Generation CLI Flag
        if (generateSvg) {
            try {
                console.log(`[+] Attempting to generate SVG via Graphviz...`);
                const svgFilename = filename.replace(".dot", ".svg");
                // This requires Graphviz to be installed on the host machine
                execSync(`dot -Tsvg ${filename} -o ${svgFilename}`);
                console.log(`[+] SVG successfully generated: ${svgFilename}`);
            } catch (error) {
                console.log(`[!] Failed to generate SVG. Is Graphviz ('dot') installed on your system?`);
            }
        }
    }
}