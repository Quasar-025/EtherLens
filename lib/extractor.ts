import { Instruction } from "./disassembler";

export interface DispatchTableEntry {
    selector: string;
    jumpDestination: number;
    selectorCheckOffset: number;
    jumpInstructionOffset: number;
}

export interface SelectorResolution {
    selector: string;
    status: "resolved" | "unresolved" | "error";
    selectedSignature: string | null;
    candidateSignatures: string[];
    collision: boolean;
    error?: string;
}

export interface ParameterHeuristic {
    parameterIndex: number;
    calldataOffset: number;
    hints: string[];
    evidence: string[];
}

export interface AbiHeuristicAnalysis {
    maxCallDataOffset: number;
    minimumParameterCount: number;
    inferredParameters: ParameterHeuristic[];
    heuristicNotes: string[];
}

export interface SelectorAnalysisResult {
    dispatchEntries: DispatchTableEntry[];
    uniqueSelectors: string[];
    resolutions: SelectorResolution[];
    abiHeuristics: AbiHeuristicAnalysis;
}

interface SignatureApiRecord {
    text_signature?: string;
}

interface SignatureApiResponse {
    count?: number;
    results?: SignatureApiRecord[];
}

const KNOWN_SELECTOR_SIGNATURES: Record<string, string> = {
    "0x06fdde03": "name()",
    "0x095ea7b3": "approve(address,uint256)",
    "0x18160ddd": "totalSupply()",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0x313ce567": "decimals()",
    "0x70a08231": "balanceOf(address)",
    "0x95d89b41": "symbol()",
    "0xa9059cbb": "transfer(address,uint256)",
    "0xd0e30db0": "deposit()",
    "0xdd62ed3e": "allowance(address,address)"
};

interface FetchLikeResponse {
    ok?: boolean;
    status?: number;
    json: () => Promise<unknown>;
}

type FetchLike = (url: string) => Promise<FetchLikeResponse>;

export interface SelectorExtractionOptions {
    fetchFn?: FetchLike;
}

function isPushInstruction(opcode: number): boolean {
    return opcode >= 0x60 && opcode <= 0x7f;
}

function normalizeSelector(rawOperand: string | null): string | null {
    if (!rawOperand) {
        return null;
    }

    const normalizedHex = rawOperand.toLowerCase().replace(/^0x/, "");
    if (normalizedHex.length === 0 || normalizedHex.length > 8 || !/^[0-9a-f]+$/.test(normalizedHex)) {
        return null;
    }

    return `0x${normalizedHex.padStart(8, "0")}`;
}

function addUniqueHint(target: ParameterHeuristic, hint: string, evidence: string): void {
    if (!target.hints.includes(hint)) {
        target.hints.push(hint);
    }
    if (!target.evidence.includes(evidence)) {
        target.evidence.push(evidence);
    }
}

function parseHexBigInt(hexValue: string | null): bigint | null {
    if (!hexValue) {
        return null;
    }

    const normalizedHex = hexValue.toLowerCase().replace(/^0x/, "");
    if (normalizedHex.length === 0 || !/^[0-9a-f]+$/.test(normalizedHex)) {
        return null;
    }

    try {
        return BigInt(`0x${normalizedHex}`);
    } catch {
        return null;
    }
}

function contiguousLowBitWidth(mask: bigint): number {
    if (mask <= 0n) {
        return 0;
    }

    let bitWidth = 0;
    let value = mask;

    while ((value & 1n) === 1n) {
        bitWidth += 1;
        value >>= 1n;
    }

    if (value !== 0n) {
        return 0;
    }

    return bitWidth;
}

function parseDispatchEntries(instructions: Instruction[]): DispatchTableEntry[] {
    const entries: DispatchTableEntry[] = [];

    for (let i = 0; i < instructions.length - 3; i++) {
        const maybePush4Selector = instructions[i];
        const maybeEq = instructions[i + 1];
        const maybePush2JumpDestination = instructions[i + 2];
        const maybeJumpi = instructions[i + 3];

        if (
            maybePush4Selector.opcode !== 0x63 ||
            maybeEq.opcode !== 0x14 ||
            maybePush2JumpDestination.opcode !== 0x61 ||
            maybeJumpi.opcode !== 0x57
        ) {
            continue;
        }

        const selector = normalizeSelector(maybePush4Selector.operand);
        if (!selector || !maybePush2JumpDestination.operand) {
            continue;
        }

        const jumpDestination = parseInt(maybePush2JumpDestination.operand, 16);
        if (!Number.isFinite(jumpDestination)) {
            continue;
        }

        entries.push({
            selector,
            jumpDestination,
            selectorCheckOffset: maybePush4Selector.offset,
            jumpInstructionOffset: maybeJumpi.offset
        });
    }

    return entries;
}

function inferAbiHeuristics(instructions: Instruction[]): AbiHeuristicAnalysis {
    let maxCallDataOffset = 0;
    const parameterHeuristicsMap = new Map<number, ParameterHeuristic>();

    for (let i = 0; i < instructions.length - 1; i++) {
        const maybePushOffset = instructions[i];
        const maybeCallDataLoad = instructions[i + 1];

        if (!isPushInstruction(maybePushOffset.opcode) || maybeCallDataLoad.opcode !== 0x35 || !maybePushOffset.operand) {
            continue;
        }

        const calldataOffset = parseInt(maybePushOffset.operand, 16);
        if (!Number.isFinite(calldataOffset)) {
            continue;
        }

        if (calldataOffset > maxCallDataOffset) {
            maxCallDataOffset = calldataOffset;
        }

        if (calldataOffset < 4) {
            continue;
        }

        const slotOffset = calldataOffset - 4;
        if (slotOffset % 32 !== 0) {
            continue;
        }

        const parameterIndex = slotOffset / 32 + 1;

        const parameterHeuristic = parameterHeuristicsMap.get(parameterIndex) || {
            parameterIndex,
            calldataOffset,
            hints: [],
            evidence: []
        };

        const loadOffsetHex = `0x${maybeCallDataLoad.offset.toString(16).padStart(4, "0")}`;
        addUniqueHint(
            parameterHeuristic,
            "uint256|bytes32",
            `Default 32-byte ABI slot read via CALLDATALOAD at ${loadOffsetHex}.`
        );

        const maybeMaskPush = instructions[i + 2];
        const maybeAnd = instructions[i + 3];
        if (
            maybeMaskPush &&
            maybeAnd &&
            isPushInstruction(maybeMaskPush.opcode) &&
            maybeAnd.opcode === 0x16 &&
            maybeMaskPush.operand
        ) {
            const mask = parseHexBigInt(maybeMaskPush.operand);
            if (mask !== null) {
                const bitWidth = contiguousLowBitWidth(mask);

                if (bitWidth === 160) {
                    addUniqueHint(parameterHeuristic, "address", "Bit-masked down to 160 bits (PUSH20 mask + AND).");
                } else if (bitWidth === 8) {
                    addUniqueHint(parameterHeuristic, "bool|uint8", "Bit-masked down to 8 bits (PUSH1 0xff + AND).");
                } else if (bitWidth > 0 && bitWidth < 256 && bitWidth % 8 === 0) {
                    addUniqueHint(parameterHeuristic, `uint${bitWidth}`, `Bit-masked down to ${bitWidth} bits.`);
                }
            }
        }

        const maybeIsZero = instructions[i + 2];
        if (maybeIsZero && maybeIsZero.opcode === 0x15) {
            addUniqueHint(parameterHeuristic, "bool", "Value is immediately consumed by ISZERO.");
        }

        const maybeAdd = instructions[i + 3];
        const maybeSecondCallDataLoad = instructions[i + 4];
        if (maybeAdd && maybeSecondCallDataLoad && maybeAdd.opcode === 0x01 && maybeSecondCallDataLoad.opcode === 0x35) {
            addUniqueHint(
                parameterHeuristic,
                "dynamic-pointer(bytes|string|array)",
                "Loaded value appears reused as a calldata pointer (ADD followed by CALLDATALOAD)."
            );
        }

        parameterHeuristicsMap.set(parameterIndex, parameterHeuristic);
    }

    const minimumParameterCount = maxCallDataOffset >= 4
        ? Math.floor((maxCallDataOffset - 4) / 32) + 1
        : 0;

    return {
        maxCallDataOffset,
        minimumParameterCount,
        inferredParameters: Array.from(parameterHeuristicsMap.values())
            .sort((a, b) => a.parameterIndex - b.parameterIndex),
        heuristicNotes: [
            "Dispatch extraction uses strict PUSH4 + EQ + PUSH2 + JUMPI matching.",
            "Minimum parameter count = floor((max calldata offset - 4) / 32) + 1.",
            "Type hints are opcode-pattern heuristics and not guaranteed ABI truth."
        ]
    };
}

function suspiciousFunctionNamePenalty(signature: string): number {
    const openParen = signature.indexOf("(");
    const functionName = (openParen === -1 ? signature : signature.slice(0, openParen)).toLowerCase();

    let penalty = 0;

    if (
        /^_?func_/.test(functionName) ||
        /tg_invmru|invmru|babbage|haha|watch_|join_|many_msg|ownertransfer/.test(functionName)
    ) {
        penalty += 3;
    }

    if (functionName.includes("_")) {
        penalty += 1;
    }

    if (functionName.length > 40) {
        penalty += 1;
    }

    return penalty;
}

function signatureRank(signature: string): { suspiciousPenalty: number; dynamicPenalty: number; length: number; parameterCount: number } {
    const dynamicPenalty = /(string|bytes(?![0-9])|\[\])/.test(signature) ? 1 : 0;
    const openParen = signature.indexOf("(");
    const closeParen = signature.lastIndexOf(")");

    let parameterCount = 0;
    if (openParen !== -1 && closeParen !== -1 && closeParen > openParen + 1) {
        parameterCount = signature.slice(openParen + 1, closeParen).split(",").length;
    }

    return {
        suspiciousPenalty: suspiciousFunctionNamePenalty(signature),
        dynamicPenalty,
        length: signature.length,
        parameterCount
    };
}

function selectBestCandidate(candidates: string[]): string[] {
    return [...candidates].sort((left, right) => {
        const leftRank = signatureRank(left);
        const rightRank = signatureRank(right);

        if (leftRank.suspiciousPenalty !== rightRank.suspiciousPenalty) {
            return leftRank.suspiciousPenalty - rightRank.suspiciousPenalty;
        }
        if (leftRank.dynamicPenalty !== rightRank.dynamicPenalty) {
            return leftRank.dynamicPenalty - rightRank.dynamicPenalty;
        }
        if (leftRank.length !== rightRank.length) {
            return leftRank.length - rightRank.length;
        }
        if (leftRank.parameterCount !== rightRank.parameterCount) {
            return leftRank.parameterCount - rightRank.parameterCount;
        }
        return left.localeCompare(right);
    });
}

async function resolveSelector(selector: string, fetchFn: FetchLike): Promise<SelectorResolution> {
    try {
        const response = await fetchFn(`https://www.4byte.directory/api/v1/signatures/?hex_signature=${selector}`);
        if (response.ok === false) {
            return {
                selector,
                status: "error",
                selectedSignature: null,
                candidateSignatures: [],
                collision: false,
                error: `4byte API returned HTTP ${response.status ?? "unknown"}.`
            };
        }

        const payload = (await response.json()) as SignatureApiResponse;
        const candidateSignatures = Array.isArray(payload.results)
            ? payload.results
                .map((entry) => entry.text_signature)
                .filter((signature): signature is string => typeof signature === "string" && signature.length > 0)
            : [];

        const uniqueCandidates = Array.from(new Set(candidateSignatures));
        if (uniqueCandidates.length === 0) {
            return {
                selector,
                status: "unresolved",
                selectedSignature: null,
                candidateSignatures: [],
                collision: false
            };
        }

        const preferredKnownSignature = KNOWN_SELECTOR_SIGNATURES[selector.toLowerCase()];
        const rankedCandidates = selectBestCandidate(uniqueCandidates);
        const selectedSignature = preferredKnownSignature && uniqueCandidates.includes(preferredKnownSignature)
            ? preferredKnownSignature
            : rankedCandidates[0];

        return {
            selector,
            status: "resolved",
            selectedSignature,
            candidateSignatures: rankedCandidates,
            collision: rankedCandidates.length > 1
        };
    } catch (error: unknown) {
        return {
            selector,
            status: "error",
            selectedSignature: null,
            candidateSignatures: [],
            collision: false,
            error: error instanceof Error ? error.message : "Unknown fetch error"
        };
    }
}

export async function extractAndResolveSelectors(
    instructions: Instruction[],
    options?: SelectorExtractionOptions
): Promise<SelectorAnalysisResult> {
    const dispatchEntries = parseDispatchEntries(instructions);
    const uniqueSelectors = Array.from(new Set(dispatchEntries.map((entry) => entry.selector))).sort();
    const fetchFn: FetchLike = options?.fetchFn ?? ((url: string) => fetch(url) as Promise<FetchLikeResponse>);

    const resolutions: SelectorResolution[] = [];
    for (const selector of uniqueSelectors) {
        resolutions.push(await resolveSelector(selector, fetchFn));
    }

    return {
        dispatchEntries,
        uniqueSelectors,
        resolutions,
        abiHeuristics: inferAbiHeuristics(instructions)
    };
}

export function formatSelectorAnalysis(report: SelectorAnalysisResult): string[] {
    const lines: string[] = [];

    lines.push(`Matched dispatch entries (PUSH4+EQ+PUSH2+JUMPI): ${report.dispatchEntries.length}`);
    if (report.dispatchEntries.length === 0) {
        lines.push("[!] No strict dispatcher entries matched. Selector extraction may be incomplete for this bytecode.");
    }

    for (const entry of report.dispatchEntries) {
        lines.push(
            `[Dispatch] ${entry.selector} -> 0x${entry.jumpDestination.toString(16).padStart(4, "0")} ` +
            `(check @0x${entry.selectorCheckOffset.toString(16).padStart(4, "0")})`
        );
    }

    lines.push(`Resolved unique selectors: ${report.uniqueSelectors.length}`);
    for (const resolution of report.resolutions) {
        if (resolution.status === "resolved") {
            if (resolution.collision) {
                lines.push(
                    `[!] ${resolution.selector} -> ${resolution.selectedSignature} ` +
                    `(collision: ${resolution.candidateSignatures.length} candidates)`
                );
                for (const candidate of resolution.candidateSignatures) {
                    lines.push(`    candidate: ${candidate}`);
                }
            } else {
                lines.push(`[+] ${resolution.selector} -> ${resolution.selectedSignature}`);
            }
        } else if (resolution.status === "unresolved") {
            lines.push(`[?] ${resolution.selector} -> [Unknown Custom Function]`);
        } else {
            lines.push(`[!] ${resolution.selector} -> [API Request Failed: ${resolution.error || "Unknown error"}]`);
        }
    }

    lines.push(
        `[Heuristic] Highest CALLDATALOAD offset: 0x${report.abiHeuristics.maxCallDataOffset.toString(16)}; ` +
        `minimum parameter count estimate: ${report.abiHeuristics.minimumParameterCount}`
    );

    if (report.abiHeuristics.inferredParameters.length === 0) {
        lines.push("[Heuristic] No parameter slots were confidently inferred from ABI read patterns.");
    }

    for (const parameter of report.abiHeuristics.inferredParameters) {
        lines.push(
            `[Heuristic] param${parameter.parameterIndex} @0x${parameter.calldataOffset.toString(16)} => ` +
            `${parameter.hints.join(" | ")}`
        );
        for (const evidence of parameter.evidence) {
            lines.push(`    evidence: ${evidence}`);
        }
    }

    for (const note of report.abiHeuristics.heuristicNotes) {
        lines.push(`[Heuristic Note] ${note}`);
    }

    return lines;
}