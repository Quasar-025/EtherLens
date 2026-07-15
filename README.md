# EtherLens

A TypeScript EVM bytecode analyzer with:
- CLI analysis for deployed contracts
- REST API analysis endpoint
- Disassembly, selector extraction, CFG generation, and security heuristics

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [API Reference](#api-reference)
- [Chain and RPC Configuration](#chain-and-rpc-configuration)
- [Deployment (Railway Free Tier)](#deployment-railway-free-tier)
- [Live URLs](#live-urls)
- [Analyzer Pipeline](#analyzer-pipeline)
- [Security Pattern Heuristics](#security-pattern-heuristics)
- [Codebase Map](#codebase-map)
- [Testing](#testing)
- [Generated Artifacts](#generated-artifacts)
- [Known Limitations](#known-limitations)

## Overview
This project reverse-engineers deployed EVM contracts from on-chain runtime bytecode. It supports:
- Disassembling opcodes (including PUSH0)
- Extracting and resolving function selectors
- Building control flow graphs (CFG)
- Running static security-pattern heuristics
- Returning machine-readable JSON for automation

Both CLI and API workflows share the same core library modules under lib/.

## Features
- Multi-chain RPC support with environment overrides (Ethereum, Polygon, Base, Arbitrum)
- Exponential backoff wrapper for RPC operations
- CBOR metadata trailer parsing and Solidity compiler hint extraction
- Selector collision-aware resolution (4byte.directory)
- CFG adjacency export with dynamic-jump markers and jump-resolution metrics
- DOT export and optional SVG generation via Graphviz
- Security heuristic checks for:
  - proxy/delegatecall patterns
  - unchecked external calls
  - payable path detection
  - selfdestruct reachability trace
  - owner-style access control checks
  - reentrancy guard/mutex or CEI patterns

## Requirements
- Node.js 18+ recommended
- npm
- Railway account (for backend deployment)
- Internet access for:
  - chain RPC calls
  - 4byte selector resolution (unless mocked)
  - research verification scraping (Etherscan)
- Optional: Graphviz (dot) if using --svg for CFG rendering

## Installation
```bash
npm install
```

## Quick Start
1. Show CLI help:
```bash
node ./bin/analyzer.js --help
```

2. Analyze a contract in text mode:
```bash
node ./bin/analyzer.js 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --chain ethereum --output text
```

3. Generate JSON output:
```bash
node ./bin/analyzer.js 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --chain ethereum --output json --cfg --selectors --security
```

4. Generate DOT (and optional SVG):
```bash
node ./bin/analyzer.js 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --chain ethereum --output dot --svg
```

5. Run API server:
```bash
npm run dev
```

## CLI Reference
Executable entrypoint:
- bin/analyzer.js -> ts-node/register -> cli.ts

Usage:
```text
analyzer <address> --chain <chain> --output <json|text|dot> [flags]
```

Flags:
- --disasm: include full disassembly output
- --selectors: include selector extraction + resolution
- --cfg: include CFG analysis
- --security: include security heuristics
- --svg: with --output dot, run Graphviz to produce SVG

Default behavior:
- If none of --disasm, --selectors, --cfg, --security is provided, CLI runs all analyses.
- In text mode with default full run, disassembly is preview-limited to first 20 instructions.

Output modes:
- text:
  - prints status/log output and analysis sections to stdout
- json:
  - prints structured JSON report to stdout
  - when CFG is included, also writes cli_output.json via exportToJson
- dot:
  - writes cli_output.dot
  - with --svg and Graphviz installed, writes cli_output.svg

## API Reference
File: api.ts

Endpoint:
- POST /analyze

Request body:
```json
{
  "address": "0x...",
  "chain": "ethereum"
}
```

Validation behavior:
- Rejects empty body with HTTP 400
- Rejects invalid or missing address with HTTP 400
- Rejects unsupported chain with HTTP 400
- Returns HTTP 404 if target address has no runtime bytecode

Response shape (high-level):
```json
{
  "success": true,
  "metadata": {
    "address": "0x...",
    "chain": "ethereum",
    "totalInstructions": 0,
    "totalBlocks": 0,
    "jumpResolution": {
      "static": 0,
      "dynamic": 0,
      "total": 0,
      "staticPercentage": 0,
      "dynamicPercentage": 0
    },
    "disassembly": {
      "metadataDetected": false,
      "metadataLength": 0,
      "cborValid": false,
      "solidityVersion": null
    }
  },
  "securityAnalysis": [],
  "cfgAdjacencyList": {},
  "selectorAnalysis": {},
  "disassemblyPreview": []
}
```

Server startup:
- Default port is 3000
- Override with PORT environment variable

Example request:
```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"address":"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","chain":"ethereum"}'
```

## Chain and RPC Configuration
Supported chains:
- ethereum
- polygon
- base
- arbitrum

Default RPC URLs are defined in lib/chains.ts.

Override via environment variables:
- ETHEREUM_RPC_URL
- POLYGON_RPC_URL
- BASE_RPC_URL
- ARBITRUM_RPC_URL

Behavior:
- Blank env values are ignored
- Chain resolution is case-insensitive and trims whitespace

## Deployment (Railway)
This repository currently contains a backend only.

### 1. Prepare environment variables
Create deployment env vars in Railway using these keys:
- PORT
- ETHEREUM_RPC_URL
- POLYGON_RPC_URL
- BASE_RPC_URL
- ARBITRUM_RPC_URL

Suggested baseline values are in .env.example.

### 2. Configure Railway service
1. Push this repository to GitHub.
2. In Railway, create a new project from the GitHub repo.
3. Railway will run npm install and npm run build, then start with npm run start.
4. Set health check path to /health.

### 3. Verify deployment
Health check:
```bash
curl https://etherlens-production.up.railway.app/health
```

Analyze endpoint check:
```bash
curl -X POST https://etherlens-production.up.railway.app/analyze \
  -H "Content-Type: application/json" \
  -d '{"address":"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","chain":"ethereum"}'
```

## Live URLs
- Backend API (Railway): https://etherlens-production.up.railway.app
- Backend Health: https://etherlens-production.up.railway.app/health
- Frontend: Deferred for this milestone (no frontend app currently in this repository)

## Analyzer Pipeline
Shared flow used by CLI/API:
1. Resolve chain -> RPC URL (lib/chains.ts)
2. Fetch runtime bytecode with retries (lib/rpc.ts)
3. Disassemble runtime bytecode (lib/disassembler.ts)
4. Extract/resolve selectors (lib/extractor.ts)
5. Build CFG and jump stats (lib/graph.ts)
6. Run security heuristics (lib/security.ts)
7. Emit output (text/json/dot/api payload)

## Security Pattern Heuristics
Implemented in SecurityAnalyzer (lib/security.ts):
1. Proxy pattern:
- Detect DELEGATECALL and storage-backed implementation slot usage
- Probes EIP-1967 and legacy slots

2. Unchecked external calls:
- Flags CALL/DELEGATECALL/STATICCALL without nearby ISZERO + JUMPI check pattern

3. Payable detection:
- Classifies non-payable guard patterns vs unguarded CALLVALUE sites

4. Selfdestruct tracing:
- Finds SELFDESTRUCT and attempts DFS path trace from entry block

5. Access control pattern:
- Looks for CALLER vs SLOAD equality checks with nearby branch/revert

6. Reentrancy guard pattern:
- Looks for mutex-like SLOAD/SSTORE around external calls
- Falls back to checks-effects-interactions style heuristic

Important:
- These are static heuristics and should be treated as triage indicators, not exploit proof.

## Codebase Map
Top level:
- api.ts
  - Express API server exposing POST /analyze
- cli.ts
  - Primary CLI command implementation and output routing
- bin/analyzer.js
  - Node executable shim that registers ts-node and runs cli.ts
- tsconfig.json
  - TypeScript compiler settings
- package.json
  - dependencies, bin mapping, test script
- cfg.dot / cfg.json / cli_output.dot / cli_output.json / cli_output.svg
  - generated analysis artifacts (gitignored)

lib/:
- lib/chains.ts
  - chain support list, defaults, env override resolution
- lib/disassembler.ts
  - bytecode disassembly, CBOR metadata parsing, instruction model
- lib/extractor.ts
  - strict dispatcher parsing, selector resolution, ABI heuristics, report formatting
- lib/graph.ts
  - basic block partitioning, edge resolution, jump metrics, JSON/DOT export
- lib/opcodes.ts
  - opcode mnemonic map, generated PUSH/DUP/SWAP/LOG mappings
- lib/rpc.ts
  - fetchWithBackoff retry utility
- lib/security.ts
  - SecurityAnalyzer heuristic suite
- lib/index.ts
  - legacy all-in-one executable workflow that writes cfg.json/cfg.dot

tests/:
- tests/chains.test.ts
  - chain config and env override behavior tests
- tests/engine.test.ts
  - disassembler, metadata parsing, CFG, backoff, selector resolution, security heuristics tests

## Testing
Default command:
```bash
npm test
```

On Windows PowerShell with restricted execution policy, use:
```bash
cmd /c npm test
```

Current observed status:
- Test files: 2 passed
- Tests: 26 passed

## Generated Artifacts
Common output files:
- cli_output.dot
- cli_output.json
- cli_output.svg
- cfg.dot
- cfg.json

Ignored by git via .gitignore.

## Known Limitations
- Selector extraction uses a strict PUSH4 + EQ + PUSH2 + JUMPI pattern and may miss non-standard dispatchers.
- Vyper and Huff contracts can require alternate dispatcher heuristics for complete selector recovery.
- Security findings are static-pattern based and can include false positives/negatives.
- API security log capture currently relies on temporary console.log interception during analysis.
- JSON CLI mode suppresses CFG build logs for cleaner machine-readable output, but side-effect files may still be emitted when CFG export is requested.
