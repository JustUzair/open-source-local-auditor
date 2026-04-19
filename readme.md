# SentinelAI — Local-First AI Security Auditor

> Local-first Solidity auditor. 573 Solodit audit reports ingested, K-Means clustered into 35 vulnerability classes, iterative multi-pass engine with suspicion propagation. Benchmarked against a real private audit.

-- **More features and enhancements coming soon**

---

## Benchmark: SentinelAI vs. Professional Private Audit

Benchmarked against a **real private audit** of `Redacted-Contract.sol` — a gaming contract with VRNG, multipliers, and token pools. The original audit identified **8 distinct vulnerabilities** (1 High, 3 Medium, 3 Low, 1 Info).

| Original Finding                            | Severity | qwen3.5:27b (local) | qwen3.5:397b (cloud) | glm-5 (cloud) |
| ------------------------------------------- | -------- | :-----------------: | :------------------: | :-----------: |
| H-01: Cross-token payout                    | High     |         ✅          |          ✅          |      ❌       |
| M-01: Multiplier config breaks distribution | Medium   |         ✅          |          ✅          |      ✅       |
| M-02: `removePool` locks user balances      | Medium   |         ✅          |          ✅          |      ❌       |
| M-03: Fee accounting bug                    | Medium   |         ❌          |          ❌          |      ❌       |
| L-01: `addMultiplierPackage` unusable       | Low      |     ⚠️ partial      |          ❌          |      ❌       |
| L-02: No fee upper bounds                   | Low      |         ❌          |          ✅          |      ✅       |
| L-03: `payFees` invalid return              | Low      |     ⚠️ partial      |          ❌          |      ❌       |
| I-01: Error naming                          | Info     |         ❌          |          ❌          |      ❌       |

**Legend:** ✅ found &nbsp;|&nbsp; ⚠️ partial &nbsp;|&nbsp; ❌ missed

### Model Summary

| Model                   | Private Audit Coverage | Additional Findings | Notes                                            |
| ----------------------- | :--------------------: | :-----------------: | ------------------------------------------------ |
| **qwen3.5:27b (local)** |        **~6/8**        |        **8+**       | Best overall — catches critical bugs, runs free  |
| qwen3.5:397b (cloud)    |          ~6/8          |          8          | Deepest reasoning, surfaces admin-abuse vectors  |
| glm-5 (cloud)           |          ~4/8          |          6          | Solid free-tier alternative                      |

**qwen3.5:27b running locally on 18 GB RAM matches paid professional coverage — and finds bugs humans missed.**

---

## How It Works

SentinelAI runs a five-phase pipeline. Each phase is deterministic where possible; LLMs only reason over facts they are explicitly given.

**Phase 0 — Source Loading**
Accepts a directory or `.zip` archive. Recursively walks the file tree, detects language (Solidity, Rust, Move, Cairo, Vyper), scores each file by attack surface (entry points, external calls, value transfers), and filters noise. Output: a ranked `SourceFile[]`, highest-risk files first.

**Phase 1 — Protocol Map (Cartographer)**
A fast LLM call per file extracts a micro-summary: what the module does, its public entry points, and its cross-file dependencies. These are assembled into a compact Protocol Map (~2k tokens for a 20-file protocol) that every subsequent agent call receives as its understanding of the codebase. LLMs never guess structure — they are told it.

**Phase 2 — Pre-Scanner + RAG Context**
Two things run in parallel before the first auditor call:
- A **deterministic regex pre-scanner** (`prescanner.ts`) runs zero-LLM pattern checks across the source — reentrancy surfaces, unchecked external calls, access control gaps, integer boundaries — and produces typed `ScanLead[]` with file and line evidence. Zero network, zero tokens, under one second.
- The **cluster-diverse retriever** embeds the Protocol Map, scores it against 35 K-Means cluster centroids built from 573 Solodit audit reports, pulls the top 3 findings from the 10 most relevant clusters (30 findings total), and synthesises them into a structured Security Briefing via a small LLM call. Agents receive a distilled pattern brief, not a raw dump of historical findings.

**Phase 3 — Iterative Auditor Passes**
The auditor model receives: Protocol Map + Security Briefing + pre-scan leads + contract source. It outputs structured findings with confidence scores and suspicion notes. If confidence on a location is above the configured threshold, that location is annotated in the Protocol Map and re-examined in the next pass with explicit focus. Passes continue until no new high-confidence suspicions emerge or `MAX_AUDIT_PASSES` is reached.

**Phase 4 — Supervisor Synthesis**
A supervisor model receives all findings from all passes and all auditors. It deduplicates by semantic similarity (not just line number), resolves severity conflicts by taking the higher assessment when confidence is comparable, and produces the final severity-ranked Markdown report.

See [`architecture.svg`](./architecture.svg) for the full data flow diagram .

---

## Setup

### Prerequisites

- Node.js 20+
- [Ollama](https://ollama.com) installed and running (for local models)

### 1. Pull models

```bash
ollama pull qwen3.5:9b              # junior auditor (local, ~6 GB)
ollama pull qwen3.5:397b-cloud      # senior auditor (API-routed)
ollama pull glm-5:cloud             # alternative senior + supervisor
ollama pull qwen3-embedding:4b      # embeddings model (required for ingest)
```

### 2. Create model personas

```bash
chmod +x ./create-local-auditors.sh
./create-local-auditors.sh
```

This creates four named Ollama models with embedded system prompts:

| Model name            | Base model             | Role              |
| --------------------- | ---------------------- | ----------------- |
| `qwen-junior-auditor` | `qwen3.5:9b`           | Auditor           |
| `qwen-senior-auditor` | `qwen3.5:397b-cloud`   | Auditor           |
| `glm-senior-auditor`  | `glm-5:cloud`          | Auditor           |
| `glm-supervisor`      | `glm-5:cloud`          | Supervisor        |

To remove them: `./delete-local-auditors.sh`

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env — set auditor models, supervisor, embedding model, context windows
```

### 4. Run setup

```bash
npm run setup
```

This checks your environment, verifies the Solodit submodule is hydrated, and confirms the vector store is ready. If the index doesn't exist yet, it runs ingest automatically. A pre-built index can be downloaded from Releases to skip ingestion.

Expected output:

```
🛡️   SentinelAI — Setup

══════════════════════════════════════════

🔧  Checking environment configuration
   ✅  .env found
   ✅  Auditor 1: ollama/qwen-junior-auditor
   ✅  Auditor 2: ollama/qwen-senior-auditor
   ✅  Supervisor: ollama/glm-supervisor
   ✅  Embeddings: ollama/qwen3-embedding:4b
   ✅  Ollama reachable at http://localhost:11434

📚  Checking solodit_content submodule
   ✅  solodit_content hydrated — 17 audit firm folders found

📦  Checking vector store
   ✅  Vector index found. Ready.

══════════════════════════════════════════
✅  SentinelAI setup complete!
```

---

## Building the Knowledge Base (First Time Only)

If you're not using the pre-built index from Releases, run these two steps once.

### Ingest

Embeds all 573 Solodit audit reports into a local HNSWlib vector store (~19,453 chunks). The pipeline is resumable — a checkpoint is written every 50 files, so a crash or interruption picks up where it left off.

```bash
npm run ingest
```

### Cluster

Runs K-Means (K=35) over all embeddings, auto-labels each cluster via an LLM call, and saves centroids for retrieval. This is what enables cluster-diverse RAG — retrieving one representative finding per vulnerability class rather than the 30 most similar findings from the same category.

```bash
npm run cluster
```

The 35 labelled clusters span vulnerability classes including `reentrancy_attack`, `oracle_price_manipulation`, `governance_quorum_attack`, `signature_validation`, `integer_overflow`, `inflation_attack`, and 29 others.

---

## Running an Audit

```bash
npm run sentinel -- audit ./path/to/contracts/
npm run sentinel -- audit ./contracts.zip
```

### CLI Flags

| Flag                    | Default              | Description                                   |
| ----------------------- | -------------------- | --------------------------------------------- |
| `--input <path>`        | required             | Directory or `.zip` archive                   |
| `--max-passes <n>`      | `MAX_AUDIT_PASSES`   | Maximum iterative audit passes                |
| `--context-window <n>`  | `CONTEXT_WINDOW`     | Token context window override                 |
| `--min-confidence <n>`  | `MIN_SUSPICION_CONFIDENCE` | Threshold for suspicion propagation     |
| `--thinking`            | from env             | Force-enable thinking mode                    |
| `--no-thinking`         | from env             | Force-disable thinking mode                   |
| `--output-dir <path>`   | `./output`           | Where to write the final report               |

### Output

Each audit produces:
- `report-<timestamp>.md` — severity-ranked findings with descriptions, exploit scenarios, and recommendations
- `rag-synthesis.md` — the Security Briefing injected into the audit prompt (useful for debugging RAG quality)
- `debug-<timestamp>.json` — full structured audit data including per-agent outputs and confidence scores

See [`output.md`](./output.md) for a complete sample audit trace.

---

## Provider Configuration

SentinelAI is model-agnostic. Any auditor or supervisor slot can be pointed at any supported provider via `.env` — no code changes required.

```bash
# .env — mix and match freely
AUDITOR_1_PROVIDER=ollama
AUDITOR_1_MODEL=qwen-senior-auditor
AUDITOR_1_BASE_URL=http://localhost:11434   # or http://192.168.0.200:11434 for LAN

AUDITOR_2_PROVIDER=anthropic
AUDITOR_2_MODEL=claude-sonnet-4-20250514

SUPERVISOR_PROVIDER=openai
SUPERVISOR_MODEL=gpt-4o
```

Supported providers: **Ollama**, **Anthropic**, **OpenAI**, **Google Gemini**, **Groq**

For teams: point `AUDITOR_N_BASE_URL` at any LAN machine running Ollama to distribute model load across hardware without redundant model loading.

---

## Repository Structure

```
sentinelai/
├── src/
│   ├── core/
│   │   ├── prescanner.ts     # Deterministic regex pre-scanner → ScanLead[]
│   │   ├── cartographer.ts   # LLM-based Protocol Map builder
│   │   ├── batcher.ts        # Token-budget-aware batch grouping
│   │   ├── engine.ts         # Iterative audit orchestrator + supervisor
│   │   └── prompts.ts        # All system prompts in one place
│   ├── data/
│   │   ├── loader.ts         # Source file loader (dir + zip, language detection)
│   │   ├── retriever.ts      # Cluster-diverse RAG + Security Briefing synthesis
│   │   ├── vector-store.ts   # HNSWlib singleton (load / save / resume)
│   │   ├── splitter.ts       # Chunk splitter for ingest
│   │   ├── ingest.ts         # Ingest helpers
│   │   └── checkpoint.ts     # Resumable ingest state
│   └── scripts/
│       ├── 00_setup.ts       # Environment + readiness check
│       ├── 01_ingest.ts      # Full ingest pipeline
│       ├── 02_cluster.ts     # K-Means clustering + auto-labelling
│       └── 03_audit.ts       # CLI entry point
├── Modelfiles/               # Ollama model personas (auditor + supervisor)
├── benchmarks/               # Raw model outputs from benchmark runs
├── idea/                     # Design documents and architectural evolution
├── architecture.svg          # Full pipeline data flow diagram
└── output.md                 # Sample audit output
```

---

## Benchmark Results (Raw)

The `benchmarks/` directory contains the complete raw output from every model run used in the benchmark — including full agent JSON, the RAG synthesis briefing each model received, and the final rendered report. See:

- `benchmarks/deepseek-v3.2:cloud/`
- `benchmarks/glm-5:cloud results/`
- `benchmarks/qwen3.5:397b-cloud results/run 1/`
- `benchmarks/qwen3.5:397b-cloud results/run 2/`

---

## Design Documents

The `idea/` directory contains the full design history:

| File                    | Contents                                                                 |
| ----------------------- | ------------------------------------------------------------------------ |
| `BLUEPRINT.md`          | Original architecture spec — N-auditor model, RAG design, core principles |
| `BLUEPRINT_UPDATE_1.md` | First major revision after initial implementation                        |
| `BLUEPRINT_UPDATE_2.md` | Iterative engine design — multi-pass audit with suspicion propagation    |
| `BLUEPRINT_UPDATE_3.md` | Spec vs. implementation delta — every deviation documented with rationale |
| `AgentImplSpec.md`      | Full agent implementation specification                                  |

---

## License

MIT
