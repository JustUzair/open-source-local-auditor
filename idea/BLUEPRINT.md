# SentinelAI — AI-Powered Solidity Security Auditor

## Complete Project Blueprint

> **Status**: Pre-build planning document. Read this entirely before writing a single file.
> **Last Updated**: March 2026
> **Author**: JustUzair + Claude

---

## Table of Contents

1. [What This Is](#1-what-this-is)
2. [Core Design Principles](#2-core-design-principles)
3. [How It Works — The Full Mental Model](#3-how-it-works)
4. [Technology Decisions](#4-technology-decisions)
5. [Project Structure](#5-project-structure)
6. [Data Flow — End to End](#6-data-flow)
7. [The Generic LLM Pattern (Non-Negotiable)](#7-the-generic-llm-pattern)
8. [Component Blueprints](#8-component-blueprints)
9. [Build Phases](#9-build-phases)
10. [CLI Flags and Override System](#10-cli-flags)
11. [Environment Variables — Full Reference](#11-environment-variables)
12. [NPM Scripts](#12-npm-scripts)
13. [Known Constraints and Mitigations](#13-known-constraints)
14. [Codebase Reuse Map](#14-codebase-reuse-map)

---

## 1. What This Is

SentinelAI is a model-agnostic, locally-runnable Solidity security auditor. It uses:

- A **pre-ingested RAG knowledge base** of real vulnerability findings from Solodit (Cyfrin's audit database), stored as local vector files — no hosted database required.
- **K-means clustered retrieval** that returns one representative finding per vulnerability class, ensuring diverse and non-redundant context per audit.
- **N independent auditor agents**, each running a complete 3-lens review (logical bugs, common pitfalls, call flow), simulating N different audit firms reviewing the same code.
- A **Supervisor agent** that cross-correlates all N auditors' findings, deduplicates, confidence-scores, and produces a final severity-ranked report.
- A **deterministic AST-based recon processor** that extracts the call graph, entry points, and reentrancy surface from the actual Solidity source — not inferred by an LLM.

It works with any LLM. Ollama (local, free, unlimited) by default. Any provider swappable via `.env` or CLI flags without touching code.

---

## 2. Core Design Principles

These are non-negotiable. Every implementation decision defers to these.

### 2.1 Model Agnosticism

No provider-specific features. No `.withStructuredOutput()`. No native tool calling. No function calling APIs.
All structured output is achieved through **prompt engineering + Zod validation + JSON extraction fallback**.
This means the tool works identically with Ollama, Gemini, Groq, OpenAI, Anthropic, or any future model.

### 2.2 Determinism Where Possible

The call graph, entry points, external call sites, and reentrancy surface are computed from the AST using `@solidity-parser/parser`. LLMs never guess code structure — they receive it as fact. LLMs only reason over it.

### 2.3 Explicit Failure, Never Silent

Every pipeline stage returns `{ ok: true, data } | { ok: false, error, stage }`.
If an agent fails Zod validation twice, its output is marked `FAILED` with the raw response logged. The supervisor works with remaining outputs. The report notes which agents failed and why.

### 2.4 Resumable by Default

The ingest pipeline writes a checkpoint file after every 50 embeddings. A crash or rate limit hit does not restart from zero. The checkpoint is the single source of truth for ingest progress.

### 2.5 Zero Friction Setup

One command — `npm run setup` — handles everything: environment check, scraping, ingestion, clustering. Users with a pre-built index skip steps 2-3 automatically. Ollama is checked but never required to be running for setup — only for auditing.

### 2.6 Interfaces Are Adapters, Engine Is The Product

`AuditEngine` knows nothing about HTTP, CLI flags, or filesystems. Web and CLI are thin adapters that feed it `SolidityFile[]` and receive `AuditReport`. The same audit logic runs regardless of interface.

---

## 3. How It Works — The Full Mental Model

### The N Auditors Concept

```
N=1 (default, local Ollama):

  Auditor 1 (ollama/deepseek-r1:8b):
    ├── Agent A: logical-bugs.md     ← reads full contract + recon + RAG
    ├── Agent B: common-pitfalls.md  ← reads full contract + recon + RAG
    └── Agent C: contextual.md      ← reads full contract + recon + RAG
    → 3 JSON finding arrays

  Supervisor: merges, deduplicates, scores severity
  → AUDIT_REPORT.md

N=2 (user adds Gemini key):

  Auditor 1 (ollama)   |   Auditor 2 (gemini-2.0-flash)
    ├── Agent A        |     ├── Agent A
    ├── Agent B        |     ├── Agent B
    └── Agent C        |     └── Agent C
    → 3 findings       |     → 3 findings

  Supervisor sees 6 finding sets.
  Cross-auditor agreement → higher confidence.
  Only Auditor 2 flagged X → MEDIUM confidence, flagged for manual review.
  → AUDIT_REPORT.md with per-finding confidence and auditor attribution

N=3: 9 finding sets → Supervisor → Report
```

Each "auditor" is the same three agents run by a different model. The supervisor's confidence scoring is what makes N>1 valuable — agreement across independent models is meaningful signal.

### What Each Agent Actually Receives

Every agent call contains exactly these four blocks in the user prompt:

```
[BLOCK 1] RECON CONTEXT
  — Deterministic. From AST parser. Not inferred.
  — Call graph, entry points, external call sites, reentrancy surface.
  — Hard capped at 100 lines. Excess truncated with a note.

[BLOCK 2] RAG FINDINGS (cluster-diverse)
  — Top 1 finding per relevant vulnerability cluster from Solodit.
  — Max 6 findings total, each trimmed to 200 tokens.
  — Formatted as: [Finding N] Category | Protocol | Pattern | Severity

[BLOCK 3] CONTRACT SOURCE CODE
  — All .sol files concatenated, each with a filename header.
  — This is what the agent actually reads and reasons over.

[BLOCK 4] TASK INSTRUCTION
  — Explicit. Tells agent what to look for (from its skill).
  — Tells agent to output JSON matching a specific schema.
  — Schema is embedded in the prompt itself (not function calling).
```

The system prompt is the skill `.md` file. That's all.

---

## 4. Technology Decisions

### Runtime

- **Node.js 20+ / TypeScript 5.x** — same as Tessera, no change
- **tsup** for building, **tsx** for development (already in Tessera)

### LLM Layer

- **LangChain JS** — already in Tessera, supports Ollama/Gemini/Groq/OpenAI/Anthropic
- **No provider-specific features used** — only `.invoke([SystemMessage, HumanMessage])`
- Temperature: 0.1 for all agents (deterministic, not creative)
- Temperature: 0.0 for supervisor (pure logic)

### Vector Store

- **HNSWLib** (`hnswlib-node` + `@langchain/community/vectorstores/hnswlib`)
- Local flat files: `data/vectorstore/hnswlib.index` + `data/vectorstore/docstore.json`
- No server, no account, no API call at query time

### Embeddings

- **Gemini Embedding** (`gemini-embedding-001`) — free, high quality, 768 dimensions
- Fallback: **Ollama embeddings** (`nomic-embed-text`) — fully local, no API key
- Configured via `EMBEDDING_PROVIDER` in `.env`

### Clustering

- **ml-kmeans** — pure JS k-means, no native dependencies
- 35 clusters, run once after ingest, saved to `data/clusters/`

### Solidity Parsing

- **`@solidity-parser/parser`** — pure JS/TS, no `solc`, no native binaries
- Powers all call graph extraction. Deterministic.

### ZIP Handling

- **`adm-zip`** — pure JS, no native binaries

### Validation

- **Zod** — already in Tessera, validates all LLM JSON output

### CLI

- **`commander`** — argument parsing, subcommands, flag overrides

### Web Interface

- **Express** — already in Tessera
- **Multer** — file upload, already in Tessera
- Frontend: minimal single-page HTML served statically (no React build step for v1)

### Progress Display

- **`ora`** — spinner for CLI
- **`cli-progress`** — progress bars for ingest script

---

## 5. Project Structure

```
sentinelai/
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── .env.example
├── .gitignore
│
├── data/                          ← gitignored except README.md inside
│   ├── .gitkeep
│   ├── raw/                       ← scraped Solodit JSON files
│   │   └── .gitkeep
│   ├── vectorstore/               ← HNSWLib index files (pre-built or generated)
│   │   └── .gitkeep
│   └── clusters/                  ← k-means output
│       └── .gitkeep
│
├── scripts/                       ← run via npm scripts, not part of app
│   ├── setup.ts                   ← orchestrates everything (npm run setup)
│   ├── 01_scrape.ts               ← Solodit scraper
│   ├── 02_ingest.ts               ← embed + store to HNSWLib, checkpoint-aware
│   └── 03_cluster.ts              ← k-means on stored embeddings
│
├── src/
│   ├── core/                      ← THE PRODUCT. No HTTP, no CLI, no FS paths.
│   │   ├── engine.ts              ← AuditEngine class — orchestrates full pipeline
│   │   ├── recon.ts               ← AST-based call graph builder
│   │   ├── agents.ts              ← N-auditor parallel runner
│   │   ├── supervisor.ts          ← cross-auditor synthesis + severity scoring
│   │   └── report.ts              ← markdown report generator
│   │
│   ├── data/                      ← data layer, no LLM logic
│   │   ├── loader.ts              ← loadFromZip(buffer), loadFromPath(dir) → SolidityFile[]
│   │   ├── splitter.ts            ← chunk documents for ingest (from Tessera 02_splitter)
│   │   ├── vector-store.ts        ← HNSWLib get/load/save (replaces Tessera 03_vector_store)
│   │   ├── ingest.ts              ← add documents to store (from Tessera 04_ingest)
│   │   ├── retriever.ts           ← cluster-aware similarity search
│   │   └── checkpoint.ts          ← read/write ingest-checkpoint.json
│   │
│   ├── skills/                    ← skill .md files (copied from Plamen EVM skills)
│   │   ├── logical-bugs.md        ← reentrancy, access control, logic errors
│   │   ├── common-pitfalls.md     ← oracle, arithmetic, flash loans
│   │   ├── contextual.md          ← call flow, state machine, token flow
│   │   ├── oracle-analysis.md     ← from Plamen agents/skills/evm/oracle-analysis/
│   │   ├── token-flow.md          ← from Plamen agents/skills/evm/token-flow-tracing/
│   │   ├── flash-loan.md          ← from Plamen agents/skills/evm/flash-loan-interaction/
│   │   └── centralization.md      ← from Plamen agents/skills/evm/centralization-risk/
│   │
│   ├── utils/
│   │   ├── env.ts                 ← Zod-validated env schema (extended from Tessera)
│   │   ├── models.ts              ← generic makeModel(slot) for N-auditor config
│   │   ├── llm.ts                 ← generic invoke + JSON extract (no provider features)
│   │   └── logger.ts              ← structured logging, stage-aware
│   │
│   ├── interfaces/
│   │   ├── web.ts                 ← Express app (upload ZIP → engine → JSON response)
│   │   └── cli.ts                 ← Commander app (path → engine → write report)
│   │
│   └── types/
│       ├── audit.ts               ← SolidityFile, AuditReport, Finding, AgentOutput
│       ├── recon.ts               ← ReconContext, FunctionInfo, CallEdge
│       └── models.ts              ← ModelSlot, AuditorConfig, ProviderName
│
└── public/                        ← static web UI (single HTML file for v1)
    └── index.html
```

---

## 6. Data Flow — End to End

```
┌─────────────────────────────────────────────────────────────────┐
│  INPUT LAYER                                                    │
│                                                                 │
│  Web:  POST /api/v1/audit/upload { zip: Buffer }               │
│  CLI:  audit ./contracts/ --output ./report.md                 │
│                                          ↓                      │
│  loader.ts: loadFromZip() OR loadFromPath()                    │
│  → SolidityFile[] = [{ filename, content }]                   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│  RECON LAYER (deterministic, no LLM)                           │
│                                                                 │
│  recon.ts: buildReconContext(files)                            │
│  → @solidity-parser/parser AST walk (2 passes)                │
│  → ReconContext {                                              │
│       callGraph: CallEdge[],                                  │
│       entryPoints: string[],                                  │
│       externalCalls: ExternalCall[],                          │
│       reentrancySurface: ReentrancySurface[],                │
│       rawSummary: string  ← formatted text, max 100 lines    │
│    }                                                           │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│  RAG LAYER (local HNSWLib, no network)                         │
│                                                                 │
│  retriever.ts: fetchClusterDiverseFindings(files, k=6)        │
│  1. Embed combined contract code (EMBEDDING_PROVIDER)          │
│  2. Compute distance to each of 35 cluster centroids           │
│  3. Select top 6 closest clusters                              │
│  4. From each cluster, retrieve 1 best matching finding        │
│  → ragContext: string (6 findings, each trimmed to 200 tokens) │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│  N-AUDITOR LAYER (parallel across auditors, parallel within)   │
│                                                                 │
│  agents.ts: runAllAuditors(files, reconContext, ragContext)    │
│                                                                 │
│  Promise.all([auditor1, auditor2, ...auditorN])               │
│                                                                 │
│  Each auditor = Promise.all([agentA, agentB, agentC])         │
│                                                                 │
│  Each agent call:                                              │
│    system: skill .md content                                   │
│    user:   reconContext + ragContext + contractCode + task     │
│    → raw string response                                       │
│    → extractJSON(response) → validate with Zod                │
│    → retry once if invalid → mark FAILED if still invalid     │
│    → AgentOutput { auditorId, agentRole, findings[], status } │
│                                                                 │
│  Result: AgentOutput[] (3×N outputs, some may be FAILED)      │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│  SUPERVISOR LAYER                                              │
│                                                                 │
│  supervisor.ts: synthesize(agentOutputs, reconContext)        │
│                                                                 │
│  Input to supervisor LLM:                                      │
│    - All agent findings (deduplicated by location+type)        │
│    - Agreement matrix (which findings appear in N auditors)   │
│    - Recon context (to validate findings against actual code)  │
│    - Task: assign severity, reject false positives, output JSON│
│                                                                 │
│  Confidence scoring:                                           │
│    N=1 auditor flagged it → base confidence from agent        │
│    2/N auditors flagged it → +25% confidence                  │
│    3/N auditors flagged it → HIGH confidence, auto-elevate    │
│                                                                 │
│  → FinalFinding[] { severity, confidence, title, file,        │
│      line, description, exploit, recommendation,              │
│      flaggedByAuditors: string[] }                            │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│  REPORT LAYER                                                  │
│                                                                 │
│  report.ts: generateReport(findings, reconContext, meta)      │
│  → AuditReport { markdown: string, findings: FinalFinding[] } │
│                                                                 │
│  Web:  res.json(report) → client downloads .md               │
│  CLI:  writeFile(outputPath, report.markdown)                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. The Generic LLM Pattern (Non-Negotiable)

### Why No Provider-Specific Features

Groq does not support native structured output. Ollama's tool calling support varies by model. Using `.withStructuredOutput()` or `.bindTools()` breaks compatibility for non-OpenAI providers.

**The solution: prompt-engineered JSON + extraction + Zod validation.**

This works with 100% of LLM providers because it requires only one capability: the model can follow text instructions. Every model that can run inference can do this.

### The Generic Invoke Pattern

This lives in `src/utils/llm.ts` and is the ONLY way any LLM is called in this codebase:

````typescript
// src/utils/llm.ts

import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { SystemMessage, HumanMessage } from "@langchain/core/messages";
import { z, ZodSchema } from "zod";

export interface LLMCallResult<T> {
  ok: true;
  data: T;
  rawResponse: string;
} | {
  ok: false;
  error: string;
  rawResponse: string;
  stage: string;
}

/**
 * Generic LLM invoke. Works with any provider.
 * No tool calling. No structured output APIs.
 * JSON is extracted from response text via prompt engineering + regex fallback.
 */
export async function invokeWithSchema<T>(
  model: BaseChatModel,
  systemPrompt: string,
  userPrompt: string,
  schema: ZodSchema<T>,
  stage: string,
  maxRetries: number = 1,
): Promise<LLMCallResult<T>> {

  // Embed the expected schema shape in the prompt
  const schemaHint = buildSchemaHint(schema);
  const fullUserPrompt = `${userPrompt}

---
OUTPUT INSTRUCTIONS (MANDATORY):
Respond with ONLY a valid JSON object. No markdown. No code fences. No explanation before or after.
The JSON must match this exact shape:
${schemaHint}

If you cannot find any findings, respond with: {"findings": []}
Do not add any text outside the JSON object.`;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    let rawResponse = "";
    try {
      const response = await model.invoke([
        new SystemMessage(systemPrompt),
        new HumanMessage(
          attempt === 0
            ? fullUserPrompt
            : `${fullUserPrompt}\n\nPrevious attempt produced invalid JSON. Try again. Output ONLY the JSON object.`
        ),
      ]);

      rawResponse = typeof response.content === "string"
        ? response.content
        : (response.content as any[]).map(b => b?.text ?? "").join("");

      const parsed = extractAndParseJSON(rawResponse);
      const validated = schema.parse(parsed);

      return { ok: true, data: validated, rawResponse };

    } catch (err) {
      if (attempt === maxRetries) {
        return {
          ok: false,
          error: `Schema validation failed after ${maxRetries + 1} attempts: ${(err as Error).message}`,
          rawResponse,
          stage,
        };
      }
      // Loop for retry
    }
  }

  // Unreachable but TypeScript needs it
  return { ok: false, error: "Unknown error", rawResponse: "", stage };
}

/**
 * Extract JSON from a response that might contain markdown fences,
 * preamble text, or postamble text. Tries multiple strategies.
 */
function extractAndParseJSON(text: string): unknown {
  // Strategy 1: Direct parse (model followed instructions perfectly)
  try {
    return JSON.parse(text.trim());
  } catch {}

  // Strategy 2: Strip markdown fences
  // Handles ```json ... ``` and ``` ... ```
  const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) {
    try {
      return JSON.parse(fenceMatch[1].trim());
    } catch {}
  }

  // Strategy 3: Extract first {...} or [...] block
  const objectMatch = text.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
  if (objectMatch) {
    try {
      return JSON.parse(objectMatch[1]);
    } catch {}
  }

  throw new Error(`Could not extract valid JSON from response. Raw: ${text.slice(0, 200)}`);
}

/**
 * Generate a human-readable schema hint to embed in the prompt.
 * This is the key to provider-agnostic structured output.
 */
function buildSchemaHint(schema: ZodSchema): string {
  // For our specific schemas, we hardcode the hints.
  // Generic Zod-to-string conversion is complex and error-prone.
  // Better to be explicit per schema.
  return JSON.stringify(getSchemaExample(schema), null, 2);
}

function getSchemaExample(schema: ZodSchema): unknown {
  // Each schema registers its example. See types/audit.ts for examples.
  return (schema as any)._example ?? { "note": "see schema definition" };
}
````

### Adding Schema Examples (in types/audit.ts)

Every Zod schema used with `invokeWithSchema` gets an `._example` attached:

```typescript
// src/types/audit.ts

export const FindingSchema = z.object({
  severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]),
  title: z.string(),
  file: z.string(),
  line: z.number(),
  description: z.string(),
  exploit: z.string(),
  recommendation: z.string(),
});

export const AgentOutputSchema = z.object({
  findings: z.array(FindingSchema),
});

// Attach example for prompt injection
(AgentOutputSchema as any)._example = {
  findings: [
    {
      severity: "High",
      title: "Reentrancy in withdraw()",
      file: "Vault.sol",
      line: 68,
      description: "State is updated after external call, enabling reentrancy.",
      exploit:
        "Attacker calls withdraw(), which calls token.transfer() before updating balances. Attacker's fallback re-enters withdraw() with unchanged balance.",
      recommendation:
        "Apply checks-effects-interactions: update balances before token.transfer() call.",
    },
  ],
};
```

---

## 8. Component Blueprints

### 8.1 AuditEngine (src/core/engine.ts)

```typescript
// Responsible for: orchestrating the full pipeline.
// Knows nothing about: HTTP, CLI, file paths, report destination.

export class AuditEngine {
  constructor(private config: EngineConfig) {}

  async audit(files: SolidityFile[]): Promise<AuditResult> {
    // Stage 1: Recon
    const reconResult = buildReconContext(files);

    // Stage 2: RAG (parallel with recon if performance needed later)
    const ragResult = await fetchClusterDiverseFindings(files);

    // Stage 3: N Auditors (all in parallel)
    const auditorOutputs = await runAllAuditors(
      files,
      reconResult,
      ragResult,
      this.config,
    );

    // Stage 4: Supervisor
    const findings = await synthesize(auditorOutputs, reconResult, this.config);

    // Stage 5: Report
    const report = generateReport(findings, reconResult, {
      filesAudited: files.map(f => f.filename),
      auditorsRun: this.config.auditors.length,
      timestamp: new Date().toISOString(),
    });

    return {
      ok: true,
      report,
      findings,
      meta: {
        reconContext: reconResult,
        auditorOutputs,
      },
    };
  }
}
```

### 8.2 Model Factory (src/utils/models.ts)

```typescript
// Reads N_AUDITORS from env. Builds one BaseChatModel per auditor slot.
// Each slot is independent. Provider + model + key all come from env.

// Supported providers: ollama | gemini | groq | openai | anthropic
// All return BaseChatModel. All called identically via .invoke().

export function makeAuditorModel(slotIndex: number): BaseChatModel {
  const provider = env[`AUDITOR_${slotIndex}_PROVIDER`] ?? "ollama";
  const model = env[`AUDITOR_${slotIndex}_MODEL`] ?? "deepseek-r1:8b";
  const apiKey = env[`AUDITOR_${slotIndex}_API_KEY`] ?? "";
  return buildModel(provider, model, apiKey, 0.1);
}

export function makeSupervisorModel(): BaseChatModel {
  return buildModel(
    env.SUPERVISOR_PROVIDER ?? "ollama",
    env.SUPERVISOR_MODEL ?? "deepseek-r1:8b",
    env.SUPERVISOR_API_KEY ?? "",
    0.0, // zero temperature — pure logic
  );
}

function buildModel(
  provider: string,
  model: string,
  apiKey: string,
  temperature: number,
): BaseChatModel {
  switch (provider) {
    case "gemini":
      return new ChatGoogleGenerativeAI({ model, apiKey, temperature });
    case "groq":
      return new ChatGroq({ model, apiKey, temperature });
    case "openai":
      return new ChatOpenAI({ model, apiKey, temperature });
    case "anthropic":
      return new ChatAnthropic({ model, apiKey, temperature });
    case "ollama":
    default:
      return new ChatOllama({
        model,
        baseUrl: env.OLLAMA_BASE_URL ?? "http://localhost:11434",
        temperature,
      });
  }
}
```

### 8.3 Checkpoint System (src/data/checkpoint.ts)

```typescript
// Reads and writes data/ingest-checkpoint.json
// Prevents re-embedding already-processed findings on crash or rate limit hit.

export interface IngestCheckpoint {
  version: number;
  startedAt: string;
  embeddingProvider: string;
  embeddingModel: string;
  completedCategories: string[]; // fully done, skip entirely
  inProgressCategory: string | null;
  inProgressOffset: number; // resume from this index within category
  totalIngested: number;
  clustered: boolean; // k-means has run on this data
}

export async function readCheckpoint(): Promise<IngestCheckpoint | null>;
export async function writeCheckpoint(cp: IngestCheckpoint): Promise<void>;
export async function clearCheckpoint(): Promise<void>;

// If embeddingProvider or embeddingModel changed since last run,
// throw an error — mixed embeddings corrupt the index silently.
export function validateCheckpointCompatibility(
  cp: IngestCheckpoint,
  currentProvider: string,
  currentModel: string,
): void;
```

### 8.4 Cluster-Aware Retriever (src/data/retriever.ts)

```typescript
// Not plain similarity search. Cluster-aware.
// Returns 1 best finding per relevant cluster.
// Prevents 6 reentrancy findings when contract has other issues too.

export async function fetchClusterDiverseFindings(
  files: SolidityFile[],
  k: number = 6,
): Promise<string> {
  const combinedCode = files.map(f => f.content).join("\n");
  const embedding = await embedText(combinedCode);
  const centroids = await loadClusterCentroids();

  // Score contract embedding against all 35 cluster centroids
  const clusterDistances = centroids
    .map((centroid, id) => ({
      clusterId: id,
      distance: cosineSimilarity(embedding, centroid.vector),
      label: centroid.label,
    }))
    .sort((a, b) => b.distance - a.distance);

  // Top k clusters
  const topClusters = clusterDistances.slice(0, k);

  // 1 finding per cluster
  const findings = await Promise.all(
    topClusters.map(({ clusterId, label }) =>
      vectorStore
        .similaritySearch(combinedCode, 1, { filter: { clusterId } })
        .then(results => ({ clusterId, label, finding: results[0] })),
    ),
  );

  return formatRagContext(findings);
}
```

### 8.5 CLI Interface (src/interfaces/cli.ts)

```typescript
// Uses commander. Pure adapter — delegates to AuditEngine.
// No audit logic here.

program
  .name("sentinel")
  .description("AI-powered Solidity security auditor")
  .version("1.0.0");

program
  .command("audit <path>")
  .description("Audit Solidity contracts at the given path or zip file")
  .option("-o, --output <path>", "Output report path", "./AUDIT_REPORT.md")
  .option(
    "-n, --auditors <number>",
    "Number of independent auditors to run",
    "1",
  )
  .option("--auditor-1-provider <provider>", "Override auditor 1 provider")
  .option("--auditor-1-model <model>", "Override auditor 1 model")
  .option(
    "--auditor-2-provider <provider>",
    "Override auditor 2 provider (enables N=2)",
  )
  .option("--auditor-2-model <model>", "Override auditor 2 model")
  .option(
    "--auditor-3-provider <provider>",
    "Override auditor 3 provider (enables N=3)",
  )
  .option("--auditor-3-model <model>", "Override auditor 3 model")
  .option("--supervisor-provider <provider>", "Override supervisor provider")
  .option("--supervisor-model <model>", "Override supervisor model")
  .action(async (inputPath, options) => {
    // Merge CLI flags into config (flags take precedence over env)
    const config = buildConfigFromOptions(options);
    const files = await loadFromPath(inputPath);
    const engine = new AuditEngine(config);
    const result = await engine.audit(files);
    await writeFile(options.output, result.report.markdown);
    console.log(`Report written to ${options.output}`);
  });
```

---

## 9. Build Phases

### Phase 1 — Foundation

**Goal**: Project compiles. No logic yet.

1. `package.json` — dependencies, scripts
2. `tsconfig.json` — compiler config
3. `src/types/` — all shared types and Zod schemas
4. `src/utils/env.ts` — Zod env validation
5. `src/utils/models.ts` — model factory (builds but not tested until Phase 3)
6. `src/utils/llm.ts` — generic invoke + JSON extraction
7. `src/utils/logger.ts` — structured logging

**Done when**: `npx tsx src/utils/env.ts` runs without error.

### Phase 2 — Data Layer

**Goal**: Vector store can be built and queried.

1. `src/data/checkpoint.ts` — read/write checkpoint
2. `src/data/splitter.ts` — document chunking (from Tessera)
3. `src/data/vector-store.ts` — HNSWLib wrapper
4. `src/data/ingest.ts` — add documents (from Tessera, MongoDB removed)
5. `src/data/retriever.ts` — cluster-aware retrieval
6. `scripts/01_scrape.ts` — Solodit scraper
7. `scripts/02_ingest.ts` — checkpoint-aware embedding pipeline
8. `scripts/03_cluster.ts` — k-means clustering
9. `scripts/setup.ts` — orchestrator

**Done when**: `npm run setup` completes and `npm run test:retriever` returns findings.

### Phase 3 — Analysis Core

**Goal**: Full audit pipeline works on a test contract.

1. `src/core/recon.ts` — AST parser (most complex, test heavily)
2. `src/data/loader.ts` — ZIP and path loaders
3. `src/skills/` — copy and adapt skill .md files
4. `src/core/agents.ts` — N-auditor parallel runner
5. `src/core/supervisor.ts` — synthesis
6. `src/core/report.ts` — report generation
7. `src/core/engine.ts` — AuditEngine orchestrator

**Done when**: `AuditEngine.audit([{ filename: "Vault.sol", content: ... }])` returns a populated report. Test against EtherStore (classic reentrancy vulnerable contract). Verify the reentrancy finding appears.

### Phase 4 — Interfaces

**Goal**: Both interfaces work. Same audit, different input/output.

1. `src/interfaces/cli.ts` — Commander CLI
2. `src/interfaces/web.ts` — Express + Multer
3. `public/index.html` — single page web UI

**Done when**:

- `npx sentinel audit ./test/contracts/ --output ./report.md` writes a valid report
- Upload to web UI downloads a valid report
- Both produce identical findings for the same contracts

---

## 10. CLI Flags

Full CLI interface:

```bash
# Basic usage
sentinel audit ./contracts/
sentinel audit ./vault.zip

# With options
sentinel audit ./contracts/ --output ./reports/vault-audit.md
sentinel audit ./contracts/ --auditors 2
sentinel audit ./contracts/ --auditors 3

# Override models at runtime (takes precedence over .env)
sentinel audit ./contracts/ \
  --auditor-1-provider ollama \
  --auditor-1-model deepseek-r1:8b \
  --auditor-2-provider gemini \
  --auditor-2-model gemini-2.0-flash \
  --supervisor-provider groq \
  --supervisor-model llama-3.3-70b-versatile

# Setup commands
sentinel setup            # run full setup
sentinel setup --download # download pre-built index instead of scraping
sentinel ingest           # re-run ingest (resumes from checkpoint)
sentinel cluster          # re-run clustering only
```

---

## 11. Environment Variables — Full Reference

```env
# ─── AUDITORS ────────────────────────────────────────────────────
# How many independent auditors to run in parallel (default: 1)
N_AUDITORS=1

# Auditor 1 (required if N_AUDITORS >= 1)
AUDITOR_1_PROVIDER=ollama        # ollama | gemini | groq | openai | anthropic
AUDITOR_1_MODEL=deepseek-r1:8b   # any model name valid for the provider
AUDITOR_1_API_KEY=               # leave empty for ollama

# Auditor 2 (required if N_AUDITORS >= 2)
AUDITOR_2_PROVIDER=gemini
AUDITOR_2_MODEL=gemini-2.0-flash
AUDITOR_2_API_KEY=

# Auditor 3 (required if N_AUDITORS >= 3)
AUDITOR_3_PROVIDER=groq
AUDITOR_3_MODEL=llama-3.3-70b-versatile
AUDITOR_3_API_KEY=

# ─── SUPERVISOR ──────────────────────────────────────────────────
SUPERVISOR_PROVIDER=ollama
SUPERVISOR_MODEL=deepseek-r1:8b
SUPERVISOR_API_KEY=

# ─── EMBEDDINGS (for RAG retrieval) ──────────────────────────────
EMBEDDING_PROVIDER=gemini        # gemini | ollama | openai
EMBEDDING_MODEL=gemini-embedding-001
EMBEDDING_API_KEY=               # your Gemini key

# If using ollama for embeddings (fully offline):
# EMBEDDING_PROVIDER=ollama
# EMBEDDING_MODEL=nomic-embed-text
# EMBEDDING_API_KEY=

# ─── LOCAL SERVICES ──────────────────────────────────────────────
OLLAMA_BASE_URL=http://localhost:11434

# ─── WEB SERVER ──────────────────────────────────────────────────
PORT=8000
ALLOWED_ORIGIN=http://localhost:3000

# ─── SOLODIT (for scraper) ────────────────────────────────────────
# Optional: improves rate limits. Get free at solodit.cyfrin.io
SOLODIT_API_KEY=

# ─── PATHS ───────────────────────────────────────────────────────
DATA_DIR=./data                  # where vectorstore + raw data lives
```

---

## 12. NPM Scripts

```json
{
  "scripts": {
    "dev": "tsx watch src/interfaces/web.ts",
    "build": "tsup src/interfaces/web.ts src/interfaces/cli.ts --format esm --clean",
    "start": "node dist/web.js",
    "sentinel": "tsx src/interfaces/cli.ts",

    "setup": "tsx scripts/setup.ts",
    "setup:download": "tsx scripts/setup.ts --download",
    "scrape": "tsx scripts/01_scrape.ts",
    "ingest": "tsx scripts/02_ingest.ts",
    "cluster": "tsx scripts/03_cluster.ts",

    "test": "vitest",
    "test:recon": "tsx scripts/test/recon.ts",
    "test:retriever": "tsx scripts/test/retriever.ts",
    "test:audit": "tsx scripts/test/audit.ts"
  }
}
```

---

## 13. Known Constraints and Mitigations

| Constraint                                                           | Mitigation                                                                                                                  |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Ollama model quality varies (3B vs 8B vs 70B)                        | README recommends deepseek-r1:8b minimum. Document model quality expectations.                                              |
| Gemini embedding rate limits during ingest                           | Checkpoint system. Batch size 50. Exponential backoff on 429.                                                               |
| `@solidity-parser/parser` edge cases in assembly blocks              | Mark assembly blocks in recon as "OPAQUE — manual review required". Never skip, never guess.                                |
| Dynamic dispatch (`IVault(addr).fn()`) cannot be statically resolved | Flag every dynamic call site explicitly in recon as "DYNAMIC — attacker-controlled if addr is user-input".                  |
| HNSWLib index is not thread-safe for concurrent writes               | Ingest is a single-threaded script, not a server route. No concurrent writes possible by design.                            |
| Supervisor receives large input for N=3 (9 agent outputs)            | Supervisor prompt caps agent output at 50 findings per agent before sending. Supervisor sees max 150 deduplicated into ~30. |
| LLM refuses to output JSON for certain prompts                       | `extractAndParseJSON` has 3 extraction strategies. If all fail, agent is marked FAILED and logged. Never crashes pipeline.  |

---

## 14. Codebase Reuse Map

### From Tessera (direct carry-over)

| Tessera File                     | New Location              | What Changes                                      |
| -------------------------------- | ------------------------- | ------------------------------------------------- |
| `backend/src/kb/02_splitter.ts`  | `src/data/splitter.ts`    | Chunk size: 800→500 for code                      |
| `backend/src/kb/04_ingest.ts`    | `src/data/ingest.ts`      | Remove MongoDB, add HNSWLib, add checkpoint calls |
| `backend/src/kb/05_retriever.ts` | `src/data/retriever.ts`   | Replace MongoDB query with cluster-aware HNSWLib  |
| `backend/src/agent/04_memory.ts` | `src/core/job-tracker.ts` | threadId→auditId, status enum, no MongoDB         |
| `backend/src/utils/env.ts`       | `src/utils/env.ts`        | New schema for N-auditor env vars                 |
| `backend/src/index.ts`           | `src/interfaces/web.ts`   | Keep Express skeleton, replace all routes         |
| `backend/src/controllers/kb.ts`  | (reference only)          | Pattern reused in web.ts upload handler           |

### From Plamen (MIT licensed, copy directly)

| Plamen File                                         | New Location                    | What Changes                                   |
| --------------------------------------------------- | ------------------------------- | ---------------------------------------------- |
| `agents/skills/evm/oracle-analysis/SKILL.md`        | `src/skills/oracle-analysis.md` | None                                           |
| `agents/skills/evm/token-flow-tracing/SKILL.md`     | `src/skills/token-flow.md`      | None                                           |
| `agents/skills/evm/flash-loan-interaction/SKILL.md` | `src/skills/flash-loan.md`      | None                                           |
| `agents/skills/evm/centralization-risk/SKILL.md`    | `src/skills/centralization.md`  | None                                           |
| `agents/skills/evm/zero-state-return/SKILL.md`      | `src/skills/zero-state.md`      | None                                           |
| `custom-mcp/solodit-scraper/solodit_mcp/scraper.py` | `scripts/01_scrape.ts`          | Python→TypeScript conversion                   |
| `agents/security-analyzer.md`                       | Supervisor system prompt        | Extract methodology, adapt to JSON output task |

### Net New (does not exist in either)

- Everything in `src/core/` except concepts
- `src/utils/llm.ts` — the generic invoke pattern
- `src/data/checkpoint.ts` — ingest resumability
- `src/data/vector-store.ts` — HNSWLib wrapper
- `scripts/03_cluster.ts` — k-means
- `scripts/setup.ts` — full setup orchestrator
- `src/interfaces/cli.ts` — Commander CLI
- `public/index.html` — web UI
- All three custom skill files: `logical-bugs.md`, `common-pitfalls.md`, `contextual.md`

---

## Quick Reference — What Goes Where

**You change the number of auditors** → `N_AUDITORS` in `.env` or `--auditors` CLI flag

**You want to add a new LLM provider** → Add one case to `buildModel()` in `models.ts`. Nothing else changes.

**You want to add a new skill / vulnerability class** → Add a `.md` file to `src/skills/`, register it in `agents.ts`. One line change.

**You want to test the recon parser** → `npm run test:recon` against any .sol file

**The ingest crashed** → `npm run ingest` — resumes from checkpoint automatically

**You want to re-cluster without re-ingesting** → `npm run cluster`

**Something is failing silently** → check `SENTINEL_LOG_LEVEL=debug` in `.env`, every stage logs its input/output at debug level

---

_End of Blueprint. When ready to build: start Phase 1, file by file._
