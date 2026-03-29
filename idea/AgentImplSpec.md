# SentinelAI — Implementation Spec: Local-First Iterative Audit Engine

> **For the dev agent.** Read BLUEPRINT.md, BLUEPRINT_UPDATE_1.md, BLUEPRINT_UPDATE_2.md in order first.
> This spec supersedes all previous references to `recon.ts`, `@solidity-parser/parser`, `SolidityFile[]`,
> and the fixed 2-pass engine described in earlier documents.

---

## What Changes and What Stays

### Drop entirely

- `src/types/recon.ts` — all AST types (`FunctionInfo`, `ContractInfo`, `CallEdge`, `ReentrancySurface`, `ReconContext`)
- `@solidity-parser/parser` — remove from `package.json`
- Any imports of `recon.ts` in the engine orchestrator

### Keep as-is (do not touch)

- `src/data/splitter.ts` — Solodit ingestion + markdown parser
- `src/data/ingest.ts` — HNSWLib batch add
- `src/data/retriever.ts` — cluster-diverse search (signature update only, see §5)
- `src/data/vector-store.ts` — HNSWLib local store
- `src/data/checkpoint.ts`
- `src/scripts/01_ingest.ts`
- `src/scripts/02_cluster.ts`
- `src/utils/` — all utilities unchanged
- `src/types/audit.ts` — partial update only (see §1)

### Modelfiles — two targeted changes only

- Add `SUSPICIONS:` output block to OUTPUT FORMAT in all auditor Modelfiles (§6)
- Add thinking mode variant Modelfile (§7)
- Supervisor Modelfile: unchanged

### New files to create

- `src/types/protocol.ts` — replaces `recon.ts`
- `src/data/loader.ts` — language-agnostic file loader (zip + path)
- `src/core/cartographer.ts` — Protocol Map generation
- `src/core/batcher.ts` — token-budget batching + iterative pass tracking
- `src/core/engine.ts` — new orchestrator with iterative pass loop

---

## 1. New Types: `src/types/protocol.ts`

```typescript
/**
 * A single source file from the protocol under audit.
 * Language-agnostic — replaces SolidityFile entirely.
 */
export interface SourceFile {
  /** Relative path within the project, e.g. "contracts/Vault.sol" */
  path: string;
  content: string;
  /** Detected from extension: "solidity" | "rust" | "move" | "go" | "typescript" | "python" | "other" */
  language: string;
  /** Character count. Used for token estimation (1 token ≈ 4 chars). */
  size: number;
  /**
   * Attack surface score 0.0–1.0.
   * Computed by scoreAttackSurface() in loader.ts.
   * Drives batch ordering — highest score files audited first.
   */
  attackScore: number;
  /**
   * Paths of files this file imports/depends on.
   * Parsed from import/use/require statements by extractImports() in loader.ts.
   * Used to keep related files in the same batch.
   */
  imports: string[];
}

/**
 * A compressed, LLM-generated description of the entire protocol.
 * Fits in ~2k tokens regardless of protocol size.
 * Prepended to EVERY auditor call — global codebase awareness for each agent.
 * Enriched with suspicion annotations before each subsequent pass.
 */
export interface ProtocolMap {
  files: FileSummary[];
  /** Formatted text ready to inject into prompts. Rebuilt after each pass. */
  formatted: string;
}

export interface FileSummary {
  path: string;
  language: string;
  /** 1-2 sentence LLM-generated description of what this file does. */
  summary: string;
  /** Public/external callable functions, max 8. */
  entryPoints: string[];
  /** Cross-file/cross-contract dependencies (not stdlib). */
  externalDependencies: string[];
  /**
   * Suspicion annotations accumulated across all completed passes.
   * Rendered as "⚠ Suspicion [Pass N]: ..." in the formatted map.
   * Empty until Pass 1 completes.
   */
  suspicions: Array<{ passNumber: number; note: string }>;
}

/**
 * A group of files audited together in one LLM call.
 * Constructed by batcher.ts to stay within the token budget.
 */
export interface AuditBatch {
  batchId: string;
  /** Which audit pass this batch belongs to (1-indexed). */
  passNumber: number;
  /** Files included at full content (high attack score). */
  fullFiles: SourceFile[];
  /** Files included as summary-only (low attack score or budget overflow). */
  summarizedFiles: FileSummary[];
  /** Estimated total tokens: map + RAG + code. */
  estimatedTokens: number;
  /**
   * If true, this is a targeted re-audit of suspicion-flagged hotspots.
   * The prompt receives a FOCUS block with the specific suspicion reasons.
   */
  isSuspicionReaudit: boolean;
  /** Suspicion notes that triggered this batch (populated when isSuspicionReaudit=true). */
  triggeringSuspicions: SuspicionNote[];
}

/**
 * A follow-up flag emitted by an auditor alongside its findings.
 * Drives the next pass — targeted re-audit of the flagged file/function.
 *
 * Only notes with confidence >= MIN_SUSPICION_CONFIDENCE propagate.
 * This is the primary guard against hallucination compounding across passes.
 */
export interface SuspicionNote {
  targetFile: string;
  targetFunction?: string;
  /** Concrete reason — must describe what is wrong, not hedge. */
  reason: string;
  /**
   * 0.0–1.0. Emitted by the auditor itself.
   * 1.0 = certain this is a real vulnerability surface.
   * 0.7 = strong signal, concrete reason, worth a targeted re-audit.
   * 0.5 = worth a second look.
   * Notes below MIN_SUSPICION_CONFIDENCE are recorded but not propagated.
   */
  confidence: number;
  auditorId: string;
  passNumber: number;
}

/** Paths of files seen at full content across all completed passes. */
export type SeenFiles = Set<string>;

export type ProtocolSize = "small" | "medium" | "large";
```

### Updates to `src/types/audit.ts`

```typescript
// Add SuspicionNote schema for Zod validation
export const SuspicionNoteSchema = z.object({
  targetFile: z.string(),
  targetFunction: z.string().optional(),
  reason: z.string().min(10),
  confidence: z.number().min(0).max(1),
});

// Extend AgentOutputSchema
export const AgentOutputSchema = z.object({
  findings: z.array(FindingSchema),
  suspicions: z.array(SuspicionNoteSchema).optional().default([]),
});

// In AuditResult (ok: true branch), update debug:
debug: {
  protocolMap: ProtocolMap;
  allSuspicionNotes: SuspicionNote[];    // every note emitted, including discarded ones
  propagatedSuspicions: SuspicionNote[]; // notes that passed confidence threshold
  auditorResults: AuditorResult[];
  passCount: number;                     // actual passes completed
  protocolSize: ProtocolSize;
};
```

---

## 2. Loader: `src/data/loader.ts`

Accepts zip path OR directory path. Returns `SourceFile[]`. Same code path internally.

### File filter

```typescript
const SKIP_PATTERNS = [
  /node_modules/,
  /\.git\//,
  /\/test(s)?\//i,
  /\/mock(s)?\//i,
  /\/script(s)?\//i,
  /\/deploy\//i,
  /\/artifacts\//,
  /\/cache\//,
  /\/coverage\//,
  /\/dist\//,
  /\/build\//,
  /\.(json|md|txt|yaml|yml|toml|lock|env)$/i,
  /\.(png|jpg|svg|gif|wasm)$/i,
];
```

### Language detection

```typescript
function detectLanguage(filePath: string): string {
  if (filePath.endsWith(".sol")) return "solidity";
  if (filePath.endsWith(".rs")) return "rust";
  if (filePath.endsWith(".move")) return "move";
  if (filePath.endsWith(".go")) return "go";
  if (filePath.endsWith(".ts") || filePath.endsWith(".js")) return "typescript";
  if (filePath.endsWith(".py")) return "python";
  return "other";
}
```

### Attack surface scoring (language-agnostic regex, returns 0.0–1.0)

```typescript
function scoreAttackSurface(content: string): number {
  let score = 0;
  const c = content.toLowerCase();

  // Value handling — strongest signal
  if (
    /transfer|withdraw|deposit|balance|stake|unstake|claim|fee|reward|pay|send|mint|burn/.test(
      c,
    )
  )
    score += 0.3;

  // External calls / cross-contract interaction
  if (/\.call\b|delegatecall|\.invoke|cpi::|cross.chain|callback|hook/.test(c))
    score += 0.25;

  // Access control
  if (
    /onlyowner|onlyadmin|require.*msg\.sender|authority|role|permission|admin/.test(
      c,
    )
  )
    score += 0.15;

  // State mutation
  if (/mapping|storage\b|mut\s+\w|global\s+\w/.test(c)) score += 0.1;

  // Custom math / accounting
  if (/muldiv|wadmul|raymul|shares?|rate|index|price|oracle|twap/.test(c))
    score += 0.15;

  // Penalty: pure interfaces / traits / libraries
  if (/^interface\s+|\/\/.*SPDX.*interface|pub\s+trait\s+/m.test(content))
    score -= 0.2;
  if (/^library\s+\w+\s*\{/m.test(content) && score < 0.2) score -= 0.1;

  return Math.max(0, Math.min(1, score));
}
```

### Import extraction (language-agnostic, no AST)

```typescript
function extractImports(content: string): string[] {
  const imports: string[] = [];

  // Solidity
  for (const m of content.matchAll(
    /import\s+(?:\{[^}]+\}\s+from\s+)?["']([^"']+)["']/g,
  ))
    imports.push(m[1]);

  // Rust: mod vault;
  for (const m of content.matchAll(/^mod\s+(\w+)\s*;/gm)) imports.push(m[1]);

  // Move: use 0x1::vault::Vault;
  for (const m of content.matchAll(/use\s+[\w:]+::(\w+)/g)) imports.push(m[1]);

  // Go: import "github.com/org/pkg/vault"
  for (const m of content.matchAll(/import\s+(?:\w+\s+)?"([^"]+)"/g))
    imports.push(m[1]);

  return [...new Set(imports)];
}
```

### Public API

```typescript
export async function loadFromPath(dirPath: string): Promise<SourceFile[]>;
export async function loadFromZip(zipPath: string): Promise<SourceFile[]>;
/** Unified entry point — auto-detects zip vs directory. */
export async function loadProtocol(input: string): Promise<SourceFile[]>;
```

Both paths call a shared `buildSourceFile(relativePath, content)` that chains
`detectLanguage` → `scoreAttackSurface` → `extractImports`.

---

## 3. Cartographer: `src/core/cartographer.ts`

### Purpose

Phase 1 — fast cheap LLM pass generating the Protocol Map before auditing begins.
Each file processed individually. Thinking mode is OFF (structured extraction, not reasoning).

### Ollama parameters for cartography calls

```typescript
const CARTOGRAPHY_PARAMS = {
  temperature: 0,
  num_predict: 256,
  num_ctx: 8192,
  think: false,
};
```

### Cartography system prompt

```
You are a code indexer. Output ONLY valid JSON — no markdown, no preamble.

{
  "summary": "1–2 sentences describing what this module does",
  "entryPoints": ["functionName(argType)", ...],
  "externalDependencies": ["ContractOrModuleName", ...]
}

Rules:
- summary: ≤ 40 words, plain language
- entryPoints: public/external callable functions only, max 8
- externalDependencies: cross-file/cross-contract calls only, never stdlib
- When unsure, use empty arrays — do not guess
```

### Protocol Map formatted output

```
PROTOCOL MAP — ProtocolName (12 files · solidity)
══════════════════════════════════════════════════
[contracts/Vault.sol] score:0.85
  What it does: Manages user deposits and routes yield to Strategy.sol.
  Entry points: deposit(), withdraw(uint256), rebalance()
  Calls into: Strategy.sol, PriceOracle.sol
  ⚠ Suspicion [Pass 1, confidence:0.9]: _harvest() invoked before balanceOf update — check reentrancy

[contracts/Strategy.sol] score:0.72
  What it does: Executes yield strategies on external DeFi protocols.
  Entry points: execute(bytes), harvest()
  Calls into: ExternalProtocol (address, untyped)
══════════════════════════════════════════════════
```

Suspicion lines are absent on first generation. Added by `injectSuspicions()` before each subsequent pass.

### Public API

```typescript
/** Build the initial Protocol Map via per-file LLM calls. */
export async function buildProtocolMap(
  files: SourceFile[],
  config: EngineConfig,
): Promise<ProtocolMap>;

/**
 * Inject confidence-filtered suspicion notes and rebuild map.formatted.
 * Called after each pass before the next one begins.
 */
export function injectSuspicions(
  map: ProtocolMap,
  notes: SuspicionNote[],
  minConfidence: number,
): ProtocolMap;
```

---

## 4. Batcher: `src/core/batcher.ts`

### Token budget constants

```typescript
const PROTOCOL_MAP_BUDGET = 2_000; // tokens — fixed, always present
const RAG_BUDGET = 4_800; // tokens — fixed (6 findings × 800)
const SUSPICION_CTX_BUDGET = 800; // tokens — for the FOCUS block in re-audit batches
const THINKING_BUFFER = 6_000; // tokens — reserved when thinking mode is ON
const OUTPUT_BUFFER = 4_096; // tokens — reserved for findings output
const CHARS_PER_TOKEN = 4;

function availableCodeBudget(
  contextWindow: number,
  thinkingEnabled: boolean,
): number {
  return (
    contextWindow -
    PROTOCOL_MAP_BUDGET -
    RAG_BUDGET -
    SUSPICION_CTX_BUDGET -
    (thinkingEnabled ? THINKING_BUFFER : 0) -
    OUTPUT_BUFFER
  );
}

// Reference values (thinking OFF):
//   64k context → ~53,840 tokens ≈ 215,360 chars of code
//   32k context → ~20,272 tokens ≈  81,088 chars of code
// Reference values (thinking ON):
//   64k context → ~47,840 tokens ≈ 191,360 chars of code
//   32k context → ~14,272 tokens ≈  57,088 chars of code
```

### Protocol size classification

```typescript
export function classifyProtocol(
  files: SourceFile[],
  contextWindow: number,
  thinkingEnabled: boolean,
): ProtocolSize {
  const totalChars = files.reduce((s, f) => s + f.size, 0);
  const budgetChars =
    availableCodeBudget(contextWindow, thinkingEnabled) * CHARS_PER_TOKEN;

  if (totalChars <= budgetChars * 0.85) return "small"; // single batch, one pass
  if (totalChars <= budgetChars * 3.0) return "medium"; // 2–3 batches, 1–2 passes
  return "large"; // iterative multi-pass
}
```

### Pass 1 batch construction

```typescript
export function buildInitialBatches(
  files: SourceFile[],
  map: ProtocolMap,
  contextWindow: number,
  thinkingEnabled: boolean,
  maxFullFilesPerBatch: number,
): AuditBatch[];
```

Algorithm:

1. Sort files by `attackScore` descending.
2. `budgetChars = availableCodeBudget(...) * CHARS_PER_TOKEN`
3. Walk sorted files, add at full content until budget consumed or `maxFullFilesPerBatch` reached.
4. Remaining files with `attackScore > 0.3`: add as `FileSummary` (no extra tokens, already in map).
5. Remaining files with `attackScore <= 0.3`: omit.
6. `small`: single batch, everything in context.
7. `medium`: split into 2–3 batches at import-graph cluster boundaries.
8. `large`: batch covers top-N files by score; the rest are seen in subsequent passes.

### Pass N+1 batch construction (iterative continuation)

```typescript
export function buildNextPassBatches(
  files: SourceFile[],
  seenFiles: SeenFiles,
  propagatedSuspicions: SuspicionNote[],
  map: ProtocolMap,
  contextWindow: number,
  thinkingEnabled: boolean,
  maxFullFilesPerBatch: number,
  passNumber: number,
): AuditBatch[];
```

Algorithm:

1. Split files into: (a) suspicion targets not yet seen at full content, (b) unseen high-score files, (c) already seen.
2. **Suspicion re-audit batches first**: group each flagged file with its import-cluster neighbours. Set `isSuspicionReaudit: true`, populate `triggeringSuspicions`.
3. **Continuation batches next**: unseen files sorted by attack score filling remaining budget.
4. Already-seen files never appear at full content again.
5. Return `[]` if no unseen files remain and no suspicion targets exist → engine stops iterating.

---

## 5. Retriever: `src/data/retriever.ts`

One signature change, internals unchanged:

```typescript
// Before:
export async function fetchClusterDiverseFindings(
  files: SolidityFile[],
  k?: number,
): Promise<string>;

// After:
export async function fetchClusterDiverseFindings(
  queryText: string,
  k?: number,
): Promise<string>;
```

Caller passes `map.formatted` as `queryText`.

---

## 6. Auditor output: suspicion notes + confidence

### Modelfile OUTPUT FORMAT addition (all auditor Modelfiles)

Add this block after the findings JSON array in the OUTPUT FORMAT section:

```
After the findings array, on a new line output:

SUSPICIONS:
[
  {
    "targetFile": "Strategy.sol",
    "targetFunction": "_harvest()",
    "reason": "called from Vault.withdraw() before balanceOf is decremented — reentrancy surface with external callback",
    "confidence": 0.9
  }
]

If you have no suspicions output: SUSPICIONS: []

Confidence guide:
- 1.0 = certain this is a real vulnerability surface
- 0.8 = strong signal, concrete reason, worth targeted re-audit
- 0.7 = worth a second look, pattern is clear
- below 0.7 = do not emit — if you are not reasonably sure, omit it entirely

HARD RULE: a suspicion must state a CONCRETE reason traceable to specific code.
Never emit a suspicion using "could potentially", "might be", or "may".
If you cannot state concretely what is wrong and why, do not emit it.
```

### Parsing in `src/utils/llm.ts`

Split on `SUSPICIONS:` before Zod validation:

```typescript
function parseAuditorOutput(raw: string): {
  findings: Finding[];
  suspicions: SuspicionNote[];
} {
  const [findingsPart, suspicionsPart] = raw.split(/SUSPICIONS:\s*/);

  const findings = parseAndValidateFindings(findingsPart.trim());
  const suspicions = suspicionsPart
    ? parseAndValidateSuspicions(suspicionsPart.trim())
    : [];

  return { findings, suspicions };
}
```

### Confidence threshold filtering in `src/core/engine.ts`

```typescript
function filterSuspicions(
  notes: SuspicionNote[],
  minConfidence: number,
): SuspicionNote[] {
  return notes.filter(n => n.confidence >= minConfidence);
}
```

All notes are stored in `debug.allSuspicionNotes`. Only those passing the filter reach
`debug.propagatedSuspicions` and drive subsequent passes.

---

## 7. Thinking Mode

Qwen3.5's extended thinking (chain-of-thought reasoning tokens) improves finding
quality on subtle multi-step bugs. Enabled selectively to balance quality vs speed.

### When to enable

```typescript
export function shouldEnableThinking(
  passNumber: number,
  isSuspicionReaudit: boolean,
  protocolSize: ProtocolSize,
  globalThinkingEnabled: boolean,
): boolean {
  if (!globalThinkingEnabled) return false;
  // Always think on suspicion re-audit — targeted, high-value, worth the cost
  if (isSuspicionReaudit) return true;
  // Small protocols: think on Pass 1 (single batch, highest leverage point)
  if (passNumber === 1 && protocolSize === "small") return true;
  // Large protocols on later passes: think on the final pass once most context is accumulated
  return false;
}
```

### Ollama API parameters

```typescript
// In src/utils/llm.ts, extend the options object per-call:
if (thinkingEnabled) {
  options.think = true;
  options.num_predict = 8192; // thinking tokens + output
} else {
  options.num_predict = 4096;
}
```

The `THINKING_BUFFER` of 6,000 tokens in the budget constants accounts for thinking
tokens generated but not returned. This prevents context overflow.

### New Modelfile variant (thinking)

```dockerfile
# Modelfiles/auditors/Modelfile.qwen-junior-auditor-think
FROM sentinel-junior-auditor
PARAMETER num_predict 8192
# The think flag is injected per-call by the engine, not set here.
# This variant just extends the output token limit to accommodate thinking output.
```

---

## 8. Engine orchestrator: `src/core/engine.ts`

The engine runs a variable number of passes — not a fixed 2-pass structure.
It stops when: all files are seen + no suspicions propagate, OR `maxAuditPasses` is reached.

```typescript
export async function runAudit(
  input: string,
  config: EngineConfig,
): Promise<AuditResult> {
  // ── Phase 0: Load ──────────────────────────────────────────────────────
  const files = await loadProtocol(input);
  if (files.length === 0)
    return {
      ok: false,
      error: "No auditable source files found",
      stage: "load",
    };

  const protocolSize = classifyProtocol(
    files,
    config.contextWindow,
    config.thinkingEnabled,
  );
  logger.info(
    "engine",
    `Protocol: ${files.length} files · size: ${protocolSize}`,
  );

  // ── Phase 1: Semantic Cartography ──────────────────────────────────────
  const protocolMap = await buildProtocolMap(files, config);

  // ── Phase 2: RAG Retrieval ─────────────────────────────────────────────
  const ragContext = await fetchClusterDiverseFindings(
    protocolMap.formatted,
    6,
  );

  // ── Phase 3: Iterative Audit Loop ──────────────────────────────────────
  const allAuditorResults: AuditorResult[] = [];
  const allSuspicionNotes: SuspicionNote[] = [];
  let propagatedSuspicions: SuspicionNote[] = [];
  let currentMap = protocolMap;
  const seenFiles: SeenFiles = new Set();
  let passNumber = 0;
  const maxPasses = config.maxAuditPasses ?? 3;

  while (passNumber < maxPasses) {
    passNumber++;

    const batches =
      passNumber === 1
        ? buildInitialBatches(
            files,
            currentMap,
            config.contextWindow,
            config.thinkingEnabled,
            config.maxFullFilesPerBatch,
          )
        : buildNextPassBatches(
            files,
            seenFiles,
            propagatedSuspicions,
            currentMap,
            config.contextWindow,
            config.thinkingEnabled,
            config.maxFullFilesPerBatch,
            passNumber,
          );

    if (batches.length === 0) {
      logger.info(
        "engine",
        `Pass ${passNumber}: nothing new to audit — stopping`,
      );
      passNumber--;
      break;
    }

    logger.info("engine", `Pass ${passNumber}: ${batches.length} batch(es)`);
    const passNewSuspicions: SuspicionNote[] = [];

    for (const batch of batches) {
      const thinkingOn = shouldEnableThinking(
        passNumber,
        batch.isSuspicionReaudit,
        protocolSize,
        config.thinkingEnabled,
      );
      const prompt = buildAuditPrompt(
        currentMap,
        ragContext,
        batch,
        passNumber,
      );

      for (const auditorCfg of config.auditors) {
        const result = await runAuditor(auditorCfg, prompt, {
          thinkingEnabled: thinkingOn,
        });
        allAuditorResults.push(result);

        const notes = extractSuspicions(result, auditorCfg.id, passNumber);
        allSuspicionNotes.push(...notes);
        passNewSuspicions.push(...notes);
      }

      batch.fullFiles.forEach(f => seenFiles.add(f.path));
    }

    // Filter by confidence before propagating to next pass
    propagatedSuspicions = filterSuspicions(
      passNewSuspicions,
      config.minSuspicionConfidence,
    );

    logger.info(
      "engine",
      `Pass ${passNumber} complete: ${passNewSuspicions.length} suspicions · ` +
        `${propagatedSuspicions.length} propagated (threshold: ${config.minSuspicionConfidence})`,
    );

    // Stop if nothing to carry forward
    const allHighScoreFilesSeen = files
      .filter(f => f.attackScore > 0.3)
      .every(f => seenFiles.has(f.path));

    if (propagatedSuspicions.length === 0 && allHighScoreFilesSeen) {
      logger.info(
        "engine",
        `Pass ${passNumber}: full coverage, no leads — stopping`,
      );
      break;
    }

    // Enrich the Protocol Map with this pass's suspicions for next pass
    if (propagatedSuspicions.length > 0) {
      currentMap = injectSuspicions(
        currentMap,
        propagatedSuspicions,
        config.minSuspicionConfidence,
      );
    }
  }

  // ── Phase 4: Supervisor Synthesis ──────────────────────────────────────
  const supervisorReport = await runSupervisor(
    allAuditorResults,
    currentMap,
    config,
  );

  return {
    ok: true,
    report: supervisorReport,
    findings: supervisorReport.findings,
    debug: {
      protocolMap: currentMap,
      allSuspicionNotes,
      propagatedSuspicions,
      auditorResults: allAuditorResults,
      passCount: passNumber,
      protocolSize,
    },
  };
}
```

### Audit prompt builder

```typescript
function buildAuditPrompt(
  map: ProtocolMap,
  ragContext: string,
  batch: AuditBatch,
  passNumber: number,
): string {
  const sections: string[] = [
    `=== PROTOCOL MAP ===\n${map.formatted}`,
    `=== HISTORICAL VULNERABILITY PATTERNS (Solodit) ===\n${ragContext}`,
  ];

  if (batch.isSuspicionReaudit && batch.triggeringSuspicions.length > 0) {
    const focusBlock = batch.triggeringSuspicions
      .map(
        s =>
          `• ${s.targetFile}${s.targetFunction ? ` → ${s.targetFunction}` : ""}\n` +
          `  Reason: ${s.reason} [confidence: ${s.confidence}]`,
      )
      .join("\n\n");

    sections.push(
      `=== PASS ${passNumber} FOCUS — INVESTIGATE THESE SPECIFICALLY ===\n` +
        `${focusBlock}\n\n` +
        `These were flagged in a previous pass. Focus your audit here.\n` +
        `Use the Protocol Map to understand cross-file context.`,
    );
  } else if (passNumber > 1) {
    sections.push(
      `=== PASS ${passNumber} — CONTINUATION ===\n` +
        `These files were not yet audited at full depth.\n` +
        `The Protocol Map includes ⚠ suspicion markers from previous passes — treat them as high-priority targets.`,
    );
  }

  sections.push(`=== CONTRACT CODE ===\n${formatBatchCode(batch)}`);
  return sections.join("\n\n");
}
```

---

## 9. Environment variables (full additions to `.env`)

```bash
# ── Audit engine ─────────────────────────────────────────────────────────────

# Context window of your local model in tokens.
# Qwen3.5 tested at 32768; set to 65536 if using a larger model or variant.
CONTEXT_WINDOW=65536

# Maximum audit passes before the engine stops regardless of remaining suspicions.
# 1 = single pass (fastest, for quick checks)
# 3 = recommended default (covers most DeFi protocols completely)
MAX_AUDIT_PASSES=3

# Minimum confidence score for a suspicion note to propagate to the next pass.
# Range: 0.0–1.0
# 0.7 = recommended (concrete, reasonably confident leads only)
# 0.0 = propagate everything (risk: hallucination compounding on uncertain outputs)
# 1.0 = only propagate certainties (risk: missing real leads)
MIN_SUSPICION_CONFIDENCE=0.7

# Max files at full content per batch. Safety cap.
MAX_FULL_FILES_PER_BATCH=15

# Enable Qwen3.5 extended thinking (chain-of-thought reasoning tokens).
# true  = higher quality, ~2x slower per call, consumes ~6k extra tokens
# false = faster, still good quality for broad passes
# The engine enables thinking selectively (suspicion re-audit and small-protocol Pass 1).
# This env var is the global on/off switch.
THINKING_ENABLED=true
```

---

## 10. New npm scripts

```json
{
  "audit": "tsx src/scripts/03_audit.ts",
  "audit:path": "tsx src/scripts/03_audit.ts --input ./path/to/protocol",
  "audit:zip": "tsx src/scripts/03_audit.ts --input ./protocol.zip",
  "audit:fast": "tsx src/scripts/03_audit.ts --input ./protocol --max-passes 1 --no-thinking"
}
```

`03_audit.ts` CLI:

1. Parse `--input`, `--max-passes`, `--no-thinking` flags (override `.env`)
2. Call `loadProtocol(input)` → `runAudit(input, config)`
3. Write report to `output/report-[timestamp].md`
4. Print summary: files audited, passes run, findings by severity, suspicions propagated

---

## 11. What the Modelfiles do NOT need to change

The auditor system prompt (MAP → INTERROGATE → CROSS-FUNCTION-PASS) is correct as-is
and fully language-agnostic. Two targeted additions only:

1. **OUTPUT FORMAT section**: add the `SUSPICIONS:` block with confidence field (§6).
2. **New thinking variant**: `Modelfile.qwen-junior-auditor-think` extending base model
   with `num_predict 8192` (§7). The `think: true` flag is controlled per-call by the engine.

Supervisor Modelfile: unchanged.
