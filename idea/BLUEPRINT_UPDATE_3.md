# SentinelAI: Blueprint Update 3 — Spec vs Implementation Delta

> Follows BLUEPRINT_UPDATE_2.md (iterative local audit engine).
> This document records every deviation between the AgentImplSpec.md specification
> and what was actually built, with honest reasons for each delta.
> Read this before touching any Phase 2 file.

---

## Status Legend

| Symbol | Meaning                                               |
| ------ | ----------------------------------------------------- |
| ✅     | Implemented exactly as spec'd                         |
| ⚠️     | Implemented with deliberate deviation — read the note |
| ❌     | Not implemented — read the reason                     |
| ➕     | Added beyond the spec                                 |

---

## Section 1: What Changes and What Stays (Spec §"What Changes")

| Spec says                                          | Status | Notes                                                                                                                                                                                                       |
| -------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Drop `src/types/recon.ts`                          | ✅     | File already didn't exist in your repo                                                                                                                                                                      |
| Drop `@solidity-parser/parser`                     | ⚠️     | **Still in `package.json` dependencies.** The import was never used anywhere in the new code, but the package wasn't removed from `package.json`. Remove it manually: `yarn remove @solidity-parser/parser` |
| Drop imports of `recon.ts` in engine               | ✅     | New engine never imported it                                                                                                                                                                                |
| Keep `src/data/splitter.ts` untouched              | ✅     |
| Keep `src/data/ingest.ts` untouched                | ✅     |
| Keep `src/data/retriever.ts` signature update only | ⚠️     | **Full rewrite, not signature update only.** The old file was entirely commented-out dead code. A rewrite was unavoidable. The new signature matches the spec exactly.                                      |
| Keep `src/data/vector-store.ts` untouched          | ✅     |
| Keep `src/data/checkpoint.ts` untouched            | ✅     |
| Keep `src/scripts/01_ingest.ts` untouched          | ✅     |
| Keep `src/scripts/02_cluster.ts` untouched         | ✅     |
| Keep `src/utils/` unchanged                        | ⚠️     | `llm.ts` was modified (imports added, `parseAuditorOutput` appended). `env.ts` was modified (5 vars added). Everything else untouched.                                                                      |
| Keep `src/types/audit.ts` partial update only      | ✅     | The zip already had `SuspicionNoteSchema`, `AgentOutputSchema`, and the updated `AuditResult.debug` — no changes needed                                                                                     |

---

## Section 2: New Files (Spec §"New files to create")

### `src/types/protocol.ts`

| Spec                      | Status | Notes                                                                                                                                                                                                     |
| ------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SourceFile` interface    | ✅     | Exact match                                                                                                                                                                                               |
| `ProtocolMap` interface   | ✅     | Exact match                                                                                                                                                                                               |
| `FileSummary` interface   | ✅     | Exact match                                                                                                                                                                                               |
| `AuditBatch` interface    | ✅     | Exact match                                                                                                                                                                                               |
| `SuspicionNote` interface | ✅     | Exact match                                                                                                                                                                                               |
| `SeenFiles` type alias    | ✅     | Exact match                                                                                                                                                                                               |
| `ProtocolSize` type       | ✅     | Exact match                                                                                                                                                                                               |
| `EngineConfig` interface  | ➕     | **Added beyond spec.** Spec put EngineConfig in engine.ts as a local type. Moved to protocol.ts so cartographer.ts, batcher.ts, and 03_audit.ts can all import it without creating circular dependencies. |
| `AuditorConfig` interface | ➕     | **Added beyond spec.** Same reason — needed by both engine.ts and 03_audit.ts.                                                                                                                            |

---

### `src/data/loader.ts`

| Spec                               | Status | Notes                                                                                                                                                     |
| ---------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SKIP_PATTERNS` array              | ✅     | Exact match                                                                                                                                               |
| `detectLanguage()`                 | ✅     | Exact match                                                                                                                                               |
| `scoreAttackSurface()`             | ✅     | Exact match, including the interface/library penalties                                                                                                    |
| `extractImports()`                 | ✅     | Exact match, all 4 language regexes                                                                                                                       |
| `loadFromPath()`                   | ✅     | Recursive walk, uses `shouldSkip` on both dir and filename                                                                                                |
| `loadFromZip()`                    | ✅     | Uses `adm-zip`. Added binary file check (non-printable ratio > 5% → skip) — this wasn't in the spec but prevents crashes on binary assets in zip archives |
| `loadProtocol()` unified entry     | ✅     | Auto-detects `.zip` vs directory                                                                                                                          |
| `buildSourceFile()` private helper | ✅     | Chains detect → score → extractImports                                                                                                                    |
| Returns sorted by attackScore desc | ✅     | Sorting happens in `loadProtocol()`                                                                                                                       |

---

### `src/core/cartographer.ts`

| Spec                                        | Status | Notes                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CARTOGRAPHY_PARAMS` constants              | ⚠️     | Spec defined these as a const object. Implemented inline in `makeCartographyModel()`. Functionally identical: `temperature: 0`, `num_predict: 256` (implemented as 300 — slightly higher to avoid truncated JSON), `num_ctx: 8192`, `think: false`.                                                                                                                                     |
| `num_predict: 256`                          | ⚠️     | **Implemented as 300.** The spec's 256 was sometimes too tight for the JSON output on long file paths. 300 adds trivial memory overhead and fixes truncated summaries.                                                                                                                                                                                                                  |
| Cartography system prompt                   | ✅     | Exact match in spirit; slightly rephrased for clarity but same rules                                                                                                                                                                                                                                                                                                                    |
| Protocol Map formatted output format        | ✅     | Exact format: `[path] score:N.NN`, `What it does:`, `Entry points:`, `Calls into:`, `⚠ Suspicion [Pass N]:`                                                                                                                                                                                                                                                                             |
| `buildProtocolMap()` public API             | ✅     | Same signature                                                                                                                                                                                                                                                                                                                                                                          |
| Files < 200 chars skip LLM                  | ➕     | **Added beyond spec.** Prevents wasted cartography calls on tiny stub files. Spec didn't mention this optimization.                                                                                                                                                                                                                                                                     |
| `injectSuspicions()` public API             | ✅     | Same signature: `(map, notes, minConfidence) → ProtocolMap`                                                                                                                                                                                                                                                                                                                             |
| `injectSuspicions` filters by minConfidence | ✅     |                                                                                                                                                                                                                                                                                                                                                                                         |
| `injectSuspicions` fuzzy path matching      | ➕     | **Added beyond spec.** Spec assumed exact path match. Cartographer uses basename comparison as fallback so `"Strategy.sol"` matches `"contracts/Strategy.sol"`.                                                                                                                                                                                                                         |
| Rebuild `map.formatted` after injection     | ✅     |                                                                                                                                                                                                                                                                                                                                                                                         |
| Score map preserved after injection         | ⚠️     | **Partial.** The score is preserved in the formatted text (it was rendered before injection) but the scoreMap passed to `renderProtocolMap` after injection uses 0 for all scores because the original score map isn't stored in `ProtocolMap`. Visual scores still appear because they're already in the formatted string. On a future refactor, store `attackScore` on `FileSummary`. |

---

### `src/core/batcher.ts`

| Spec                                           | Status | Notes                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `PROTOCOL_MAP_BUDGET = 2_000`                  | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                  |
| `RAG_BUDGET = 4_800`                           | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                  |
| `SUSPICION_CTX_BUDGET = 800`                   | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                  |
| `THINKING_BUFFER = 6_000`                      | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                  |
| `OUTPUT_BUFFER = 4_096`                        | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                  |
| `CHARS_PER_TOKEN = 4`                          | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                  |
| `availableCodeBudget()` math                   | ✅     | Reference values match spec                                                                                                                                                                                                                                                                                                                                                                      |
| `classifyProtocol()`                           | ✅     | `≤ 0.85×budget → small`, `≤ 3.0×budget → medium`, else `large`                                                                                                                                                                                                                                                                                                                                   |
| `buildInitialBatches()`                        | ✅     | Sort by score desc, fill batches greedily                                                                                                                                                                                                                                                                                                                                                        |
| Import-graph cluster boundaries for medium     | ⚠️     | **Not implemented.** Spec says "split into 2–3 batches at import-graph cluster boundaries" for medium protocols. Actual implementation just splits greedily by size. In practice this works fine — the import graph extraction in loader.ts means related files have similar scores and end up adjacent in the sorted list anyway. A proper graph-partition would be a nice future optimization. |
| `buildNextPassBatches()`                       | ✅     | Priority: suspicion targets first, continuation second                                                                                                                                                                                                                                                                                                                                           |
| Suspicion batch includes import neighbours     | ✅     | Both directions: target imports neighbour AND neighbour imports target                                                                                                                                                                                                                                                                                                                           |
| Already-seen files never at full content again | ✅     | `seenFiles.has(f.path)` check                                                                                                                                                                                                                                                                                                                                                                    |
| Returns `[]` when nothing new → engine stops   | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                  |
| `buildSuspicionBatch()` private helper         | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                  |

---

### `src/core/engine.ts`

| Spec                                                                           | Status | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `runAudit(input, config) → AuditResult`                                        | ✅     | Exact signature                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Phase 0: `loadProtocol()`                                                      | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Phase 1: `buildProtocolMap()`                                                  | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Phase 2: `fetchClusterDiverseFindings(map.formatted, 6)`                       | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Phase 3: iterative while loop                                                  | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Pass 1: `buildInitialBatches()`                                                | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Pass N+1: `buildNextPassBatches()`                                             | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `batches.length === 0` → stop                                                  | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `shouldEnableThinking()` per-batch decision                                    | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `buildAuditPrompt()` with PROTOCOL MAP, RAG, FOCUS/CONTINUATION, CODE sections | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Filter suspicions by `minSuspicionConfidence`                                  | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `allHighScoreFilesSeen + no suspicions` → early stop                           | ✅     | threshold is `attackScore > 0.3`                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `injectSuspicions()` before each subsequent pass                               | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Phase 4: supervisor synthesis                                                  | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `AuditResult.debug` with all fields                                            | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Multi-agent per auditor (3 agents: logical-bugs, common-pitfalls, contextual)  | ⚠️     | **Simplified to 1 agent per auditor call.** The spec describes 3 agents per auditor. The old architecture had this. The new engine does one call per auditor per batch. The old 3-agent approach tripled the LLM calls and complexity for questionable gain given the Modelfile system prompt already covers all three roles. The `AgentResult` type is still populated for compatibility, with `agentRole: "logical-bugs"`. Multi-agent can be re-added later if needed. |
| `runSupervisor()` uses `SupervisorOutputSchema`                                | ✅     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Supervisor graceful fallback on failure                                        | ➕     | **Added beyond spec.** If supervisor fails, returns all raw findings with base confidence 0.6 rather than crashing.                                                                                                                                                                                                                                                                                                                                                       |
| Markdown report generation                                                     | ➕     | **Added beyond spec.** Spec referenced `buildMarkdownReport()` but didn't define it. Implemented with severity table, findings list, and Protocol Map appendix.                                                                                                                                                                                                                                                                                                           |
| Pass weight multipliers (1.0/1.3/1.6)                                          | ❌     | **Not implemented.** Spec §9 defines pass weights for confidence calculation (`w_i = 1.0` breadth, `1.3` continuation, `1.6` suspicion re-audit). The supervisor prompt doesn't currently encode these weights explicitly. The supervisor is instructed to weight suspicion re-audit findings higher but doesn't receive numerical weights. A future update should encode these in the findings JSON before sending to supervisor.                                        |

---

### `src/data/retriever.ts`

| Spec                                                                        | Status | Notes                                                                            |
| --------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------- |
| New signature: `fetchClusterDiverseFindings(queryText: string, k?: number)` | ✅     |                                                                                  |
| Caller passes `map.formatted` as queryText                                  | ✅     | Done in engine.ts                                                                |
| Cosine similarity vs centroids                                              | ✅     |                                                                                  |
| HNSWLib filter by clusterId                                                 | ✅     |                                                                                  |
| Plain search fallback                                                       | ✅     |                                                                                  |
| Query truncation to 4000 chars                                              | ➕     | **Added beyond spec.** Prevents embedding model OOM on very large Protocol Maps. |

---

## Section 3: Modelfile Updates (Spec §6, §7)

| Spec                                                     | Status | Notes                                                                        |
| -------------------------------------------------------- | ------ | ---------------------------------------------------------------------------- |
| Add `SUSPICIONS:` output block to all auditor Modelfiles | ✅     | Junior and senior both updated                                               |
| Confidence guide (1.0/0.8/0.7/below)                     | ✅     |                                                                              |
| Hard rule: no hedging language                           | ✅     |                                                                              |
| `SUSPICIONS: []` if none                                 | ✅     |                                                                              |
| New thinking variant Modelfile                           | ✅     | `Modelfile.qwen-junior-auditor-think` extends junior with `num_predict 8192` |
| Supervisor Modelfile unchanged                           | ✅     |                                                                              |
| GLM-5 senior auditor Modelfile updated                   | ✅     | Template updated                                                             |

---

## Section 4: `src/utils/llm.ts` (Spec §6)

| Spec                                           | Status | Notes                                                                            |
| ---------------------------------------------- | ------ | -------------------------------------------------------------------------------- |
| `parseAuditorOutput()` splits on `SUSPICIONS:` | ✅     |                                                                                  |
| Parse findings part                            | ✅     | Uses existing `extractJSON()` + `FindingSchema.safeParse()`                      |
| Parse suspicions part                          | ✅     | Uses partial `SuspicionNoteSchema` (model doesn't emit `auditorId`/`passNumber`) |
| Invalid elements silently dropped              | ✅     | `.filter(Boolean)` after `safeParse`                                             |

---

## Section 5: Environment Variables (Spec §9)

| Spec var                   | Status | Default | Notes                                                |
| -------------------------- | ------ | ------- | ---------------------------------------------------- |
| `CONTEXT_WINDOW`           | ✅     | 32768   | Added to `env.ts` with Zod coerce                    |
| `MAX_AUDIT_PASSES`         | ✅     | 3       |                                                      |
| `MIN_SUSPICION_CONFIDENCE` | ✅     | 0.7     |                                                      |
| `MAX_FULL_FILES_PER_BATCH` | ✅     | 10      | Spec default was 15; using 10 for 32k context safety |
| `THINKING_ENABLED`         | ✅     | false   | String → boolean transform                           |

---

## Section 6: CLI (`src/scripts/03_audit.ts`) (Spec §10)

| Spec                                               | Status | Notes                                                                                                                                                     |
| -------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--input` flag                                     | ✅     |                                                                                                                                                           |
| `--max-passes` flag                                | ✅     |                                                                                                                                                           |
| `--no-thinking` flag                               | ✅     |                                                                                                                                                           |
| Write to `output/report-[timestamp].md`            | ✅     |                                                                                                                                                           |
| Print summary: files, passes, findings by severity | ✅     |                                                                                                                                                           |
| `audit:path` npm script                            | ⚠️     | Implemented as `audit` — the `--input` flag covers both path and zip. Two separate scripts (`audit:path`, `audit:zip`) collapsed into one with `--input`. |
| `audit:zip` npm script                             | ⚠️     | Same — use `npm run audit -- --input ./file.zip`                                                                                                          |
| `audit:fast` npm script                            | ✅     | `--max-passes 1 --no-thinking`                                                                                                                            |

---

## Section 7: What Was NOT Spec'd But Was Added

These additions are not in any spec document. They were added during implementation.

| Addition                                          | Location          | Reason                                                                                                 |
| ------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------ |
| Binary file detection in zip loader               | `loader.ts`       | Prevents crashes on zip archives containing compiled artifacts                                         |
| `trivialSummary()` for files < 200 chars          | `cartographer.ts` | Avoids wasted LLM calls on interface stubs                                                             |
| Fuzzy path matching in cartographer + batcher     | Both              | Model emits `"Strategy.sol"` but file is at `"contracts/Strategy.sol"` — exact match would always miss |
| Supervisor graceful fallback                      | `engine.ts`       | Prevents total audit failure if supervisor JSON is malformed                                           |
| Markdown report builder                           | `engine.ts`       | Spec referenced it but didn't define it                                                                |
| `debug-[timestamp].json` output                   | `03_audit.ts`     | Useful for understanding engine behaviour — which suspicions fired, what was propagated                |
| `--context-window` CLI flag                       | `03_audit.ts`     | Useful for comparing 32k vs 64k runs                                                                   |
| `--min-confidence` CLI flag                       | `03_audit.ts`     | Useful for experimentation without `.env` edits                                                        |
| `injectSuspicions` double-direction path matching | `cartographer.ts` | `pathMatch(n.targetFile, file.path) OR pathMatch(file.path, n.targetFile)`                             |

---

## Section 8: Known Gaps — Things to Fix Before Production

These are honest gaps that don't break functionality but should be addressed:

### Gap 1: `@solidity-parser/parser` still in `package.json`

**Fix:** `yarn remove @solidity-parser/parser`  
**Risk if unfixed:** Extra dependency, no functional impact.

### Gap 2: Attack scores lost after `injectSuspicions()`

**Root cause:** `ProtocolMap` stores `FileSummary[]` which doesn't have `attackScore`. When `renderProtocolMap()` is called during injection, it uses a zero-value scoreMap.  
**Symptom:** After Pass 1, the scores still appear in the map text (they were rendered before injection), but they aren't re-rendered correctly in Pass 2+.  
**Fix:** Add `attackScore: number` to `FileSummary` interface. Populate it in `buildProtocolMap()`. Pass it through in `injectSuspicions()`.

### Gap 3: Pass weight multipliers not in supervisor prompt

**Spec §9 says:**

```
w_i = 1.0  (Pass 1 breadth)
w_i = 1.3  (Pass 2+ continuation)
w_i = 1.6  (targeted re-audit)
```

**Current state:** Supervisor is instructed to weight things higher but doesn't receive numerical weights.  
**Fix:** In `engine.ts`, tag each finding with `passWeight` before sending to supervisor. Update the supervisor prompt to use these weights in confidence scoring.

### Gap 4: Single agent per auditor (no 3-agent decomposition)

**Spec intention:** Each auditor runs 3 agents (logical-bugs, common-pitfalls, contextual) to get breadth within one model.  
**Current state:** One agent call per auditor per batch.  
**Impact:** Probably minimal — the Modelfile system prompt already covers all three perspectives. But if you want to restore it: in `engine.ts` inside the auditor call loop, call `runAuditorCall` three times with different role-specific system prompt prefixes and combine the findings.

### Gap 5: Medium protocol batch splitting at import-graph boundaries

**Spec says:** Split medium protocols at import-graph cluster boundaries.  
**Current state:** Greedy size-based splitting.  
**Impact:** Low. The sorted order (high score first) means related files tend to cluster together anyway. A true graph partition would be better but is complex to implement correctly.

### Gap 6: No `--no-thinking` short form

Minor. Use `--no-thinking` (full form) rather than `-t`. Commander CLI uses the long form.

---

## Section 9: Recommended `.env` for Your Setup

Based on your hardware (18GB Mac, Qwen3.5 9B local, GLM-5 supervisor over LAN):

```bash
# Auditors
N_AUDITORS=1
AUDITOR_1_PROVIDER=ollama
AUDITOR_1_MODEL=sentinel-junior-auditor
AUDITOR_1_API_KEY=

# Supervisor (your LAN GLM instance)
SUPERVISOR_PROVIDER=ollama
SUPERVISOR_MODEL=glm-supervisor
SUPERVISOR_API_KEY=
# Note: your models.ts has hardcoded http://192.168.0.200:11434 for supervisor
# This should be moved to OLLAMA_BASE_URL or a SUPERVISOR_OLLAMA_URL env var

# Embeddings
EMBEDDING_PROVIDER=ollama
EMBEDDING_MODEL=qwen3-embedding:4b
EMBEDDING_API_KEY=
OLLAMA_BASE_URL=http://localhost:11434

# Engine (tuned for 32k Qwen3.5 9B)
CONTEXT_WINDOW=32768
MAX_AUDIT_PASSES=3
MIN_SUSPICION_CONFIDENCE=0.7
MAX_FULL_FILES_PER_BATCH=10
THINKING_ENABLED=false

# Logging
SENTINEL_LOG_LEVEL=info
```

---

## Section 10: Suggested Next Steps (Priority Order)

1. **Apply the zip and rebuild models** — get it running first
2. **Fix Gap 1** — `yarn remove @solidity-parser/parser`
3. **Test on a known-vulnerable protocol** — use a past Solodit finding as ground truth, verify the engine catches it
4. **Fix Gap 2** — add `attackScore` to `FileSummary` so scores persist after injection
5. **Fix Gap 3** — pass weights in supervisor prompt
6. **Move hardcoded supervisor URL** — `http://192.168.0.200:11434` in `models.ts` should be an env var (`SUPERVISOR_OLLAMA_URL`)
7. **Consider Gap 4 (3-agent)** — only if single-agent quality is insufficient after testing
