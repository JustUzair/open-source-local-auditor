# SentinelAI: Blueprint Update 2 — Iterative Local Audit Engine

> Follows BLUEPRINT_UPDATE_1.md (local-first stack, Ollama, Qwen3.5, HNSWLib RAG).
> The concrete build spec derived from this ideation lives in `SENTINELAI_IMPL_SPEC.md`.

---

## What Problem This Solves

After establishing the local-first stack (Update 1), two issues remained:

**Issue 1 — AST bottleneck.** The original blueprint used `@solidity-parser/parser` to build a deterministic call graph before handing context to auditors. This was Solidity-only and contradicted the project's core asset: a language-agnostic RAG database of 5,000+ findings spanning Solidity, Rust, Move, and more. Using an AST parser actively prevented the system from being the multi-language auditor it was designed to be.

**Issue 2 — Context window ceiling.** A local model with a 32k–64k context cannot hold a large protocol in one call. Cloud models solve this by spending enormous amounts on KV cache memory. The question was whether we could match their _reasoning quality_ locally without their token budget.

The honest answer to that second question required first understanding what cloud LLMs actually do.

---

## What Cloud LLMs Actually Do (and Do Not Do)

They mostly just paste tokens in. Claude Opus with 200k context, Gemini with 1M — the architecture is the same transformer, just with massive KV cache. There is no internal multi-pass reasoning magic. The model reads left-to-right, once, and produces findings. The cost scales quadratically with context length, which is why it is expensive.

The counterintuitive finding from research: **long context performance degrades.** The "lost in the middle" problem is well-documented — models pay systematically less attention to content in the middle of very long contexts. A 200k context audit of 80 files may be _worse_ for subtle logic bugs than a focused 40k audit of the 20 highest-priority files, because attention is spread thin.

This reframes the local model disadvantage as a partial advantage: **focused attention on the right files beats distracted attention on all files.** The gap is real for protocols where the critical bug spans two distant, unrelated files. For everything else — which is most audits — a well-constructed 64k context window with the right files selected is competitive with cloud.

---

## The Strategy

| Dimension            | Blueprint v1                   | Blueprint v2                                    |
| :------------------- | :----------------------------- | :---------------------------------------------- |
| Recon method         | AST call graph (Solidity only) | LLM-generated Protocol Map (any language)       |
| Context strategy     | Single pass, truncated         | Adaptive iterative passes with token budget     |
| Cross-file awareness | AST edges                      | Protocol Map + suspicion propagation            |
| Language support     | Solidity                       | Solidity, Rust, Move, Go, Python, TS            |
| Loader output        | `SolidityFile[]`               | `SourceFile[]` with language + attack score     |
| Pass count           | Fixed (1 or 2)                 | Adaptive (1–N, stops when coverage is complete) |
| Thinking mode        | Not used                       | Qwen3.5 extended thinking, selectively enabled  |

---

## 1. The Protocol Map

The AST gave us: "function A calls function B" — deterministic, brittle, Solidity-only.

The Protocol Map gives us the same information through a different mechanism: the local LLM reads each file in a fast Phase 1 pass (`temperature: 0`, `num_predict: 256`, `num_ctx: 8192`) and outputs a structured summary. A 20-file protocol with 50,000 tokens of code becomes a 2,000-token map:

```
PROTOCOL MAP — Protocol (12 files · solidity)
══════════════════════════════════════════════
[contracts/Vault.sol] score:0.85
  What it does: Manages user deposits and routes yield to Strategy.sol.
  Entry points: deposit(), withdraw(uint256), rebalance()
  Calls into: Strategy.sol, PriceOracle.sol

[contracts/Strategy.sol] score:0.72
  What it does: Executes yield strategies on external DeFi protocols.
  Entry points: execute(bytes), harvest()
  Calls into: ExternalProtocol (address, untyped)
══════════════════════════════════════════════
```

This map is prepended to _every_ auditor call across _every_ pass. Every agent has global codebase awareness regardless of which files it is currently reading at full depth. The map is also where suspicion annotations accumulate between passes.

`src/types/recon.ts` and `@solidity-parser/parser` are dropped. The Protocol Map replaces `ReconContext` in the type system.

---

## 2. Iterative Passes — Replacing Fixed 2-Pass

The previous spec described a fixed 2-pass structure: Pass 1 (breadth), Pass 2 (targeted re-audit). The updated engine runs an **adaptive loop** that stops when the work is done — not when a hardcoded pass count is reached.

### How the loop works

```
While passNumber < MAX_AUDIT_PASSES:
  passNumber++

  If pass 1:
    Build batches covering highest-attack-score files within token budget
  Else:
    Build batches covering: (a) suspicion targets not yet seen, (b) unseen high-score files
    If no batches: stop — nothing new to audit

  For each batch:
    Run auditor(s) with: Protocol Map + RAG + batch code
    Collect findings + suspicion notes

  Filter suspicion notes by confidence threshold
  Inject propagated suspicions into Protocol Map (annotated as ⚠ markers)

  If no suspicions propagated AND all high-score files seen: stop early
```

For a **small protocol** (fits in one 64k batch): one pass covers everything. The loop exits after Pass 1 because there are no unseen files and likely no suspicions worth chasing. Single-call audit, full context.

For a **medium protocol** (2–3 batches): Pass 1 covers the highest-score files. Pass 2 covers the remainder plus any suspicion targets from Pass 1. Usually done in 2 passes.

For a **large protocol** (many files): the loop continues until all attack-surface files have been seen at full content and no high-confidence suspicions remain. The Protocol Map accumulates annotations from each pass, so every subsequent pass operates with increasingly rich context. `MAX_AUDIT_PASSES` is the safety cap (default: 3).

### What each pass sees

Every pass receives the same Protocol Map prepended — but the map grows richer over time. By Pass 2, the auditor reading `Strategy.sol` for the first time can already see in the Protocol Map: "⚠ Suspicion [Pass 1, confidence:0.9]: `_harvest()` invoked before `balanceOf` update in `Vault.sol` — check reentrancy." It enters the deep audit already knowing what to look for.

This is how human senior auditors work: build a mental model of the whole system first, then deep-dive on the dangerous parts with that model intact.

---

## 3. Suspicion Propagation and Confidence Thresholding

Suspicion notes are the mechanism by which early passes inform later ones.

An auditor emits a suspicion when it notices something in its current batch that implicates a _different_ file it cannot currently read at full depth:

```json
{
  "targetFile": "Strategy.sol",
  "targetFunction": "_harvest()",
  "reason": "called from Vault.withdraw() before balanceOf is decremented — reentrancy surface with external callback",
  "confidence": 0.9
}
```

**The confidence threshold is the primary guard against hallucination compounding.**

Without it: a weak suspicion from Pass 1 triggers a focused Pass 2 call. If that call also produces a weak suspicion (the model is pattern-matching noise), Pass 3 focuses on another red herring. Error compounds across passes.

With a threshold of 0.7: only notes where the model stated a concrete, traceable reason propagate. The hard rule in the Modelfile reinforces this — suspicions must never use "could potentially", "might be", or "may". If the model cannot state _exactly_ what is wrong and _exactly_ why, it does not emit the note.

All notes (including those below threshold) are stored in `debug.allSuspicionNotes` for transparency and post-audit review.

---

## 4. Thinking Mode — Qwen3.5 Extended Reasoning

Qwen3.5's extended thinking generates chain-of-thought reasoning tokens before producing output. The model works through the code before committing to findings:

```
[thinking: "the _harvest() function is called at line 84 before balanceOf is updated
at line 91... and the Protocol Map shows Vault.withdraw() calls this... so a
malicious Strategy could re-enter withdraw() during the harvest callback with
stale balances... that's a concrete reentrancy surface, emitting High finding"]
→ [findings output]
```

This reasoning multiplier is significant for subtle multi-step bugs. It is enabled selectively rather than universally, because it consumes approximately 6,000 extra tokens per call (thinking tokens are generated but not returned to the caller — they must be budgeted).

**When thinking is enabled:**

- Always on suspicion re-audit batches (targeted, highest value, worth the cost)
- On Pass 1 for small protocols (single batch, highest leverage point)
- Off for broad continuation passes on large protocols (breadth over depth)

The `THINKING_ENABLED` env var is the global switch. The engine's `shouldEnableThinking()` function makes the per-call decision based on pass number, batch type, and protocol size.

---

## 5. Attack Surface Scoring — Replacing the AST Recon

The original `ReconContext` computed reentrancy surfaces and call graphs deterministically from the AST. That computation is replaced by two cheaper mechanisms:

**File-level scoring** (in `loader.ts`): language-agnostic regex heuristics score each file 0.0–1.0 based on the presence of value-handling patterns, external call patterns, access control patterns, and custom math. High-score files are audited first and at full content. Low-score files (interfaces, libraries, constants) are represented by their Protocol Map summary only.

**Import graph extraction** (in `loader.ts`): import/use/require statements are parsed by regex across all languages. This gives a dependency graph without AST — used by `batcher.ts` to keep related files (e.g., `Vault.sol` and `Strategy.sol`) in the same batch.

These two together give the batcher enough information to construct sensible batches without any language-specific parser.

---

## 6. Token Budget Architecture

```
Total context window (e.g., 65,536 tokens)
├── Protocol Map:        ~2,000  (fixed — always present)
├── RAG findings:        ~4,800  (fixed — 6 × 800 tokens each)
├── Suspicion context:     ~800  (fixed — FOCUS block for re-audit batches)
├── Thinking buffer:     ~6,000  (only when thinking=ON)
├── Output buffer:       ~4,096  (reserved for findings JSON)
└── Code budget:        ~47,840  (thinking ON) / ~53,840 (thinking OFF)
```

At thinking OFF with 64k context: approximately 215,000 characters of code per batch. Most DeFi protocols (under 80 files) fit in a single batch — one pass, full coverage, zero truncation.

At 32k context: approximately 80,000 characters per batch. This comfortably covers the core contracts of most protocols; peripheral files (libraries, interfaces) are handled via their Protocol Map summaries.

---

## 7. The Loader: Unified and Language-Agnostic

`loadProtocol(input: string)` accepts either a directory path or a zip file. Both paths produce `SourceFile[]` — the same type, the same downstream pipeline.

`SourceFile` replaces `SolidityFile`. It carries: path, content, detected language, character count, attack score, and import list. All downstream components (cartographer, batcher, engine) consume `SourceFile[]` without knowing or caring about the input format.

---

## 8. Honest Assessment: Where Gaps Remain

The approach is sound and practical for the majority of DeFi protocol audits. One gap is worth documenting honestly:

**Cross-batch spanning vulnerabilities.** A bug whose exploit path requires simultaneously understanding File A (audited in batch 1, Pass 1) and File C (audited in batch 2, Pass 2) at the same time is harder to catch than it would be with infinite context. The Protocol Map partially mitigates this — Pass 2's auditor reading File C can see File A's entry in the map — but this is less reliable than having both files at full content in the same call.

In practice, these cross-batch spanning bugs are rare. Most serious vulnerabilities are concentrated in a small number of high-attack-score files that share an import cluster and therefore end up in the same batch. The scoring + import-graph grouping in `batcher.ts` is specifically designed to keep interacting contracts together.

The suspicion propagation mechanism is the secondary mitigation: if the Pass 1 auditor reading File A notices something that implicates File C, it emits a high-confidence suspicion. Pass 2 then reads File C with that suspicion in the Protocol Map — maximally focused, with full context on the lead.

---

## 9. Updated Confidence Math

Blueprint v1 defined confidence as:

$$C = \frac{\sum_{i=1}^{N} A_i \cdot w_i}{N}$$

where $A_i = 1$ if auditor $i$ flagged the bug, and $w_i = 1.0$ for Pass 1 findings.

Update 2 extends the weight to reflect pass context:

$$w_i = \begin{cases} 1.0 & \text{Pass 1 (breadth)} \\ 1.3 & \text{Pass 2+ continuation (more context in map)} \\ 1.6 & \text{Pass N targeted re-audit (focused + suspicion-primed)} \end{cases}$$

A finding confirmed in a targeted re-audit — where the auditor entered with a specific suspicion and full Protocol Map context — carries more evidential weight than one found incidentally in a broad first pass. The supervisor uses these weights when deduplicating and scoring final findings.

---

## 10. Next Steps for the Build

Ordered by dependency:

1. `src/types/protocol.ts` — new type definitions (no dependencies)
2. `src/data/loader.ts` — requires `protocol.ts` types only
3. `src/core/cartographer.ts` — requires `loader.ts` + `llm.ts`
4. `src/core/batcher.ts` — requires `protocol.ts` types
5. `src/data/retriever.ts` — signature update only
6. `src/types/audit.ts` — partial update (add `SuspicionNoteSchema`, update `AuditResult.debug`)
7. Modelfiles — add `SUSPICIONS:` block + thinking variant
8. `src/utils/llm.ts` — add `parseAuditorOutput()` split on `SUSPICIONS:`
9. `src/core/engine.ts` — new iterative orchestrator (all above must exist first)
10. `src/scripts/03_audit.ts` — CLI entry point
11. Drop `src/types/recon.ts` and `@solidity-parser/parser`
