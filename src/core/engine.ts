/**
 * src/core/engine.ts — SentinelAI Iterative Audit Orchestrator
 *
 * Audit prompt structure (what each auditor model sees per call):
 *
 *   === PROTOCOL MAP ===
 *   PROTOCOL MAP — Vault (8 files · solidity)
 *   ════════════════════════════════════════════
 *   [contracts/Vault.sol] score:0.85
 *     What it does: Manages user deposits and routes yield to Strategy.sol.
 *     Entry points: deposit(), withdraw(uint256), rebalance()
 *     Calls into: Strategy.sol, PriceOracle.sol
 *     ⚠ Suspicion [Pass 1, confidence:0.9]: _harvest() before balanceOf update
 *
 *   === HISTORICAL VULNERABILITY PATTERNS (Solodit RAG) ===
 *   6 relevant vulnerability patterns from Solodit audit database:
 *   [Finding 1] Category: reentrancy_via_callback | Severity: High | ...
 *
 *   === PASS 2 FOCUS — INVESTIGATE THESE SPECIFICALLY ===       ← only on re-audit
 *   • Strategy.sol → _harvest()
 *     Reason: called before balanceOf is decremented [confidence: 0.9]
 *
 *   === CONTRACT CODE ===
 *   // ═══ contracts/Strategy.sol [solidity] ═══
 *   pragma solidity ^0.8.0; ...full file content...
 */

import { SystemMessage, HumanMessage } from "@langchain/core/messages";
import { ChatOllama } from "@langchain/ollama";
import { nanoid } from "nanoid";
import { loadProtocol } from "../data/loader.js";
import { buildProtocolMap, injectSuspicions } from "./cartographer.js";
import {
  classifyProtocol,
  buildInitialBatches,
  buildNextPassBatches,
} from "./batcher.js";
import { fetchClusterDiverseFindings } from "../data/retriever.js";
import { makeSupervisorModel, buildAuditorModel } from "../utils/models.js";
import { invokeWithSchema, extractJSON } from "../utils/llm.js";
import { parseAuditorOutput } from "../utils/llm.js";
import { env } from "../utils/env.js";
import { logger } from "../utils/logger.js";
import { AUDITOR_SYSTEM } from "./prompts.js";
import type {
  SourceFile,
  AuditBatch,
  ProtocolMap,
  SuspicionNote,
  SeenFiles,
  ProtocolSize,
  EngineConfig,
  AuditorConfig,
} from "../types/protocol.js";
import type {
  Finding,
  FinalFinding,
  AuditResult,
  AuditReport,
  AuditMeta,
  AuditorResult,
  AgentResult,
} from "../types/audit.js";
import { SupervisorOutputSchema } from "../types/audit.js";

// ─── Public API ───────────────────────────────────────────────────────────────

export async function runAudit(
  input: string,
  config: EngineConfig,
): Promise<AuditResult> {
  const startMs = Date.now();

  // ── Phase 0: Load ──────────────────────────────────────────────────────
  let files: SourceFile[];
  try {
    files = await loadProtocol(input);
  } catch (err) {
    return { ok: false, error: (err as Error).message, stage: "load" };
  }

  if (files.length === 0) {
    return {
      ok: false,
      error: "No auditable source files found in input.",
      stage: "load",
    };
  }

  logger.info("engine", `Loaded ${files.length} files from ${input}`);
  logAuditorConfig(config);

  const protocolSize = classifyProtocol(
    files,
    config.contextWindow,
    config.thinkingEnabled,
  );
  logger.info(
    "engine",
    `Protocol size: ${protocolSize} (context: ${config.contextWindow} tokens)`,
  );

  // ── Phase 1: Semantic Cartography ──────────────────────────────────────
  logger.info("engine", "Phase 1: Building protocol map...");
  let currentMap: ProtocolMap;
  try {
    currentMap = await buildProtocolMap(files, config);
  } catch (err) {
    return { ok: false, error: (err as Error).message, stage: "cartography" };
  }

  // ── Phase 2: RAG Retrieval ─────────────────────────────────────────────
  logger.info("engine", "Phase 2: Fetching RAG context...");
  const ragContext = await fetchClusterDiverseFindings(currentMap.formatted, 6);
  logger.info(`engine`, `RAG Context\n`, ragContext);
  // ── Phase 3: Iterative Audit Loop ──────────────────────────────────────
  logger.info("engine", "Phase 3: Iterative audit loop...");

  const allAuditorResults: AuditorResult[] = [];
  const allSuspicionNotes: SuspicionNote[] = [];
  let propagatedSuspicions: SuspicionNote[] = [];
  const seenFiles: SeenFiles = new Set();
  let passNumber = 0;
  const maxPasses = config.maxAuditPasses;

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

    logger.info(
      "engine",
      `Pass ${passNumber}: ${batches.length} batch(es) across ${batches.reduce(
        (s, b) => s + b.fullFiles.length,
        0,
      )} files`,
    );

    const passNewSuspicions: SuspicionNote[] = [];

    for (const batch of batches) {
      const thinkingOn = shouldEnableThinking(
        passNumber,
        batch.isSuspicionReaudit,
        config.thinkingEnabled,
      );

      const prompt = buildAuditPrompt(
        currentMap,
        ragContext,
        batch,
        passNumber,
      );

      for (const auditorCfg of config.auditors) {
        logger.debug(
          "engine",
          `Running auditor ${auditorCfg.id} [${auditorCfg.role ?? "junior"}] ` +
            `on batch ${batch.batchId} ` +
            `(${batch.fullFiles.length} files, thinking: ${thinkingOn}, ` +
            `provider: ${auditorCfg.provider}, ` +
            `url: ${auditorCfg.ollamaBaseUrl ?? env.OLLAMA_BASE_URL})`,
        );
        const callResult = await runAuditorCall(auditorCfg, prompt, thinkingOn);
        logger.info(
          `engine`,
          `Auditor ${auditorCfg.id} call result: ${callResult.status}`,
          callResult,
        );

        const agentResult: AgentResult = {
          auditorId: auditorCfg.id,
          agentRole: "logical-bugs",
          model: auditorCfg.model,
          status: callResult.status,
          findings: callResult.findings,
          error: callResult.error,
          rawResponse: callResult.rawResponse.slice(0, 1000),
        };

        logger.info(
          `engine`,
          `Auditor ${auditorCfg.id} agent result: ${agentResult.status}\n`,
          agentResult,
        );

        const auditorResult: AuditorResult = {
          auditorId: auditorCfg.id,
          model: auditorCfg.model,
          agents: [agentResult],
          allFindings: callResult.findings,
        };

        logger.info(
          `engine`,
          `Auditor ${auditorCfg.id} findings: ${callResult.findings.length}\n`,
          auditorResult,
        );

        allAuditorResults.push(auditorResult);

        // Tag suspicions with auditor id and pass number
        const taggedSuspicions: SuspicionNote[] = callResult.suspicions.map(
          s => ({ ...s, auditorId: auditorCfg.id, passNumber }),
        );

        allSuspicionNotes.push(...taggedSuspicions);
        passNewSuspicions.push(...taggedSuspicions);

        logger.info(
          "engine",
          `  ${auditorCfg.id}: ${callResult.findings.length} finding(s), ` +
            `${callResult.suspicions.length} suspicion(s)`,
        );
      }

      batch.fullFiles.forEach(f => seenFiles.add(f.path));
    }

    // Filter by confidence before propagating
    propagatedSuspicions = passNewSuspicions.filter(
      n => n.confidence >= config.minSuspicionConfidence,
    );

    logger.info(
      "engine",
      `Pass ${passNumber} complete — ${passNewSuspicions.length} suspicion(s), ` +
        `${propagatedSuspicions.length} propagated (threshold: ${config.minSuspicionConfidence})`,
    );

    // Early stop: all high-score files seen and no leads to follow
    const allHighScoreFilesSeen = files
      .filter(f => f.attackScore > 0.3)
      .every(f => seenFiles.has(f.path));

    if (propagatedSuspicions.length === 0 && allHighScoreFilesSeen) {
      logger.info(
        "engine",
        `Pass ${passNumber}: full coverage, no propagated leads — stopping`,
      );
      break;
    }

    // Enrich map with suspicions for next pass
    if (propagatedSuspicions.length > 0) {
      currentMap = injectSuspicions(
        currentMap,
        propagatedSuspicions,
        config.minSuspicionConfidence,
      );
    }
  }

  // ── Phase 4: Supervisor Synthesis ──────────────────────────────────────
  logger.info("engine", "Phase 4: Supervisor synthesis...");

  const allFindings = allAuditorResults.flatMap(r => r.allFindings);
  if (allFindings.length === 0) {
    logger.warn(
      "engine",
      "No findings from any auditor — producing empty report",
    );
  }

  const supervisorReport = await runSupervisor(
    allAuditorResults,
    currentMap,
    config,
    passNumber,
  );

  const durationMs = Date.now() - startMs;
  const meta: AuditMeta = {
    filesAudited: [...seenFiles],
    auditorsRun: config.auditors.length,
    auditorModels: config.auditors.map(a => a.model),
    supervisorModel: env.SUPERVISOR_MODEL,
    timestamp: new Date().toISOString(),
    durationMs,
  };

  const report: AuditReport = {
    markdown: buildMarkdownReport(supervisorReport.findings, currentMap, meta),
    findings: supervisorReport.findings,
    meta,
  };

  return {
    ok: true,
    report,
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

// ─── Auditor Call ─────────────────────────────────────────────────────────────

interface AuditorCallResult {
  findings: Finding[];
  suspicions: Omit<SuspicionNote, "auditorId" | "passNumber">[];
  rawResponse: string;
  status: "ok" | "failed" | "empty";
  error?: string;
}

/**
 * Run one auditor call against a batch.
 *
 * KEY DESIGN:
 * - Uses buildAuditorModel() → supports ANY provider (ollama/anthropic/openai/gemini/groq)
 * - Injects the system prompt as a SystemMessage → same behaviour regardless of whether
 *   the model was created from a Modelfile or is a raw cloud model
 * - For Ollama: if thinkingEnabled, rebuilds the model and
 *   options.think:true — this is Ollama-specific and skipped for cloud providers
 * - For cloud providers (Claude, GPT, Gemini): thinkingEnabled increases maxTokens
 *   but doesn't activate model-specific thinking modes (those require separate API flags)
 *
 * MULTI-MACHINE:
 * - auditorCfg.ollamaBaseUrl routes this specific auditor to its assigned machine
 * - auditor-1 → localhost:11434 (Mac), auditor-2 → 192.168.0.200:11434 (network box)
 * - Both see the SAME prompt, SAME system prompt, SAME RAG context
 */
async function runAuditorCall(
  auditorCfg: AuditorConfig,
  prompt: string,
  thinkingEnabled: boolean,
): Promise<AuditorCallResult> {
  // Pick the right system prompt based on role
  const systemPrompt = AUDITOR_SYSTEM;

  try {
    let model = buildAuditorModel(auditorCfg, 0.05);

    // Thinking mode: Ollama-specific adjustments
    // Cloud providers handle generation length differently (maxTokens in buildModel)
    if (thinkingEnabled && auditorCfg.provider === "ollama") {
      const ollamaUrl = auditorCfg.ollamaBaseUrl ?? env.OLLAMA_BASE_URL;
      model = new ChatOllama({
        model: auditorCfg.model,
        baseUrl: ollamaUrl,
        temperature: 0,
        think: true,
        streaming: false,
        
      });
    }

    const response = await model.invoke([
      new SystemMessage(systemPrompt),
      new HumanMessage(prompt),
    ]);

    const rawResponse = extractContentString(response.content);
    const { findings, suspicions } = parseAuditorOutput(rawResponse);

    // For logging: strip thinking blocks so the log shows actual findings,
    // not thousands of chars of reasoning that obscure the output.
    const loggableResponse = rawResponse
      .replace(/<think>[\s\S]*?<\/think>/gi, "[thinking stripped]")
      .slice(0, 1000);

    return {
      findings,
      suspicions,
      rawResponse: loggableResponse,
      status: findings.length === 0 ? "empty" : "ok",
    };
  } catch (err) {
    const error = (err as Error).message;
    logger.error("engine", `Auditor ${auditorCfg.id} call failed`, { error });
    return {
      findings: [],
      suspicions: [],
      rawResponse: "",
      status: "failed",
      error,
    };
  }
}

// ─── Supervisor ───────────────────────────────────────────────────────────────

async function runSupervisor(
  auditorResults: AuditorResult[],
  map: ProtocolMap,
  config: EngineConfig,
  passCount: number,
): Promise<{ findings: FinalFinding[] }> {
  const allFindings = auditorResults.flatMap(r =>
    r.allFindings.map(f => ({ ...f, auditorId: r.auditorId })),
  );

  if (allFindings.length === 0) return { findings: [] };

  const findingsJson = JSON.stringify(allFindings, null, 2);

  const supervisorPrompt =
    `You are a senior security auditor supervisor. Below are raw findings from ` +
    `${config.auditors.length} auditor(s) across ${passCount} audit pass(es).\n\n` +
    `Your job:\n` +
    `1. DEDUPLICATE — merge findings that describe the same vulnerability (same file, same root cause).\n` +
    `2. SCORE confidence — 0.6 base. +0.2 for each additional auditor that found the same bug. Max 1.0.\n` +
    `3. APPLY pass weights — targeted re-audit findings carry more evidential weight than breadth pass findings.\n` +
    `4. PRESERVE all unique findings — do not drop findings just because only one auditor found them.\n` +
    `5. RANK by severity then confidence.\n\n` +
    `Protocol map (for context):\n${map.formatted.slice(0, 1500)}\n\n` +
    `Raw findings from all auditors:\n${findingsJson.slice(0, 8000)}`;

  const model = makeSupervisorModel();

  const result = await invokeWithSchema({
    model,
    systemPrompt:
      "You are a smart contract security supervisor. Output ONLY valid JSON. No markdown. No preamble.",
    userPrompt: supervisorPrompt,
    schema: SupervisorOutputSchema,
    stage: "supervisor",
    maxRetries: 1,
  });

  if (result.ok) return result.data;

  logger.warn("engine", "Supervisor synthesis failed — returning raw findings");

  // Graceful fallback: return all findings with base confidence
  const fallbackFindings: FinalFinding[] = allFindings.slice(0, 20).map(f => ({
    severity: f.severity,
    title: f.title,
    file: f.file,
    line: f.line,
    description: f.description,
    exploit: f.exploit,
    recommendation: f.recommendation,
    confidence: 0.6,
    flaggedByAuditors: [f.auditorId],
    agentRoles: ["logical-bugs"],
  }));

  return { findings: fallbackFindings };
}

// ─── Prompt Builder ───────────────────────────────────────────────────────────

function buildAuditPrompt(
  map: ProtocolMap,
  ragContext: string,
  batch: AuditBatch,
  passNumber: number,
): string {
  const sections: string[] = [
    `=== PROTOCOL MAP ===\n${map.formatted}`,
    `=== HISTORICAL VULNERABILITY PATTERNS (Solodit RAG) ===\n${ragContext}`,
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
        `These were flagged in a previous pass. Prioritize these functions.\n` +
        `Use the Protocol Map to understand full cross-file context.`,
    );
  } else if (passNumber > 1) {
    sections.push(
      `=== PASS ${passNumber} — CONTINUATION ===\n` +
        `These files were not audited at full depth in previous passes.\n` +
        `The Protocol Map includes ⚠ suspicion markers from prior passes — treat them as high-priority.`,
    );
  }

  sections.push(`=== CONTRACT CODE ===\n${formatBatchCode(batch)}`);
  return sections.join("\n\n");
}

function formatBatchCode(batch: AuditBatch): string {
  if (batch.fullFiles.length === 0) return "(no files in batch)";
  return batch.fullFiles
    .map(f => `// ═══ ${f.path} [${f.language}] ═══\n` + f.content)
    .join("\n\n");
}

// ─── Thinking Mode ────────────────────────────────────────────────────────────

export function shouldEnableThinking(
  passNumber: number,
  isSuspicionReaudit: boolean,
  globalThinkingEnabled: boolean,
): boolean {
  if (!globalThinkingEnabled) return false;
  // Always think on targeted re-audits — focused, high-value, worth the cost
  if (isSuspicionReaudit) return true;
  // Small protocols: think on Pass 1 (single batch, highest leverage)
  if (passNumber === 1) return true;
  // Broad passes on medium/large protocols: off (breadth > depth)
  return false;
}

// ─── Report Rendering ─────────────────────────────────────────────────────────

function buildMarkdownReport(
  findings: FinalFinding[],
  map: ProtocolMap,
  meta: AuditMeta,
): string {
  const severityOrder = ["Critical", "High", "Medium", "Low", "Info"];
  const sorted = [...findings].sort((a, b) => {
    const si = severityOrder.indexOf(a.severity);
    const sj = severityOrder.indexOf(b.severity);
    if (si !== sj) return si - sj;
    return b.confidence - a.confidence;
  });

  const counts = severityOrder.reduce(
    (acc, s) => {
      acc[s] = findings.filter(f => f.severity === s).length;
      return acc;
    },
    {} as Record<string, number>,
  );

  const lines: string[] = [
    "# SentinelAI Security Audit Report",
    "",
    `**Generated:** ${meta.timestamp}`,
    `**Duration:** ${(meta.durationMs / 1000).toFixed(1)}s`,
    `**Files audited:** ${meta.filesAudited.length}`,
    `**Auditors:** ${meta.auditorModels.join(", ")}`,
    `**Supervisor:** ${meta.supervisorModel}`,
    "",
    "## Summary",
    "",
    `| Severity | Count |`,
    `|----------|-------|`,
    ...severityOrder.map(s => `| ${s} | ${counts[s] ?? 0} |`),
    "",
    `**Total findings:** ${findings.length}`,
    "",
    "## Findings",
    "",
  ];

  if (sorted.length === 0) {
    lines.push("*No vulnerabilities found.*");
  } else {
    sorted.forEach(f => {
      lines.push(`### [${f.severity}] ${f.title}`);
      lines.push("");
      lines.push(`**File:** \`${f.file}\` (line ${f.line})`);
      lines.push(`**Confidence:** ${(f.confidence * 100).toFixed(0)}%`);
      lines.push(`**Flagged by:** ${f.flaggedByAuditors.join(", ")}`);
      lines.push("");
      lines.push(`**Description:** ${f.description}`);
      lines.push("");
      lines.push(`**Exploit:** ${f.exploit}`);
      lines.push("");
      lines.push(`**Recommendation:** ${f.recommendation}`);
      lines.push("");
      lines.push("---");
      lines.push("");
    });
  }

  lines.push("## Protocol Map");
  lines.push("");
  lines.push("```");
  lines.push(map.formatted);
  lines.push("```");

  return lines.join("\n");
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractContentString(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map(block => {
        if (typeof block === "string") return block;
        if (typeof block === "object" && block !== null && "text" in block)
          return String((block as any).text);
        return "";
      })
      .join("");
  }
  return String(content);
}

/** Log a clear summary of the auditor configuration at startup. */
function logAuditorConfig(config: EngineConfig): void {
  logger.info("engine", `Auditor configuration:`);
  for (const a of config.auditors) {
    logger.info(
      "engine",
      `  ${a.id}: provider=${a.provider} model=${a.model} ` +
        `role=${a.role ?? "junior"} ` +
        `url=${a.provider === "ollama" ? (a.ollamaBaseUrl ?? env.OLLAMA_BASE_URL) : "cloud"}`,
    );
  }
}
