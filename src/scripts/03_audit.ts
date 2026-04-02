/**
 * 03_audit.ts — CLI entry point for the SentinelAI audit engine.
 *
 * Usage:
 *   npm run audit -- --input ./contracts/
 *   npm run audit -- --input ./protocol.zip
 *   npm run audit -- --input ./contracts/ --max-passes 1 --no-thinking
 *   npm run audit -- --input ./contracts/ --context-window 65536
 *
 * Flags:
 *   --input <path>          required — directory or .zip
 *   --max-passes <n>        overrides MAX_AUDIT_PASSES
 *   --context-window <n>    overrides CONTEXT_WINDOW
 *   --min-confidence <n>    overrides MIN_SUSPICION_CONFIDENCE
 *   --no-thinking           force disable thinking
 *   --thinking              force enable thinking
 *   --output-dir <dir>      where to write reports (default: ./output)
 *
 * Multi-machine Ollama setup (set in .env):
 *   AUDITOR_1_OLLAMA_URL=http://localhost:11434          # Mac
 *   AUDITOR_2_OLLAMA_URL=http://192.168.0.200:11434      # Network machine
 *   SUPERVISOR_OLLAMA_URL=http://192.168.0.200:11434     # Supervisor machine
 *
 * Multi-provider setup (mix local + cloud):
 *   AUDITOR_1_PROVIDER=ollama   AUDITOR_1_MODEL=qwen3.5:9b
 *   AUDITOR_2_PROVIDER=anthropic AUDITOR_2_MODEL=claude-sonnet-4-5 AUDITOR_2_API_KEY=sk-ant-...
 *   AUDITOR_3_PROVIDER=openai   AUDITOR_3_MODEL=gpt-4o             AUDITOR_3_API_KEY=sk-...
 *
 * Output files:
 *   ./output/report-[timestamp].md   — human-readable audit report
 *   ./output/debug-[timestamp].json  — suspicion notes, pass count, file list
 */

import { writeFile, mkdir } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { Command } from "commander";
import dotenv from "dotenv";
import { runAudit } from "../core/engine.js";
import { env } from "../utils/env.js";
import { logger } from "../utils/logger.js";
import type { EngineConfig, AuditorConfig } from "../types/protocol.js";

dotenv.config();

// ─── CLI Definition ───────────────────────────────────────────────────────────

const program = new Command();

program
  .name("sentinel-audit")
  .description(
    "SentinelAI — local-first AI-powered smart contract security auditor",
  )
  .requiredOption("--input <path>", "Path to contract directory or .zip file")
  .option(
    "--max-passes <n>",
    "Maximum audit passes (overrides MAX_AUDIT_PASSES)",
    String(env.MAX_AUDIT_PASSES),
  )
  .option(
    "--context-window <n>",
    "Model context window in tokens (overrides CONTEXT_WINDOW)",
    String(env.CONTEXT_WINDOW),
  )
  .option(
    "--min-confidence <n>",
    "Min suspicion confidence to propagate (overrides MIN_SUSPICION_CONFIDENCE)",
    String(env.MIN_SUSPICION_CONFIDENCE),
  )
  .option("--no-thinking", "Disable extended thinking mode")
  .option("--thinking", "Enable extended thinking mode")
  .option(
    "--output-dir <dir>",
    "Directory to write the report (default: ./output)",
    "./output",
  )
  .parse(process.argv);

const opts = program.opts<{
  input: string;
  maxPasses: string;
  contextWindow: string;
  minConfidence: string;
  thinking: boolean;
  noThinking: boolean;
  outputDir: string;
}>();

// ─── Config Builder ───────────────────────────────────────────────────────────

/**
 * Build the EngineConfig from env vars.
 *
 * Per-auditor Ollama URL resolution order:
 *   1. AUDITOR_N_OLLAMA_URL  (most specific — that auditor on that machine)
 *   2. OLLAMA_BASE_URL       (global fallback for all Ollama auditors)
 *
 * Role assignment:
 *   - auditor-1 and auditor-2: "junior" (Step 1-3 value store + interrogation)
 *   - auditor-3 (typically the stronger model): "senior" (Feynman + Nemesis)
 *   This is a convention — override by setting AUDITOR_N_ROLE in your env if needed.
 */
function buildEngineConfig(): EngineConfig {
  const auditors: AuditorConfig[] = [];

  // ── Auditor 1 — always required ──────────────────────────────────────
  auditors.push({
    id: "auditor-1",
    provider: env.AUDITOR_1_PROVIDER,
    model: env.AUDITOR_1_MODEL,
    apiKey:
      env.AUDITOR_1_PROVIDER !== "ollama"
        ? (env.AUDITOR_1_API_KEY ?? "")
        : undefined,
    ollamaBaseUrl: env.AUDITOR_1_OLLAMA_URL ?? env.OLLAMA_BASE_URL,
  });

  // ── Auditor 2 — optional ──────────────────────────────────────────────
  if (env.N_AUDITORS >= 2 && env.AUDITOR_2_MODEL) {
    auditors.push({
      id: "auditor-2",
      provider: env.AUDITOR_2_PROVIDER ?? "ollama",
      model: env.AUDITOR_2_MODEL,
      apiKey:
        (env.AUDITOR_2_PROVIDER ?? "ollama") !== "ollama"
          ? (env.AUDITOR_2_API_KEY ?? "")
          : undefined,
      ollamaBaseUrl: env.AUDITOR_2_OLLAMA_URL ?? env.OLLAMA_BASE_URL,
    });
  }

  // ── Auditor 3 — optional, assigned senior role if present ─────────────
  if (env.N_AUDITORS >= 3 && env.AUDITOR_3_MODEL) {
    auditors.push({
      id: "auditor-3",
      provider: env.AUDITOR_3_PROVIDER ?? "ollama",
      model: env.AUDITOR_3_MODEL,
      apiKey:
        (env.AUDITOR_3_PROVIDER ?? "ollama") !== "ollama"
          ? (env.AUDITOR_3_API_KEY ?? "")
          : undefined,
      ollamaBaseUrl: env.AUDITOR_3_OLLAMA_URL ?? env.OLLAMA_BASE_URL,
      // Auditor 3 is the "senior" — deeper Feynman+Nemesis dual-pass methodology.
      // If using GLM-5 or a cloud model here, it benefits from the richer prompt.
    });
  }

  // ── Thinking mode: CLI flags override env ─────────────────────────────
  const thinkingEnabled = opts.noThinking
    ? false
    : opts.thinking
      ? true
      : env.THINKING_ENABLED;

  return {
    auditors,
    contextWindow:
      parseInt(opts.contextWindow, 32768) || env.CONTEXT_WINDOW || 65536,
    maxAuditPasses: parseInt(opts.maxPasses, 10) || env.MAX_AUDIT_PASSES || 3,
    minSuspicionConfidence:
      parseFloat(opts.minConfidence) || env.MIN_SUSPICION_CONFIDENCE || 0.7,
    maxFullFilesPerBatch: env.MAX_FULL_FILES_PER_BATCH || 5,
    thinkingEnabled,
  };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("\n🔵  SentinelAI — Iterative Local Audit Engine\n");

  const config = buildEngineConfig();

  console.log("⚙️   Configuration:");
  console.log(`   Input:            ${opts.input}`);
  for (const a of config.auditors) {
    const url =
      a.provider === "ollama"
        ? (a.ollamaBaseUrl ?? env.OLLAMA_BASE_URL)
        : "cloud";
    console.log(
      `   ${a.id}:        [auditor] ${a.provider}/${a.model} @ ${url}`,
    );
  }
  console.log(`   Context window:   ${config.contextWindow} tokens`);
  console.log(`   Max passes:       ${config.maxAuditPasses}`);
  console.log(`   Min confidence:   ${config.minSuspicionConfidence}`);
  console.log(`   Thinking mode:    ${config.thinkingEnabled}`);
  console.log(`   Max files/batch:  ${config.maxFullFilesPerBatch}`);
  console.log();

  const result = await runAudit(opts.input, config);

  if (!result.ok) {
    console.error(
      `\n❌  Audit failed at stage "${result.stage}": ${result.error}\n`,
    );
    process.exit(1);
  }

  logger.info(`audit.ts`, `Audit complete\n\n`, result);
  // ── Print summary ──────────────────────────────────────────────────────
  const { report, debug } = result;

  console.log("\n📊  Audit Summary");
  console.log(`   Protocol size:    ${debug.protocolSize}`);
  console.log(`   Passes run:       ${debug.passCount}`);
  console.log(`   Files audited:    ${report.meta.filesAudited.length}`);
  console.log(
    `   Duration:         ${(report.meta.durationMs / 1000).toFixed(1)}s`,
  );
  console.log();

  const severities = ["Critical", "High", "Medium", "Low", "Info"] as const;
  for (const sev of severities) {
    const count = report.findings.filter(f => f.severity === sev).length;
    if (count > 0) console.log(`   ${sev.padEnd(10)} ${count} finding(s)`);
  }

  if (report.findings.length === 0) {
    console.log("   No findings reported.");
  }

  console.log();
  console.log(`   Suspicions emitted:    ${debug.allSuspicionNotes.length}`);
  console.log(`   Suspicions propagated: ${debug.propagatedSuspicions.length}`);

  // ── Write report ───────────────────────────────────────────────────────
  if (!existsSync(opts.outputDir)) {
    await mkdir(opts.outputDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const reportPath = join(opts.outputDir, `report-${timestamp}.md`);
  const debugPath = join(opts.outputDir, `debug-${timestamp}.json`);

  await writeFile(reportPath, report.markdown, "utf-8");
  console.log(`\n✅  Report written to: ${reportPath}`);

  await writeFile(
    debugPath,
    JSON.stringify(
      {
        passCount: debug.passCount,
        protocolSize: debug.protocolSize,
        filesAudited: report.meta.filesAudited,
        auditorConfig: config.auditors.map(a => ({
          id: a.id,
          provider: a.provider,
          model: a.model,
          url:
            a.provider === "ollama"
              ? (a.ollamaBaseUrl ?? env.OLLAMA_BASE_URL)
              : "cloud",
        })),
        allSuspicionNotes: debug.allSuspicionNotes,
        propagatedSuspicions: debug.propagatedSuspicions,
        findingCount: report.findings.length,
      },
      null,
      2,
    ),
    "utf-8",
  );
  console.log(`   Debug JSON:         ${debugPath}\n`);
}

main().catch(err => {
  console.error("\nAudit failed:", err);
  process.exit(1);
});
