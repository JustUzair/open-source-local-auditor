import { z } from "zod";
import { logger } from "../utils/logger.js";
import { invokeWithSchema } from "../utils/llm.js";
import { buildCartographyModel } from "../utils/models.js";
import { CARTOGRAPHY_SYSTEM } from "./prompts.js";
import type {
  SourceFile,
  ProtocolMap,
  FileSummary,
  SuspicionNote,
  EngineConfig,
} from "../types/protocol.js";
import { SystemMessage, HumanMessage } from "@langchain/core/messages";

// ─── Cartography Model ────────────────────────────────────────────────────────

/**
 * Build the cartography model from the first auditor config.
 * Uses buildCartographyModel() which handles both Ollama (with 8192 ctx + 300
 * output budget) and cloud providers (they manage context internally).
 * Always uses auditor-1 — cheap extraction, no need to distribute across machines.
 */
function makeCartographyModel(config: EngineConfig) {
  return buildCartographyModel(config.auditors[0]);
}

// ─── Schema ───────────────────────────────────────────────────────────────────

const FileSummaryLLMSchema = z.object({
  summary: z
    .string()
    .max(200)
    .describe("1–2 sentences describing what this module does (≤40 words)"),
  entryPoints: z
    .array(z.string())
    .describe(
      "public/external callable functions only, use understanding to decide what to include",
    ),
  externalDependencies: z
    .array(z.string())
    .describe("cross-file/cross-contract calls only, never stdlib"),
});

(FileSummaryLLMSchema as any)._example = {
  summary: "Manages user deposits and routes yield to Strategy.sol.",
  entryPoints: ["deposit(uint256)", "withdraw(uint256)", "rebalance()"],
  externalDependencies: ["Strategy.sol", "PriceOracle.sol"],
};

// CARTOGRAPHY_SYSTEM is imported from prompts.ts

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Build the Protocol Map via fast per-file LLM calls (Phase 1 of the audit).
 *
 * Each file gets a structured summary at minimal context cost.
 * Files < 200 chars are inferred without an LLM call.
 * The resulting map is prepended to every subsequent auditor call.
 */
export async function buildProtocolMap(
  files: SourceFile[],
  config: EngineConfig,
): Promise<ProtocolMap> {
  console.log(`Files`, files.map(file => file.path).join("\n"));

  logger.info(
    "cartographer",
    `Building protocol map: ${files.length} file(s) to index`,
  );

  const model = makeCartographyModel(config);
  const summaries: FileSummary[] = [];

  for (const file of files) {
    // Tiny files (interfaces, constants), skip LLM, infer from metadata
    if (file.size < 200) {
      summaries.push(trivialSummary(file));
      continue;
    }

    // Truncate to 6k chars — 1.5k tokens — comfortably within num_ctx 8192
    const snippet = file.content.slice(0, 6000);
    const userPrompt = `Index this ${file.language} file:\n\nFile: ${file.path}\n\`\`\`\n${snippet}\n\`\`\``;

    // console.log(`

    //     Text Index Prompt\n\n

    //     ${CARTOGRAPHY_SYSTEM}
    //     ${userPrompt}`);

    const result = await invokeWithSchema({
      model,
      systemPrompt: CARTOGRAPHY_SYSTEM,
      userPrompt,
      schema: FileSummaryLLMSchema,
      stage: `cartography:${file.path}`,
      maxRetries: 0,
    });

    if (result.ok) {
      //   logger.info(`cartographer`, `protocol mapped: `, result.data);
      summaries.push({
        path: file.path,
        language: file.language,
        summary: result.data.summary,
        entryPoints: result.data.entryPoints,
        externalDependencies: result.data.externalDependencies,
        suspicions: [],
      });
    } else {
      logger.warn(
        "cartographer",
        `Failed to index ${file.path} — using fallback`,
      );
      summaries.push(fallbackSummary(file));
    }
  }

  // Sort high attack score first for the formatted output
  const scoreMap = new Map(files.map(f => [f.path, f.attackScore]));
  const sorted = [...summaries].sort(
    (a, b) => (scoreMap.get(b.path) ?? 0) - (scoreMap.get(a.path) ?? 0),
  );

  const protocolName = inferProtocolName(files);
  const dominantLanguage = inferDominantLanguage(files);

  const formatted = renderProtocolMap(
    sorted,
    protocolName,
    dominantLanguage,
    scoreMap,
  );

  logger.info(
    "cartographer",
    `Protocol map built — ${summaries.length} file(s) indexed`,
  );

  return { files: sorted, formatted };
}

/**
 * Inject confidence-filtered suspicion notes into the map before the next pass.
 * Rebuilds map.formatted so every subsequent auditor call sees the annotations.
 */
export function injectSuspicions(
  map: ProtocolMap,
  notes: SuspicionNote[],
  minConfidence: number,
): ProtocolMap {
  const filtered = notes.filter(n => n.confidence >= minConfidence);
  if (filtered.length === 0) return map;

  logger.info(
    "cartographer",
    `Injecting ${filtered.length} suspicion(s) into protocol map`,
  );

  const updatedFiles = map.files.map(file => {
    const matching = filtered.filter(
      n =>
        pathMatch(n.targetFile, file.path) ||
        pathMatch(file.path, n.targetFile),
    );
    if (matching.length === 0) return file;

    const newSuspicions = matching.map(n => ({
      passNumber: n.passNumber,
      note: n.targetFunction
        ? `${n.targetFunction}: ${n.reason} [confidence: ${n.confidence}]`
        : `${n.reason} [confidence: ${n.confidence}]`,
    }));

    return {
      ...file,
      suspicions: [...file.suspicions, ...newSuspicions],
    };
  });

  // Rebuild formatted text
  const scoreMap = new Map(map.files.map(f => [f.path, 0]));
  const protocolName = extractFromFormatted(
    map.formatted,
    /PROTOCOL MAP — (.+?) \(/,
    "Protocol",
  );
  const language = extractFromFormatted(
    map.formatted,
    /\d+ files? · (.+?)\)/,
    "mixed",
  );

  return {
    files: updatedFiles,
    formatted: renderProtocolMap(
      updatedFiles,
      protocolName,
      language,
      scoreMap,
    ),
  };
}

// ─── Rendering ────────────────────────────────────────────────────────────────

function renderProtocolMap(
  summaries: FileSummary[],
  protocolName: string,
  language: string,
  scoreMap: Map<string, number>,
): string {
  const sep = "═".repeat(52);
  const lines: string[] = [
    `PROTOCOL MAP — ${protocolName} (${summaries.length} files · ${language})`,
    sep,
    "",
  ];

  for (const s of summaries) {
    const score = scoreMap.get(s.path);
    const scoreStr =
      score !== undefined && score > 0 ? ` score:${score.toFixed(2)}` : "";
    lines.push(`[${s.path}]${scoreStr}`);
    lines.push(`  What it does: ${s.summary}`);
    if (s.entryPoints.length > 0)
      lines.push(`  Entry points: ${s.entryPoints.join(", ")}`);
    if (s.externalDependencies.length > 0)
      lines.push(`  Calls into: ${s.externalDependencies.join(", ")}`);
    for (const sus of s.suspicions) {
      lines.push(`  ⚠ Suspicion [Pass ${sus.passNumber}]: ${sus.note}`);
    }
    lines.push("");
  }

  lines.push(sep);
  return lines.join("\n");
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function trivialSummary(file: SourceFile): FileSummary {
  return {
    path: file.path,
    language: file.language,
    summary: `Small ${file.language} file — likely interface, constants, or stub.`,
    entryPoints: [],
    externalDependencies: file.imports,
    suspicions: [],
  };
}

function fallbackSummary(file: SourceFile): FileSummary {
  return {
    path: file.path,
    language: file.language,
    summary: `${file.language} file with ${file.imports.length} import(s). Score: ${file.attackScore.toFixed(2)}.`,
    entryPoints: [],
    externalDependencies: file.imports,
    suspicions: [],
  };
}

function inferProtocolName(files: SourceFile[]): string {
  if (files.length === 0) return "Protocol";
  // Take the first non-trivial segment of the first file path
  const parts = files[0].path.split("/");
  const candidate = parts.length > 1 ? parts[0] : "Protocol";
  return candidate === "." ? (parts[1] ?? "Protocol") : candidate;
}

function inferDominantLanguage(files: SourceFile[]): string {
  const counts: Record<string, number> = {};
  for (const f of files) counts[f.language] = (counts[f.language] ?? 0) + 1;
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "mixed";
}

function extractFromFormatted(
  formatted: string,
  pattern: RegExp,
  fallback: string,
): string {
  return formatted.match(pattern)?.[1] ?? fallback;
}

/**
 * Fuzzy path match — handles both "Strategy.sol" and "contracts/Strategy.sol"
 * matching against each other.
 */
function pathMatch(a: string, b: string): boolean {
  if (a === b) return true;
  const aBase = a.split("/").pop() ?? a;
  const bBase = b.split("/").pop() ?? b;
  return aBase === bBase || a.includes(b) || b.includes(a);
}
