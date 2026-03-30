/**
    32,768 total tokens
    -  2,000  Protocol Map (always present)
    -  4,800  RAG findings (6 × 800 tokens each)
    -    800  Suspicion FOCUS block (re-audit batches)
    -  4,096  Output buffer (findings JSON)
    ──────────
    = 21,072 tokens available for code
    × 4 chars/token
    = ~84,288 chars of actual contract code
    */

import { nanoid } from "nanoid";
import type {
  SourceFile,
  AuditBatch,
  FileSummary,
  SuspicionNote,
  SeenFiles,
  ProtocolMap,
  ProtocolSize,
} from "../types/protocol.js";
import { logger } from "../utils/logger.js";

const PROTOCOL_MAP_BUDGET = 2_000;
const RAG_BUDGET = 4_800;
const SUSPICION_CTX_BUDGET = 800;
const THINKING_BUFFER = 6_000;
const OUTPUT_BUFFER = 4_096;
const CHARS_PER_TOKEN = 4;

function availableCodeBudgetChars(
  contextWindow: number,
  thinkingEnabled: boolean,
): number {
  const tokens =
    contextWindow -
    PROTOCOL_MAP_BUDGET -
    RAG_BUDGET -
    SUSPICION_CTX_BUDGET -
    (thinkingEnabled ? THINKING_BUFFER : 0) -
    OUTPUT_BUFFER;
  return Math.max(tokens, 0) * CHARS_PER_TOKEN;
}

export function classifyProtocol(
  files: SourceFile[],
  contextWindow: number,
  thinkingEnabled: boolean,
): ProtocolSize {
  const totalChars = files.reduce((s, f) => s + f.size, 0);
  const budgetChars = availableCodeBudgetChars(contextWindow, thinkingEnabled);
  if (totalChars <= budgetChars * 0.85) return "small";
  if (totalChars <= budgetChars * 3.0) return "medium";
  return "large";
}

export function buildInitialBatches(
  files: SourceFile[],
  map: ProtocolMap,
  contextWindow: number,
  thinkingEnabled: boolean,
  maxFullFilesPerBatch: number,
): AuditBatch[] {
  const budgetChars = availableCodeBudgetChars(contextWindow, thinkingEnabled);
  const sorted = [...files].sort((a, b) => b.attackScore - a.attackScore);
  const batches: AuditBatch[] = [];
  let remaining = [...sorted];
  let safety = 0;

  while (remaining.length > 0 && safety++ < 50) {
    const { batch, leftover, consumed } = sliceBatch(
      remaining,
      map,
      budgetChars,
      maxFullFilesPerBatch,
      1,
      false,
      [],
    );
    batches.push(batch);
    remaining = leftover;
    if (consumed === 0) break;
  }

  return batches;
}

export function buildNextPassBatches(
  files: SourceFile[],
  seenFiles: SeenFiles,
  propagatedSuspicions: SuspicionNote[],
  map: ProtocolMap,
  contextWindow: number,
  thinkingEnabled: boolean,
  maxFullFilesPerBatch: number,
  passNumber: number,
): AuditBatch[] {
  const budgetChars = availableCodeBudgetChars(contextWindow, thinkingEnabled);
  const batches: AuditBatch[] = [];

  if (propagatedSuspicions.length > 0) {
    const sb = buildSuspicionBatch(
      files,
      propagatedSuspicions,
      map,
      budgetChars,
      maxFullFilesPerBatch,
      passNumber,
    );
    if (sb) batches.push(sb);
  }

  const unseenFiles = files
    .filter(f => !seenFiles.has(f.path) && f.attackScore > 0.1)
    .sort((a, b) => b.attackScore - a.attackScore);
  let remaining = [...unseenFiles];
  let safety = 0;

  while (remaining.length > 0 && safety++ < 50) {
    const { batch, leftover, consumed } = sliceBatch(
      remaining,
      map,
      budgetChars,
      maxFullFilesPerBatch,
      passNumber,
      false,
      [],
    );
    batches.push(batch);
    remaining = leftover;
    if (consumed === 0) break;
  }

  return batches;
}

function buildSuspicionBatch(
  files: SourceFile[],
  suspicions: SuspicionNote[],
  map: ProtocolMap,
  budgetChars: number,
  maxFullFilesPerBatch: number,
  passNumber: number,
): AuditBatch | null {
  const suspicionTargets = files.filter(f =>
    suspicions.some(s => pathMatch(s.targetFile, f.path)),
  );
  if (suspicionTargets.length === 0) return null;

  const targetSet = new Set(suspicionTargets.map(f => f.path));
  const neighbours = files.filter(f => {
    if (targetSet.has(f.path)) return false;
    return suspicionTargets.some(
      t =>
        t.imports.some(
          imp => f.path.includes(imp) || imp.includes(f.path.split("/").pop()!),
        ) ||
        f.imports.some(
          imp => t.path.includes(imp) || imp.includes(t.path.split("/").pop()!),
        ),
    );
  });

  const candidates = [...suspicionTargets, ...neighbours];
  let charBudget = budgetChars;
  const fullFiles: SourceFile[] = [];

  for (const f of candidates) {
    if (fullFiles.length >= maxFullFilesPerBatch) break;
    if (f.size <= charBudget) {
      fullFiles.push(f);
      charBudget -= f.size;
    }
  }

  if (fullFiles.length === 0) return null;

  return {
    batchId: nanoid(8),
    passNumber,
    fullFiles,
    summarizedFiles: map.files.filter(
      s => !fullFiles.some(f => f.path === s.path),
    ),
    estimatedTokens:
      Math.round((budgetChars - charBudget) / CHARS_PER_TOKEN) +
      PROTOCOL_MAP_BUDGET +
      RAG_BUDGET +
      SUSPICION_CTX_BUDGET,
    isSuspicionReaudit: true,
    triggeringSuspicions: suspicions.filter(s =>
      suspicionTargets.some(f => pathMatch(s.targetFile, f.path)),
    ),
  };
}

function sliceBatch(
  files: SourceFile[],
  map: ProtocolMap,
  budgetChars: number,
  maxFullFiles: number,
  passNumber: number,
  isSuspicionReaudit: boolean,
  triggeringSuspicions: SuspicionNote[],
): { batch: AuditBatch; leftover: SourceFile[]; consumed: number } {
  let charBudget = budgetChars;
  const fullFiles: SourceFile[] = [];
  const leftover: SourceFile[] = [];

  for (const file of files) {
    if (fullFiles.length >= maxFullFiles || file.size > charBudget) {
      leftover.push(file);
    } else {
      fullFiles.push(file);
      charBudget -= file.size;
    }
  }

  return {
    batch: {
      batchId: nanoid(8),
      passNumber,
      fullFiles,
      summarizedFiles: map.files.filter(
        s => !fullFiles.some(f => f.path === s.path),
      ),
      estimatedTokens:
        Math.round((budgetChars - charBudget) / CHARS_PER_TOKEN) +
        PROTOCOL_MAP_BUDGET +
        RAG_BUDGET,
      isSuspicionReaudit,
      triggeringSuspicions,
    },
    leftover,
    consumed: fullFiles.length,
  };
}

function pathMatch(suspicionTarget: string, filePath: string): boolean {
  if (suspicionTarget === filePath) return true;
  const tBase = suspicionTarget.split("/").pop() ?? suspicionTarget;
  const fBase = filePath.split("/").pop() ?? filePath;
  return (
    tBase === fBase ||
    filePath.includes(suspicionTarget) ||
    suspicionTarget.includes(filePath)
  );
}
