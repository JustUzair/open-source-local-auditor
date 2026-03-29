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
