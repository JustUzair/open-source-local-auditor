/**
 * Supported LLM providers. All are called identically via .invoke() —
 * no provider-specific APIs used anywhere in this codebase.
 */
export type ProviderName =
  | "ollama"
  | "gemini"
  | "groq"
  | "openai"
  | "anthropic";

/** Providers that support embedding generation. */
export type EmbeddingProviderName = "ollama" | "gemini" | "openai";

/** Config for a single model slot (one auditor or the supervisor). */
export interface ModelSlotConfig {
  provider: ProviderName;
  model: string;
  apiKey?: string;
}

/**
 * One complete auditor = 3 agents (logical-bugs, common-pitfalls, contextual)
 * all running on the same underlying model. slotIndex maps to AUDITOR_N_* env vars.
 */
export interface AuditorConfig {
  slotIndex: 1 | 2 | 3;
  auditorId: string; // e.g. "auditor-1"
  model: ModelSlotConfig;
}

/** Full engine configuration resolved from env + CLI flags. */
export interface EngineConfig {
  nAuditors: number;
  auditors: AuditorConfig[];
  supervisor: ModelSlotConfig;
}
