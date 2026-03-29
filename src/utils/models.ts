import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { Embeddings } from "@langchain/core/embeddings";
import {
  ChatGoogleGenerativeAI,
  GoogleGenerativeAIEmbeddings,
} from "@langchain/google-genai";
import { ChatGroq } from "@langchain/groq";
import { ChatOpenAI, OpenAIEmbeddings } from "@langchain/openai";
import { ChatAnthropic } from "@langchain/anthropic";
import { ChatOllama, OllamaEmbeddings } from "@langchain/ollama";
import type {
  ProviderName,
  EmbeddingProviderName,
  ModelSlotConfig,
} from "../types/models.js";
import { env } from "./env.js";
import { logger } from "./logger.js";

// ─── Chat Model Builder ───────────────────────────────────────────────────────

/**
 * Build a BaseChatModel from a slot config.
 *
 * RULE: Only .invoke([SystemMessage, HumanMessage]) is called on the result.
 * No provider-specific APIs. This is what makes the tool model-agnostic.
 */
export function buildModel(
  slot: ModelSlotConfig,
  temperature: number,
  OLLAMA_BASE_URL: string = env.OLLAMA_BASE_URL,
): BaseChatModel {
  const { provider, model, apiKey } = slot;

  logger.debug("models", `Building model`, { provider, model, temperature });

  switch (provider as ProviderName) {
    case "gemini":
      return new ChatGoogleGenerativeAI({
        model,
        apiKey,
        temperature,
        maxOutputTokens: 4096,
      });

    case "groq":
      return new ChatGroq({
        model,
        apiKey,
        temperature,
        maxTokens: 4096,
      });

    case "openai":
      return new ChatOpenAI({
        model,
        apiKey,
        temperature,
        maxTokens: 4096,
      });

    case "anthropic":
      return new ChatAnthropic({
        model,
        apiKey,
        temperature,
        maxTokens: 4096,
      });

    case "ollama":
    default:
      // Default: ollama. Also the fallback if an unknown provider is set,
      // so misconfiguration degrades gracefully to local.
      return new ChatOllama({
        model,
        baseUrl: OLLAMA_BASE_URL,
        temperature,
        numPredict: 4096,
      });
  }
}

// ─── Slot Readers ─────────────────────────────────────────────────────────────

/**
 * Read auditor slot N config. CLI flag overrides come in via process.env
 * (the CLI sets them before calling this). Env var takes final precedence.
 */
export function readAuditorSlot(slotIndex: 1 | 2 | 3): ModelSlotConfig {
  // Fallback to slot 1 config if a slot's vars aren't set
  const provider = (process.env[`AUDITOR_${slotIndex}_PROVIDER`] ??
    env.AUDITOR_1_PROVIDER) as ProviderName;
  const model =
    process.env[`AUDITOR_${slotIndex}_MODEL`] ?? env.AUDITOR_1_MODEL;
  const apiKey =
    process.env[`AUDITOR_${slotIndex}_API_KEY`] ?? env.AUDITOR_1_API_KEY;
  return { provider, model, apiKey };
}

export function readSupervisorSlot(): ModelSlotConfig {
  return {
    provider: env.SUPERVISOR_PROVIDER as ProviderName,
    model: env.SUPERVISOR_MODEL,
    apiKey: env.SUPERVISOR_API_KEY,
  };
}

/** Factory convenience — builds the model for a given auditor slot. */
export function makeAuditorModel(slotIndex: 1 | 2 | 3): BaseChatModel {
  return buildModel(readAuditorSlot(slotIndex), 0.1);
}

/** Supervisor uses temperature 0.0 — purely logical, no creativity. */
export function makeSupervisorModel(): BaseChatModel {
  return buildModel(readSupervisorSlot(), 0.0, "http://192.168.0.200:11434");
}

// ─── Embedding Model ──────────────────────────────────────────────────────────

/**
 * Embedding model for RAG retrieval.
 * Must stay consistent across ingest and audit runs —
 * the checkpoint enforces this.
 */
export function makeEmbeddingsModel(): Embeddings {
  const { provider, model, apiKey } = {
    provider: env.EMBEDDING_PROVIDER as EmbeddingProviderName,
    model: env.EMBEDDING_MODEL,
    apiKey: env.EMBEDDING_API_KEY,
  };

  logger.debug("models", "Building embeddings model", { provider, model });

  switch (provider) {
    case "gemini":
      return new GoogleGenerativeAIEmbeddings({
        apiKey,
        model,
        // RETRIEVAL_DOCUMENT for ingest, RETRIEVAL_QUERY for queries.
        // We use RETRIEVAL_DOCUMENT as the default — the retriever overrides for queries.
        taskType: "RETRIEVAL_DOCUMENT" as any,
      });

    case "openai":
      return new OpenAIEmbeddings({ apiKey, model });

    case "ollama":
    default:
      return new OllamaEmbeddings({
        model,
        baseUrl: env.OLLAMA_BASE_URL,
      });
  }
}

// ─── CLI Override Helper ──────────────────────────────────────────────────────

/**
 * Apply CLI flag overrides to process.env before model factories read them.
 * The CLI calls this before constructing the engine.
 */
export function applyAuditorOverrides(
  slotIndex: 1 | 2 | 3,
  overrides: { provider?: string; model?: string; apiKey?: string },
): void {
  if (overrides.provider)
    process.env[`AUDITOR_${slotIndex}_PROVIDER`] = overrides.provider;
  if (overrides.model)
    process.env[`AUDITOR_${slotIndex}_MODEL`] = overrides.model;
  if (overrides.apiKey)
    process.env[`AUDITOR_${slotIndex}_API_KEY`] = overrides.apiKey;
}

export function applySupervisorOverrides(overrides: {
  provider?: string;
  model?: string;
  apiKey?: string;
}): void {
  if (overrides.provider) process.env.SUPERVISOR_PROVIDER = overrides.provider;
  if (overrides.model) process.env.SUPERVISOR_MODEL = overrides.model;
  if (overrides.apiKey) process.env.SUPERVISOR_API_KEY = overrides.apiKey;
}
