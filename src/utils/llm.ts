import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { SystemMessage, HumanMessage } from "@langchain/core/messages";
import { ZodSchema, ZodError } from "zod";
import { logger } from "./logger.js";
import { FindingSchema } from "../types/audit.js";
import { SuspicionNoteSchema } from "../types/audit.js";
import type { Finding } from "../types/audit.js";
import type { SuspicionNote } from "../types/protocol.js";
// ─── Result Types ─────────────────────────────────────────────────────────────

export type LLMSuccess<T> = {
  ok: true;
  data: T;
  rawResponse: string;
};

export type LLMFailure = {
  ok: false;
  error: string;
  rawResponse: string;
  stage: string;
};

export type LLMResult<T> = LLMSuccess<T> | LLMFailure;

// ─── Main Invocation Function ─────────────────────────────────────────────────

/**
 * Invoke any LLM model and parse + validate its JSON response.
 *
 * Strategy:
 * 1. Embed the schema example in the prompt as the output spec.
 * 2. Call model with SystemMessage (skill) + HumanMessage (context + task + spec).
 * 3. Extract JSON using 3 fallback strategies (direct → fence strip → regex).
 * 4. Validate with Zod. Retry once with correction hint on failure.
 *
 * This is the ONLY function that calls model.invoke() in this codebase.
 * All LLM calls go through here.
 */
export async function invokeWithSchema<T>(opts: {
  model: BaseChatModel;
  systemPrompt: string;
  userPrompt: string;
  schema: ZodSchema<T>;
  stage: string;
  /** Max retries on JSON parse/schema failure. Default: 1 (2 total attempts). */
  maxRetries?: number;
}): Promise<LLMResult<T>> {
  const {
    model,
    systemPrompt,
    userPrompt,
    schema,
    stage,
    maxRetries = 1,
  } = opts;

  // Pull the example that was attached to the schema in types/audit.ts
  const schemaExample = (schema as any)._example;
  if (!schemaExample) {
    return {
      ok: false,
      error: `Schema for stage "${stage}" has no ._example attached. See types/audit.ts.`,
      rawResponse: "",
      stage,
    };
  }

  const outputSpec = buildOutputSpec(schemaExample);
  let rawResponse = "";

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const retryHint =
        attempt > 0
          ? "\n\n⚠️  Your previous response contained invalid JSON. " +
            "Output ONLY the JSON object. No other text."
          : "";

      const userMessage = `${userPrompt}\n\n${outputSpec}${retryHint}`;

      logger.debug(stage, `LLM call attempt ${attempt + 1}/${maxRetries + 1}`);

      const response = await model.invoke([
        new SystemMessage(systemPrompt),
        new HumanMessage(userMessage),
      ]);

      rawResponse = extractContentString(response.content);

      logger.debug(stage, "Raw response\n", rawResponse);

      const parsed = extractJSON(rawResponse);
      const validated = schema.parse(parsed);

      logger.debug(stage, "Schema validation passed");

      return { ok: true, data: validated, rawResponse };
    } catch (err) {
      const isLast = attempt === maxRetries;
      const msg =
        err instanceof ZodError
          ? `Schema mismatch: ${err.errors
              .map(e => `${e.path.join(".")}: ${e.message}`)
              .join("; ")}`
          : (err as Error).message;

      if (isLast) {
        logger.error(stage, `All ${maxRetries + 1} attempts failed`, {
          lastError: msg,
          rawPreview: rawResponse,
        });
        return { ok: false, error: msg, rawResponse, stage };
      }

      logger.warn(stage, `Attempt ${attempt + 1} failed, retrying`, {
        error: msg,
      });
    }
  }

  // Never reached — TypeScript requires an explicit return
  return { ok: false, error: "Unknown failure", rawResponse: "", stage };
}

// ─── JSON Extraction ──────────────────────────────────────────────────────────

export function extractJSON(text: string): unknown {
  const t = text.trim();

  // Strategy 1: direct parse
  try {
    return JSON.parse(t);
  } catch {}

  // Strategy 2: strip markdown fences
  const fenceMatch = t.match(/```(?:json)?\s*([\s\S]*?)```/s);
  if (fenceMatch?.[1]) {
    try {
      return JSON.parse(fenceMatch[1].trim());
    } catch {}
  }

  // Strategy 3: RIGHT-TO-LEFT search for last JSON array or object.
  // The old greedy regex started from the FIRST [ (inside <think> blocks
  // like "balances[addr]") and matched garbage. Searching right-to-left
  // finds the LAST [ which is almost always the actual findings array.
  let arrayStart = t.lastIndexOf("[");
  while (arrayStart >= 0) {
    try {
      return JSON.parse(t.slice(arrayStart));
    } catch {}
    arrayStart = t.lastIndexOf("[", arrayStart - 1);
  }

  let objectStart = t.lastIndexOf("{");
  while (objectStart >= 0) {
    try {
      return JSON.parse(t.slice(objectStart));
    } catch {}
    objectStart = t.lastIndexOf("{", objectStart - 1);
  }

  throw new Error(
    `Could not extract valid JSON from LLM response. ` +
      `First 300 chars: ${t.slice(0, 300)}`,
  );
}

// ─── Private Helpers ──────────────────────────────────────────────────────────

/**
 * Normalize LangChain's response.content to a plain string.
 * Some providers return a string, others return an array of content blocks.
 */
function extractContentString(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map(block => {
        if (typeof block === "string") return block;
        if (typeof block === "object" && block !== null && "text" in block) {
          return String((block as any).text);
        }
        return "";
      })
      .join("");
  }
  return String(content);
}

/**
 * Build the output instruction block that gets appended to every user prompt.
 * The schema example is embedded so the model knows exactly what shape to produce.
 */
function buildOutputSpec(example: unknown): string {
  return `
---
OUTPUT SPECIFICATION (MANDATORY — read before responding):

Your response must be ONLY a valid JSON object. Nothing before it. Nothing after it.
Do not use markdown code fences. Do not explain your answer. Start with { and end with }.

Required JSON structure:
${JSON.stringify(example, null, 2)}

If you find no issues, respond with: {"findings": []}
`.trim();
}

// ─── Auditor Output Parser ────────────────────────────────────────────────────

export function parseAuditorOutput(raw: string): {
  findings: Finding[];
  suspicions: Omit<SuspicionNote, "auditorId" | "passNumber">[];
} {
  // Strip thinking blocks FIRST.
  // Qwen3.5 (and other reasoning models) wrap chain-of-thought in <think>...</think>.
  // These blocks contain brackets from code analysis (balances[addr], pools[0], etc.)
  // that corrupt any regex-based JSON finder if left in place.
  const stripped = raw.replace(/<think>[\s\S]*?<\/think>/gi, "").trim();

  const splitIdx = stripped.indexOf("SUSPICIONS:");
  const findingsPart =
    splitIdx >= 0 ? stripped.slice(0, splitIdx).trim() : stripped.trim();
  const suspicionsPart =
    splitIdx >= 0 ? stripped.slice(splitIdx + "SUSPICIONS:".length).trim() : "";

  return {
    findings: parseFindingsArray(findingsPart),
    suspicions: suspicionsPart ? parseSuspicionsArray(suspicionsPart) : [],
  };
}

function parseFindingsArray(text: string): Finding[] {
  if (!text) return [];
  try {
    const parsed = extractJSON(text);
    const arr = Array.isArray(parsed)
      ? parsed
      : ((parsed as any)?.findings ?? []);
    return arr
      .map((item: unknown) => {
        const result = FindingSchema.safeParse(item);
        return result.success ? result.data : null;
      })
      .filter(Boolean) as Finding[];
  } catch {
    return [];
  }
}

function parseSuspicionsArray(
  text: string,
): Omit<SuspicionNote, "auditorId" | "passNumber">[] {
  if (!text) return [];
  try {
    const parsed = extractJSON(text);
    const arr = Array.isArray(parsed) ? parsed : [];
    // SuspicionNoteSchema has auditorId and passNumber as required fields,
    // but the model doesn't emit them — use a partial schema for parsing.
    const PartialSchema = SuspicionNoteSchema.pick({
      targetFile: true,
      targetFunction: true,
      reason: true,
      confidence: true,
    });
    return arr
      .map((item: unknown) => {
        const result = PartialSchema.safeParse(item);
        return result.success ? result.data : null;
      })
      .filter(Boolean) as Omit<SuspicionNote, "auditorId" | "passNumber">[];
  } catch {
    return [];
  }
}
