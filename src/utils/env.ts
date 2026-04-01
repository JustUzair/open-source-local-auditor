import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

const Provider = z.enum(["ollama", "gemini", "groq", "openai", "anthropic"]);
const EmbedProvider = z.enum(["ollama", "gemini", "openai"]);
const LogLevel = z.enum(["debug", "info", "warn", "error"]).default("info");

// Helper to convert empty string to undefined
const emptyToUndef = z.preprocess(
  val => (val === "" ? undefined : val),
  z.any(),
);

const EnvSchema = z
  .object({
    N_AUDITORS: z.coerce.number().int().min(1).max(3).default(1),

    // Auditor 1 (always required)
    AUDITOR_1_PROVIDER: Provider.default("ollama"),
    AUDITOR_1_MODEL: z.string().min(1).default("qwen-junior-auditor"),
    AUDITOR_1_API_KEY: emptyToUndef.pipe(z.string().optional()),
    /** Ollama base URL for this auditor's machine. Falls back to OLLAMA_BASE_URL. */
    AUDITOR_1_OLLAMA_URL: emptyToUndef.pipe(z.string().url().optional()),

    // Auditor 2 (conditionally required)
    AUDITOR_2_PROVIDER: emptyToUndef.pipe(Provider.optional()),
    AUDITOR_2_MODEL: emptyToUndef.pipe(z.string().min(1).optional()),
    AUDITOR_2_API_KEY: emptyToUndef.pipe(z.string().optional()),
    AUDITOR_2_OLLAMA_URL: emptyToUndef.pipe(z.string().url().optional()),

    // Auditor 3 (conditionally required)
    AUDITOR_3_PROVIDER: emptyToUndef.pipe(Provider.optional()),
    AUDITOR_3_MODEL: emptyToUndef.pipe(z.string().min(1).optional()),
    AUDITOR_3_API_KEY: emptyToUndef.pipe(z.string().optional()),
    AUDITOR_3_OLLAMA_URL: emptyToUndef.pipe(z.string().url().optional()),

    // Supervisor
    SUPERVISOR_PROVIDER: Provider,
    SUPERVISOR_MODEL: z.string().min(1).default("glm-supervisor"),
    SUPERVISOR_API_KEY: z.string().default(""),
    /** Ollama base URL for the supervisor machine. Falls back to OLLAMA_BASE_URL. */
    SUPERVISOR_OLLAMA_URL: emptyToUndef.pipe(z.string().url().optional()),

    // Embeddings
    EMBEDDING_PROVIDER: EmbedProvider,
    EMBEDDING_MODEL: z.string().min(1).default("qwen3-embedding:4b"),
    EMBEDDING_API_KEY: z.string().default(""),

    OLLAMA_BASE_URL: z.string().url().default("http://localhost:11434"),
    PORT: z.coerce.number().int().positive().default(8000),
    ALLOWED_ORIGIN: z.string().default("http://localhost:3000"),
    SOLODIT_API_KEY: z.string().default(""),
    DATA_DIR: z.string().min(1).default("./data"),
    SENTINEL_LOG_LEVEL: LogLevel,
    NODE_ENV: z
      .enum(["development", "production", "test"])
      .default("development"),

    // ── Audit engine ─────────────────────────────────────────────────────
    /** Context window of the auditor model in tokens. Qwen3.5 9B = 32768. */
    CONTEXT_WINDOW: z.coerce.number().int().positive().optional(),
    /** Maximum audit passes before forced stop. */
    MAX_AUDIT_PASSES: z.coerce.number().int().min(1).max(10).default(3),
    /** Minimum confidence for a suspicion note to propagate. */
    MIN_SUSPICION_CONFIDENCE: z.coerce.number().min(0).max(1).default(0.7),
    /** Max files at full content per batch. */
    MAX_FULL_FILES_PER_BATCH: z.coerce.number().int().min(1).default(10),
    /** Enable Qwen3.5 extended thinking (chain-of-thought). */
    THINKING_ENABLED: z
      .string()
      .transform(v => v === "true" || v === "1")
      .default("false"),
  })
  .superRefine((data, ctx) => {
    const n = data.N_AUDITORS;

    // Auditor 2 required if N_AUDITORS >= 2
    if (n >= 2) {
      if (!data.AUDITOR_2_PROVIDER) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["AUDITOR_2_PROVIDER"],
          message: "Required when N_AUDITORS >= 2",
        });
      }
      if (!data.AUDITOR_2_MODEL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["AUDITOR_2_MODEL"],
          message: "Required when N_AUDITORS >= 2",
        });
      }
    }

    // Auditor 3 required if N_AUDITORS >= 3
    if (n >= 3) {
      if (!data.AUDITOR_3_PROVIDER) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["AUDITOR_3_PROVIDER"],
          message: "Required when N_AUDITORS >= 3",
        });
      }
      if (!data.AUDITOR_3_MODEL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["AUDITOR_3_MODEL"],
          message: "Required when N_AUDITORS >= 3",
        });
      }
    }
  });

export type Env = z.infer<typeof EnvSchema>;

let _validated: Env | undefined;

function validate(): Env {
  if (_validated) return _validated;

  const result = EnvSchema.safeParse(process.env);

  if (!result.success) {
    // Print every failing field before exiting, not just the first one.
    console.error("\n❌  SentinelAI | invalid environment configuration:\n");
    for (const issue of result.error.issues) {
      const path = issue.path.length ? issue.path.join(".") : "(root)";
      console.error(`   ${path}: ${issue.message}`);
    }
    console.error("\nSee .env.example for the full reference.\n");
    process.exit(1);
  }

  _validated = result.data;
  return _validated;
}

/**
 * Lazy proxy, validates once on first field access.
 * Import this anywhere: `import { env } from "./env.js"`
 */
export const env = new Proxy({} as Env, {
  get(_target, key: string) {
    return validate()[key as keyof Env];
  },
});
