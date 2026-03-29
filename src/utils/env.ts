import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

const Provider = z.enum(["ollama", "gemini", "groq", "openai", "anthropic"]);
const EmbedProvider = z.enum(["ollama", "gemini", "openai"]);
const LogLevel = z.enum(["debug", "info", "warn", "error"]).default("info");

const EnvSchema = z.object({
  // ── Auditor count ──────────────────────────────────────────────────────────
  N_AUDITORS: z.coerce.number().int().min(1).max(3).default(1),

  // ── Auditor 1 (always required) ────────────────────────────────────────────
  AUDITOR_1_PROVIDER: Provider.default("ollama"),
  AUDITOR_1_MODEL: z.string().min(1).default("qwen-junior-auditor"),
  AUDITOR_1_API_KEY: z.string().default(""),

  // ── Auditor 2 (required when N_AUDITORS >= 2) ──────────────────────────────
  AUDITOR_2_PROVIDER: Provider.default("ollama"),
  AUDITOR_2_MODEL: z.string().default("qwen-senior-auditor"),
  AUDITOR_2_API_KEY: z.string().default(""),

  // ── Auditor 3 (required when N_AUDITORS >= 3) ──────────────────────────────
  AUDITOR_3_PROVIDER: Provider.default("ollama"),
  AUDITOR_3_MODEL: z.string().default("glm-senior-auditor"),
  AUDITOR_3_API_KEY: z.string().default(""),

  // ── Supervisor ─────────────────────────────────────────────────────────────
  SUPERVISOR_PROVIDER: Provider.default("ollama"),
  SUPERVISOR_MODEL: z.string().min(1).default("glm-supervisor"),
  SUPERVISOR_API_KEY: z.string().default(""),

  // ── Embeddings ─────────────────────────────────────────────────────────────
  EMBEDDING_PROVIDER: EmbedProvider.default("gemini"),
  EMBEDDING_MODEL: z.string().min(1).default("gemini-embedding-001"),
  EMBEDDING_API_KEY: z.string().default(""),

  // ── Local services ─────────────────────────────────────────────────────────
  OLLAMA_BASE_URL: z.string().url().default("http://localhost:11434"),

  // ── Web server ─────────────────────────────────────────────────────────────
  PORT: z.coerce.number().int().positive().default(8000),
  ALLOWED_ORIGIN: z.string().default("http://localhost:3000"),

  // ── Data sources ───────────────────────────────────────────────────────────
  SOLODIT_API_KEY: z.string().default(""),

  // ── Paths ──────────────────────────────────────────────────────────────────
  DATA_DIR: z.string().min(1).default("./data"),

  // ── Developer ──────────────────────────────────────────────────────────────
  SENTINEL_LOG_LEVEL: LogLevel,
  NODE_ENV: z
    .enum(["development", "production", "test"])
    .default("development"),
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
