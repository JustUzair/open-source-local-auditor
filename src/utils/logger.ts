import { env } from "./env.js";

type Level = "debug" | "info" | "warn" | "error";

const LEVEL_RANK: Record<Level, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const LEVEL_PREFIX: Record<Level, string> = {
  debug: "🔍 DEBUG",
  info: "ℹ️  INFO ",
  warn: "⚠️  WARN ",
  error: "❌ ERROR",
};

function log(
  level: Level,
  stage: string,
  message: string,
  data?: unknown,
): void {
  const configured = (env.SENTINEL_LOG_LEVEL ?? "info") as Level;
  if (LEVEL_RANK[level] < LEVEL_RANK[configured]) return;

  const ts = new Date().toLocaleString();
  const tag = `[${ts}] ${LEVEL_PREFIX[level]} [${stage}]`;
  const line = `${tag} ${message}`;

  if (data === undefined) {
    console.log(line);
    return;
  }

  // Pretty-print objects, inline primitives
  if (typeof data === "object" && data !== null) {
    console.log(line);
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(`${line} →`, data);
  }
}

export const logger = {
  debug: (stage: string, msg: string, data?: unknown) =>
    log("debug", stage, msg, data),
  info: (stage: string, msg: string, data?: unknown) =>
    log("info", stage, msg, data),
  warn: (stage: string, msg: string, data?: unknown) =>
    log("warn", stage, msg, data),
  error: (stage: string, msg: string, data?: unknown) =>
    log("error", stage, msg, data),
};
