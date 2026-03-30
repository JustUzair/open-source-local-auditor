import { z } from "zod";
import { ProtocolMap, SuspicionNote, ProtocolSize } from "./protocol.js";

// ─── Finding Schemas ──────────────────────────────────────────────────────────

export const SeverityEnum = z.enum([
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
]);
export type Severity = z.infer<typeof SeverityEnum>;

export const FindingSchema = z.object({
  severity: SeverityEnum,
  title: z.string().min(5),
  file: z.string(),
  /** Line number in the file. 0 if not determinable. */
  line: z.number().int().nonnegative(),
  /** Clear description of what the vulnerability is. */
  description: z.string().min(20),
  /** Concrete exploit path — how an attacker would use this. */
  exploit: z.string().min(10),
  /** Concrete fix recommendation. */
  recommendation: z.string().min(10),
});
export type Finding = z.infer<typeof FindingSchema>;

export const SuspicionNoteSchema = z.object({
  targetFile: z.string(),
  targetFunction: z.string().optional(),
  reason: z.string().min(10),
  confidence: z.number().min(0).max(1),
});

export const AgentOutputSchema = z.object({
  findings: z.array(FindingSchema),
  suspicions: z.array(SuspicionNoteSchema).optional().default([]),
});
export type AgentOutput = z.infer<typeof AgentOutputSchema>;

// Attach example — used by invokeWithSchema to embed in the LLM prompt.
// This is the mechanism for provider-agnostic structured output.
(AgentOutputSchema as any)._example = {
  findings: [
    {
      severity: "High",
      title: "Reentrancy in withdraw()",
      file: "Vault.sol",
      line: 68,
      description:
        "The withdraw() function sends ETH to the caller before updating the internal balance. An attacker can re-enter withdraw() before their balance is zeroed, draining the vault.",
      exploit:
        "Deploy an attacker contract with a receive() fallback that calls vault.withdraw(). Call vault.deposit{value:1 ether}(), then vault.withdraw(1 ether). The fallback fires before balances[attacker] is decremented, enabling repeated withdrawals.",
      recommendation:
        "Update balances[msg.sender] = 0 before the external call. Or add OpenZeppelin ReentrancyGuard and the nonReentrant modifier.",
    },
  ],
};

// ─── Supervisor Output ────────────────────────────────────────────────────────

export const FinalFindingSchema = FindingSchema.extend({
  /**
   * 0.0–1.0. Boosted when multiple auditors flag the same issue.
   * Base: 0.6 (1 auditor). +0.2 per additional auditor. Max: 1.0.
   */
  confidence: z.number().min(0).max(1),
  /** Which auditor IDs flagged this, e.g. ["auditor-1", "auditor-2"] */
  flaggedByAuditors: z.array(z.string()),
  /** Which agent roles found this, e.g. ["logical-bugs", "contextual"] */
  agentRoles: z.array(z.string()),
});
export type FinalFinding = z.infer<typeof FinalFindingSchema>;

export const SupervisorOutputSchema = z.object({
  findings: z.array(FinalFindingSchema),
});
export type SupervisorOutput = z.infer<typeof SupervisorOutputSchema>;

(SupervisorOutputSchema as any)._example = {
  findings: [
    {
      severity: "High",
      title: "Reentrancy in withdraw()",
      file: "Vault.sol",
      line: 68,
      description: "...",
      exploit: "...",
      recommendation: "...",
      confidence: 0.8,
      flaggedByAuditors: ["auditor-1"],
      agentRoles: ["logical-bugs"],
    },
  ],
};

// ─── Agent Pipeline Types ─────────────────────────────────────────────────────

export type AgentRole = "logical-bugs" | "common-pitfalls" | "contextual";

export interface AgentResult {
  auditorId: string;
  agentRole: AgentRole;
  model: string;
  status: "ok" | "failed" | "empty";
  findings: Finding[];
  /** Set when status === "failed". Contains the parse/validation error. */
  error?: string;
  /** Always stored for debugging. Truncated to 1000 chars in logs. */
  rawResponse?: string;
  thinkingContent?: string;
}

export interface AuditorResult {
  auditorId: string;
  model: string;
  agents: AgentResult[];
  /** Flat union of all findings from all 3 agents of this auditor. */
  allFindings: Finding[];
}

// ─── Report + Engine Output ───────────────────────────────────────────────────

export interface AuditMeta {
  filesAudited: string[];
  auditorsRun: number;
  auditorModels: string[];
  supervisorModel: string;
  timestamp: string;
  durationMs: number;
}

export interface AuditReport {
  markdown: string;
  findings: FinalFinding[];
  meta: AuditMeta;
}

export type AuditResult =
  | {
      ok: true;
      report: AuditReport;
      findings: FinalFinding[];
      debug: {
        protocolMap: ProtocolMap;
        allSuspicionNotes: SuspicionNote[]; // every note emitted, including discarded ones
        propagatedSuspicions: SuspicionNote[]; // notes that passed confidence threshold
        auditorResults: AuditorResult[];
        passCount: number; // actual passes completed
        protocolSize: ProtocolSize;
      };
    }
  | {
      ok: false;
      error: string;
      stage: string;
    };
