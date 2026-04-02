/**
 * src/core/prescanner.ts — Deterministic Pre-Scanner
 *
 * Runs regex-based vulnerability patterns against source files before any LLM call.
 * Produces ScanLead[] — structured suspicious locations with file:line evidence.
 *
 * These leads are injected into the audit prompt as "verify these first" targets,
 * changing the LLM's job from open-ended discovery to structured verification + extension.
 *
 * Architecture:
 *   LANGUAGE REGISTRY → per-language patterns → common ScanLead output
 *   Adding a new language: implement patterns, register in PATTERN_REGISTRY
 *
 * Performance: < 1 second on any codebase. Zero LLM calls. Zero network.
 */

import { logger } from "../utils/logger.js";
import type { SourceFile } from "../types/protocol.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ScanLead {
  patternId: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  file: string;
  line: number;
  snippet: string;
  signal: string;
  verify: string;
  category: string;
  language: string;
}

interface PatternCheck {
  id: string;
  severity: ScanLead["severity"];
  confidence: number;
  category: string;
  check: (
    line: string,
    lineIdx: number,
    lines: string[],
    ctx: FileContext,
    filePath: string,
  ) => Omit<ScanLead, "file" | "language"> | null;
}

interface FileContext {
  content: string;
  lower: string;
  hasSafeERC20: boolean;
  hasReentrancyGuard: boolean;
  hasChainId: boolean;
  hasSafeMath: boolean;
  pragmaMinor: number;
  reportedIds: Set<string>;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function linesAround(lines: string[], fromIdx: number, count: number): string {
  return lines
    .slice(fromIdx, Math.min(fromIdx + count, lines.length))
    .join("\n");
}

function linesBefore(lines: string[], fromIdx: number, count: number): string {
  return lines.slice(Math.max(0, fromIdx - count), fromIdx).join("\n");
}

// ─── Solidity Pattern Registry (all 45+ patterns from the Python script) ─────

const SOLIDITY_PATTERNS: PatternCheck[] = [
  // ── ETH-001: CEI Violation ────────────────────────────────────────────────
  {
    id: "ETH-001",
    severity: "CRITICAL",
    confidence: 0.8,
    category: "reentrancy",
    check(line, idx, lines, ctx) {
      if (!line.includes(".call{value:") && !line.includes(".call{ value:"))
        return null;
      if (linesBefore(lines, idx, 5).toLowerCase().includes("nonreentrant"))
        return null;
      if (ctx.reportedIds.has("ETH-001")) return null;
      const ahead = linesAround(lines, idx + 1, 20);
      const hasStateUpdate =
        /\w+\[.*?\]\s*[-+*]?=\s/.test(ahead) ||
        /balance\w*\s*[-+]?=/.test(ahead) ||
        /\b(state|total|amount|counter|reserved)\w*\s*[-+]?=/.test(ahead);
      if (!hasStateUpdate) return null;
      ctx.reportedIds.add("ETH-001");
      return {
        patternId: "ETH-001",
        severity: "CRITICAL",
        confidence: 0.8,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "External call with value transfer detected BEFORE state update (CEI violation)",
        verify:
          "Is nonReentrant present on this function? Is state (pool.reserved, balances, etc.) updated BEFORE this call?",
        category: "reentrancy",
      };
    },
  },

  // ── ETH-004: Read-only Reentrancy ────────────────────────────────────────
  {
    id: "ETH-004",
    severity: "HIGH",
    confidence: 0.7,
    category: "reentrancy",
    check(line, idx, lines, ctx) {
      if (ctx.reportedIds.has("ETH-004")) return null;
      if (
        (line.includes("receive()") || line.includes("fallback()")) &&
        line.includes("external")
      ) {
        for (let j = idx; j < Math.min(idx + 15, lines.length); j++) {
          const ctxLine = lines[j];
          if (
            /(target|vuln|victim)\w*\.\w+\(/.test(ctxLine) ||
            ctxLine.includes("get_virtual_price") ||
            ctxLine.includes("getReward")
          ) {
            ctx.reportedIds.add("ETH-004");
            return {
              patternId: "ETH-004",
              severity: "HIGH",
              confidence: 0.7,
              line: idx + 1,
              snippet: line.trim(),
              signal:
                "Callback (receive/fallback) reads external state during reentrancy window.",
              verify:
                "Use reentrancy-aware oracles or check reentrancy lock in view functions.",
              category: "reentrancy",
            };
          }
        }
      }
      if (
        line.includes("view") &&
        line.includes("function") &&
        (line.includes("external") || line.includes("public")) &&
        ctx.lower.includes("get_virtual_price") &&
        ctx.lower.includes("remove_liquidity")
      ) {
        ctx.reportedIds.add("ETH-004");
        return {
          patternId: "ETH-004",
          severity: "HIGH",
          confidence: 0.65,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "View function returns state dependent on external oracle, exploitable during reentrancy.",
          verify:
            "Use reentrancy-aware oracles or check reentrancy lock in view functions.",
          category: "reentrancy",
        };
      }
      return null;
    },
  },

  // ── ETH-006: Missing Access Control ──────────────────────────────────────
  {
    id: "ETH-006",
    severity: "CRITICAL",
    confidence: 0.7,
    category: "access-control",
    check(line, idx, lines, ctx, filePath) {
      if (
        !line.includes("function") ||
        (!line.includes("external") && !line.includes("public"))
      )
        return null;
      const funcMatch = line.match(/function\s+(\w+)/);
      if (!funcMatch) return null;
      const fname = funcMatch[1].toLowerCase();
      const sensitiveNames = [
        "withdraw",
        "mint",
        "burn",
        "upgrade",
        "setowner",
        "setfee",
        "setprice",
        "setoracle",
        "setsigner",
        "pause",
        "unpause",
        "kill",
        "destroy",
        "removeliquidity",
        "removefee",
        "addfee",
        "addliquidity",
      ];
      if (!sensitiveNames.some(s => fname.includes(s))) return null;
      const hasModifier = [
        "onlyOwner",
        "onlyRole",
        "onlyAdmin",
        "only",
        "auth",
        "restricted",
        "initializer",
        "nonReentrant",
      ].some(m => line.includes(m));
      if (hasModifier) return null;
      const ahead = linesAround(lines, idx + 1, 6);
      if (!/\b\w+\s*=\s*[^=]/.test(ahead)) return null;
      return {
        patternId: "ETH-006",
        severity: "CRITICAL",
        confidence: 0.7,
        line: idx + 1,
        snippet: line.trim(),
        signal: `Sensitive function '${funcMatch[1]}' modifies state without access control modifier`,
        verify:
          "Is access control enforced via a modifier, require(), or caller validation anywhere in this function or its callers?",
        category: "access-control",
      };
    },
  },

  // ── ETH-007: tx.origin Authentication ────────────────────────────────────
  {
    id: "ETH-007",
    severity: "CRITICAL",
    confidence: 0.9,
    category: "access-control",
    check(line, idx) {
      if (!line.includes("tx.origin")) return null;
      if (!line.includes("require") && !line.includes("if")) return null;
      return {
        patternId: "ETH-007",
        severity: "CRITICAL",
        confidence: 0.9,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "tx.origin used for authentication — phishable via intermediate contract",
        verify:
          "Replace tx.origin with msg.sender. Is there any legitimate use case here?",
        category: "access-control",
      };
    },
  },

  // ── ETH-008: selfdestruct ────────────────────────────────────────────────
  {
    id: "ETH-008",
    severity: "HIGH",
    confidence: 0.75,
    category: "access-control",
    check(line, idx) {
      if (!line.includes("selfdestruct") && !line.includes("suicide"))
        return null;
      return {
        patternId: "ETH-008",
        severity: "HIGH",
        confidence: 0.75,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "selfdestruct found. Check access control and proxy implications.",
        verify:
          "Ensure selfdestruct has proper access control. Consider removing if not needed.",
        category: "access-control",
      };
    },
  },

  // ── ETH-009: Unprotected Ownership Function ───────────────────────────────
  {
    id: "ETH-009",
    severity: "CRITICAL",
    confidence: 0.85,
    category: "access-control",
    check(line, idx) {
      const funcMatch = line.match(/function\s+(\w+)/);
      if (!funcMatch) return null;
      const fname = funcMatch[1].toLowerCase();
      const ownerFuncs = [
        "changeowner",
        "setowner",
        "transferownership",
        "updateowner",
      ];
      if (!ownerFuncs.includes(fname)) return null;
      const hasMod = ["onlyOwner", "only", "auth"].some(m => line.includes(m));
      if (hasMod) return null;
      return {
        patternId: "ETH-009",
        severity: "CRITICAL",
        confidence: 0.85,
        line: idx + 1,
        snippet: line.trim(),
        signal: "Ownership change function accessible without access control.",
        verify: "Add onlyOwner modifier to restrict access.",
        category: "access-control",
      };
    },
  },

  // ── ETH-010: Uninitialized Proxy / Public init() ─────────────────────────
  {
    id: "ETH-010",
    severity: "CRITICAL",
    confidence: 0.85,
    category: "proxy",
    check(line, idx, lines) {
      if (
        !/function\s+(init|initialize)\s*\(/.test(line) ||
        (!line.includes("public") && !line.includes("external"))
      )
        return null;
      let hasInitMod = line.includes("initializer");
      if (!hasInitMod) {
        for (let j = idx; j < Math.min(idx + 3, lines.length); j++) {
          const ctx = lines[j];
          if (
            ctx.includes("initializer") ||
            ctx.includes("initialized") ||
            ctx.includes("require(!_initialized")
          ) {
            hasInitMod = true;
            break;
          }
        }
      }
      if (hasInitMod) return null;
      return {
        patternId: "ETH-010",
        severity: "CRITICAL",
        confidence: 0.85,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "Public init/initialize function without initializer modifier. Anyone can call it to take ownership.",
        verify:
          "Add OpenZeppelin initializer modifier or require(!initialized) check.",
        category: "proxy",
      };
    },
  },

  // ── ETH-012: Hidden Backdoor via Assembly ─────────────────────────────────
  {
    id: "ETH-012",
    severity: "HIGH",
    confidence: 0.65,
    category: "access-control",
    check(line, idx, lines, ctx) {
      if (!line.includes("sstore")) return null;
      if (!ctx.lower.includes("assembly")) return null;
      return {
        patternId: "ETH-012",
        severity: "HIGH",
        confidence: 0.65,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "Assembly sstore — Potential Backdoor. Direct storage write may indicate hidden state manipulation.",
        verify:
          "Review assembly sstore usage. Ensure no unauthorized storage modifications.",
        category: "access-control",
      };
    },
  },

  // ── ETH-013: Unchecked Arithmetic ─────────────────────────────────────────
  {
    id: "ETH-013",
    severity: "HIGH",
    confidence: 0.7,
    category: "arithmetic",
    check(line, idx, lines, ctx) {
      if (line.includes("unchecked") && line.includes("{")) {
        const ahead = linesAround(lines, idx, 10);
        if (/[+\-*]/.test(ahead)) {
          return {
            patternId: "ETH-013",
            severity: "HIGH",
            confidence: 0.7,
            line: idx + 1,
            snippet: line.trim(),
            signal: "unchecked {} block disables overflow/underflow protection",
            verify:
              "Are all values inside this block guaranteed by invariants to never overflow? Are any user-controlled inputs involved?",
            category: "arithmetic",
          };
        }
      }
      // old pragma without SafeMath
      if (ctx.pragmaMinor < 8 && !ctx.hasSafeMath) {
        if (
          /[\w\]]\s*[-+\*]=\s*\w/.test(line) ||
          /\w+\s*=\s*\w+\s*[-+\*]\s*\w/.test(line)
        ) {
          if (
            !line.includes("function") &&
            !line.includes("pragma") &&
            !line.includes("import") &&
            !line.includes("event")
          ) {
            return {
              patternId: "ETH-013",
              severity: "HIGH",
              confidence: 0.8,
              line: idx + 1,
              snippet: line.trim(),
              signal:
                "Arithmetic Without Overflow Protection (pre-0.8.0). No SafeMath detected.",
              verify:
                "Upgrade to Solidity >= 0.8.0 or use OpenZeppelin SafeMath library.",
              category: "arithmetic",
            };
          }
        }
      }
      // unsafe downcast
      const downcast = line.match(/\buint(8|16|32|64|128)\s*\(/);
      if (downcast && !line.includes("function") && !line.includes("event")) {
        return {
          patternId: "ETH-013",
          severity: "HIGH",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal: `Unsafe integer downcast to uint${downcast[1]} may silently truncate larger values.`,
          verify:
            "Use OpenZeppelin SafeCast library or validate value fits in target type.",
          category: "arithmetic",
        };
      }
      return null;
    },
  },

  // ── ETH-014: Division Before Multiplication ───────────────────────────────
  {
    id: "ETH-014",
    severity: "MEDIUM",
    confidence: 0.7,
    category: "arithmetic",
    check(line, idx) {
      if (
        /[\w\)]\s*\/\s*[\w\(]+[\w\)]\s*\)\s*\*\s*\w+/.test(line) ||
        /\b\w+\s*\/\s*\w+\s*\*\s*\w+/.test(line)
      ) {
        if (!line.startsWith("//") && !line.startsWith("/*")) {
          return {
            patternId: "ETH-014",
            severity: "MEDIUM",
            confidence: 0.7,
            line: idx + 1,
            snippet: line.trim(),
            signal:
              "Division before multiplication causes precision loss due to integer truncation.",
            verify:
              "Reorder to multiply first: (a * c) / b instead of (a / b) * c.",
            category: "arithmetic",
          };
        }
      }
      return null;
    },
  },

  // ── ETH-017: Precision Loss ───────────────────────────────────────────────
  {
    id: "ETH-017",
    severity: "MEDIUM",
    confidence: 0.7,
    category: "arithmetic",
    check(line, idx, lines, ctx) {
      if (ctx.reportedIds.has("ETH-017")) return null;
      if (
        /\s*\/\s*\(?\s*(?:\d+\s*(?:days|hours|minutes|seconds)\s*\*\s*1e\d+|1e\d{2,})/.test(
          line,
        )
      ) {
        ctx.reportedIds.add("ETH-017");
        return {
          patternId: "ETH-017",
          severity: "MEDIUM",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Division by very large denominator (1eN). Small numerators will round to zero.",
          verify:
            "Use higher precision intermediates or mulDiv for precise division.",
          category: "arithmetic",
        };
      }
      if (
        /\b\w+\s*\/\s*\w+\s*;/.test(line) &&
        !line.includes("10") &&
        /price|rate|ratio|share|reward|precision|debt/.test(ctx.lower)
      ) {
        ctx.reportedIds.add("ETH-017");
        return {
          patternId: "ETH-017",
          severity: "MEDIUM",
          confidence: 0.55,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Integer division truncates result. May cause precision loss in financial calculations.",
          verify:
            "Use higher precision intermediates or mulDiv for precise division.",
          category: "arithmetic",
        };
      }
      return null;
    },
  },

  // ── ETH-018: Unchecked External Call Return ───────────────────────────────
  {
    id: "ETH-018",
    severity: "HIGH",
    confidence: 0.7,
    category: "external-calls",
    check(line, idx, lines) {
      if (!line.includes(".call(") && !line.includes(".call{")) return null;
      let hasCheck = false;
      for (let j = idx; j < Math.min(idx + 4, lines.length); j++) {
        const ctx = lines[j];
        if (/require|if.*success|assert/.test(ctx) || ctx.includes("success")) {
          hasCheck = true;
          break;
        }
      }
      if (hasCheck) return null;
      return {
        patternId: "ETH-018",
        severity: "HIGH",
        confidence: 0.7,
        line: idx + 1,
        snippet: line.trim(),
        signal: "Low-level .call() return value not checked in next 4 lines",
        verify:
          "Is the success boolean captured and checked? A failing call silently continues.",
        category: "external-calls",
      };
    },
  },

  // ── ETH-019: delegatecall ─────────────────────────────────────────────────
  {
    id: "ETH-019",
    severity: "CRITICAL",
    confidence: 0.75,
    category: "external-calls",
    check(line, idx) {
      if (!line.includes("delegatecall(")) return null;
      return {
        patternId: "ETH-019",
        severity: "CRITICAL",
        confidence: 0.75,
        line: idx + 1,
        snippet: line.trim(),
        signal: "delegatecall executes code in caller's storage context",
        verify:
          "Is the delegatecall target a trusted, immutable address? Can an attacker control the target address?",
        category: "external-calls",
      };
    },
  },

  // ── ETH-021: DoS with Failed Call ─────────────────────────────────────────
  {
    id: "ETH-021",
    severity: "HIGH",
    confidence: 0.7,
    category: "gas-dos",
    check(line, idx, lines, ctx) {
      if (ctx.reportedIds.has("ETH-021")) return null;
      // .transfer/.send in loop
      if (
        (line.includes(".transfer(") || line.includes(".send(")) &&
        ctx.lower.includes("for")
      ) {
        ctx.reportedIds.add("ETH-021");
        return {
          patternId: "ETH-021",
          severity: "HIGH",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            ".transfer()/.send() in loop context. Single failure reverts entire batch.",
          verify:
            "Use pull-payment pattern. Let recipients withdraw instead of pushing funds.",
          category: "gas-dos",
        };
      }
      // call{value:} + require(sent)
      if (line.includes(".call{value:") || line.includes(".call{ value:")) {
        for (let j = idx; j < Math.min(idx + 3, lines.length); j++) {
          const ctxLine = lines[j];
          if (/require\s*\(\s*\w+\s*,/.test(ctxLine)) {
            ctx.reportedIds.add("ETH-021");
            return {
              patternId: "ETH-021",
              severity: "HIGH",
              confidence: 0.65,
              line: idx + 1,
              snippet: line.trim(),
              signal:
                "External call with required success. If callee reverts, function is permanently blocked.",
              verify:
                "Use pull-payment pattern or continue on failure. Don't require external call success.",
              category: "gas-dos",
            };
          }
        }
      }
      return null;
    },
  },

  // ── ETH-024: Oracle Manipulation (spot price) ────────────────────────────
  {
    id: "ETH-024",
    severity: "CRITICAL",
    confidence: 0.8,
    category: "oracle",
    check(line, idx, lines, ctx) {
      if (ctx.reportedIds.has("ETH-024")) return null;
      const hasReserves =
        line.includes("getReserves()") &&
        /rate|price|borrow|liquidat|collateral|value/.test(ctx.lower);
      const hasBalanceOfPricing =
        line.includes("balanceOf(address(this))") &&
        /price|rate|oracle|getprice/.test(ctx.lower);
      if (!hasReserves && !hasBalanceOfPricing) return null;
      ctx.reportedIds.add("ETH-024");
      return {
        patternId: "ETH-024",
        severity: "CRITICAL",
        confidence: 0.8,
        line: idx + 1,
        snippet: line.trim(),
        signal: hasReserves
          ? "getReserves() spot price used for financial calculation — flash-loan manipulable in same tx"
          : "balanceOf(address(this)) used for pricing — manipulable via donation or flash loan",
        verify:
          "Is a TWAP oracle or Chainlink feed used instead of spot price? Is there same-block manipulation protection?",
        category: "oracle",
      };
    },
  },

  // ── ETH-025: Flash Loan Pattern ──────────────────────────────────────────
  {
    id: "ETH-025",
    severity: "HIGH",
    confidence: 0.65,
    category: "oracle",
    check(line, idx) {
      if (/function\s+flashLoan|flashMint|flashBorrow/i.test(line)) {
        return {
          patternId: "ETH-025",
          severity: "HIGH",
          confidence: 0.65,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Flash loan function detected. Verify all dependent state is flash-loan resistant.",
          verify:
            "Add same-block protection. Ensure oracle prices are not manipulable within a single tx.",
          category: "oracle",
        };
      }
      return null;
    },
  },

  // ── ETH-026: MEV / Sandwich Attack Risk ──────────────────────────────────
  {
    id: "ETH-026",
    severity: "HIGH",
    confidence: 0.7,
    category: "defi",
    check(line, idx, lines, ctx) {
      if (ctx.reportedIds.has("ETH-026")) return null;
      if (!/swap|exactInput|swapExact/i.test(line)) return null;
      let hasSlippage = false;
      let hasDeadline = false;
      for (
        let j = Math.max(0, idx - 5);
        j < Math.min(idx + 10, lines.length);
        j++
      ) {
        const ctxLine = lines[j];
        if (/minAmount|amountOutMin|slippage|minReturn/i.test(ctxLine))
          hasSlippage = true;
        if (/deadline|block\.timestamp/.test(ctxLine)) hasDeadline = true;
      }
      if (hasSlippage && hasDeadline) return null;
      ctx.reportedIds.add("ETH-026");
      return {
        patternId: "ETH-026",
        severity: "HIGH",
        confidence: 0.7,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "Swap operation without slippage protection or deadline. Vulnerable to sandwich attacks.",
        verify:
          "Add minimum output amount and transaction deadline parameters.",
        category: "defi",
      };
    },
  },

  // ── ETH-027: Zero Slippage Protection ─────────────────────────────────────
  {
    id: "ETH-027",
    severity: "HIGH",
    confidence: 0.85,
    category: "defi",
    check(line, idx) {
      const zeroSlippage =
        /amountOutMin.*:\s*0\b/.test(line) ||
        /amountOut(?:Minimum|Min)\s*:\s*0\b/.test(line) ||
        /swap\w*\([^,]+,\s*0\s*,/.test(line);
      if (!zeroSlippage) return null;
      return {
        patternId: "ETH-027",
        severity: "HIGH",
        confidence: 0.85,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "Swap accepts zero minimum output — any slippage including total loss is accepted",
        verify:
          "Can the user specify their own minAmountOut? Is this intentional (gas optimization) or a missing parameter?",
        category: "defi",
      };
    },
  },

  // ── ETH-028: Stale Oracle (no staleness check) ────────────────────────────
  {
    id: "ETH-028",
    severity: "HIGH",
    confidence: 0.8,
    category: "oracle",
    check(line, idx, lines, ctx) {
      if (!line.includes("latestRoundData")) return null;
      if (ctx.reportedIds.has("ETH-028")) return null;
      let hasStaleness = false;
      for (let j = idx; j < Math.min(idx + 12, lines.length); j++) {
        const ctxLine = lines[j];
        if (
          ctxLine.includes("updatedAt") ||
          ctxLine.includes("answeredInRound")
        ) {
          hasStaleness = true;
          break;
        }
      }
      if (hasStaleness) return null;
      ctx.reportedIds.add("ETH-028");
      return {
        patternId: "ETH-028",
        severity: "HIGH",
        confidence: 0.8,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "Chainlink latestRoundData() called without checking updatedAt for staleness",
        verify:
          "Is there a require(updatedAt > block.timestamp - MAX_DELAY) check anywhere in this function? Stale price can be used to manipulate protocol.",
        category: "oracle",
      };
    },
  },

  // ── ETH-029: Uninitialized Storage Pointer ────────────────────────────────
  {
    id: "ETH-029",
    severity: "HIGH",
    confidence: 0.65,
    category: "storage",
    check(line, idx) {
      if (
        /\bstorage\b/.test(line) &&
        !line.includes("function") &&
        !line.includes("pragma")
      ) {
        if (!line.includes("=")) {
          return {
            patternId: "ETH-029",
            severity: "HIGH",
            confidence: 0.65,
            line: idx + 1,
            snippet: line.trim(),
            signal:
              "Storage pointer declared without initialization. May point to unexpected slot.",
            verify:
              "Initialize storage pointers explicitly. Use memory for local variables.",
            category: "storage",
          };
        }
      }
      return null;
    },
  },

  // ── ETH-030: Storage Collision (Proxy) ────────────────────────────────────
  {
    id: "ETH-030",
    severity: "CRITICAL",
    confidence: 0.7,
    category: "storage",
    check(line, idx, lines, ctx) {
      if (ctx.reportedIds.has("ETH-030")) return null;
      // delegatecall in proxy pattern
      if (
        line.includes("delegatecall") &&
        ctx.lower.includes("implementation")
      ) {
        ctx.reportedIds.add("ETH-030");
        return {
          patternId: "ETH-030",
          severity: "CRITICAL",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "delegatecall in proxy pattern. Storage layout mismatch causes slot collision.",
          verify:
            "Use EIP-1967 storage slots. Ensure proxy and impl have compatible storage layouts.",
          category: "storage",
        };
      }
      // state variable in proxy contract
      if (line.match(/contract\s+\w+\s+is\s+\w*(?:Proxy|Upgradeable)/)) {
        for (let j = idx + 1; j < Math.min(idx + 15, lines.length); j++) {
          const ctxLine = lines[j];
          if (
            /^\s+(?:address|uint256|bytes32|bool)\s+(?:private|internal)\s+\w+/.test(
              ctxLine,
            )
          ) {
            const codePart = ctxLine.split("//")[0];
            if (
              !codePart.includes("constant") &&
              !codePart.includes("immutable") &&
              !codePart.toUpperCase().includes("_SLOT")
            ) {
              ctx.reportedIds.add("ETH-030");
              return {
                patternId: "ETH-030",
                severity: "CRITICAL",
                confidence: 0.8,
                line: j + 1,
                snippet: ctxLine.trim(),
                signal:
                  "State variable in proxy contract collides with implementation slot 0.",
                verify:
                  "Remove state variables from proxy. Use EIP-1967 storage slots.",
                category: "storage",
              };
            }
          }
          if (/^\s*(function|constructor|event)/.test(ctxLine)) break;
        }
      }
      // mutable storage slot
      if (
        /bytes32\s+(?:internal|private)\s+\w*(?:SLOT|slot)\w*\s*=\s*keccak256/.test(
          line,
        ) &&
        !line.includes("constant")
      ) {
        ctx.reportedIds.add("ETH-030");
        return {
          patternId: "ETH-030",
          severity: "CRITICAL",
          confidence: 0.85,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Storage slot variable is not constant. Can be overwritten, breaking proxy.",
          verify:
            "Mark storage slot as constant: bytes32 constant internal _IMPL_SLOT = keccak256(...);",
          category: "storage",
        };
      }
      return null;
    },
  },

  // ── ETH-032: Strict Equality on Ether Balance ────────────────────────────
  {
    id: "ETH-032",
    severity: "HIGH",
    confidence: 0.8,
    category: "logic",
    check(line, idx) {
      if (
        line.includes("address(this).balance") &&
        (line.includes("==") ||
          /require\s*\(.*address\(this\)\.balance\s*==/.test(line))
      ) {
        return {
          patternId: "ETH-032",
          severity: "HIGH",
          confidence: 0.8,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Strict equality check on address(this).balance. Attacker can force ETH via selfdestruct to break invariants.",
          verify:
            "Use >= or <= instead of == for balance checks. Never assume exact balance.",
          category: "logic",
        };
      }
      return null;
    },
  },

  // ── ETH-033: Write to Arbitrary Storage ───────────────────────────────────
  {
    id: "ETH-033",
    severity: "CRITICAL",
    confidence: 0.9,
    category: "storage",
    check(line, idx, lines, ctx) {
      // array length manipulation (Solidity < 0.6.0)
      if (ctx.pragmaMinor < 6 && /\.\s*length\s*[-+]?=/.test(line)) {
        return {
          patternId: "ETH-033",
          severity: "CRITICAL",
          confidence: 0.9,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Direct array .length modification in Solidity < 0.6.0 enables arbitrary storage slot writes via array underflow.",
          verify:
            "Upgrade to Solidity >= 0.6.0 where direct .length modification is prohibited.",
          category: "storage",
        };
      }
      // assembly sstore with user-influenced slot
      if (line.includes("sstore") && ctx.lower.includes("assembly")) {
        return {
          patternId: "ETH-033",
          severity: "HIGH",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Assembly sstore (Potential Arbitrary Storage Write). If slot is user-controllable, enables arbitrary storage overwrites.",
          verify:
            "Validate storage slot values. Use Solidity state variables instead of raw sstore.",
          category: "storage",
        };
      }
      return null;
    },
  },

  // ── ETH-034: Strict Equality on Balance ───────────────────────────────────
  {
    id: "ETH-034",
    severity: "HIGH",
    confidence: 0.7,
    category: "logic",
    check(line, idx) {
      if (
        /(balance|totalSupply|supply)\w*\s*==\s*\d/.test(line) ||
        /require\s*\(.*balance\w*\s*==/.test(line) ||
        /\.balanceOf\s*\([^)]*\)\s*==\s*\d/.test(line) ||
        /\.balance\s*==\s*\d/.test(line)
      ) {
        return {
          patternId: "ETH-034",
          severity: "HIGH",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Strict equality check on balance/supply. Attacker can manipulate via transfer/selfdestruct to break invariant.",
          verify: "Use >= or <= instead of == for balance comparisons.",
          category: "logic",
        };
      }
      return null;
    },
  },

  // ── ETH-037: Weak Randomness ──────────────────────────────────────────────
  {
    id: "ETH-037",
    severity: "HIGH",
    confidence: 0.75,
    category: "logic",
    check(line, idx, lines, ctx) {
      const usesBlockAttrs =
        line.includes("block.timestamp") ||
        line.includes("block.prevrandao") ||
        line.includes("blockhash(");
      if (!usesBlockAttrs) return null;
      const randomContext = /random|seed|lottery|guess|winner|pick|roll/.test(
        ctx.lower,
      );
      if (!randomContext) return null;
      return {
        patternId: "ETH-037",
        severity: "HIGH",
        confidence: 0.75,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "Block attributes used as randomness source — miners/validators can manipulate",
        verify:
          "Is Chainlink VRF or a commit-reveal scheme used? Block attributes are predictable by block producers.",
        category: "logic",
      };
    },
  },

  // ── ETH-038: ecrecover Without Zero‑Check ────────────────────────────────
  {
    id: "ETH-038",
    severity: "HIGH",
    confidence: 0.8,
    category: "logic",
    check(line, idx, lines) {
      if (!line.includes("ecrecover")) return null;
      let hasZeroCheck = false;
      for (let j = idx; j < Math.min(idx + 8, lines.length); j++) {
        const ctx = lines[j];
        if (
          ctx.includes("address(0)") ||
          ctx.includes("!= 0") ||
          ctx.includes("!= address")
        ) {
          hasZeroCheck = true;
          break;
        }
      }
      if (hasZeroCheck) return null;
      return {
        patternId: "ETH-038",
        severity: "HIGH",
        confidence: 0.8,
        line: idx + 1,
        snippet: line.trim(),
        signal: "ecrecover() return value not checked against address(0)",
        verify:
          "Invalid signatures return address(0). Is that checked? Could an attacker pass a null signature to bypass auth?",
        category: "logic",
      };
    },
  },

  // ── ETH-039: Signature Replay (no chainId) ────────────────────────────────
  {
    id: "ETH-039",
    severity: "CRITICAL",
    confidence: 0.7,
    category: "logic",
    check(line, idx, lines, ctx) {
      if (!line.includes("ecrecover")) return null;
      if (ctx.reportedIds.has("ETH-039")) return null;
      if (ctx.hasChainId) return null;
      ctx.reportedIds.add("ETH-039");
      return {
        patternId: "ETH-039",
        severity: "CRITICAL",
        confidence: 0.7,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "ecrecover used but no block.chainid found in file — signature may be replayable cross-chain",
        verify:
          "Does the signed hash include block.chainid and this contract address? Missing these allows replay attacks on other chains.",
        category: "logic",
      };
    },
  },

  // ── ETH-041: ERC-20 Transfer Without SafeERC20 ────────────────────────────
  {
    id: "ETH-041",
    severity: "HIGH",
    confidence: 0.75,
    category: "token",
    check(line, idx, lines, ctx) {
      if (ctx.hasSafeERC20) return null;
      if (!line.includes(".transfer(") || line.includes("safeTransfer"))
        return null;
      if (line.includes("msg.sender.transfer") || line.includes("payable("))
        return null;
      if (!/\.transfer\(\s*\w+.*,\s*\w+/.test(line)) return null;
      return {
        patternId: "ETH-041",
        severity: "HIGH",
        confidence: 0.75,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "ERC-20 transfer without SafeERC20 — some tokens (USDT) don't return bool",
        verify:
          "Is SafeERC20 used for this token? Non-compliant tokens that return nothing will cause a revert.",
        category: "token",
      };
    },
  },

  // ── ETH-042: Fee-on-Transfer Incompatibility ──────────────────────────────
  {
    id: "ETH-042",
    severity: "HIGH",
    confidence: 0.55,
    category: "token",
    check(line, idx, lines, ctx) {
      if (ctx.reportedIds.has("ETH-042")) return null;
      if (!line.includes("transferFrom")) return null;
      const context = linesAround(lines, Math.max(0, idx - 3), 8);
      const hasBalanceCheck =
        /balanceOf/.test(context) && /(before|after|bal\w*)/i.test(context);
      if (hasBalanceCheck) return null;
      ctx.reportedIds.add("ETH-042");
      return {
        patternId: "ETH-042",
        severity: "HIGH",
        confidence: 0.55,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "transferFrom without balance diff check — fee-on-transfer tokens deliver less than requested",
        verify:
          "Does this protocol support fee-on-transfer tokens? If so, check balanceOf before and after to get actual received amount.",
        category: "token",
      };
    },
  },

  // ── ETH-044: ERC-777 Reentrancy Hook ──────────────────────────────────────
  {
    id: "ETH-044",
    severity: "HIGH",
    confidence: 0.75,
    category: "token",
    check(line, idx, lines, ctx) {
      if (
        /ERC777|IERC777|tokensReceived|tokensToSend/.test(line) &&
        !ctx.hasReentrancyGuard
      ) {
        return {
          patternId: "ETH-044",
          severity: "HIGH",
          confidence: 0.75,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "ERC-777 token hooks can trigger reentrancy. No ReentrancyGuard detected.",
          verify: "Add nonReentrant modifier or use ERC-20 instead of ERC-777.",
          category: "token",
        };
      }
      return null;
    },
  },

  // ── ETH-045: Missing Zero Address Check ───────────────────────────────────
  {
    id: "ETH-045",
    severity: "MEDIUM",
    confidence: 0.65,
    category: "token",
    check(line, idx, lines) {
      if (
        /function\s+\w*(set|update|change|transfer)\w*(Owner|Admin|Manager|Address)\w*\s*\(/.test(
          line,
        ) &&
        line.includes("address") &&
        (line.includes("public") || line.includes("external"))
      ) {
        let hasZeroCheck = false;
        for (let j = idx; j < Math.min(idx + 5, lines.length); j++) {
          const ctx = lines[j];
          if (
            ctx.includes("address(0)") &&
            (ctx.includes("!=") || ctx.includes("require"))
          ) {
            hasZeroCheck = true;
            break;
          }
        }
        if (!hasZeroCheck) {
          return {
            patternId: "ETH-045",
            severity: "MEDIUM",
            confidence: 0.65,
            line: idx + 1,
            snippet: line.trim(),
            signal:
              "Setter function for critical address parameter without address(0) validation.",
            verify: "Add require(newAddr != address(0)) before assignment.",
            category: "token",
          };
        }
      }
      return null;
    },
  },

  // ── ETH-046: Approval Race Condition ──────────────────────────────────────
  {
    id: "ETH-046",
    severity: "MEDIUM",
    confidence: 0.6,
    category: "token",
    check(line, idx, lines, ctx) {
      if (line.includes(".approve(") && !line.includes("safeApprove")) {
        if (ctx.reportedIds.has("ETH-046")) return null;
        ctx.reportedIds.add("ETH-046");
        return {
          patternId: "ETH-046",
          severity: "MEDIUM",
          confidence: 0.6,
          line: idx + 1,
          snippet: line.trim(),
          signal: "approve() is vulnerable to front-running race condition.",
          verify:
            "Use safeIncreaseAllowance/safeDecreaseAllowance or set to 0 first.",
          category: "token",
        };
      }
      return null;
    },
  },

  // ── ETH-047: Infinite Approval ────────────────────────────────────────────
  {
    id: "ETH-047",
    severity: "LOW",
    confidence: 0.75,
    category: "token",
    check(line, idx) {
      if (line.includes("type(uint256).max") && line.includes("approve")) {
        return {
          patternId: "ETH-047",
          severity: "LOW",
          confidence: 0.75,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Unlimited token approval (type(uint256).max). If approved address is compromised, all tokens are at risk.",
          verify:
            "Approve only the exact amount needed. Use increaseAllowance/decreaseAllowance.",
          category: "token",
        };
      }
      return null;
    },
  },

  // ── ETH-048: Unprotected Minting / Swap Manipulation ──────────────────────
  {
    id: "ETH-048",
    severity: "HIGH",
    confidence: 0.65,
    category: "token",
    check(line, idx, lines, ctx) {
      if (line.includes("_mint(")) {
        let hasAuth = false;
        for (let j = Math.max(0, idx - 3); j <= idx; j++) {
          const ctxLine = lines[j];
          if (/onlyOwner|onlyRole|only|auth|require/.test(ctxLine)) {
            hasAuth = true;
            break;
          }
        }
        if (!hasAuth) {
          return {
            patternId: "ETH-048",
            severity: "HIGH",
            confidence: 0.65,
            line: idx + 1,
            snippet: line.trim(),
            signal:
              "_mint() called without access control. May allow unauthorized token creation.",
            verify:
              "Restrict minting to authorized roles with onlyOwner/onlyRole modifier.",
            category: "token",
          };
        }
      }
      if (
        /function\s+onSwap\b/.test(line) ||
        (/reserves?\w*\s*(?:TokenIn|TokenOut|In|Out)/i.test(line) &&
          /swap|onswap|pool|amm/.test(ctx.lower))
      ) {
        if (ctx.reportedIds.has("ETH-048")) return null;
        ctx.reportedIds.add("ETH-048");
        return {
          patternId: "ETH-048",
          severity: "HIGH",
          confidence: 0.65,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Swap callback uses reserve parameters that can be manipulated via flash loans.",
          verify:
            "Use TWAP oracle or verify reserves haven't been manipulated in same block.",
          category: "token",
        };
      }
      return null;
    },
  },

  // ── ETH-049: Missing _disableInitializers ─────────────────────────────────
  {
    id: "ETH-049",
    severity: "CRITICAL",
    confidence: 0.8,
    category: "proxy",
    check(line, idx, lines, ctx) {
      if (
        (line.includes("Initializable") ||
          (line.includes("initializer") && !line.includes("modifier"))) &&
        !ctx.reportedIds.has("ETH-049")
      ) {
        if (
          ctx.lower.includes("function initialize") &&
          !ctx.lower.includes("_disableinitializers")
        ) {
          ctx.reportedIds.add("ETH-049");
          return {
            patternId: "ETH-049",
            severity: "CRITICAL",
            confidence: 0.8,
            line: idx + 1,
            snippet: line.trim(),
            signal:
              "Initializable contract without _disableInitializers() in constructor. Implementation can be initialized by attacker.",
            verify:
              "Add constructor() { _disableInitializers(); } to prevent implementation takeover.",
            category: "proxy",
          };
        }
      }
      return null;
    },
  },

  // ── ETH-055: Governance Manipulation ──────────────────────────────────────
  {
    id: "ETH-055",
    severity: "HIGH",
    confidence: 0.65,
    category: "defi",
    check(line, idx, lines, ctx) {
      if (
        /function\s+\w*(propose|vote|execute)\w*\s*\(/i.test(line) &&
        !ctx.reportedIds.has("ETH-055")
      ) {
        let hasSnapshot = false;
        for (
          let j = Math.max(0, idx - 20);
          j < Math.min(idx + 20, lines.length);
          j++
        ) {
          const ctxLine = lines[j];
          if (/snapshot|checkpoint|getPastVotes|getPriorVotes/i.test(ctxLine)) {
            hasSnapshot = true;
            break;
          }
        }
        if (!hasSnapshot) {
          ctx.reportedIds.add("ETH-055");
          return {
            patternId: "ETH-055",
            severity: "HIGH",
            confidence: 0.65,
            line: idx + 1,
            snippet: line.trim(),
            signal:
              "Governance function without vote snapshotting. Attacker can flash-loan tokens to manipulate votes.",
            verify:
              "Use ERC20Votes with getPastVotes() and proposal snapshot blocks.",
            category: "defi",
          };
        }
      }
      return null;
    },
  },

  // ── ETH-057: Vault Share Inflation / First Depositor ──────────────────────
  {
    id: "ETH-057",
    severity: "CRITICAL",
    confidence: 0.75,
    category: "defi",
    check(line, idx, lines, ctx) {
      if (ctx.reportedIds.has("ETH-057")) return null;
      const isZeroCheck =
        /totalSupply\s*(\(\s*\))?\s*==\s*0|totalShares\s*==\s*0/.test(line) ||
        /total\w*\.(?:amount|assets?)\s*==\s*0/.test(line);
      if (isZeroCheck && /deposit|mint|share|convert/.test(ctx.lower)) {
        ctx.reportedIds.add("ETH-057");
        return {
          patternId: "ETH-057",
          severity: "CRITICAL",
          confidence: 0.75,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Share calculation when totalSupply == 0 — first depositor can inflate share price",
          verify:
            "Is there a virtual offset (ERC-4626 style +1/+1) or minimum dead shares minted at deployment? Without this, first depositor can steal from subsequent depositors.",
          category: "defi",
        };
      }
      if (
        /totalSupply\s*[/\*].*balanceOf|balanceOf.*[/\*].*totalSupply/.test(
          line,
        ) &&
        /deposit|withdraw|share|vault/.test(ctx.lower)
      ) {
        if (ctx.reportedIds.has("ETH-057")) return null;
        ctx.reportedIds.add("ETH-057");
        return {
          patternId: "ETH-057",
          severity: "HIGH",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Balance-based share calculation (donation attack risk). Share price derived from balanceOf/totalSupply ratio.",
          verify:
            "Use internal accounting instead of balanceOf. Add virtual offset or minimum deposit.",
          category: "defi",
        };
      }
      return null;
    },
  },

  // ── ETH-060: Ineffective Deadline ─────────────────────────────────────────
  {
    id: "ETH-060",
    severity: "MEDIUM",
    confidence: 0.8,
    category: "defi",
    check(line, idx) {
      const badDeadline =
        /deadline\s*:\s*block\.timestamp\b/.test(line) ||
        (/type\(uint256\)\.max/.test(line) && /deadline/.test(line));
      if (badDeadline) {
        return {
          patternId: "ETH-060",
          severity: "MEDIUM",
          confidence: 0.8,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Deadline set to block.timestamp or uint256.max — provides no expiry protection",
          verify:
            "Should the user be able to specify their own deadline? A hardcoded deadline means transactions can be held and executed at any future price.",
          category: "defi",
        };
      }
      if (/amountOut(?:Minimum|Min)\s*:\s*0\b/.test(line)) {
        return {
          patternId: "ETH-060",
          severity: "HIGH",
          confidence: 0.85,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Zero slippage in swap parameters — accepts any output amount.",
          verify: "Allow user to specify minimum output. Never hardcode to 0.",
          category: "defi",
        };
      }
      return null;
    },
  },

  // ── ETH-064: Unprotected Callback ─────────────────────────────────────────
  {
    id: "ETH-064",
    severity: "HIGH",
    confidence: 0.65,
    category: "defi",
    check(line, idx, lines) {
      if (
        !/function\s+(onERC721Received|onERC1155Received|onFlashLoan|uniswapV\dCall|pancakeCall)/.test(
          line,
        )
      )
        return null;
      let hasSenderCheck = false;
      for (let j = idx; j < Math.min(idx + 8, lines.length); j++) {
        const ctx = lines[j];
        if (/msg\.sender/.test(ctx) && /(require|==|if)/.test(ctx)) {
          hasSenderCheck = true;
          break;
        }
      }
      if (hasSenderCheck) return null;
      return {
        patternId: "ETH-064",
        severity: "HIGH",
        confidence: 0.65,
        line: idx + 1,
        snippet: line.trim(),
        signal: "Callback function without msg.sender validation",
        verify:
          "Is msg.sender checked against the expected caller (e.g., the flash loan pool, NFT contract)? Anyone can call this function directly.",
        category: "defi",
      };
    },
  },

  // ── ETH-065: Cross-protocol Integration Risk ──────────────────────────────
  {
    id: "ETH-065",
    severity: "MEDIUM",
    confidence: 0.6,
    category: "defi",
    check(line, idx, lines, ctx) {
      if (
        /function\s+\w+\s*\([^)]*(?:Protocol|address)\s+\w*(?:protocol|target|router|pool)/i.test(
          line,
        ) &&
        !ctx.reportedIds.has("ETH-065")
      ) {
        ctx.reportedIds.add("ETH-065");
        return {
          patternId: "ETH-065",
          severity: "MEDIUM",
          confidence: 0.6,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Function accepts user-controlled protocol/contract address. Attacker can pass malicious contract.",
          verify:
            "Whitelist allowed protocol addresses or validate against a registry.",
          category: "defi",
        };
      }
      return null;
    },
  },

  // ── ETH-066: Unbounded Loop ────────────────────────────────────────────────
  {
    id: "ETH-066",
    severity: "HIGH",
    confidence: 0.7,
    category: "gas-dos",
    check(line, idx) {
      if (/\bfor\b/.test(line) && line.includes(".length")) {
        return {
          patternId: "ETH-066",
          severity: "HIGH",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Loop over dynamic array .length — may exceed block gas limit as array grows",
          verify:
            "Is there an upper bound on array size? Can an attacker add elements to grief this function?",
          category: "gas-dos",
        };
      }
      return null;
    },
  },

  // ── ETH-071: Floating Pragma ───────────────────────────────────────────────
  {
    id: "ETH-071",
    severity: "LOW",
    confidence: 0.95,
    category: "miscellaneous",
    check(line, idx, lines, ctx) {
      if (ctx.reportedIds.has("ETH-071")) return null;
      if (
        !line.includes("pragma solidity ^") &&
        !line.includes("pragma solidity >=")
      )
        return null;
      ctx.reportedIds.add("ETH-071");
      return {
        patternId: "ETH-071",
        severity: "LOW",
        confidence: 0.95,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "Floating pragma — contract can compile with different compiler versions",
        verify: "Lock to specific version: pragma solidity 0.8.x",
        category: "miscellaneous",
      };
    },
  },

  // ── ETH-072: Outdated compiler ─────────────────────────────────────────────
  {
    id: "ETH-072",
    severity: "LOW",
    confidence: 0.95,
    category: "miscellaneous",
    check(line, idx) {
      if (line.includes("pragma solidity")) {
        for (const oldVer of ["0.4.", "0.5.", "0.6.", "0.7."]) {
          if (
            line.includes(`pragma solidity ${oldVer}`) ||
            line.includes(`pragma solidity ^${oldVer}`)
          ) {
            return {
              patternId: "ETH-072",
              severity: "LOW",
              confidence: 0.95,
              line: idx + 1,
              snippet: line.trim(),
              signal:
                "Using outdated Solidity version. Missing overflow protection and security fixes.",
              verify:
                "Upgrade to Solidity 0.8.x+ for built-in overflow checks.",
              category: "miscellaneous",
            };
          }
        }
      }
      return null;
    },
  },

  // ── ETH-073: abi.encodePacked Hash Collision ──────────────────────────────
  {
    id: "ETH-073",
    severity: "MEDIUM",
    confidence: 0.65,
    category: "logic",
    check(line, idx) {
      if (!line.includes("abi.encodePacked")) return null;
      const argCount = (line.match(/,/g) || []).length;
      if (argCount < 1) return null;
      return {
        patternId: "ETH-073",
        severity: "MEDIUM",
        confidence: 0.65,
        line: idx + 1,
        snippet: line.trim(),
        signal:
          "abi.encodePacked with multiple args — hash collision possible if any arg is dynamic type",
        verify:
          "Are any arguments strings, bytes, or dynamic arrays? If so, use abi.encode instead.",
        category: "logic",
      };
    },
  },

  // ── ETH-075: Code With No Effects (array deletion, validation loops) ─────
  {
    id: "ETH-075",
    severity: "MEDIUM",
    confidence: 0.65,
    category: "miscellaneous",
    check(line, idx, lines, ctx) {
      if (/\bdelete\s+\w+\[/.test(line) && !line.includes("mapping")) {
        return {
          patternId: "ETH-075",
          severity: "MEDIUM",
          confidence: 0.65,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "delete on array element sets to zero but doesn't remove. Leaves gap in array.",
          verify: "Swap with last element and pop, or shift elements left.",
          category: "miscellaneous",
        };
      }
      if (
        /\bdelete\s+\w+\s*;/.test(line) &&
        ctx.lower.includes("struct") &&
        ctx.lower.includes("mapping")
      ) {
        return {
          patternId: "ETH-075",
          severity: "MEDIUM",
          confidence: 0.6,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "delete on struct with nested mapping doesn't clear the mapping.",
          verify: "Manually clear mapping entries before deleting struct.",
          category: "miscellaneous",
        };
      }
      // validation loop bypassable with empty array
      if (
        /for\s*\(\s*\w+\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*\w+\.length/.test(line)
      ) {
        let hasValidationInLoop = false;
        let braceDepth = 0;
        let loopEnd = -1;
        for (let j = idx; j < Math.min(idx + 20, lines.length); j++) {
          const ctxLine = lines[j];
          braceDepth +=
            (ctxLine.match(/{/g) || []).length -
            (ctxLine.match(/}/g) || []).length;
          if (/verify|require|ecrecover/i.test(ctxLine))
            hasValidationInLoop = true;
          if (braceDepth <= 0 && j > idx) {
            loopEnd = j;
            break;
          }
        }
        if (hasValidationInLoop && loopEnd > 0) {
          for (let j = loopEnd; j < Math.min(loopEnd + 5, lines.length); j++) {
            const ctxLine = lines[j];
            if (
              ctxLine.includes(".transfer(") ||
              ctxLine.includes(".call{") ||
              ctxLine.includes(".send(")
            ) {
              return {
                patternId: "ETH-075",
                severity: "HIGH",
                confidence: 0.75,
                line: idx + 1,
                snippet: line.trim(),
                signal:
                  "Validation in loop can be bypassed by passing empty array. Action executes regardless.",
                verify:
                  "Add require(array.length > 0) before loop to prevent empty input bypass.",
                category: "miscellaneous",
              };
            }
          }
        }
      }
      // return in nested for loop (should be break)
      if (/return;/.test(line)) {
        let forCount = 0;
        for (let j = Math.max(0, idx - 15); j < idx; j++) {
          if (/for\s*\(/.test(lines[j])) forCount++;
        }
        if (forCount >= 2) {
          return {
            patternId: "ETH-075",
            severity: "MEDIUM",
            confidence: 0.7,
            line: idx + 1,
            snippet: line.trim(),
            signal:
              "return inside nested loop exits entire function. Use break to exit inner loop only.",
            verify:
              "Replace return with break in inner loop to continue outer loop processing.",
            category: "miscellaneous",
          };
        }
      }
      return null;
    },
  },

  // ── ETH-076: Missing Event Emission ──────────────────────────────────────
  {
    id: "ETH-076",
    severity: "LOW",
    confidence: 0.55,
    category: "miscellaneous",
    check(line, idx, lines, ctx) {
      if (
        /\b(owner|admin|paused|implementation)\s*=\s*/.test(line) &&
        !line.includes("function") &&
        !line.includes("constructor") &&
        !line.includes("event")
      ) {
        let hasEmit = false;
        for (let j = idx; j < Math.min(idx + 4, lines.length); j++) {
          if (lines[j].includes("emit ")) {
            hasEmit = true;
            break;
          }
        }
        if (!hasEmit && !ctx.reportedIds.has("ETH-076")) {
          ctx.reportedIds.add("ETH-076");
          return {
            patternId: "ETH-076",
            severity: "LOW",
            confidence: 0.55,
            line: idx + 1,
            snippet: line.trim(),
            signal:
              "Critical state variable modified without event emission. Makes off-chain monitoring impossible.",
            verify:
              "Emit an event after updating critical state variables (owner, admin, implementation).",
            category: "miscellaneous",
          };
        }
      }
      return null;
    },
  },

  // ── ETH-078: Private Data On-Chain ────────────────────────────────────────
  {
    id: "ETH-078",
    severity: "MEDIUM",
    confidence: 0.7,
    category: "miscellaneous",
    check(line, idx, lines, ctx) {
      if (
        /(password|secret|key|pin|seed|private)/i.test(line) &&
        /\bprivate\b/.test(line)
      ) {
        return {
          patternId: "ETH-078",
          severity: "MEDIUM",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Sensitive private data stored on-chain. Private variables are still readable via storage slots.",
          verify:
            "Never store secrets on-chain. Use commit-reveal or off-chain storage.",
          category: "miscellaneous",
        };
      }
      if (
        /^\s+(uint|int|address|bytes|string|bool)\s+private\s+\w+/.test(line) &&
        !ctx.reportedIds.has("ETH-078")
      ) {
        ctx.reportedIds.add("ETH-078");
        return {
          patternId: "ETH-078",
          severity: "LOW",
          confidence: 0.5,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Private state variable (readable on-chain despite visibility).",
          verify:
            "Do not rely on 'private' for data confidentiality. All on-chain data is public.",
          category: "miscellaneous",
        };
      }
      if (
        /ipfs|dweb|metadata|tokenURI|baseURI/i.test(line) &&
        /nft|erc721|mint|tokenid/i.test(ctx.lower) &&
        !ctx.reportedIds.has("ETH-078")
      ) {
        ctx.reportedIds.add("ETH-078");
        return {
          patternId: "ETH-078",
          severity: "MEDIUM",
          confidence: 0.6,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "Exposed NFT metadata / predictable URI. Attacker can snipe rare NFTs.",
          verify:
            "Use commit-reveal pattern or encrypt metadata until minting completes.",
          category: "miscellaneous",
        };
      }
      return null;
    },
  },

  // ── ETH-079: Hardcoded gas (.transfer / .send) ────────────────────────────
  {
    id: "ETH-079",
    severity: "LOW",
    confidence: 0.8,
    category: "miscellaneous",
    check(line, idx) {
      if (line.includes(".transfer(") || line.includes(".send(")) {
        return {
          patternId: "ETH-079",
          severity: "LOW",
          confidence: 0.8,
          line: idx + 1,
          snippet: line.trim(),
          signal: ".transfer() and .send() forward only 2300 gas.",
          verify: "Use .call{value: amount}('') with reentrancy guard instead.",
          category: "miscellaneous",
        };
      }
      return null;
    },
  },

  // ── ETH-081: Transient storage slot collision ────────────────────────────
  {
    id: "ETH-081",
    severity: "CRITICAL",
    confidence: 0.8,
    category: "transient-storage",
    check(line, idx) {
      const slotMatch = line.match(
        /tstore\s*\(\s*(0x[0-9a-fA-F]{1,4}|[0-9]{1,3})\s*,/,
      );
      if (slotMatch) {
        return {
          patternId: "ETH-081",
          severity: "CRITICAL",
          confidence: 0.8,
          line: idx + 1,
          snippet: line.trim(),
          signal: `TSTORE uses hardcoded small slot (${slotMatch[1]}). Risk of collision.`,
          verify:
            "Use namespaced slots: bytes32 slot = keccak256('Contract.lock');",
          category: "transient-storage",
        };
      }
      return null;
    },
  },

  // ── ETH-086: tx.origin == msg.sender (EIP-7702) ───────────────────────────
  {
    id: "ETH-086",
    severity: "CRITICAL",
    confidence: 0.9,
    category: "access-control",
    check(line, idx) {
      if (
        line.includes("tx.origin") &&
        line.includes("msg.sender") &&
        (line.includes("==") || line.includes("require"))
      ) {
        return {
          patternId: "ETH-086",
          severity: "CRITICAL",
          confidence: 0.9,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "tx.origin == msg.sender no longer guarantees EOA after EIP-7702.",
          verify: "Remove tx.origin == msg.sender check.",
          category: "access-control",
        };
      }
      return null;
    },
  },

  // ── ETH-089: extcodesize/isContract (EIP-7702) ───────────────────────────
  {
    id: "ETH-089",
    severity: "HIGH",
    confidence: 0.7,
    category: "access-control",
    check(line, idx) {
      if (line.includes("extcodesize") || line.includes("isContract")) {
        return {
          patternId: "ETH-089",
          severity: "HIGH",
          confidence: 0.7,
          line: idx + 1,
          snippet: line.trim(),
          signal:
            "extcodesize/isContract cannot reliably distinguish EOAs from contracts after EIP-7702.",
          verify: "Do not rely on code size to determine account type.",
          category: "access-control",
        };
      }
      return null;
    },
  },

  // ── ETH-097: Known Compiler Bug (Dirty Bytes) ────────────────────────────
  {
    id: "ETH-097",
    severity: "HIGH",
    confidence: 0.7,
    category: "miscellaneous",
    check(line, idx, lines, ctx) {
      const pragmaMinor = ctx.pragmaMinor;
      if (
        pragmaMinor === 8 &&
        lines.join("\n").includes(".push(") &&
        ctx.lower.includes("bytes")
      ) {
        // version between 0.8.0 and 0.8.14
        const pragmaPatch = (ctx.content.match(
          /pragma solidity[^0-9]*0\.8\.(\d+)/,
        ) || [])[1];
        if (pragmaPatch && parseInt(pragmaPatch) < 15) {
          return {
            patternId: "ETH-097",
            severity: "HIGH",
            confidence: 0.7,
            line: idx + 1,
            snippet: line.trim(),
            signal: `Known compiler bug — dirty bytes (Solidity ${ctx.content.match(/pragma solidity[^0-9]*0\.8\.\d+/)?.[0] || "0.8.x"}) .push() may include dirty data.`,
            verify: "Upgrade to Solidity >= 0.8.15 to fix dirty bytes issue.",
            category: "miscellaneous",
          };
        }
      }
      return null;
    },
  },

  // ── ETH-098: Missing input validation ────────────────────────────────────
  {
    id: "ETH-098",
    severity: "HIGH",
    confidence: 0.6,
    category: "input-validation",
    check(line, idx, lines) {
      if (
        line.includes("function") &&
        (line.includes("external") || line.includes("public")) &&
        !line.includes("internal") &&
        !line.includes("private")
      ) {
        const paramsMatch = line.match(/function\s+\w+\s*\(([^)]+)\)/);
        if (paramsMatch) {
          const params = paramsMatch[1];
          const hasUint = /uint|int/.test(params);
          const hasAddr = /address/.test(params);
          if (hasUint || hasAddr) {
            let hasValidation = false;
            for (let j = idx; j < Math.min(idx + 6, lines.length); j++) {
              const ctxLine = lines[j];
              if (/require\(|revert|if \(/.test(ctxLine)) {
                hasValidation = true;
                break;
              }
            }
            if (!hasValidation) {
              return {
                patternId: "ETH-098",
                severity: "HIGH",
                confidence: 0.6,
                line: idx + 1,
                snippet: line.trim(),
                signal:
                  "External/public function accepts parameters without input validation.",
                verify:
                  "Add require() checks for parameter bounds and zero address.",
                category: "input-validation",
              };
            }
          }
        }
      }
      // invariant msg.value check in loop
      if (/require\s*\(\s*msg\.value\s*>=/.test(line)) {
        for (let j = Math.max(0, idx - 10); j < idx; j++) {
          if (/for\s*\(/.test(lines[j])) {
            return {
              patternId: "ETH-098",
              severity: "HIGH",
              confidence: 0.8,
              line: idx + 1,
              snippet: line.trim(),
              signal:
                "msg.value checked in loop — same value passes every iteration. Allows multiple operations for single payment.",
              verify:
                "Check total cost outside loop: require(msg.value >= price * amount).",
              category: "input-validation",
            };
          }
        }
      }
      return null;
    },
  },
];

// ─── Language Registry ─────────────────────────────────────────────────────────

const PATTERN_REGISTRY: Record<string, PatternCheck[]> = {
  solidity: SOLIDITY_PATTERNS,
  vyper: SOLIDITY_PATTERNS,
  // rust, move, go: add here when implementing those language pattern sets
};

// ─── Public API ───────────────────────────────────────────────────────────────

export function runPreScanner(files: SourceFile[]): ScanLead[] {
  const allLeads: ScanLead[] = [];

  for (const file of files) {
    const patterns = PATTERN_REGISTRY[file.language];
    if (!patterns || patterns.length === 0) continue;

    const lines = file.content.split("\n");
    const lower = file.content.toLowerCase();

    const ctx: FileContext = {
      content: file.content,
      lower,
      hasSafeERC20:
        lower.includes("safetransfer(") || lower.includes("safetransferfrom("),
      hasReentrancyGuard:
        lower.includes("nonreentrant") || lower.includes("reentrancyguard"),
      hasChainId: lower.includes("block.chainid") || lower.includes("chainid"),
      hasSafeMath: lower.includes("using safemath for"),
      pragmaMinor: extractPragmaMinor(file.content),
      reportedIds: new Set<string>(),
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (
        trimmed.startsWith("//") ||
        trimmed.startsWith("*") ||
        trimmed.startsWith("/*")
      )
        continue;

      for (const pattern of patterns) {
        try {
          const result = pattern.check(line, i, lines, ctx, file.path);
          if (result) {
            allLeads.push({
              ...result,
              file: file.path,
              language: file.language,
            });
          }
        } catch {
          // Individual pattern errors are silent — scanner must never crash
        }
      }
    }
  }

  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  return allLeads.sort((a, b) => {
    if (Math.abs(b.confidence - a.confidence) > 0.05)
      return b.confidence - a.confidence;
    return (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
  });
}

export function formatLeadsBlock(leads: ScanLead[], maxLeads = 8): string {
  if (leads.length === 0) return "";

  const top = leads.slice(0, maxLeads);
  const lines: string[] = [
    `=== PRE-SCAN LEADS — verify these first (${top.length} of ${leads.length} found) ===`,
    "",
  ];

  top.forEach((lead, i) => {
    lines.push(
      `[LEAD-${i + 1}] ${lead.patternId} | ${lead.severity} | confidence:${(lead.confidence * 100).toFixed(0)}% | ${lead.file}:${lead.line}`,
    );
    lines.push(`  Code:   ${lead.snippet.slice(0, 120)}`);
    lines.push(`  Signal: ${lead.signal}`);
    lines.push(`  Verify: ${lead.verify}`);
    lines.push("");
  });

  lines.push(
    "After verifying each lead, apply methodology to find what the scanner missed.",
    "A genuine zero-finding result is extremely rare. If leads look like false positives,",
    "explain why specifically before concluding — do not silently dismiss.",
    "===",
  );

  return lines.join("\n");
}

function extractPragmaMinor(content: string): number {
  const m = content.match(/pragma solidity\s*[\^>=<~]*\s*0\.(\d+)\./);
  return m ? parseInt(m[1], 10) : 8;
}
