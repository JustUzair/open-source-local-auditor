/** A single .sol file with its raw content. Both interfaces use this. */
export interface SolidityFile {
  /** Relative path within the project, e.g. "contracts/Vault.sol" */
  filename: string;
  content: string;
}

/** Extracted info about a single function inside a contract. */
export interface FunctionInfo {
  name: string;
  contract: string;
  file: string;
  visibility: "public" | "external" | "internal" | "private" | "default";
  /** Modifier names, e.g. ["onlyOwner", "nonReentrant"] */
  modifiers: string[];
  /** State variable names this function writes to. */
  stateWrites: string[];
  /**
   * In-scope calls: "ContractName.functionName" for calls to other
   * contracts/functions found in the uploaded files.
   */
  callsInternal: string[];
  /** External calls that leave scope (to addresses, interfaces, etc.) */
  callsExternal: ExternalCallSite[];
  lineStart: number;
  lineEnd: number;
}

export interface ExternalCallSite {
  /** The call expression as a string, e.g. "token.transferFrom" */
  expression: string;
  line: number;
}

export interface ContractInfo {
  name: string;
  file: string;
  /** Only contracts found in the uploaded files — external libs excluded. */
  inheritsFromScope: string[];
  functions: FunctionInfo[];
  stateVars: StateVarInfo[];
}

export interface StateVarInfo {
  name: string;
  typeName: string;
  contract: string;
}

/** Directed edge in the call graph. */
export interface CallEdge {
  from: string; // "ContractName.functionName"
  to: string; // same format, or raw expression for external calls
  line: number;
  isExternal: boolean;
}

/**
 * A function that both writes state AND makes external calls.
 * This is the primary reentrancy surface — not a confirmed bug,
 * but the set of functions that need close scrutiny.
 */
export interface ReentrancySurface {
  functionPath: string; // "ContractName.functionName"
  externalCalls: ExternalCallSite[];
  stateWritten: string[];
  /** True if function has a nonReentrant or equivalent modifier. */
  hasGuard: boolean;
  risk: "HIGH" | "LOW";
}

/**
 * The complete output of the recon processor. This is computed
 * deterministically from the AST — the LLM never generates this.
 */
export interface ReconContext {
  files: string[];
  contracts: ContractInfo[];
  callGraph: CallEdge[];
  /** All public/external functions — the attacker-reachable surface. */
  entryPoints: string[];
  reentrancySurface: ReentrancySurface[];
  /** Formatted text version fed to agents. Hard-capped at 100 lines. */
  rawSummary: string;
  /** Non-fatal parse errors. Agents are told which files had issues. */
  parseErrors: string[];
}
