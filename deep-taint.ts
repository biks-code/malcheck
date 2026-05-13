import * as fs from 'fs';
import * as path from 'path';
import { Finding, Severity, Scanner } from '../types';

const JS_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx']);

// Dangerous sources: where tainted data originates
// needsString: true means the pattern must match against codeLines (string content preserved)
// needsString: false means the pattern is tested against scopeLines (strings stripped)
const CREDENTIAL_ENV_PATTERN = /process\.env\.(AWS_|SECRET|TOKEN|KEY|PASSWORD|PASS|CREDENTIAL|AUTH|PRIVATE|API_KEY|NPM_TOKEN|GH_TOKEN|GITHUB_TOKEN)/i;
const SOURCES: Array<{ pattern: RegExp; label: string; needsString?: boolean }> = [
  { pattern: CREDENTIAL_ENV_PATTERN, label: 'credential env var' },
  { pattern: /fs\.(readFileSync|readFile)\s*\(/, label: 'fs.readFile' },
  { pattern: /require\s*\(\s*['"`]child_process/, label: 'child_process import', needsString: true },
  { pattern: /Buffer\.from\s*\(/, label: 'Buffer.from' },
  { pattern: /atob\s*\(|decodeURIComponent\s*\(/, label: 'decode function' },
  { pattern: /os\.homedir\s*\(|os\.hostname\s*\(/, label: 'os info access' },
  { pattern: /(?:readFile|readFileSync|readdir|open|createReadStream|access)\s*\(\s*.*(?:[\/\\]\.ssh|[\/\\]\.aws\/credentials|[\/\\]\.npmrc|\.env\b)/, label: 'credential path', needsString: true },
];

// Dangerous sinks: where tainted data shouldn't end up
const SINKS: Array<{ pattern: RegExp; label: string; severity: Severity }> = [
  { pattern: /\beval\s*\(/, label: 'eval()', severity: 'CRITICAL' },
  { pattern: /\bexec\s*\(|execSync\s*\(|spawn\s*\(|spawnSync\s*\(/, label: 'exec/spawn', severity: 'CRITICAL' },
  { pattern: /\bfetch\s*\(|axios\.|http\.request|https\.request/, label: 'network request', severity: 'CRITICAL' },
  { pattern: /net\.Socket|new\s+Socket|socket\.connect/, label: 'socket connection', severity: 'CRITICAL' },
  { pattern: /Function\s*\(/, label: 'Function constructor', severity: 'CRITICAL' },
  { pattern: /\.apply\s*\(|\.call\s*\(/, label: 'indirect call', severity: 'WARNING' },
];

// Variable aliasing patterns: assigning a dangerous function to a variable
// needsString: true for patterns that need to see require('module-name') string content
const ALIAS_PATTERNS: Array<{ pattern: RegExp; aliasedSink: string; needsString?: boolean }> = [
  { pattern: /(?:const|let|var)\s+(\w+)\s*=\s*eval\b/, aliasedSink: 'eval' },
  { pattern: /(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"`]child_process['"`]\s*\)/, aliasedSink: 'child_process', needsString: true },
  { pattern: /(?:const|let|var)\s+\{\s*(\w+(?:\s*,\s*\w+)*)\s*\}\s*=\s*require\s*\(\s*['"`]child_process['"`]\s*\)/, aliasedSink: 'child_process destructured', needsString: true },
  { pattern: /(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"`]fs['"`]\s*\)/, aliasedSink: 'fs module', needsString: true },
  { pattern: /(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"`]https?['"`]\s*\)/, aliasedSink: 'http module', needsString: true },
];

// Dynamic property access patterns
// needsString: true for patterns that match string content inside brackets
const DYNAMIC_ACCESS: Array<{ pattern: RegExp; label: string; needsString?: boolean }> = [
  { pattern: /\w+\[\s*['"`]\w+['"`]\s*\+\s*['"`]\w+['"`]\s*\]/, label: 'string concatenation property access', needsString: true },
  { pattern: /\w+\[\s*\w+\s*\]\s*\(/, label: 'computed property call' },
  { pattern: /require\s*\(\s*\w+\s*\+/, label: 'dynamic require with concatenation' },
  { pattern: /require\s*\(\s*\[.*\]/, label: 'dynamic require with array' },
];

interface ScopeInfo {
  id: number;
  startLine: number;
  endLine: number;
  parentId: number | null;
}

interface TaintState {
  sources: Array<{ line: number; label: string; variable?: string; scopeId: number }>;
  sinks: Array<{ line: number; label: string; severity: Severity; scopeId: number }>;
  aliases: Array<{ line: number; varName: string; aliasedSink: string; scopeId: number }>;
  dynamicAccess: Array<{ line: number; label: string; scopeId: number }>;
  scopes: ScopeInfo[];
  lineScopeIds: number[];
  codeLines: string[];
}

interface CodeExtraction {
  codeLines: string[];   // block-comments and template-literal bodies removed; strings preserved
  scopeLines: string[];  // strings, comments, template-literals ALL removed (only structural braces remain)
  scopes: ScopeInfo[];
  lineScopeIds: number[]; // pre-computed: lineScopeIds[i] = scope ID for line i+1
}

function extractCode(lines: string[]): CodeExtraction {
  const codeLines: string[] = [];
  const scopeLines: string[] = [];
  let inBlock = false;
  // Template literal stack: each entry is the brace depth inside ${} interpolation.
  // 0 = inside template body (not interpolation), >0 = inside interpolation braces.
  let templateStack: number[] = [];

  // Scope-building state
  const scopes: ScopeInfo[] = [{ id: 0, startLine: 1, endLine: lines.length, parentId: null }];
  const scopeStack: number[] = [0];
  let nextId = 1;
  let braceDepth = 0;
  const scopeStartDepths: Map<number, number> = new Map();
  scopeStartDepths.set(0, 0);
  const fnPattern = /(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>)|\w+\s*\([^)]*\)\s*\{)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let codeOut = '';
    let scopeOut = '';
    let j = 0;

    while (j < line.length) {
      // Inside block comment
      if (inBlock) {
        if (line[j] === '*' && line[j + 1] === '/') { inBlock = false; j += 2; continue; }
        j++;
        continue;
      }

      // Inside template literal body (not in interpolation)
      if (templateStack.length > 0 && templateStack[templateStack.length - 1] === 0) {
        if (line[j] === '\\') { j += 2; continue; }
        if (line[j] === '`') { templateStack.pop(); j++; continue; }
        if (line[j] === '$' && line[j + 1] === '{') {
          templateStack[templateStack.length - 1] = 1;
          j += 2;
          continue;
        }
        j++;
        continue;
      }

      // Inside template interpolation — treat as regular code but track braces
      if (templateStack.length > 0 && templateStack[templateStack.length - 1] > 0) {
        if (line[j] === '{') {
          templateStack[templateStack.length - 1]++;
          codeOut += line[j]; scopeOut += line[j]; j++;
          continue;
        }
        if (line[j] === '}') {
          templateStack[templateStack.length - 1]--;
          if (templateStack[templateStack.length - 1] === 0) {
            // Back to template body
            j++;
            continue;
          }
          codeOut += line[j]; scopeOut += line[j]; j++;
          continue;
        }
        // Fall through to normal code parsing for content inside interpolation
      }

      // Single-line comment
      if (line[j] === '/' && line[j + 1] === '/') break;
      // Block comment start
      if (line[j] === '/' && line[j + 1] === '*') { inBlock = true; j += 2; continue; }
      // Template literal start (or nested template inside interpolation)
      if (line[j] === '`') { templateStack.push(0); j++; continue; }
      // String literals
      if (line[j] === '"' || line[j] === "'") {
        const quote = line[j];
        codeOut += line[j];
        j++;
        while (j < line.length) {
          if (line[j] === '\\') { codeOut += line[j] + (line[j + 1] || ''); j += 2; continue; }
          if (line[j] === quote) { codeOut += line[j]; j++; break; }
          codeOut += line[j];
          j++;
        }
        continue;
      }
      // Regular code character
      codeOut += line[j];
      scopeOut += line[j];
      j++;
    }

    codeLines.push(codeOut);
    scopeLines.push(scopeOut);

    // Build scopes from scopeOut
    const isFnStart = fnPattern.test(scopeOut) && scopeOut.includes('{');

    for (let c = 0; c < scopeOut.length; c++) {
      if (scopeOut[c] === '{') {
        braceDepth++;
        if (isFnStart && c === scopeOut.indexOf('{')) {
          const scope: ScopeInfo = {
            id: nextId++,
            startLine: i + 1,
            endLine: lines.length,
            parentId: scopeStack[scopeStack.length - 1],
          };
          scopes.push(scope);
          scopeStack.push(scope.id);
          scopeStartDepths.set(scope.id, braceDepth);
          break;
        }
      } else if (scopeOut[c] === '}') {
        braceDepth--;
        const currentScopeId = scopeStack[scopeStack.length - 1];
        if (currentScopeId !== 0 && braceDepth < (scopeStartDepths.get(currentScopeId) || 0)) {
          const scope = scopes[currentScopeId];
          if (scope) scope.endLine = i + 1;
          scopeStack.pop();
        }
      }
    }
  }

  // Pre-compute line→scope mapping (O(lines * scopes), done once)
  const lineScopeIds: number[] = new Array(lines.length);
  for (let ln = 0; ln < lines.length; ln++) {
    let best = 0;
    for (const scope of scopes) {
      if ((ln + 1) >= scope.startLine && (ln + 1) <= scope.endLine && scope.id > best) {
        best = scope.id;
      }
    }
    lineScopeIds[ln] = best;
  }

  return { codeLines, scopeLines, scopes, lineScopeIds };
}

function stripNonCode(line: string): string {
  let result = '';
  let i = 0;
  while (i < line.length) {
    if (line[i] === '/' && line[i + 1] === '/') break;
    if (line[i] === '"' || line[i] === "'" || line[i] === '`') {
      const quote = line[i];
      i++;
      while (i < line.length) {
        if (line[i] === '\\') { i += 2; continue; }
        if (line[i] === quote) { i++; break; }
        if (quote === '`' && line[i] === '$' && line[i + 1] === '{') {
          i += 2;
          let depth = 1;
          while (i < line.length && depth > 0) {
            if (line[i] === '{') depth++;
            else if (line[i] === '}') depth--;
            i++;
          }
          continue;
        }
        i++;
      }
      continue;
    }
    result += line[i];
    i++;
  }
  return result;
}


function scopesOverlap(scopeA: number, scopeB: number, scopeMap: Map<number, ScopeInfo>): boolean {
  if (scopeA === scopeB) return true;
  if (scopeA === 0 || scopeB === 0) return true;

  let current = scopeA;
  while (current !== null && current !== 0) {
    if (current === scopeB) return true;
    const scope = scopeMap.get(current);
    current = scope?.parentId ?? 0;
  }
  current = scopeB;
  while (current !== null && current !== 0) {
    if (current === scopeA) return true;
    const scope = scopeMap.get(current);
    current = scope?.parentId ?? 0;
  }
  return false;
}

function analyzeTaint(content: string): TaintState {
  const lines = content.split('\n');
  const { codeLines, scopeLines, scopes, lineScopeIds } = extractCode(lines);
  const scopeMap = new Map<number, ScopeInfo>();
  for (const s of scopes) scopeMap.set(s.id, s);
  const state: TaintState = { sources: [], sinks: [], aliases: [], dynamicAccess: [], scopes, lineScopeIds, codeLines };

  for (let i = 0; i < lines.length; i++) {
    const codeLine = codeLines[i];
    const scopeLine = scopeLines[i];
    if (!codeLine.trim() && !scopeLine.trim()) continue;
    const codeT = codeLine.length > 2000 ? codeLine.substring(0, 2000) : codeLine;
    const scopeT = scopeLine.length > 2000 ? scopeLine.substring(0, 2000) : scopeLine;
    const scopeId = lineScopeIds[i];

    for (const src of SOURCES) {
      const testLine = src.needsString ? codeT : scopeT;
      if (src.pattern.test(testLine)) {
        const varMatch = scopeT.match(/(?:const|let|var)\s+(\w+)\s*=/);
        state.sources.push({
          line: i + 1,
          label: src.label,
          variable: varMatch ? varMatch[1] : undefined,
          scopeId
        });
      }
    }

    for (const sink of SINKS) {
      if (sink.pattern.test(scopeT)) {
        state.sinks.push({ line: i + 1, label: sink.label, severity: sink.severity, scopeId });
      }
    }

    for (const alias of ALIAS_PATTERNS) {
      const testLine = alias.needsString ? codeT : scopeT;
      const match = testLine.match(alias.pattern);
      if (match) {
        state.aliases.push({ line: i + 1, varName: match[1], aliasedSink: alias.aliasedSink, scopeId });
      }
    }

    for (const dyn of DYNAMIC_ACCESS) {
      const testLine = dyn.needsString ? codeT : scopeT;
      if (dyn.pattern.test(testLine)) {
        state.dynamicAccess.push({ line: i + 1, label: dyn.label, scopeId });
      }
    }
  }

  return state;
}

function isVariableUsedInCode(line: string, varName: string): boolean {
  // Word-boundary match: variable used as identifier, not inside a string or comment
  const stripped = stripNonCode(line);
  const pattern = new RegExp(`\\b${varName}\\b`);
  return pattern.test(stripped);
}

function detectTaintFlows(state: TaintState, lines: string[], scopeMap: Map<number, ScopeInfo>, lineScopeIds: number[], codeLines: string[]): Finding[] {
  const findings: Finding[] = [];

  for (const source of state.sources) {
    if (!source.variable) continue;
    for (const sink of state.sinks) {
      if (sink.line === source.line) continue;
      if (!scopesOverlap(source.scopeId, sink.scopeId, scopeMap)) continue;
      const sinkLine = lines[sink.line - 1] || '';
      if (isVariableUsedInCode(sinkLine, source.variable)) {
        findings.push({
          ruleId: 'DT-001',
          ruleName: 'taint-flow-source-to-sink',
          severity: sink.severity,
          description: `Taint flow: ${source.label} (line ${source.line}) → ${sink.label} (line ${sink.line}) via variable '${source.variable}'`,
          category: 'taint-tracking',
          filePath: '',
          lineNumber: sink.line,
          lineContent: sinkLine.trim().substring(0, 200),
          matchedText: source.variable,
          scanner: 'package-scripts'
        });
      }
    }
  }

  for (const alias of state.aliases) {
    const aliasCallPattern = new RegExp(`\\b${alias.varName}\\s*\\(`);
    for (let i = alias.line; i < lines.length; i++) {
      if (aliasCallPattern.test(lines[i])) {
        const callScope = lineScopeIds[i];
        if (!scopesOverlap(alias.scopeId, callScope, scopeMap)) continue;
        findings.push({
          ruleId: 'DT-002',
          ruleName: 'aliased-dangerous-function',
          severity: 'CRITICAL',
          description: `Aliased ${alias.aliasedSink} called via '${alias.varName}' — evades direct pattern matching`,
          category: 'obfuscation-evasion',
          filePath: '',
          lineNumber: i + 1,
          lineContent: lines[i].trim().substring(0, 200),
          matchedText: alias.varName,
          scanner: 'package-scripts'
        });
        break;
      }
    }
  }

  for (const dyn of state.dynamicAccess) {
    findings.push({
      ruleId: 'DT-003',
      ruleName: 'dynamic-property-invocation',
      severity: 'WARNING',
      description: `Dynamic property access: ${dyn.label} — may be used to obfuscate dangerous calls`,
      category: 'obfuscation-evasion',
      filePath: '',
      lineNumber: dyn.line,
      lineContent: lines[dyn.line - 1].trim().substring(0, 200),
      matchedText: dyn.label,
      scanner: 'package-scripts'
    });
  }

  // DT-004: credential-to-network flow with taint propagation
  if (state.sources.length > 0 && state.sinks.length > 0) {
    const credSources = state.sources.filter(s =>
      s.label === 'credential path' || s.label === 'credential env var' || s.label === 'fs.readFile'
    );
    const networkSinks = state.sinks.filter(s =>
      s.label === 'network request' || s.label === 'socket connection'
    );

    for (const source of credSources) {
      if (!source.variable) continue;
      for (const sink of networkSinks) {
        if (sink.line <= source.line) continue;
        if (!scopesOverlap(source.scopeId, sink.scopeId, scopeMap)) continue;

        const taintedVars = new Set<string>([source.variable]);
        for (let i = source.line; i < sink.line && i <= lines.length; i++) {
          const codeLine = codeLines[i - 1] || '';
          const stripped = stripNonCode(lines[i - 1] || '');
          // const/let/var assignment propagation
          const assignMatch = stripped.match(/(?:const|let|var)\s+(\w+)\s*=/);
          if (assignMatch) {
            const lhs = assignMatch[1];
            for (const tv of taintedVars) {
              if (new RegExp(`\\b${tv}\\b`).test(codeLine)) {
                taintedVars.add(lhs);
                break;
              }
            }
          }
          // Property assignment propagation: obj.prop = taintedVar or obj[key] = taintedVar
          const propAssign = stripped.match(/(\w+)\s*(?:\.\w+|\[[^\]]+\])\s*=/);
          if (propAssign) {
            const obj = propAssign[1];
            for (const tv of taintedVars) {
              if (new RegExp(`\\b${tv}\\b`).test(codeLine)) {
                taintedVars.add(obj);
                break;
              }
            }
          }
        }

        // Use codeLine for sink check (comments stripped, template interpolation preserved)
        const sinkCodeLine = codeLines[sink.line - 1] || '';
        let reachesSink = false;
        for (const tv of taintedVars) {
          if (new RegExp(`\\b${tv}\\b`).test(sinkCodeLine)) {
            reachesSink = true;
            break;
          }
        }

        if (reachesSink) {
          findings.push({
            ruleId: 'DT-004',
            ruleName: 'credential-to-network-flow',
            severity: 'CRITICAL',
            description: `Credential/file access (line ${source.line}, var '${source.variable}') flows to network call (line ${sink.line}) — potential exfiltration`,
            category: 'data-exfiltration',
            filePath: '',
            lineNumber: sink.line,
            lineContent: lines[sink.line - 1].trim().substring(0, 200),
            matchedText: `${source.variable} → network`,
            scanner: 'package-scripts'
          });
          break;
        }
      }
    }
  }

  return findings;
}

export class DeepTaintScanner implements Scanner {
  name = 'deep-taint' as const;

  scan(rootPath: string, files: string[]): Finding[] {
    const findings: Finding[] = [];
    const jsFiles = files.filter(f => JS_EXTENSIONS.has(path.extname(f).toLowerCase()));

    for (const file of jsFiles) {
      const fullPath = path.join(rootPath, file);
      let content: string;
      try {
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');
      const state = analyzeTaint(content);

      if (state.sources.length === 0 && state.aliases.length === 0 && state.dynamicAccess.length === 0) {
        continue;
      }

      const scopeMap = new Map<number, ScopeInfo>();
      for (const s of state.scopes) scopeMap.set(s.id, s);
      const fileFindings = detectTaintFlows(state, lines, scopeMap, state.lineScopeIds, state.codeLines);
      for (const finding of fileFindings) {
        finding.filePath = file.replace(/\\/g, '/');
        findings.push(finding);
      }
    }

    return findings;
  }
}
