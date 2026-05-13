#!/usr/bin/env bun

import * as fs from 'fs';
import * as path from 'path';
import { Finding, ScanReport, ScanOptions, Scanner } from './types';
import { PromptInjectionScanner } from './scanners/prompt-injection';
import { PackageScriptsScanner } from './scanners/package-scripts';
import { UnicodeTricksScanner } from './scanners/unicode-tricks';
import { DeepTaintScanner } from './scanners/deep-taint';
import { renderTerminalReport } from './output/terminal';
import { renderJsonReport } from './output/json';
import { renderSarifReport } from './output/sarif';

const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'build', '.git', '.next',
  'coverage', '__pycache__', '.venv', 'venv', '.tox',
  'target', 'out', '.parcel-cache'
]);

const ALLOWED_DOT_DIRS = new Set(['.github', '.claude', '.cursor']);

const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.wav', '.avi', '.mov',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.exe', '.dll', '.so', '.dylib', '.bin',
  '.lock', '.map'
]);

const MAX_FILE_SIZE = 1_000_000;

function loadIgnorePatterns(rootPath: string): string[] {
  const ignorePath = path.join(rootPath, '.malcheckignore');
  if (!fs.existsSync(ignorePath)) return [];
  const content = fs.readFileSync(ignorePath, 'utf-8');
  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
}

function globToRegex(pattern: string): RegExp {
  let regexStr = '';
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === '*' && pattern[i + 1] === '*') {
      // ** matches any path segment(s)
      regexStr += '.*';
      i += 2;
      if (pattern[i] === '/') i++; // skip trailing slash after **
    } else if (ch === '*') {
      // * matches anything except /
      regexStr += '[^/]*';
      i++;
    } else if (ch === '?') {
      regexStr += '[^/]';
      i++;
    } else if ('.+^${}()|[]\\'.includes(ch)) {
      regexStr += '\\' + ch;
      i++;
    } else {
      regexStr += ch;
      i++;
    }
  }
  return new RegExp('^' + regexStr + '$');
}

function isIgnored(relativePath: string, ignorePatterns: string[]): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  let ignored = false;

  for (const pattern of ignorePatterns) {
    const normalizedPattern = pattern.replace(/\\/g, '/');

    // Negation pattern (re-include)
    if (normalizedPattern.startsWith('!')) {
      const negated = normalizedPattern.slice(1);
      if (matchesPattern(normalized, negated)) {
        ignored = false;
      }
      continue;
    }

    if (matchesPattern(normalized, normalizedPattern)) {
      ignored = true;
    }
  }
  return ignored;
}

function matchesPattern(filePath: string, pattern: string): boolean {
  // Directory match (pattern ends with /)
  if (pattern.endsWith('/')) {
    const dir = pattern.slice(0, -1);
    if (filePath.startsWith(dir + '/') || filePath === dir) return true;
    if (filePath.startsWith(pattern)) return true;
  }

  // Exact match
  if (filePath === pattern) return true;

  // Prefix match (directory without trailing slash)
  if (filePath.startsWith(pattern + '/')) return true;

  // Glob pattern (contains *, **, or ?)
  if (pattern.includes('*') || pattern.includes('?')) {
    const regex = globToRegex(pattern);
    if (regex.test(filePath)) return true;
    // Also test against just the basename for patterns like *.test.js
    if (!pattern.includes('/') && regex.test(path.basename(filePath))) return true;
  }

  // Basename match (pattern has no path separator)
  if (!pattern.includes('/')) {
    if (path.basename(filePath) === pattern) return true;
  }

  return false;
}

function discoverFilesUnfiltered(rootPath: string): string[] {
  const files: string[] = [];
  function walk(dir: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch { return; }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith('.') && !ALLOWED_DOT_DIRS.has(entry.name)) continue;
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SKIP_EXTENSIONS.has(ext)) continue;
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > MAX_FILE_SIZE) continue;
        } catch { continue; }
        files.push(path.relative(rootPath, fullPath));
      }
    }
  }
  walk(rootPath);
  return files;
}

function discoverFiles(rootPath: string): { files: string[]; skipped: number; ignored: number } {
  const files: string[] = [];
  let skipped = 0;
  let ignored = 0;
  const ignorePatterns = loadIgnorePatterns(rootPath);

  function walk(dir: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      skipped++;
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(rootPath, fullPath);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {
          skipped++;
          continue;
        }
        if (entry.name.startsWith('.') && !ALLOWED_DOT_DIRS.has(entry.name)) {
          skipped++;
          continue;
        }
        if (isIgnored(relativePath, ignorePatterns)) {
          ignored++;
          continue;
        }
        walk(fullPath);
      } else if (entry.isFile()) {
        if (isIgnored(relativePath, ignorePatterns)) {
          ignored++;
          continue;
        }
        const ext = path.extname(entry.name).toLowerCase();
        if (SKIP_EXTENSIONS.has(ext)) {
          skipped++;
          continue;
        }
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > MAX_FILE_SIZE) {
            skipped++;
            continue;
          }
        } catch {
          skipped++;
          continue;
        }
        files.push(relativePath);
      }
    }
  }

  walk(rootPath);
  return { files, skipped, ignored };
}

function buildReport(
  scanPath: string,
  findings: Finding[],
  totalFiles: number,
  skipped: number,
  ignored: number,
  startTime: number
): ScanReport {
  const durationMs = Date.now() - startTime;
  const critical = findings.filter(f => f.severity === 'CRITICAL').length;
  const warning = findings.filter(f => f.severity === 'WARNING').length;
  const info = findings.filter(f => f.severity === 'INFO').length;

  return {
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    scanPath,
    findings: findings.sort((a, b) => {
      const order = { CRITICAL: 0, WARNING: 1, INFO: 2 };
      return order[a.severity] - order[b.severity];
    }),
    summary: {
      totalFiles: totalFiles + skipped + ignored,
      filesScanned: totalFiles,
      filesSkipped: skipped,
      filesIgnored: ignored,
      totalFindings: findings.length,
      critical,
      warning,
      info,
      clean: critical === 0 && warning === 0,
      durationMs
    }
  };
}

function printHelp(): void {
  console.log(`
  malcheck v1.0.0 — Supply chain security scanner

  USAGE:
    malcheck scan <path> [options]
    malcheck init
    malcheck --help

  COMMANDS:
    scan <path>    Scan a directory for malware and prompt injection threats
    init           Install git pre-commit hook for automatic scanning
    update         Pull latest detection rules from GitHub

  OPTIONS:
    --deep               Enable taint tracking (variable aliasing + indirect calls)
    --strict             Scan ignored files for CRITICAL findings
    --threshold <level>  Exit code threshold: "critical" or "warning" (default: warning)
    --json               Output structured JSON report
    --sarif              Output SARIF 2.1.0 format (GitHub Code Scanning / GitLab SAST)
    --verbose            Show files being scanned
    --help, -h           Show this help message
    --version, -v        Show version

  INLINE SUPPRESSION:
    // malcheck-disable                  Suppress all findings on this line
    // malcheck-disable MW-003           Suppress specific rule on this line
    // malcheck-disable MW-003 MW-012    Suppress multiple rules on this line
    // malcheck-disable-next-line        Suppress all findings on next line
    // malcheck-disable-next-line MW-003 Suppress specific rule on next line

  EXAMPLES:
    malcheck scan .
    malcheck scan ./my-project --json
    malcheck scan /path/to/repo --verbose
`);
}

function initGitHook(): void {
  const RESET = '\x1b[0m';
  const BOLD = '\x1b[1m';
  const GREEN = '\x1b[32m';
  const RED = '\x1b[31m';
  const DIM = '\x1b[2m';

  // Find .git directory (walk up from cwd)
  let dir = process.cwd();
  let gitDir = '';
  while (true) {
    const candidate = path.join(dir, '.git');
    if (fs.existsSync(candidate)) {
      gitDir = candidate;
      break;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  if (!gitDir) {
    console.error(`${RED}Error: not a git repository${RESET}`);
    console.error('Run this command from inside a git repo.');
    process.exit(2);
  }

  const hooksDir = path.join(gitDir, 'hooks');
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  const hookPath = path.join(hooksDir, 'pre-commit');
  const hookContent = `#!/bin/sh
# malcheck pre-commit hook — blocks commits containing malware or prompt injections
# Installed by: malcheck init

# Get the repo root
REPO_ROOT=$(git rev-parse --show-toplevel)

# Run malcheck scan on staged files only
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

# Create temp dir with staged file contents
MALCHECK_TMPDIR=$(mktemp -d)
trap 'rm -rf "$MALCHECK_TMPDIR"' EXIT

for FILE in $STAGED_FILES; do
  mkdir -p "$MALCHECK_TMPDIR/$(dirname "$FILE")"
  git show ":$FILE" > "$MALCHECK_TMPDIR/$FILE" 2>/dev/null || continue
done

# Run malcheck on the staged files
if command -v bun >/dev/null 2>&1; then
  MALCHECK_BIN="bun run"
elif command -v bunx >/dev/null 2>&1; then
  MALCHECK_BIN="bunx"
else
  echo "malcheck: bun runtime not found — cannot scan"
  echo "  Install bun: https://bun.sh"
  echo "  Or set MALCHECK_ALLOW_MISSING=1 to skip"
  [ "\${MALCHECK_ALLOW_MISSING:-0}" = "1" ] && exit 0
  exit 1
fi

# Find malcheck install location
MALCHECK_PATH=""
if [ -f "$REPO_ROOT/node_modules/.bin/malcheck" ]; then
  MALCHECK_PATH="$REPO_ROOT/node_modules/.bin/malcheck"
elif command -v malcheck >/dev/null 2>&1; then
  MALCHECK_PATH="malcheck"
else
  SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
  REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
  if [ -f "$REPO/src/cli.ts" ]; then
    MALCHECK_PATH="$MALCHECK_BIN $REPO/src/cli.ts"
  fi
fi

if [ -z "$MALCHECK_PATH" ]; then
  echo "malcheck: scanner not found in PATH or node_modules"
  echo "  Set MALCHECK_ALLOW_MISSING=1 to skip"
  [ "\${MALCHECK_ALLOW_MISSING:-0}" = "1" ] && exit 0
  exit 1
fi

echo ""
echo "malcheck: scanning staged files..."
echo ""

$MALCHECK_PATH scan "$MALCHECK_TMPDIR"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
  echo ""
  echo "\\033[31m\\033[1m  ✗ Commit blocked — threats detected in staged files\\033[0m"
  echo "\\033[2m    Fix the issues above or use --no-verify to bypass (not recommended)\\033[0m"
  echo ""
  exit 1
fi

exit 0
`;

  // Check if hook already exists
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf-8');
    if (existing.includes('malcheck')) {
      console.log(`${GREEN}${BOLD}  ✓ malcheck hook already installed${RESET}`);
      console.log(`${DIM}    ${hookPath}${RESET}`);
      return;
    }
    // Backup existing hook
    const backupPath = hookPath + '.backup';
    fs.writeFileSync(backupPath, existing);
    console.log(`${DIM}    Backed up existing hook to ${backupPath}${RESET}`);
  }

  fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });

  console.log('');
  console.log(`${GREEN}${BOLD}  ✓ Git pre-commit hook installed${RESET}`);
  console.log('');
  console.log(`${DIM}    Location: ${hookPath}${RESET}`);
  console.log(`${DIM}    Every commit will now be scanned for:${RESET}`);
  console.log(`      • Malware patterns (credential theft, reverse shells, crypto miners)`);
  console.log(`      • Prompt injections (hidden instructions targeting AI assistants)`);
  console.log(`      • Invisible Unicode tricks (zero-width chars, RTL overrides)`);
  console.log('');
  console.log(`${DIM}    To bypass in emergencies: git commit --no-verify${RESET}`);
  console.log('');
}

async function computeHash(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function validateRuleStructure(parsed: any, ruleFile: string): string | null {
  if (!parsed.rules || !Array.isArray(parsed.rules)) {
    return 'missing rules array';
  }
  for (let i = 0; i < parsed.rules.length; i++) {
    const rule = parsed.rules[i];
    if (!rule.id || !rule.pattern || !rule.severity) {
      return `rule[${i}] missing required fields (id, pattern, severity)`;
    }
    // Validate regex compiles without catastrophic backtracking indicators
    try {
      new RegExp(rule.pattern, rule.flags || '');
    } catch {
      return `rule[${i}] (${rule.id}) has invalid regex`;
    }
  }
  return null;
}

async function updateRules(): Promise<void> {
  const RESET = '\x1b[0m';
  const BOLD = '\x1b[1m';
  const GREEN = '\x1b[32m';
  const RED = '\x1b[31m';
  const YELLOW = '\x1b[33m';
  const DIM = '\x1b[2m';

  const RULES_BASE_URL = 'https://raw.githubusercontent.com/biks-code/malcheck/main/src/rules';
  const ruleFiles = ['prompt-patterns.json', 'malware-patterns.json'];

  const localRulesDir = path.join(__dirname, 'rules');

  console.log('');
  console.log(`${BOLD}  malcheck update${RESET}`);
  console.log(`${DIM}  Fetching latest rules from GitHub...${RESET}`);
  console.log('');

  let updated = 0;
  let failed = 0;

  for (const ruleFile of ruleFiles) {
    const url = `${RULES_BASE_URL}/${ruleFile}`;
    try {
      const response = await fetch(url);
      if (!response.ok) {
        console.log(`${RED}    ✗ ${ruleFile}: HTTP ${response.status}${RESET}`);
        failed++;
        continue;
      }

      const content = await response.text();

      // Validate JSON structure
      let parsed: any;
      try {
        parsed = JSON.parse(content);
      } catch {
        console.log(`${RED}    ✗ ${ruleFile}: invalid JSON${RESET}`);
        failed++;
        continue;
      }

      // Deep validation of rule structure
      const validationError = validateRuleStructure(parsed, ruleFile);
      if (validationError) {
        console.log(`${RED}    ✗ ${ruleFile}: ${validationError}${RESET}`);
        failed++;
        continue;
      }

      const localPath = path.join(localRulesDir, ruleFile);
      const existingContent = fs.readFileSync(localPath, 'utf-8');

      // Compare by content hash, not rule count
      const localHash = await computeHash(existingContent);
      const remoteHash = await computeHash(content);

      if (localHash === remoteHash) {
        console.log(`${DIM}    ○ ${ruleFile}: already up to date (${parsed.rules.length} rules)${RESET}`);
      } else {
        const existing = JSON.parse(existingContent);
        const diff = parsed.rules.length - existing.rules.length;

        // Backup before overwriting
        const backupPath = localPath + '.backup';
        fs.writeFileSync(backupPath, existingContent);

        fs.writeFileSync(localPath, content);
        const diffStr = diff > 0 ? `+${diff} new` : diff < 0 ? `${diff} removed` : 'patterns changed';
        console.log(`${GREEN}    ✓ ${ruleFile}: updated (${existing.rules.length} → ${parsed.rules.length} rules, ${diffStr})${RESET}`);
        console.log(`${DIM}      hash: ${remoteHash.substring(0, 12)}...${RESET}`);
        console.log(`${DIM}      backup: ${backupPath}${RESET}`);
        updated++;
      }
    } catch (err: any) {
      console.log(`${RED}    ✗ ${ruleFile}: ${err.message || 'network error'}${RESET}`);
      failed++;
    }
  }

  console.log('');
  if (failed > 0) {
    console.log(`${RED}  ${failed} rule file(s) failed to update${RESET}`);
    console.log(`${DIM}  Check your internet connection and try again${RESET}`);
  } else if (updated > 0) {
    console.log(`${GREEN}${BOLD}  ✓ Rules updated successfully${RESET}`);
    console.log(`${YELLOW}${DIM}  Review changes with: diff src/rules/*.backup src/rules/*.json${RESET}`);
  } else {
    console.log(`${GREEN}  ✓ All rules are current${RESET}`);
  }
  console.log('');
}

function applyInlineSuppression(rootPath: string, findings: Finding[], preloaded?: Map<string, string[]>): Finding[] {
  const fileCache = preloaded || new Map<string, string[]>();

  function getLines(filePath: string): string[] {
    if (fileCache.has(filePath)) return fileCache.get(filePath)!;
    try {
      const fullPath = path.join(rootPath, filePath);
      const lines = fs.readFileSync(fullPath, 'utf-8').split('\n');
      fileCache.set(filePath, lines);
      return lines;
    } catch {
      return [];
    }
  }

  // Only match suppression directives inside comments (// or /* */)
  const COMMENT_DISABLE = /\/\/\s*malcheck-disable(?!-next-line)\s*([\w\s,-]*)|\/\*\s*malcheck-disable(?!-next-line)\s*([\w\s,-]*?)\s*\*\//;
  const COMMENT_DISABLE_NEXT = /\/\/\s*malcheck-disable-next-line\s*([\w\s,-]*)|\/\*\s*malcheck-disable-next-line\s*([\w\s,-]*?)\s*\*\//;

  function matchesSuppressionRules(ruleList: string, findingRuleId: string): boolean {
    const trimmed = ruleList.trim();
    if (!trimmed) return true;
    const rules = trimmed.split(/[\s,]+/).filter(Boolean);
    return rules.includes(findingRuleId);
  }

  return findings.filter(finding => {
    const lines = getLines(finding.filePath);
    if (lines.length === 0) return true;

    const lineIdx = finding.lineNumber - 1;

    const currentLine = lines[lineIdx] || '';
    const currentMatch = currentLine.match(COMMENT_DISABLE);
    if (currentMatch) {
      const ruleList = currentMatch[1] || currentMatch[2] || '';
      if (matchesSuppressionRules(ruleList, finding.ruleId)) return false;
    }

    if (lineIdx > 0) {
      const prevLine = lines[lineIdx - 1] || '';
      const prevMatch = prevLine.match(COMMENT_DISABLE_NEXT);
      if (prevMatch) {
        const ruleList = prevMatch[1] || prevMatch[2] || '';
        if (matchesSuppressionRules(ruleList, finding.ruleId)) return false;
      }
    }

    return true;
  });
}

function main(): void {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log('malcheck v1.0.0');
    process.exit(0);
  }

  const command = args[0];

  if (command === 'init') {
    initGitHook();
    process.exit(0);
  }

  if (command === 'update') {
    updateRules().then(() => process.exit(0)).catch(() => process.exit(2));
    return;
  }

  if (command === 'scan') {
    const targetPath = args[1];
    if (!targetPath) {
      console.error('Error: please provide a path to scan');
      console.error('Usage: malcheck scan <path>');
      process.exit(2);
    }

    const options: ScanOptions = {
      json: args.includes('--json'),
      sarif: args.includes('--sarif'),
      verbose: args.includes('--verbose'),
      deep: args.includes('--deep'),
      strict: args.includes('--strict'),
    };

    const resolvedPath = path.resolve(targetPath);

    if (!fs.existsSync(resolvedPath)) {
      console.error(`Error: path does not exist: ${resolvedPath}`);
      process.exit(2);
    }

    const startTime = Date.now();
    const { files, skipped, ignored } = discoverFiles(resolvedPath);

    if (options.verbose) {
      console.error(`Scanning ${files.length} files (${skipped} skipped, ${ignored} ignored)...`);
    }

    const scanners: Scanner[] = [
      new PromptInjectionScanner(),
      new PackageScriptsScanner(),
      new UnicodeTricksScanner(),
    ];

    if (options.deep) {
      scanners.push(new DeepTaintScanner());
      if (options.verbose) {
        console.error('Deep analysis: AST taint tracking enabled');
      }
    }

    // In --strict mode, scan ignored files for CRITICAL findings (they can't be suppressed)
    const ignorePatterns = loadIgnorePatterns(resolvedPath);
    const ignoredFiles: string[] = [];
    if (options.strict && ignorePatterns.length > 0) {
      const allDiscovered = discoverFilesUnfiltered(resolvedPath);
      for (const f of allDiscovered) {
        if (isIgnored(f, ignorePatterns) && !files.includes(f)) {
          ignoredFiles.push(f);
        }
      }
    }

    const allFindings: Finding[] = [];
    for (const scanner of scanners) {
      const findings = scanner.scan(resolvedPath, files);
      allFindings.push(...findings);

      // --strict: scan ignored files but only keep CRITICAL findings
      if (options.strict && ignoredFiles.length > 0) {
        const ignoredFindings = scanner.scan(resolvedPath, ignoredFiles);
        for (const f of ignoredFindings) {
          if (f.severity === 'CRITICAL') {
            f.description = '[ignored file] ' + f.description;
            allFindings.push(f);
          }
        }
      }
    }

    // Pre-load files that have findings (avoids redundant reads in suppression)
    const fileContentCache = new Map<string, string[]>();
    const uniqueFiles = new Set(allFindings.map(f => f.filePath));
    for (const filePath of uniqueFiles) {
      try {
        const content = fs.readFileSync(path.join(resolvedPath, filePath), 'utf-8');
        fileContentCache.set(filePath, content.split('\n'));
      } catch { /* skip unreadable */ }
    }

    const filteredFindings = applyInlineSuppression(resolvedPath, allFindings, fileContentCache);

    const report = buildReport(resolvedPath, filteredFindings, files.length, skipped, ignored, startTime);

    if (options.sarif) {
      console.log(renderSarifReport(report));
    } else if (options.json) {
      renderJsonReport(report);
    } else {
      renderTerminalReport(report);
    }

    // --threshold: only fail on specified severity or above
    const thresholdIdx = args.indexOf('--threshold');
    const threshold = thresholdIdx !== -1 ? args[thresholdIdx + 1] : null;

    if (threshold === 'critical') {
      process.exit(report.summary.critical > 0 ? 1 : 0);
    } else if (threshold === 'warning') {
      process.exit((report.summary.critical > 0 || report.summary.warning > 0) ? 1 : 0);
    }

    if (report.summary.critical > 0 || report.summary.warning > 0) {
      process.exit(1);
    }
    process.exit(0);
  }

  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(2);
}

main();
