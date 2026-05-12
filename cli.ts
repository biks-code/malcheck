#!/usr/bin/env bun

import * as fs from 'fs';
import * as path from 'path';
import { Finding, ScanReport, ScanOptions } from './types';
import { PromptInjectionScanner } from './scanners/prompt-injection';
import { PackageScriptsScanner } from './scanners/package-scripts';
import { UnicodeTricksScanner } from './scanners/unicode-tricks';
import { renderTerminalReport } from './output/terminal';
import { renderJsonReport } from './output/json';

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

function isIgnored(relativePath: string, ignorePatterns: string[]): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  for (const pattern of ignorePatterns) {
    const normalizedPattern = pattern.replace(/\\/g, '/');
    // Directory match (pattern ends with /)
    if (normalizedPattern.endsWith('/')) {
      if (normalized.startsWith(normalizedPattern) || normalized.startsWith(normalizedPattern.slice(0, -1))) {
        return true;
      }
    }
    // Exact file match
    if (normalized === normalizedPattern) return true;
    // Prefix match (pattern is a directory without trailing slash)
    if (normalized.startsWith(normalizedPattern + '/')) return true;
    // Basename match (pattern matches just the filename)
    const basename = path.basename(normalized);
    if (basename === normalizedPattern) return true;
  }
  return false;
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

  OPTIONS:
    --json         Output structured JSON report
    --verbose      Show files being scanned
    --help, -h     Show this help message
    --version, -v  Show version

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
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

for FILE in $STAGED_FILES; do
  # Recreate directory structure
  mkdir -p "$TMPDIR/$(dirname "$FILE")"
  # Get staged version of the file
  git show ":$FILE" > "$TMPDIR/$FILE" 2>/dev/null || continue
done

# Run malcheck on the staged files
if command -v bun >/dev/null 2>&1; then
  MALCHECK_BIN="bun run"
elif command -v bunx >/dev/null 2>&1; then
  MALCHECK_BIN="bunx"
else
  echo "malcheck: bun not found, skipping scan"
  exit 0
fi

# Find malcheck install location
MALCHECK_PATH=""
if [ -f "$REPO_ROOT/node_modules/.bin/malcheck" ]; then
  MALCHECK_PATH="$REPO_ROOT/node_modules/.bin/malcheck"
elif command -v malcheck >/dev/null 2>&1; then
  MALCHECK_PATH="malcheck"
else
  # Try to find it relative to this hook (covers local dev)
  SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
  REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
  if [ -f "$REPO/src/cli.ts" ]; then
    MALCHECK_PATH="$MALCHECK_BIN $REPO/src/cli.ts"
  fi
fi

if [ -z "$MALCHECK_PATH" ]; then
  echo "malcheck: scanner not found in PATH or node_modules, skipping"
  exit 0
fi

echo ""
echo "malcheck: scanning staged files..."
echo ""

$MALCHECK_PATH scan "$TMPDIR"
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

  if (command === 'scan') {
    const targetPath = args[1];
    if (!targetPath) {
      console.error('Error: please provide a path to scan');
      console.error('Usage: malcheck scan <path>');
      process.exit(2);
    }

    const options: ScanOptions = {
      json: args.includes('--json'),
      verbose: args.includes('--verbose'),
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

    const scanners = [
      new PromptInjectionScanner(),
      new PackageScriptsScanner(),
      new UnicodeTricksScanner(),
    ];

    const allFindings: Finding[] = [];
    for (const scanner of scanners) {
      const findings = scanner.scan(resolvedPath, files);
      allFindings.push(...findings);
    }

    const report = buildReport(resolvedPath, allFindings, files.length, skipped, ignored, startTime);

    if (options.json) {
      renderJsonReport(report);
    } else {
      renderTerminalReport(report);
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
