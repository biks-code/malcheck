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

function discoverFiles(rootPath: string): { files: string[]; skipped: number } {
  const files: string[] = [];
  let skipped = 0;

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

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {
          skipped++;
          continue;
        }
        if (entry.name.startsWith('.') && !ALLOWED_DOT_DIRS.has(entry.name)) {
          skipped++;
          continue;
        }
        walk(fullPath);
      } else if (entry.isFile()) {
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
        files.push(path.relative(rootPath, fullPath));
      }
    }
  }

  walk(rootPath);
  return { files, skipped };
}

function buildReport(
  scanPath: string,
  findings: Finding[],
  totalFiles: number,
  skipped: number,
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
      totalFiles: totalFiles + skipped,
      filesScanned: totalFiles,
      filesSkipped: skipped,
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
    init           Install git hooks for automatic scanning (v1.1)

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
    console.log('Git hook integration coming in v1.1');
    console.log('For now, run: malcheck scan . before committing');
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
    const { files, skipped } = discoverFiles(resolvedPath);

    if (options.verbose) {
      console.error(`Scanning ${files.length} files (${skipped} skipped)...`);
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

    const report = buildReport(resolvedPath, allFindings, files.length, skipped, startTime);

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
