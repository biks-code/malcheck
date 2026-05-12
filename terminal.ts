import { ScanReport, Finding, Severity } from '../types';

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const UNDERLINE = '\x1b[4m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const WHITE = '\x1b[37m';
const BG_RED = '\x1b[41m';
const BG_YELLOW = '\x1b[43m';
const BG_BLUE = '\x1b[44m';
const BLACK = '\x1b[30m';

function severityBadge(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return `${BG_RED}${WHITE}${BOLD} CRITICAL ${RESET}`;
    case 'WARNING': return `${BG_YELLOW}${BLACK} WARNING  ${RESET}`;
    case 'INFO': return `${BG_BLUE}${WHITE}  INFO    ${RESET}`;
  }
}

function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const existing = map.get(f.filePath) || [];
    existing.push(f);
    map.set(f.filePath, existing);
  }
  return map;
}

export function renderTerminalReport(report: ScanReport): void {
  console.log('');

  if (report.summary.clean) {
    console.log(`${GREEN}${BOLD}  ✓ No threats detected${RESET}`);
    console.log(`${DIM}    Scanned ${report.summary.filesScanned} files in ${report.summary.durationMs}ms${RESET}`);
    console.log('');
    return;
  }

  const grouped = groupByFile(report.findings);

  for (const [file, findings] of grouped) {
    console.log(`\n  ${UNDERLINE}${WHITE}${file}${RESET}`);
    for (const f of findings) {
      const badge = severityBadge(f.severity);
      console.log(`    ${badge} Line ${f.lineNumber}: ${f.description}`);
      console.log(`${DIM}             ${f.lineContent.substring(0, 120)}${RESET}`);
    }
  }

  console.log(`\n${BOLD}  Summary${RESET}`);
  console.log('  ' + '-'.repeat(50));

  if (report.summary.critical > 0) {
    console.log(`${RED}    CRITICAL: ${report.summary.critical}${RESET}`);
  }
  if (report.summary.warning > 0) {
    console.log(`${YELLOW}    WARNING:  ${report.summary.warning}${RESET}`);
  }
  if (report.summary.info > 0) {
    console.log(`${BLUE}    INFO:     ${report.summary.info}${RESET}`);
  }

  const ignoredStr = report.summary.filesIgnored ? `, ${report.summary.filesIgnored} ignored` : '';
  console.log(`${DIM}\n    ${report.summary.filesScanned} files scanned, ${report.summary.filesSkipped} skipped${ignoredStr}, ${report.summary.durationMs}ms${RESET}`);
  console.log('');
}
