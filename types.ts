export type Severity = 'CRITICAL' | 'WARNING' | 'INFO';

export interface Rule {
  id: string;
  name: string;
  pattern: string;
  flags: string;
  severity: Severity;
  description: string;
  category: string;
  file_context?: string[];
}

export interface RuleFile {
  version: string;
  description: string;
  rules: Rule[];
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  description: string;
  category: string;
  filePath: string;
  lineNumber: number;
  lineContent: string;
  matchedText: string;
  scanner: 'prompt-injection' | 'package-scripts' | 'unicode-tricks';
}

export interface ScanSummary {
  totalFiles: number;
  filesScanned: number;
  filesSkipped: number;
  filesIgnored?: number;
  totalFindings: number;
  critical: number;
  warning: number;
  info: number;
  clean: boolean;
  durationMs: number;
}

export interface ScanReport {
  version: string;
  timestamp: string;
  scanPath: string;
  findings: Finding[];
  summary: ScanSummary;
}

export interface Scanner {
  name: string;
  scan(rootPath: string, files: string[]): Finding[];
}

export interface ScanOptions {
  json?: boolean;
  verbose?: boolean;
}
