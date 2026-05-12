import * as fs from 'fs';
import * as path from 'path';
import { Finding, Severity, Scanner } from '../types';

interface UnicodeRule {
  pattern: RegExp;
  name: string;
  severity: Severity;
  id: string;
}

function buildRules(): UnicodeRule[] {
  return [
    { id: 'UC-001', pattern: new RegExp('​', 'g'), name: 'zero-width-space', severity: 'WARNING' },
    { id: 'UC-002', pattern: new RegExp('‌', 'g'), name: 'zero-width-non-joiner', severity: 'INFO' },
    { id: 'UC-003', pattern: new RegExp('‍', 'g'), name: 'zero-width-joiner', severity: 'INFO' },
    { id: 'UC-004', pattern: new RegExp('﻿', 'g'), name: 'byte-order-mark-mid-file', severity: 'WARNING' },
    { id: 'UC-005', pattern: new RegExp('­', 'g'), name: 'soft-hyphen', severity: 'INFO' },
    { id: 'UC-006', pattern: new RegExp('[‮‭]', 'g'), name: 'bidi-override', severity: 'CRITICAL' },
    { id: 'UC-007', pattern: new RegExp('[‏‎]', 'g'), name: 'bidi-mark', severity: 'WARNING' },
    { id: 'UC-008', pattern: new RegExp('[⁦⁧⁨⁩]', 'g'), name: 'directional-isolate', severity: 'WARNING' },
    { id: 'UC-009', pattern: new RegExp('[  ]', 'g'), name: 'line/paragraph-separator', severity: 'INFO' },
    { id: 'UC-010', pattern: new RegExp('[--]', 'g'), name: 'control-character', severity: 'WARNING' },
  ];
}

const TEXT_EXTENSIONS = new Set([
  '.md', '.txt', '.js', '.ts', '.mjs', '.cjs', '.py', '.sh',
  '.json', '.yaml', '.yml', '.toml', '.xml', '.html', '.css',
  '.jsx', '.tsx', '.vue', '.svelte', '.rs', '.go', '.rb',
  '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.swift',
]);

export class UnicodeTricksScanner implements Scanner {
  name = 'unicode-tricks' as const;
  private rules: UnicodeRule[];

  constructor() {
    this.rules = buildRules();
  }

  private isTextFile(relativePath: string): boolean {
    const ext = path.extname(relativePath).toLowerCase();
    if (TEXT_EXTENSIONS.has(ext)) return true;
    const basename = path.basename(relativePath);
    if (!basename.includes('.')) return true;
    return false;
  }

  private isBinary(buffer: Buffer): boolean {
    const checkBytes = Math.min(buffer.length, 8192);
    for (let i = 0; i < checkBytes; i++) {
      if (buffer[i] === 0) return true;
    }
    return false;
  }

  scan(rootPath: string, files: string[]): Finding[] {
    const findings: Finding[] = [];
    const textFiles = files.filter(f => this.isTextFile(f));

    for (const file of textFiles) {
      const fullPath = path.join(rootPath, file);
      let buffer: Buffer;
      try {
        buffer = fs.readFileSync(fullPath);
      } catch {
        continue;
      }

      if (this.isBinary(buffer)) continue;

      const content = buffer.toString('utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        for (const rule of this.rules) {
          if (rule.id === 'UC-004' && i === 0) continue;

          rule.pattern.lastIndex = 0;
          const match = lines[i].match(rule.pattern);
          if (match) {
            findings.push({
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              description: 'Invisible Unicode detected: ' + rule.name,
              category: 'unicode-steganography',
              filePath: file.replace(/\\/g, '/'),
              lineNumber: i + 1,
              lineContent: lines[i].trim().substring(0, 100),
              matchedText: 'U+' + match[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'),
              scanner: 'unicode-tricks'
            });
            break;
          }
        }
      }
    }

    return findings;
  }
}