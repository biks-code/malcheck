import * as fs from 'fs';
import * as path from 'path';
import { Finding, Rule, RuleFile, Scanner } from '../types';

const TARGET_EXTENSIONS = new Set(['.md', '.txt', '.rst', '.mdx']);
const TARGET_FILENAMES = new Set([
  '.cursorrules',
  '.cursorignore',
  'claude.md',
  'agents.md',
  'copilot-instructions.md',
]);
const TARGET_DIRS = new Set(['.github', '.claude', '.cursor']);

export class PromptInjectionScanner implements Scanner {
  name = 'prompt-injection' as const;
  private compiledRules: Array<{ rule: Rule; regex: RegExp }>;

  constructor() {
    const rulesPath = path.join(__dirname, '..', 'rules', 'prompt-patterns.json');
    const ruleFile: RuleFile = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
    this.compiledRules = ruleFile.rules.map(rule => ({
      rule,
      regex: new RegExp(rule.pattern, rule.flags || '')
    }));
  }

  private isTargetFile(relativePath: string): boolean {
    const basename = path.basename(relativePath).toLowerCase();
    const ext = path.extname(relativePath).toLowerCase();
    const parts = relativePath.replace(/\\/g, '/').split('/');

    if (TARGET_FILENAMES.has(basename)) return true;
    if (TARGET_EXTENSIONS.has(ext)) return true;
    if (parts.some(p => TARGET_DIRS.has(p))) return true;

    return false;
  }

  scan(rootPath: string, files: string[]): Finding[] {
    const findings: Finding[] = [];
    const targetFiles = files.filter(f => this.isTargetFile(f));

    for (const file of targetFiles) {
      const fullPath = path.join(rootPath, file);
      let content: string;
      try {
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        for (const { rule, regex } of this.compiledRules) {
          regex.lastIndex = 0;
          const match = lines[i].match(regex);
          if (match) {
            findings.push({
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              description: rule.description,
              category: rule.category,
              filePath: file.replace(/\\/g, '/'),
              lineNumber: i + 1,
              lineContent: lines[i].trim(),
              matchedText: match[0],
              scanner: 'prompt-injection'
            });
          }
        }
      }
    }

    return findings;
  }
}
