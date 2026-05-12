import * as fs from 'fs';
import * as path from 'path';
import { Finding, Rule, RuleFile, Scanner } from '../types';

const DANGEROUS_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];
const CODE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.py', '.sh']);

export class PackageScriptsScanner implements Scanner {
  name = 'package-scripts' as const;
  private compiledRules: Array<{ rule: Rule; regex: RegExp }>;

  constructor() {
    const rulesPath = path.join(__dirname, '..', 'rules', 'malware-patterns.json');
    const ruleFile: RuleFile = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
    this.compiledRules = ruleFile.rules.map(rule => ({
      rule,
      regex: new RegExp(rule.pattern, rule.flags || '')
    }));
  }

  private matchesFileContext(filePath: string, fileContext?: string[]): boolean {
    if (!fileContext || fileContext.length === 0) return true;
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath).toLowerCase();
    return fileContext.some(ctx => {
      if (ctx.startsWith('*')) return ext === ctx.slice(1);
      if (ctx.includes(':')) return basename === ctx.split(':')[0];
      return basename === ctx;
    });
  }

  private scanFileContent(filePath: string, fullPath: string): Finding[] {
    const findings: Finding[] = [];
    let content: string;
    try {
      content = fs.readFileSync(fullPath, 'utf-8');
    } catch {
      return findings;
    }

    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      for (const { rule, regex } of this.compiledRules) {
        if (!this.matchesFileContext(filePath, rule.file_context)) continue;
        regex.lastIndex = 0;
        const match = lines[i].match(regex);
        if (match) {
          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            description: rule.description,
            category: rule.category,
            filePath: filePath.replace(/\\/g, '/'),
            lineNumber: i + 1,
            lineContent: lines[i].trim(),
            matchedText: match[0],
            scanner: 'package-scripts'
          });
        }
      }
    }

    return findings;
  }

  private scanPackageJson(rootPath: string, pkgFile: string): Finding[] {
    const findings: Finding[] = [];
    const fullPath = path.join(rootPath, pkgFile);
    let content: string;
    try {
      content = fs.readFileSync(fullPath, 'utf-8');
    } catch {
      return findings;
    }

    let pkg: any;
    try {
      pkg = JSON.parse(content);
    } catch {
      return findings;
    }

    if (!pkg.scripts) return findings;

    for (const scriptName of DANGEROUS_SCRIPTS) {
      const scriptValue = pkg.scripts[scriptName];
      if (!scriptValue) continue;

      for (const { rule, regex } of this.compiledRules) {
        regex.lastIndex = 0;
        const match = scriptValue.match(regex);
        if (match) {
          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            description: `[${scriptName} script] ${rule.description}`,
            category: rule.category,
            filePath: pkgFile.replace(/\\/g, '/'),
            lineNumber: 1,
            lineContent: `"${scriptName}": "${scriptValue}"`,
            matchedText: match[0],
            scanner: 'package-scripts'
          });
        }
      }
    }

    return findings;
  }

  scan(rootPath: string, files: string[]): Finding[] {
    const findings: Finding[] = [];

    const packageJsonFiles = files.filter(f => path.basename(f) === 'package.json');
    for (const pkgFile of packageJsonFiles) {
      findings.push(...this.scanPackageJson(rootPath, pkgFile));
    }

    const codeFiles = files.filter(f => CODE_EXTENSIONS.has(path.extname(f).toLowerCase()));
    for (const codeFile of codeFiles) {
      const fullPath = path.join(rootPath, codeFile);
      findings.push(...this.scanFileContent(codeFile, fullPath));
    }

    return findings;
  }
}
