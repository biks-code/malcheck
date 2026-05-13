import { test, expect, describe } from 'bun:test';
import * as path from 'path';
import { PromptInjectionScanner } from '../scanners/prompt-injection';
import { PackageScriptsScanner } from '../scanners/package-scripts';
import { UnicodeTricksScanner } from '../scanners/unicode-tricks';
import { DeepTaintScanner } from '../scanners/deep-taint';
import { Finding } from '../types';

const FIXTURES = path.resolve(__dirname, '../../test-fixtures');

describe('PromptInjectionScanner', () => {
  const scanner = new PromptInjectionScanner();

  test('detects prompt injection in evil README', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'prompt-injection'),
      ['evil-readme.md']
    );
    const critical = findings.filter(f => f.severity === 'CRITICAL');
    expect(critical.length).toBeGreaterThan(0);
    expect(critical.some(f => f.ruleId === 'PI-001')).toBe(true);
    expect(critical.some(f => f.ruleId === 'PI-004')).toBe(true);
  });

  test('detects jailbreak keywords in cursorrules', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'prompt-injection'),
      ['evil-cursorrules.md']
    );
    expect(findings.some(f => f.ruleId === 'PI-014')).toBe(true);
    expect(findings.some(f => f.ruleId === 'PI-017')).toBe(true);
  });

  test('produces zero findings on clean README', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'clean'),
      ['README.md']
    );
    expect(findings.length).toBe(0);
  });

  test('does not scan non-target files', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'clean'),
      ['index.js']
    );
    expect(findings.length).toBe(0);
  });
});

describe('PackageScriptsScanner', () => {
  const scanner = new PackageScriptsScanner();

  test('detects malicious postinstall scripts', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'malware'),
      ['package.json']
    );
    const critical = findings.filter(f => f.severity === 'CRITICAL');
    expect(critical.length).toBeGreaterThan(0);
    expect(critical.some(f => f.ruleId === 'MW-002')).toBe(true);
  });

  test('detects credential theft in JS files', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'malware'),
      ['stealer.js']
    );
    expect(findings.some(f => f.ruleId === 'MW-012')).toBe(true);
    expect(findings.some(f => f.ruleId === 'MW-018')).toBe(true);
  });

  test('detects eval+encoded pattern', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'malware'),
      ['stealer.js']
    );
    expect(findings.some(f => f.ruleId === 'MW-001')).toBe(true);
  });

  test('detects cross-line data exfiltration (multiline rule)', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'malware'),
      ['stealer.js']
    );
    expect(findings.some(f => f.ruleId === 'MW-010')).toBe(true);
  });

  test('does NOT fire MW-002 on clean package.json', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'clean'),
      ['package.json']
    );
    const mw002 = findings.filter(f => f.ruleId === 'MW-002');
    expect(mw002.length).toBe(0);
  });

  test('clean JS file produces zero findings', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'clean'),
      ['index.js']
    );
    expect(findings.length).toBe(0);
  });
});

describe('UnicodeTricksScanner', () => {
  const scanner = new UnicodeTricksScanner();

  test('clean files have no unicode findings', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'clean'),
      ['README.md', 'index.js', 'package.json']
    );
    expect(findings.length).toBe(0);
  });
});

describe('DeepTaintScanner', () => {
  const scanner = new DeepTaintScanner();

  test('detects aliased eval (const fn = eval; fn(x))', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'malware'),
      ['evasion-sample.js']
    );
    const aliased = findings.filter(f => f.ruleId === 'DT-002');
    expect(aliased.length).toBeGreaterThan(0);
    expect(aliased[0].description).toContain('eval');
  });

  test('detects credential-to-network flow', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'malware'),
      ['evasion-sample.js']
    );
    const flows = findings.filter(f => f.ruleId === 'DT-004');
    expect(flows.length).toBeGreaterThan(0);
  });

  test('detects dynamic property access', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'malware'),
      ['evasion-sample.js']
    );
    const dynamic = findings.filter(f => f.ruleId === 'DT-003');
    expect(dynamic.length).toBeGreaterThan(0);
  });

  test('clean JS produces zero findings', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'clean'),
      ['index.js']
    );
    expect(findings.length).toBe(0);
  });

  test('detects destructured child_process aliasing', () => {
    const findings = scanner.scan(
      path.join(FIXTURES, 'malware'),
      ['stealer.js']
    );
    const aliased = findings.filter(f => f.ruleId === 'DT-002');
    expect(aliased.length).toBeGreaterThan(0);
  });
});

describe('False positive regression', () => {
  const piScanner = new PromptInjectionScanner();
  const mwScanner = new PackageScriptsScanner();
  const ucScanner = new UnicodeTricksScanner();
  const dtScanner = new DeepTaintScanner();

  test('clean fixtures produce zero CRITICAL/WARNING findings across all scanners', () => {
    const cleanDir = path.join(FIXTURES, 'clean');
    const files = ['README.md', 'index.js', 'package.json'];

    const allFindings: Finding[] = [
      ...piScanner.scan(cleanDir, files),
      ...mwScanner.scan(cleanDir, files),
      ...ucScanner.scan(cleanDir, files),
    ];

    const actionable = allFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'WARNING');
    expect(actionable.length).toBe(0);
  });

  test('DT-004 does NOT fire on Express app reading process.env.PORT + fetch', () => {
    const findings = dtScanner.scan(
      path.join(FIXTURES, 'clean'),
      ['server.js']
    );
    const dt004 = findings.filter(f => f.ruleId === 'DT-004');
    expect(dt004.length).toBe(0);
  });

  test('DT-004 DOES fire on credential exfiltration pattern', () => {
    const findings = dtScanner.scan(
      path.join(FIXTURES, 'malware'),
      ['evasion-sample.js']
    );
    const dt004 = findings.filter(f => f.ruleId === 'DT-004');
    expect(dt004.length).toBeGreaterThan(0);
    expect(dt004[0].description).toContain('secret');
  });

  test('DT-004 does NOT fire when credential var is unused in fetch call', () => {
    const findings = dtScanner.scan(
      path.join(FIXTURES, 'clean'),
      ['unrelated-usage.js']
    );
    const dt004 = findings.filter(f => f.ruleId === 'DT-004');
    expect(dt004.length).toBe(0);
  });

  test('does NOT detect sources/sinks inside string literals', () => {
    const findings = dtScanner.scan(
      path.join(FIXTURES, 'clean'),
      ['string-mentions.js']
    );
    expect(findings.length).toBe(0);
  });

  test('detects taint through nested template literals', () => {
    const findings = dtScanner.scan(
      path.join(FIXTURES, 'malware'),
      ['nested-template.js']
    );
    const dt004 = findings.filter(f => f.ruleId === 'DT-004');
    expect(dt004.length).toBeGreaterThan(0);
    expect(dt004[0].description).toContain('secret');
  });
});
