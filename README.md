# malcheck

Supply chain security scanner that detects **malware in packages** and **prompt injections targeting AI coding assistants**.

One command. Two seconds. Zero config.

```bash
bun run src/cli.ts scan .
```

## Why this exists

Hackers are increasingly targeting open source with two attack vectors:

1. **Malware in packages** — malicious postinstall scripts, credential stealers, reverse shells, crypto miners hidden in npm/PyPI packages
2. **Prompt injection in repos** — hidden instructions in README files, `.cursorrules`, and YAML that manipulate AI coding assistants (Copilot, Claude Code, Cursor)

No existing tool covers both. Existing scanners (Snyk, npm audit, Socket.dev) focus on known CVEs and require accounts. malcheck works offline, in 2 seconds, with zero setup.

## Installation

Requires [Bun](https://bun.sh) (v1.0+):

```bash
git clone https://github.com/biks-code/malcheck.git
cd malcheck
bun run src/cli.ts scan <path>
```

## Usage

```bash
# Scan a directory
bun run src/cli.ts scan .

# Scan a specific repo you cloned
bun run src/cli.ts scan ../some-project

# Get JSON output (for CI/CD pipelines)
bun run src/cli.ts scan . --json

# Verbose mode (shows files being scanned)
bun run src/cli.ts scan . --verbose
```

## What it detects

### Prompt Injection (27 rules)

| Category | Examples |
|----------|----------|
| Direct overrides | "ignore previous instructions", "you are now..." |
| Hidden HTML instructions | `<!-- override safety -->` in markdown |
| Jailbreak keywords | DAN mode, unrestricted mode, god mode |
| Template injection | `<\|im_start\|>`, `[INST]` tokens in repo files |
| Invisible Unicode | Zero-width spaces, RTL overrides hiding content |
| Tool/MCP manipulation | Attempts to hijack AI tool invocations |
| Delimiter escapes | Closing system prompt tags prematurely |
| Multi-agent cascade | Instructions designed to propagate across agents |
| YAML metadata injection | AI instructions hidden in front matter |

### Malware Detection (27 rules)

| Category | Examples |
|----------|----------|
| Obfuscated execution | `eval(Buffer.from(...))`, encoded payloads |
| Install script abuse | Network calls in postinstall/preinstall hooks |
| Credential theft | Reading .ssh/id_rsa, .env, .aws/credentials, .npmrc |
| Data exfiltration | Discord webhooks, DNS tunneling, HTTP POST to C2 |
| Reverse shells | net.Socket piped to /bin/sh |
| Crypto miners | stratum+tcp, xmrig, mining pool connections |
| Persistence | crontab, systemctl, registry Run keys |
| Encrypted payloads | AES decryption with env var as key (event-stream style) |
| Conditional detonation | Code that only executes in specific environments |
| Dropper patterns | Download binary + chmod +x + execute |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no threats found |
| 1 | Threats detected (CRITICAL or WARNING findings) |
| 2 | Scanner error (invalid path, etc.) |

## Severity Levels

- **CRITICAL** — Active exfiltration, credential theft, prompt override, reverse shell
- **WARNING** — Suspicious pattern with high confidence of malicious intent
- **INFO** — Low-confidence match, may be benign (not counted toward exit code 1)

## Project Structure

```
malcheck/
├── src/
│   ├── cli.ts                    # CLI entry point
│   ├── types.ts                  # TypeScript interfaces
│   ├── scanners/
│   │   ├── prompt-injection.ts   # Scans markdown/config for prompt attacks
│   │   ├── package-scripts.ts    # Scans package.json + code for malware
│   │   └── unicode-tricks.ts     # Detects invisible Unicode characters
│   ├── rules/
│   │   ├── prompt-patterns.json  # 27 prompt injection detection rules
│   │   └── malware-patterns.json # 27 malware detection rules
│   └── output/
│       ├── terminal.ts           # Colored CLI output
│       └── json.ts               # Structured JSON output
├── test-fixtures/                # Known-bad samples for testing
├── package.json
└── tsconfig.json
```

## Roadmap

- [x] CLI scanner with heuristic rules
- [x] Prompt injection detection (27 rules)
- [x] Malware pattern detection (27 rules)
- [x] Invisible Unicode detection
- [x] JSON output for CI/CD
- [ ] `malcheck init` — auto-install git hooks
- [ ] `--deep` flag — AI-powered semantic analysis
- [ ] Community trust network — crowdsourced package reputation
- [ ] Browser extension for npmjs.com/PyPI
- [ ] VS Code extension

## Contributing

Add new detection rules to `src/rules/prompt-patterns.json` or `src/rules/malware-patterns.json`. Each rule needs:

```json
{
  "id": "PI-028",
  "name": "short-kebab-name",
  "pattern": "regex pattern here",
  "flags": "i",
  "severity": "CRITICAL",
  "description": "What this rule detects",
  "category": "category-name"
}
```

Test your rule against the `test-fixtures/` directory to verify it catches real attacks without false-positiving on clean code.

## Research

See [Prompt_Injection_and_Malware_Research.md](./Prompt_Injection_and_Malware_Research.md) for the threat landscape analysis that informed these detection rules.

## License

MIT
