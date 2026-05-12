# malcheck

Fast heuristic scanner that catches **obvious supply chain malware** and **prompt injections targeting AI coding assistants** in your repos.

It won't catch sophisticated attackers. It will catch the lazy ones — which is [most of them](https://blog.phylum.io/the-state-of-software-supply-chain-security/).

```bash
bun run src/cli.ts scan .
```

## What this is (and isn't)

**This IS:**
- A zero-config tripwire that catches copy-paste malware (eval + encoded payloads, webhook exfil, postinstall curl)
- The only CLI scanner for AI-assistant-targeted repo poisoning (.cursorrules, CLAUDE.md, copilot-instructions.md)
- A pre-commit hook that stops accidental credential patterns from reaching your remote
- A CI gate for low-effort supply chain attacks (which covers ~60% of real-world npm malware)

**This is NOT:**
- A replacement for Socket.dev, Snyk, or npm audit (those use AST analysis, dataflow tracking, behavioral sandboxing)
- A security boundary you can rely on against targeted attacks
- Able to catch variable indirection, string splitting, or multi-layer obfuscation

**Honest limitation:** Any attacker who reads these rules can bypass them. The value is catching attackers who don't bother.

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

# Install pre-commit hook (scans staged files before every commit)
bun run src/cli.ts init

# Get JSON output (for CI/CD pipelines)
bun run src/cli.ts scan . --json

# Verbose mode (shows files being scanned)
bun run src/cli.ts scan . --verbose
```

## What it detects

### Prompt Injection (27 regex rules)

Scans markdown, .cursorrules, CLAUDE.md, copilot-instructions.md, and YAML front matter.

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

### Malware Detection (27 regex rules)

Scans JS, TS, Python, shell scripts, and package.json install hooks.

| Category | Examples |
|----------|----------|
| Obfuscated execution | `eval(Buffer.from(...))`, encoded payloads |
| Install script abuse | Network calls in postinstall/preinstall hooks |
| Credential theft | Reading .ssh/id_rsa, .env, .aws/credentials, .npmrc |
| Data exfiltration | Discord webhooks, DNS tunneling, HTTP POST to C2 |
| Reverse shells | net.Socket piped to /bin/sh |
| Crypto miners | stratum+tcp, xmrig, mining pool connections |
| Persistence | crontab, systemctl, registry Run keys |
| Encrypted payloads | AES decryption with env var as key |
| Conditional detonation | Code that only executes in specific environments |
| Dropper patterns | Download binary + chmod +x + execute |

### Limitations of regex detection

These rules catch **literal patterns**. They will NOT catch:
- `const e = eval; e(payload)` (variable indirection)
- String concatenation across multiple lines
- Dynamic property access (`obj['ev' + 'al']`)
- Multi-file attacks where setup and detonation are separated

For deeper analysis, use AST-based tools like [Socket.dev](https://socket.dev) or [Snyk](https://snyk.io) alongside this.

## .malcheckignore

Create a `.malcheckignore` file in your project root to suppress false positives:

```
# Ignore security research docs (they discuss attacks by nature)
Prompt_Injection_and_Malware_Research.md

# Ignore test fixtures (intentionally malicious samples)
test-fixtures/

# Ignore specific files
docs/security-guide.md
```

Supports file paths and directory paths (with trailing `/`). One entry per line. Lines starting with `#` are comments.

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
│   ├── cli.ts                    # CLI entry point + init command
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
├── .malcheckignore               # Suppresses false positives on own files
├── package.json
└── tsconfig.json
```

## Roadmap

- [x] CLI scanner with heuristic rules
- [x] Prompt injection detection (27 rules)
- [x] Malware pattern detection (27 rules)
- [x] Invisible Unicode detection
- [x] JSON output for CI/CD
- [x] `malcheck init` — git pre-commit hook
- [x] `.malcheckignore` — suppress false positives
- [ ] `--deep` flag — AST-based analysis for variable indirection and dataflow
- [ ] `malcheck update` — pull latest rules from GitHub
- [ ] Community trust network — crowdsourced package reputation
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
