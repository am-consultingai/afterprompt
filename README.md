# Afterprompt

**Find the API keys, tokens and passwords that leaked into your AI coding assistant's history.**

AI coding assistants keep a local record of every session: what you typed, which files they read, and what
commands printed. One `cat .env`, `printenv` or pasted key writes those values into a transcript that stays on
your disk for months. The same text was also sent to the model vendor as chat context.

Afterprompt searches that history on your own machine. It tells you which credentials were exposed, where they
appeared, and whether they are still sitting on your disk, so you know what to rotate.

**Website:** https://am-consultingai.github.io/afterprompt/

---

## Quick start

```bash
git clone https://github.com/am-consultingai/afterprompt.git
cd afterprompt
./afterprompt.sh
```

When the scan finishes, it prints the path to your report. Nothing is uploaded anywhere.

## Supported platforms

| Platform | How to run |
|---|---|
| macOS | Terminal |
| Linux | Any shell |
| Windows | Inside **WSL**. The scan covers both your WSL home and your Windows user profile (`/mnt/c/Users/<you>`) |

Git Bash and PowerShell are not supported on Windows. Use WSL.

**Requirements:** Python 3.9+ (standard library only, nothing to `pip install`) and
[ripgrep](https://github.com/BurntSushi/ripgrep) 13 or newer. If ripgrep is missing, `afterprompt.sh` downloads
ripgrep 15.2.0 from its official GitHub release into `~/.afterprompt/bin/` and verifies a pinned SHA-256 checksum
before using it. Pass `--no-download` to prevent this.

## What it scans

| Tool | Data |
|---|---|
| **Claude Code** | Session transcripts, prompt history, file history, pasted content, MCP server logs, `~/.claude.json`, per-project `.claude/` folders and `.mcp.json` files |
| **Cursor** | Chat databases (`state.vscdb`, including `.backup` copies and write-ahead logs), agent transcripts, plans, `mcp.json` |

On Windows under WSL, both the Linux-side and Windows-side copies of each tool are scanned. Only the Windows user
running the scan is included. Other people's profiles on the same machine are not. If the Windows profile cannot
be detected automatically, pass `--windows-home /mnt/c/Users/<you>`.

Support for other assistants (Codex CLI, Gemini CLI, Windsurf, Copilot) is planned. Each tool's locations are
defined in one registry (`afterprompt/sources.py`), so adding one does not touch the scanning engine.

## How it decides something is a leak

Afterprompt combines three signals, from strongest to weakest:

1. **Your live credentials, found in AI history.** It reads the credentials that already exist on your machine
   and searches the history for those exact values. Every match is a real credential of yours sitting in a
   transcript, with no false positives by construction. It also proves the negative: credentials that were *not*
   found. The stores it reads:
   - AWS, Azure, gcloud, Docker, npm, PyPI, Cargo, RubyGems
   - `.netrc`, `.pgpass`, git credentials
   - SSH keys, kube config, GitHub CLI, Terraform
   - AI tool MCP configuration
   - `.env` files in the projects your AI tools worked in
2. **Vendor patterns.** 140 patterns for specific key formats (Anthropic, OpenAI, Google, AWS, Azure, GitHub,
   Stripe, Slack, Atlassian and more), plus structural shapes like private keys and connection strings.
3. **Decoded and high-randomness strings** (deep mode only). Keys are often hidden inside JSON escaping, URL
   encoding, base64, hex, gzip or JWTs. Deep mode decodes these recursively, then runs the patterns and an entropy
   sweep over the result.

Common false alarms are dismissed automatically, and the report counts each reason:
- placeholders and environment-variable references
- code shipped inside apps and plugins
- expired tokens
- local development databases (`localhost` connection strings)
- certificates, design-token files, `.env.example` defaults, and OAuth client IDs
- a tool's own login file

## Quick and deep modes

| | Quick (default) | Deep (`--deep`) |
|---|---|---|
| Live-credential check | ✓ | ✓ |
| Vendor patterns over raw data | ✓ | ✓ |
| Password-like strings in your prompts | ✓ | ✓ |
| Decode nested payloads, then re-scan | | ✓ |
| Entropy sweep | | ✓ |
| Writes decoded plaintext to disk | No | Yes, capped at 10 GB, deleted when the scan ends |
| Run time | Fast | Can take hours on large histories |

Start with quick mode. Run deep mode when you want the most complete answer and have the time and disk space.
A deep scan needs at least 2 GB of free disk space.

Scans can be interrupted with Ctrl-C. Running `./afterprompt.sh` again with the same options resumes where it stopped.
`./afterprompt.sh --fresh` starts over.

## Options

```text
./afterprompt.sh [options]

  --deep                 decode nested payloads and run the entropy sweep
  --out DIR              where to write the report (default: ~/.afterprompt/runs/<run-id>)
  --extra-root PATH      also scan PATH (repeatable)
  --exclude PATTERN      skip files whose full path matches this regular expression (repeatable)
  --max-disk GB          cap on decoded plaintext in deep mode (default: 10)
  --workers N            parallel workers (default: based on CPU count and memory)
  --keep-work            keep intermediate files, including decoded plaintext, after the scan
  --include-keychain     macOS: also check Claude Code's Keychain login (shows a permission prompt)
  --windows-home PATH    WSL: the Windows profile to scan, or "none" to skip the Windows side
  --no-download          never download ripgrep; fail if it is not installed
  --fresh                discard an unfinished scan and start over
  --status               show progress of a running or interrupted scan
  --version              print the version
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; nothing to rotate |
| 10 | Scan completed; credentials to rotate |
| 2 | Invalid options |
| 3 | Missing dependency (Python 3.9+ or ripgrep) |
| 4 | Unsupported environment (for example Git Bash) |
| 5 | Scan failed (details in `run.log`; running again retries from the failed step) |
| 6 | Not enough disk space for a deep scan |
| 130 | Interrupted |

## Reading the report

The report is written as `report.html`, `report.md` and `findings.json`, with three sections:

- **Rotate now:** your live credentials found in AI history, and vendor-specific keys. Each entry shows:
  - which tool and session exposed it
  - whether the value is still on disk (for example, in a `.env` file)
  - where to revoke it
- **Review:** weaker signals you should look at. These are credentials stored in plain text in AI tool
  configuration, possible credentials in less specific formats, session cookies, and password-like strings from
  your own prompts.
- **Coverage:** what was scanned, what could not be read, and what the scan cannot see.

Every value is masked to its first 6 and last 4 characters. The report never contains a full credential.

## What to do with the results

**Rotate every credential under "Rotate now."** Deleting the transcript does not undo the exposure, because the
value was already sent to the model vendor as chat context. Revoking and reissuing the credential is the fix.

Afterwards, remove any hardcoded copies it found and move them to environment variables or a secrets manager.
Almost every leak comes from two habits:

- pasting keys into prompts
- letting an agent `cat` or grep `.env` files, or print environment variables

## Privacy

- **Runs entirely on your machine.** The only network access is the optional one-time ripgrep download. The HTML
  report loads no remote resources.
- **The report and findings files hold only masked values**, a SHA-256 prefix for matching, and surrounding
  context with other token-like strings scrubbed out.
- **Work files live in `~/.afterprompt/`**, readable only by you, and are never scanned themselves.
- **Plaintext copies are temporary.** To read Cursor's chat databases, the scan writes a text copy of them to the
  work folder. Deep mode also writes decoded plaintext there. Both are deleted when the scan ends, unless you pass
  `--keep-work`. If you interrupt a scan, they stay until you resume it or run `--fresh`.
- **Deletion is not overwriting.** On SSDs, deleted data cannot be reliably overwritten. Keep full-disk encryption
  (FileVault, BitLocker, LUKS) turned on.

## Limits

- Text inside screenshots is not read (no OCR). Compressed PDF streams are skipped.
- Tokens that contain no digits are not treated as entropy candidates, to keep noise down.
- Assistants prune old transcripts (Claude Code after about 30 days). Exposure older than a tool's retention
  window can't be recovered locally, apart from prompt history.
- The scan does not contact any service, so it cannot tell whether a credential is still valid.
- Copies held on vendors' servers cannot be scanned or deleted from your machine.
- While Cursor is running on Windows, it may lock its databases. The report lists any database it could not
  read. Quit Cursor and run the scan again.

## Project layout

```text
afterprompt.sh          entry point: checks the environment, finds or downloads ripgrep, runs the scanner
afterprompt/
  cli.py                options, resumable run lifecycle, exit codes
  sources.py            where each AI tool keeps its data, per platform (the registry)
  platforms.py          macOS / Linux / WSL detection, Windows profile detection
  cursor.py             Cursor SQLite extraction
  manifest.py           file enumeration
  vendor.py             pattern passes (one ripgrep run per pattern)
  patterns.py           the 140 patterns, labels and revoke links
  decode.py             deep mode decoding
  entropy.py            deep mode entropy sweep
  stores.py, known.py   live credential collection and search
  prompts.py            password-like strings in prompts
  triage.py             grouping, dismissal rules, rotate / review decisions
  report.py             findings.json, report.md, report.html
  pool.py               crash-tolerant process pool with a memory watchdog
  assets/               report styling and logo (see NOTICE.md)
tests/                  unit, integration and launcher tests; test secrets are generated at run time
site/                   the website (plain HTML), deployed to GitHub Pages by .github/workflows/pages.yml
```

## Development

```bash
python3 -m unittest discover -s tests -t .
```

The integration tests run `afterprompt.sh` against generated fixture machines (macOS, Linux and WSL layouts) with
planted secrets. They check the report contents, and that no planted value appears in any output. CI runs the
suite on Linux and macOS (Python 3.9 and 3.12) and inside WSL on Windows.

## License

Afterprompt is **free to use**, including at work and for client engagements, under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE) (FSL-1.1-ALv2).

- **Allowed:** using, copying, modifying and sharing it, for any purpose other than a competing use.
- **Not allowed:** offering Afterprompt, or a product or service with substantially similar functionality, as a
  commercial product or service.
- **Becomes Apache 2.0:** each release converts to the Apache License 2.0 two years after it is published.

The license is "source-available", not OSI open source. Built by AM Consulting. The AM Consulting name, logo and
report styling in `afterprompt/assets/` are not covered by the license; see
[`afterprompt/assets/NOTICE.md`](afterprompt/assets/NOTICE.md).
