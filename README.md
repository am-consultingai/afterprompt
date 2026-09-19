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
| macOS | Terminal: `./afterprompt.sh` |
| Linux | Any shell: `./afterprompt.sh` |
| Windows | `afterprompt.cmd`, from cmd.exe, PowerShell or a double-click. **WSL is not required** |
| Windows, inside WSL | `./afterprompt.sh`. The scan covers your WSL home *and* your Windows profile (`/mnt/c/Users/<you>`) |

**One run covers the whole machine.** On Windows, run it either way: it scans the Windows profile *and* every WSL
distribution it finds, and writes one report. Each distro is scanned from inside itself, where its files read
far faster than Windows can reach them across the `\\wsl.localhost` share: Afterprompt copies itself into the
distro's `~/.afterprompt/engine` and starts there. You never have to open a second terminal.

- A distro that was stopped is started for the scan, and the output says so. WSL stops it again when idle.
- A distro with no Python 3 is read from Windows over `\\wsl.localhost` instead (slower, but complete).
- A distro that cannot be scanned at all is named in the report with the reason, and the run exits with code 7
  rather than 0, so "clean" never means "clean where we happened to look".
- `--no-wsl` scans only the machine you ran it on.

Git Bash, MSYS and Cygwin are not supported: use `afterprompt.cmd` instead.

**Requirements:** Python 3.9+ (standard library only, nothing to `pip install`) and
[ripgrep](https://github.com/BurntSushi/ripgrep) 13 or newer. If ripgrep is missing, the launcher downloads
ripgrep 15.2.0 from its official GitHub release into `~/.afterprompt/bin/` and verifies a pinned SHA-256 checksum
before using it. Pass `--no-download` to prevent this.

On Windows, install Python from [python.org](https://www.python.org/downloads/windows/) or with
`winget install Python.Python.3.13`. A `python` that opens the Microsoft Store is a stub, not an interpreter;
the launcher skips those and tells you so. Windows PowerShell 5.1 (shipped with Windows 10 and later) is
enough — nothing else needs installing or configuring, and `afterprompt.cmd` does not change any machine
setting: it runs the unsigned script under a policy scoped to that one process.

## What it scans

| Tool | Data |
|---|---|
| **Claude Code** | Session transcripts, prompt history, file history, pasted content, MCP server logs, `~/.claude.json`, per-project `.claude/` folders and `.mcp.json` files |
| **Cursor** | Chat databases (`state.vscdb`, including `.backup` copies and write-ahead logs), agent transcripts, plans, `mcp.json` |
| **Codex CLI** | Session rollouts (`~/.codex/sessions`, archived sessions), prompt history, its SQLite state and log databases, memories, shell snapshots (which capture exported environment variables), `config.toml`, `~/.codex/.env` |
| **Gemini CLI** | Chat recordings, prompt logs, tool output and checkpoints under `~/.gemini/tmp`, `settings.json`, `~/.gemini/.env` |
| **OpenCode** | The `opencode.db` session database (its own login tables are skipped), legacy JSON storage, logs, tool output, plans, prompt history, `opencode.json` |
| **Ollama** | `ollama run` prompt history, logs, the desktop app's chat database (macOS and Windows), and the config backups it keeps |

A native Windows run scans the profile it runs as: `%USERPROFILE%\.claude`, `%APPDATA%\Cursor`,
`%LOCALAPPDATA%\claude-cli-nodejs` and the rest. Under WSL, both the Linux-side and Windows-side copies of each
tool are scanned. Either way only the user running the scan is included: other people's profiles and home
folders on the same machine are listed in the report, never read, and the scan never asks for elevation. If the Windows profile cannot be detected automatically from WSL, pass
`--windows-home /mnt/c/Users/<you>`.

Each tool's own login file (Codex `auth.json`, Gemini `oauth_creds.json`, OpenCode `auth.json`) is read as a live
credential: a token from it that turns up in any AI history is reported under Rotate now, but the login file
itself is its intended home and is not flagged. Windsurf is not covered yet: its Cascade conversations are stored
encrypted. Each tool's locations are defined in one data file (`afterprompt/catalogue.json`), so adding one does
not touch the scanning engine.

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
  --no-wsl               scan only this machine, not the WSL distributions on it
  --theme neutral|am     report look: neutral (default, unbranded) or am (AM Consulting brand)
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
| 7 | Scan completed; nothing to rotate, but at least one environment (a WSL distro) could not be scanned |
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
afterprompt.sh          entry point on macOS, Linux and WSL: checks the environment, finds or downloads
                        ripgrep, runs the scanner
afterprompt.cmd         entry point on Windows (a shim so the unsigned .ps1 runs under the default policy)
afterprompt.ps1         the Windows launcher itself: same checks, same environment variables, same exit codes
tools/winrun.sh         development only: start Windows processes from a WSL checkout, to exercise the
                        Windows behaviour without driving PowerShell by hand
afterprompt/
  cli.py                options, resumable run lifecycle, exit codes
  catalogue.json        where each AI tool keeps its data, per platform, and which of its files are
                        configuration, its own login store, or shipped code (catalogue.py checks it)
  sources.py            finds those locations on this machine
  platforms.py          macOS / Linux / WSL / Windows detection, Windows profile and WSL distro discovery
  envs.py               the environments on this machine, and starting a worker inside each one
  worker.py             the worker protocol: JSON lines on the worker's stdout, masked values only
  merge.py              one report from several environments, deduplicated by value hash
  databases.py          SQLite extraction (Cursor's chat databases and the like)
  manifest.py           file enumeration
  vendor.py             pattern passes (one ripgrep run per pattern)
  patterns.json         the 140 patterns, labels, revoke links and rotate/review flags (patterns.py checks them)
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

The integration tests run the launcher against generated fixture machines (macOS, Linux, WSL and Windows layouts) with
planted secrets. They check the report contents, and that no planted value appears in any output. CI runs the
suite on Linux and macOS (Python 3.9 and 3.12), inside WSL on Windows, and on native Windows (Python 3.9 and 3.13).

## License

Afterprompt is **free to use**, including at work and for client engagements, under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE) (FSL-1.1-ALv2).

- **Allowed:** using, copying, modifying and sharing it, for any purpose other than a competing use.
- **Not allowed:** offering Afterprompt, or a product or service with substantially similar functionality, as a
  commercial product or service.
- **Becomes Apache 2.0:** each release converts to the Apache License 2.0 two years after it is published.

The license is "source-available", not OSI open source. Built by AM Consulting. Reports are unbranded by default;
the AM Consulting name, logo and brand styling used by `--theme am` (in `afterprompt/assets/`) are not covered by
the license; see [`afterprompt/assets/NOTICE.md`](afterprompt/assets/NOTICE.md).
