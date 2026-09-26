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
| **Cursor** | Chat databases (`state.vscdb`, including `.backup` copies and write-ahead logs), the Cursor CLI agent's `~/.cursor/chats` stores, agent transcripts, plans, `mcp.json` |
| **Codex CLI** | Session rollouts (`~/.codex/sessions`, archived sessions), prompt history, its SQLite state and log databases, memories, shell snapshots (which capture exported environment variables), `config.toml`, `~/.codex/.env` |
| **Gemini CLI** | Chat recordings, prompt logs, tool output and checkpoints under `~/.gemini/tmp`, `settings.json`, `~/.gemini/.env` |
| **OpenCode** | The `opencode.db` session database (its own login tables are skipped), legacy JSON storage, logs, tool output, plans, prompt history, `opencode.json` |
| **GitHub Copilot** | VS Code chat sessions (the `.jsonl` log since VS Code 1.109, and the older `.json` files), empty-window and transferred sessions, edit-session state, and Copilot CLI session state |
| **Cline, Roo Code, Kilo Code** | Task history in every VS Code-family editor they run in (VS Code, Insiders, VSCodium, Cursor, Windsurf, Kiro, Antigravity and others, including remote `~/.vscode-server` profiles), `~/.cline/data`, Kilo's `kilo.db` (login tables skipped) |
| **Continue** | `~/.continue` sessions, dev data, `config.yaml`/`config.json`, `.env` |
| **Amazon Q Developer** | Chat history under `~/.aws/amazonq/history` |
| **Google Antigravity** | CLI prompt history, per-conversation transcripts and raw step output (`brain/`), conversation databases and summaries, logs, MCP config; the IDE's `brain`, `knowledge` and conversation databases |
| **Aider** | `.aider.chat.history.md`, `.aider.input.history`, `.aider.llm.history` and `.aider.conf.yml`, in your home and in every project the scan finds |
| **Goose, Qwen Code, Amp, Junie, Devin CLI** | Session databases and transcripts, prompt history, logs and config for each |
| **LM Studio, Jan** | Saved conversations and MCP configuration |
| **Claude Desktop** | Local agent-mode sessions (Claude Code-format transcripts), logs and `claude_desktop_config.json`. Ordinary chats live on Anthropic's servers, not on your machine |
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
  --quick                the faster scan, when your saved settings make deep the default
  --sarif                also write report.sarif (SARIF 2.1.0) for code-scanning and SIEM pipelines
  --ui                   also show the scan in your browser, with a rotate checklist you tick off
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

## The browser view (`--ui`)

`--ui` prints a link and hands the scan over to your browser. **It does not start scanning.** The page opens on
a Start screen that has read nothing: it names the steps it would take and what the scan is set to do, and the
scan begins when you press **Start scan**. Until then the run sits waiting, and Ctrl-C ends it having read
nothing. A rail down the left edge holds the Start button and the four screens:

- **Scan** — before the press, the Start screen. After it, one line per step, each staying on screen with what
  it found, a progress bar where the total is knowable and an honest counter where it is not, and the console
  output.
- **Credentials** — everything found, ordered worst first by what the credential opens (spend money, reach
  stored data, act as you, one service), with the first three named at the top. Grouped by vendor, or by what
  it opens, or by the AI tool it leaked into; only non-empty groups are shown and each is collapsible. Many
  values of one kind from one place fold into a single row that opens, so one noisy transcript cannot fill the
  list. Choosing one shows where it leaked, whether a copy is still on disk, and **what to do about it**:
  numbered steps from that vendor's own documentation, a link straight to the page where you revoke it, its
  audit log where one exists, and a tick that is remembered by value hash so the next scan still knows you have
  done it.
- **Settings** — the defaults for the next scan (depth, disk cap, workers, report styling, SARIF) and this
  page's own preferences. Changes apply immediately and are saved in `~/.afterprompt/settings.json`, which the
  CLI reads as its defaults; a command-line flag still wins.

Keyboard throughout: arrows or `j`/`k` move, `←`/`→` collapse and expand a group, `Enter` opens the detail,
`Escape` goes back, `Space` ticks a credential off. `Ctrl-K` (or `/`) opens a palette that jumps to any
credential by name, vendor or the visible part of its value, and runs the page's few commands; `g` then `s`,
`c`, `,` or `a` goes to Scan, Credentials, Settings or About. It is a view over the same scan, not a different one, and it
closes itself when you close the tab.

It is built so that nothing else can use it: it listens on `127.0.0.1` only, every request needs the one-time
key from the link (which travels in the URL fragment, never to a server, and is removed from the address bar),
requests naming another host are refused (DNS rebinding), cross-site requests are refused, no CORS header is
ever sent, and the page is served with a strict Content-Security-Policy and loads nothing from the internet.
Everything it shows was already masked for `findings.json`.

**Open it** beside a location shows that file in your file manager (Explorer with the file selected, Finder's
reveal, or the folder on Linux). The page names only the finding and which of its locations; the path is looked
up by Afterprompt in its own findings, and a file in another environment (another WSL distribution, a container)
is refused rather than guessed at. It never opens the file itself.

## Reading the report

The report is written as `report.html`, `report.md` and `findings.json`, with three sections:

- **Rotate now:** your live credentials found in AI history, and vendor-specific keys. Each entry shows:
  - what it opens: whether the value can spend money, reach stored data, act as you, or only use one service
  - which tool and session exposed it
  - whether the value is still on disk (for example, in a `.env` file)
  - where to revoke it — a link to that vendor's page wherever one is known, and what to do instead when it
    is not

  The list is ordered by how far the credential reaches, worst first, and names the first three, so a long
  list still has somewhere to start. Within a group, the surest findings come first.
- **Review:** weaker signals you should look at. These are credentials stored in plain text in AI tool
  configuration, possible credentials in less specific formats, session cookies, and password-like strings from
  your own prompts. Nothing here is confirmed. Repeats are folded: many values of the same kind in the same
  file are one row with a count, so a single transcript full of generated test values cannot crowd out the
  rest. Each value is still listed individually in `findings.json`.
- **Coverage:** what was scanned, what could not be read, and what the scan cannot see. It also names AI tools
  that are installed but not scanned yet, and why, so a clean result never hides a tool Afterprompt cannot read.
  Detection only looks: it reads app lists, folders and PATH, and never runs anything.

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
  ui.py, assets/ui/     the --ui loopback server and its three screens; vendors.json (marks) and
                        rotation.json (per-vendor rotation steps, each with its source)
  settings.py           saved defaults for the next scan, and the settings screen's field table
  progress.py           live progress from the stages that can measure it
  detect.py             which AI tools are installed (read-only)
  sarif.py              report.sarif
  databases.py          SQLite extraction (Cursor's chat databases and the like)
  manifest.py           file enumeration
  vendor.py             pattern passes (one ripgrep run per pattern)
  patterns.json         the 140 patterns, labels, revoke links and rotate/review flags (patterns.py checks them)
  decode.py             deep mode decoding
  entropy.py            deep mode entropy sweep
  stores.py, known.py   live credential collection and search
  prompts.py            password-like strings in prompts
  triage.py             grouping, dismissal rules, rotate / review decisions, where to revoke
  impact.py             how far a leaked credential reaches, which is the order of "Rotate now"
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
