#!/usr/bin/env bash
# Afterprompt launcher: checks the environment and dependencies, then runs the scanner (python3 -m afterprompt).
# Works with bash 3.2 (macOS) and later. Usage: ./afterprompt.sh [options]   (./afterprompt.sh --help for all options)
set -eu

RG_VERSION="15.2.0"
RG_SHA_X86_64_LINUX="33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c"
RG_SHA_AARCH64_LINUX="800b1e7206afe799dfb5a6901f23147cfaabe0e52210538100f61e86e1740915"
RG_SHA_X86_64_DARWIN="af7825fcc69a2afc7a7aea55fc9af90e26421d8f20fe59df32e233c0b8a231c1"
RG_SHA_AARCH64_DARWIN="3750b2e93f37e0c692657da574d7019a101c0084da05a790c83fd335bad973e4"

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

fail() {
  code="$1"
  shift
  printf 'afterprompt.sh: %s\n' "$@" >&2
  exit "$code"
}

# ---- supported environment
UNAME_S="${AFTERPROMPT_UNAME:-$(uname -s)}"
UNAME_M="${AFTERPROMPT_UNAME_M:-$(uname -m)}"
case "$UNAME_S" in
  MINGW* | MSYS* | CYGWIN*)
    fail 4 "Git Bash, MSYS and Cygwin are not supported." \
      "On Windows, run afterprompt.cmd instead (from cmd.exe, PowerShell, or by double-clicking it). WSL is not required." \
      "If you do use WSL, running ./afterprompt.sh inside the distribution covers both the WSL side and your Windows profile in one pass."
    ;;
  Linux) OS="linux" ;;
  Darwin) OS="darwin" ;;
  *) fail 4 "Unsupported operating system: $UNAME_S. Afterprompt runs on macOS, Linux, and Windows (natively via afterprompt.cmd, or inside WSL)." ;;
esac

# ---- arguments that the launcher itself acts on
NO_DOWNLOAD=0
NEEDS_RG=1
for arg in ${1+"$@"}; do
  case "$arg" in
    --no-download) NO_DOWNLOAD=1 ;;
    -h | --help | --version | --status) NEEDS_RG=0 ;;
  esac
done

# ---- python
PY="${AFTERPROMPT_PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1 ||
  ! "$PY" -c 'import sys, sqlite3; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
  if [ "$OS" = "darwin" ]; then
    hint="Install it with: xcode-select --install   (or: brew install python)"
  else
    hint="Install it with: sudo apt install python3   (or your distribution's package manager)"
  fi
  fail 3 "Python 3.9 or newer (with the sqlite3 module) is required and was not found as '$PY'." "$hint"
fi

BASE_DIR="${AFTERPROMPT_DIR:-$HOME/.afterprompt}"
mkdir -p "$BASE_DIR"
chmod 700 "$BASE_DIR"

rg_major() {
  "$1" --version 2>/dev/null | head -n 1 | sed -n 's/^ripgrep \([0-9][0-9]*\)\..*/\1/p'
}

rg_version() {
  "$1" --version 2>/dev/null | head -n 1 | sed -n 's/^ripgrep \([0-9][0-9.]*\).*/\1/p'
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    return 1
  fi
}

install_hint() {
  if [ "$OS" = "darwin" ]; then
    echo "Install ripgrep with: brew install ripgrep"
  else
    echo "Install ripgrep with: sudo apt install ripgrep   (or your distribution's package manager)"
  fi
}

download_rg() {
  case "$UNAME_M" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *) fail 3 "No ripgrep download is available for CPU architecture '$UNAME_M'." "$(install_hint)" ;;
  esac
  if [ "$OS" = "darwin" ]; then
    target="$arch-apple-darwin"
  else
    target="$arch-unknown-linux-musl"
  fi
  case "$target" in
    x86_64-unknown-linux-musl) expected="$RG_SHA_X86_64_LINUX" ;;
    aarch64-unknown-linux-musl) expected="$RG_SHA_AARCH64_LINUX" ;;
    x86_64-apple-darwin) expected="$RG_SHA_X86_64_DARWIN" ;;
    aarch64-apple-darwin) expected="$RG_SHA_AARCH64_DARWIN" ;;
  esac
  expected="${AFTERPROMPT_RG_SHA256:-$expected}"
  asset="ripgrep-$RG_VERSION-$target.tar.gz"
  base_url="${AFTERPROMPT_RG_BASE_URL:-https://github.com/BurntSushi/ripgrep/releases/download/$RG_VERSION}"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/afterprompt-rg.XXXXXX")"
  echo "ripgrep not found; downloading ripgrep $RG_VERSION ($target) from its official GitHub release…"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp/$asset" "$base_url/$asset" || { rm -rf "$tmp"; fail 3 "Download failed: $base_url/$asset" "$(install_hint)"; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp/$asset" "$base_url/$asset" || { rm -rf "$tmp"; fail 3 "Download failed: $base_url/$asset" "$(install_hint)"; }
  else
    rm -rf "$tmp"
    fail 3 "Neither curl nor wget is available to download ripgrep." "$(install_hint)"
  fi
  actual="$(sha256_of "$tmp/$asset")" || { rm -rf "$tmp"; fail 3 "No sha256sum or shasum available to verify the download." "$(install_hint)"; }
  if [ "$actual" != "$expected" ]; then
    rm -rf "$tmp"
    fail 3 "Checksum mismatch for $asset; the download was discarded." "expected $expected" "got      $actual"
  fi
  tar -xzf "$tmp/$asset" -C "$tmp" || { rm -rf "$tmp"; fail 3 "Could not extract $asset."; }
  found="$(find "$tmp" -type f -name rg | head -n 1)"
  [ -n "$found" ] || { rm -rf "$tmp"; fail 3 "The ripgrep archive did not contain an rg binary."; }
  mkdir -p "$BASE_DIR/bin"
  cp "$found" "$BASE_DIR/bin/rg"
  chmod 755 "$BASE_DIR/bin/rg"
  rm -rf "$tmp"
  echo "Installed ripgrep to $BASE_DIR/bin/rg (checksum verified)."
}

RG=""
if [ "$NEEDS_RG" = "1" ]; then
  if [ -n "${AFTERPROMPT_RG:-}" ] && [ -x "${AFTERPROMPT_RG}" ]; then
    RG="$AFTERPROMPT_RG"
  fi
  if [ -z "$RG" ] && [ "${AFTERPROMPT_IGNORE_SYSTEM_RG:-0}" != "1" ] && command -v rg >/dev/null 2>&1; then
    major="$(rg_major "$(command -v rg)")"
    if [ -n "$major" ] && [ "$major" -ge 13 ]; then
      RG="$(command -v rg)"
    fi
  fi
  if [ -z "$RG" ] && [ -x "$BASE_DIR/bin/rg" ] && [ "$(rg_version "$BASE_DIR/bin/rg")" = "$RG_VERSION" ]; then
    RG="$BASE_DIR/bin/rg"
  fi
  if [ -z "$RG" ]; then
    if [ "$NO_DOWNLOAD" = "1" ]; then
      fail 3 "ripgrep 13 or newer is required and was not found (--no-download is set)." "$(install_hint)"
    fi
    download_rg
    RG="$BASE_DIR/bin/rg"
  fi
fi

if [ "${AFTERPROMPT_BOOTSTRAP_ONLY:-0}" = "1" ]; then
  echo "python=$PY rg=$RG"
  exit 0
fi

export AFTERPROMPT_RG="$RG"
export PYTHONUTF8=1
export PYTHONPATH="$INSTALL_DIR${PYTHONPATH:+:$PYTHONPATH}"

set -- "$PY" -X utf8 -m afterprompt ${1+"$@"}
if command -v ionice >/dev/null 2>&1; then
  set -- ionice -c3 -t "$@"
fi
if command -v nice >/dev/null 2>&1; then
  set -- nice -n 10 "$@"
fi
exec "$@"
