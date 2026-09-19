#!/usr/bin/env bash
# Run a Windows process from WSL and get clean output + the real exit code.
#
# Development tooling: it is how Windows behaviour gets exercised from a WSL checkout without a
# person driving PowerShell by hand. It is not used by the scanner at runtime.
#
#   winrun.sh ps  '<powershell>'      run a PowerShell command
#   winrun.sh cmd '<cmd>'             run a cmd.exe command
#   winrun.sh script <file.ps1> [a..] stage a .ps1 into Windows temp and run it
#   winrun.sh py    <file.py>   [a..] stage a .py  into Windows temp, run with Windows Python
#   winrun.sh mod   <dir> <mod> [a..] stage a directory, run `python -m <mod>` inside it
#   winrun.sh pyexe                   print the Windows Python path
#
# Why this exists: cmd.exe refuses a UNC working directory (\\wsl.localhost\...),
# PowerShell emits UTF-16 with NULs and CRs through the interop pipe, and a failed
# Windows process must still fail the WSL shell. All three are handled here.
set -euo pipefail

# Where Windows drives are mounted. /mnt is only the default: /etc/wsl.conf can move it, so ask
# wslpath first and fall back to parsing the config rather than assuming.
if [ -n "${WINRUN_DRIVE:-}" ]; then
  WIN_C="$WINRUN_DRIVE"
elif command -v wslpath >/dev/null 2>&1 && WIN_C="$(wslpath -u 'C:/' 2>/dev/null)"; then
  WIN_C="${WIN_C%/}"
else
  automount_root=$(awk -F= '
    /^\[/ { section = $0 }
    section ~ /automount/ && $1 ~ /^[[:space:]]*root[[:space:]]*$/ { gsub(/[[:space:]"'"'"']/, "", $2); print $2 }
  ' /etc/wsl.conf 2>/dev/null | tail -n 1)
  WIN_C="${automount_root:-/mnt/}"
  WIN_C="${WIN_C%/}/c"
fi
PS_EXE=""
for c in "$(command -v powershell.exe 2>/dev/null || true)" \
         "$WIN_C/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"; do
  [ -n "$c" ] && [ -x "$c" ] && { PS_EXE="$c"; break; }
done
CMD_EXE=""
for c in "$(command -v cmd.exe 2>/dev/null || true)" "$WIN_C/Windows/System32/cmd.exe"; do
  [ -n "$c" ] && [ -x "$c" ] && { CMD_EXE="$c"; break; }
done
[ -n "$PS_EXE" ] || { echo "winrun: no powershell.exe found (is WSL interop enabled?)" >&2; exit 4; }

# Staging lives in the Windows user's own TEMP, which always exists and is always writable;
# a fixed path like C:\Users\Public is neither on a locked-down machine. Resolving it costs a
# PowerShell round trip, so the answer is cached per user.
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/afterprompt-winrun.path"
if [ -s "$CACHE" ]; then
  WIN_TMP_W="$(cat "$CACHE")"
else
  # shellcheck disable=SC2016  # $env:TEMP is a PowerShell variable, expanded by PowerShell
  WIN_TMP_W="$( (cd "$WIN_C" && "$PS_EXE" -NoProfile -NonInteractive -Command \
    'Write-Output $env:TEMP') 2>/dev/null | tr -d '\0' | sed 's/\r$//' | grep -v '^$' | head -n 1)"
  [ -n "$WIN_TMP_W" ] || { echo "winrun: could not resolve the Windows TEMP directory" >&2; exit 4; }
  WIN_TMP_W="$WIN_TMP_W\\afterprompt-winrun"
  mkdir -p "$(dirname "$CACHE")" && printf '%s\n' "$WIN_TMP_W" > "$CACHE"
fi
# Windows path -> WSL path (C:\x\y -> <mount>/c/x/y), without assuming the drive is C.
win_to_wsl() {
  if command -v wslpath >/dev/null 2>&1; then
    wslpath -u "$1" 2>/dev/null && return 0
  fi
  printf '%s\n' "$1" | sed -e 's|\\|/|g' -e "s|^\([A-Za-z]\):|$(dirname "$WIN_C")/\L\1|"
}
WIN_TMP_L="$(win_to_wsl "$WIN_TMP_W")"
mkdir -p "$WIN_TMP_L"

clean() { tr -d '\0' | sed 's/\r$//'; }

# cmd.exe and PowerShell both dislike a UNC cwd; run everything from the C: root.
run_ps() { (cd "$WIN_C" && "$PS_EXE" -NoProfile -NonInteractive -ExecutionPolicy Bypass "$@"); }

find_python() {
  local out
  # shellcheck disable=SC2016  # these are PowerShell variables, expanded by PowerShell, not by bash
  out=$(run_ps -Command '
    $c = @()
    $c += (Get-Command py.exe -ErrorAction SilentlyContinue).Source
    $c += (Get-Command python.exe -ErrorAction SilentlyContinue | ForEach-Object Source)
    foreach ($root in @("$env:LOCALAPPDATA\Programs\Python", "$env:ProgramFiles\Python")) {
      if ($root -and (Test-Path $root)) {
        foreach ($d in (Get-ChildItem $root -Directory -EA SilentlyContinue | Sort-Object Name -Descending)) {
          $c += (Join-Path $d.FullName "python.exe")
        }
      }
    }
    foreach ($p in $c) {
      if ($p -and (Test-Path $p) -and $p -notlike "*WindowsApps*") {
        # WindowsApps entries are Microsoft Store stubs, not interpreters.
        & $p -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Output $p; break }
      }
    }' 2>/dev/null | clean | grep -v '^$' | head -n 1)
  [ -n "$out" ] || { echo "winrun: no Windows Python 3.9+ found" >&2; return 3; }
  printf '%s\n' "$out"
}

mode="${1:-}"; shift || true
case "$mode" in
  ps)
    run_ps -Command "$1" 2>&1 | clean
    exit "${PIPESTATUS[0]}"
    ;;
  cmd)
    [ -n "$CMD_EXE" ] || { echo "winrun: no cmd.exe found" >&2; exit 4; }
    (cd "$WIN_C" && "$CMD_EXE" /c "$1") 2>&1 | clean
    exit "${PIPESTATUS[0]}"
    ;;
  script)
    src="$1"; shift
    base="$(basename "$src")"
    cp "$src" "$WIN_TMP_L/$base"
    run_ps -File "$WIN_TMP_W\\$base" "$@" 2>&1 | clean
    exit "${PIPESTATUS[0]}"
    ;;
  py)
    src="$1"; shift
    base="$(basename "$src")"
    cp "$src" "$WIN_TMP_L/$base"
    py="$(find_python)"
    run_ps -Command "& '$py' '$WIN_TMP_W\\$base' $*; exit \$LASTEXITCODE" 2>&1 | clean
    exit "${PIPESTATUS[0]}"
    ;;
  mod)
    src="$1"; mod="$2"; shift 2
    stage="$WIN_TMP_L/stage"
    rm -rf "$stage"; mkdir -p "$stage"
    cp -r "$src"/. "$stage"/
    find "$stage" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
    py="$(find_python)"
    run_ps -Command "Set-Location '$WIN_TMP_W\\stage'; & '$py' -m $mod $*; exit \$LASTEXITCODE" 2>&1 | clean
    exit "${PIPESTATUS[0]}"
    ;;
  pyexe) find_python ;;
  *)
    sed -n '2,12p' "$0" >&2
    exit 2
    ;;
esac
