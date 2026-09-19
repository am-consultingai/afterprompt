<#
  Afterprompt launcher for Windows (no WSL required).

  Mirrors afterprompt.sh: checks the environment and dependencies, then runs
  python -m afterprompt. Usage: .\afterprompt.ps1 [options]   (-Help for all options)

  Exit codes match the scanner: 0 clean, 10 rotate something, 2 bad usage,
  3 missing dependency, 4 unsupported environment, 5 scan failed,
  6 not enough disk space, 130 interrupted.
#>
# No param() block and no [CmdletBinding()] on purpose: with them, PowerShell's parameter binder
# claims scanner options that look like parameters ("--out" is ambiguous with -OutVariable/-OutBuffer)
# and the scan never sees them. Reading $args keeps every option intact.
$ScanArgs = @($args)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RG_VERSION = '15.2.0'
$RG_SHA = @{
    'x86_64-pc-windows-msvc'  = '71b2fef860abe467217a538ff31de02f5258807c0129f771846f87bd029aafc5'
    'aarch64-pc-windows-msvc' = 'e4abca10c3a64ebea742667dd7009449d49403db5460dd6873e389fa2945360f'
}
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Fail([int] $Code, [string[]] $Lines) {
    foreach ($l in $Lines) { [Console]::Error.WriteLine("afterprompt.ps1: $l") }
    exit $Code
}

function Env-Or($Name, $Default) {
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrEmpty($v)) { return $Default } else { return $v }
}

# ---- supported environment
# $IsWindows only exists in PowerShell Core, so ask the runtime instead: this must work
# on Windows PowerShell 5.1, which is what ships with Windows.
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    Fail 4 @('This launcher is for Windows. On macOS or Linux run ./afterprompt.sh instead.')
}

# Expand-Archive and Get-FileHash arrived in PowerShell 5.0; Windows 10 and later ship 5.1, but say
# so plainly rather than failing later with a missing-cmdlet error on an older machine.
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Fail 4 @("Windows PowerShell 5.0 or newer is required; this is $($PSVersionTable.PSVersion).",
             'Install Windows Management Framework 5.1, or install ripgrep yourself and pass --no-download.')
}

# ---- python
# A "python.exe" under WindowsApps is the Microsoft Store stub: it opens the Store
# rather than running anything, so it is skipped.
function Find-Python {
    $override = Env-Or 'AFTERPROMPT_PYTHON' ''
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($override) { $candidates.Add($override) }
    else {
        foreach ($n in @('py.exe', 'python3.exe', 'python.exe')) {
            foreach ($c in (Get-Command $n -All -ErrorAction SilentlyContinue)) { $candidates.Add($c.Source) }
        }
        # The usual install locations, discovered rather than listed by version: a hard-coded set of
        # version numbers would stop finding Python the year a new one ships.
        foreach ($root in @("$env:LOCALAPPDATA\Programs\Python", "$env:ProgramFiles\Python",
                            "${env:ProgramFiles(x86)}\Python")) {
            if (-not $root -or -not (Test-Path $root)) { continue }
            foreach ($d in (Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
                            Sort-Object Name -Descending)) {
                $candidates.Add((Join-Path $d.FullName 'python.exe'))
            }
        }
    }
    foreach ($p in $candidates) {
        if (-not $p -or $p -like '*\WindowsApps\*' -or -not (Test-Path $p)) { continue }
        & $p -c 'import sys, sqlite3; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) { return $p }
    }
    return $null
}

$PY = Find-Python
if (-not $PY) {
    Fail 3 @('Python 3.9 or newer (with the sqlite3 module) is required and was not found.',
             'Install it from https://www.python.org/downloads/windows/ or with: winget install Python.Python.3.13',
             'A "python" entry that opens the Microsoft Store is a stub, not an interpreter.')
}

$BaseDir = Env-Or 'AFTERPROMPT_DIR' (Join-Path $env:USERPROFILE '.afterprompt')
New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null

# ---- arguments the launcher itself acts on
$NoDownload = $false
$NeedsRg = $true
foreach ($a in $ScanArgs) {
    if ($a -eq '--no-download') { $NoDownload = $true }
    if ($a -in @('-h', '--help', '--version', '--status')) { $NeedsRg = $false }
}

function Rg-Version($Path) {
    try { $line = (& $Path --version 2>$null | Select-Object -First 1) } catch { return $null }
    if ($line -match '^ripgrep ([0-9.]+)') { return $Matches[1] }
    return $null
}

function Install-Rg {
    # PROCESSOR_ARCHITEW6432 is set when a 32-bit process runs on 64-bit Windows, where
    # PROCESSOR_ARCHITECTURE says "x86" and would pick the wrong build.
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { $target = 'x86_64-pc-windows-msvc' }
        'ARM64' { $target = 'aarch64-pc-windows-msvc' }
        'x86'   { $target = 'x86_64-pc-windows-msvc' }
        default { Fail 3 @("No ripgrep download is available for '$arch'.",
                           'Install ripgrep with: winget install BurntSushi.ripgrep.MSVC') }
    }
    $expected = Env-Or 'AFTERPROMPT_RG_SHA256' $RG_SHA[$target]
    $asset = "ripgrep-$RG_VERSION-$target.zip"
    $baseUrl = Env-Or 'AFTERPROMPT_RG_BASE_URL' "https://github.com/BurntSushi/ripgrep/releases/download/$RG_VERSION"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("afterprompt-rg-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        Write-Host "ripgrep not found; downloading ripgrep $RG_VERSION ($target) from its official GitHub release..."
        $zip = Join-Path $tmp $asset
        try {
            $ProgressPreference = 'SilentlyContinue'
            # Windows PowerShell 5.1 can still default to TLS 1.0/1.1, which GitHub refuses.
            try {
                [Net.ServicePointManager]::SecurityProtocol =
                    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            } catch { }
            Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile $zip -UseBasicParsing
        } catch {
            Fail 3 @("Download failed: $baseUrl/$asset", 'Install ripgrep with: winget install BurntSushi.ripgrep.MSVC')
        }
        $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
        if ($actual -ne $expected.ToLower()) {
            Fail 3 @("Checksum mismatch for $asset; the download was discarded.",
                     "expected $expected", "got      $actual")
        }
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $found = Get-ChildItem -Path $tmp -Recurse -Filter 'rg.exe' | Select-Object -First 1
        if (-not $found) { Fail 3 @("The ripgrep archive did not contain rg.exe.") }
        $binDir = Join-Path $BaseDir 'bin'
        New-Item -ItemType Directory -Force -Path $binDir | Out-Null
        Copy-Item $found.FullName (Join-Path $binDir 'rg.exe') -Force
        Write-Host "Installed ripgrep to $binDir\rg.exe (checksum verified)."
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

$RG = ''
if ($NeedsRg) {
    $envRg = Env-Or 'AFTERPROMPT_RG' ''
    if ($envRg -and (Test-Path $envRg)) { $RG = $envRg }
    if (-not $RG -and (Env-Or 'AFTERPROMPT_IGNORE_SYSTEM_RG' '0') -ne '1') {
        $sys = Get-Command rg.exe -ErrorAction SilentlyContinue
        if ($sys) {
            $v = Rg-Version $sys.Source
            if ($v -and [int]($v.Split('.')[0]) -ge 13) { $RG = $sys.Source }
        }
    }
    $own = Join-Path $BaseDir 'bin\rg.exe'
    if (-not $RG -and (Test-Path $own) -and (Rg-Version $own) -eq $RG_VERSION) { $RG = $own }
    if (-not $RG) {
        if ($NoDownload) {
            Fail 3 @('ripgrep 13 or newer is required and was not found (--no-download is set).',
                     'Install ripgrep with: winget install BurntSushi.ripgrep.MSVC')
        }
        Install-Rg
        $RG = $own
    }
}

if ((Env-Or 'AFTERPROMPT_BOOTSTRAP_ONLY' '0') -eq '1') {
    Write-Output "python=$PY rg=$RG"
    exit 0
}

$env:AFTERPROMPT_RG = $RG
$env:PYTHONUTF8 = '1'
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$InstallDir;$env:PYTHONPATH" } else { $InstallDir }

# Windows command-line quoting: a value is only quoted when it needs to be, backslashes that
# precede a quote (or end the value) are doubled, and embedded quotes are escaped. ProcessStartInfo
# takes a single string here because .ArgumentList does not exist in Windows PowerShell 5.1.
function Quote-Arg([string] $a) {
    if ($a -ne '' -and $a -notmatch '[\s"]') { return $a }
    $escaped = [regex]::Replace($a, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

# Below-normal priority keeps a long scan from making the machine feel slow, the
# counterpart of nice/ionice in afterprompt.sh.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $PY
$psi.UseShellExecute = $false
$psi.WorkingDirectory = $InstallDir
$argv = @('-X', 'utf8', '-m', 'afterprompt') + @($ScanArgs | Where-Object { $null -ne $_ })
$psi.Arguments = (($argv | ForEach-Object { Quote-Arg $_ }) -join ' ')
$proc = [System.Diagnostics.Process]::Start($psi)
try { $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch { }
$proc.WaitForExit()
exit $proc.ExitCode
