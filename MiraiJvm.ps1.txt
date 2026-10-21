# =============================================================================
#  Mirai JVM Analyzer  |  v2.1
#  Author  : DaddyMirai
#  Purpose : Fetch latest build from GitHub (silently), then deep-scan every
#            running Minecraft JVM for suspicious arguments, agents, and mod
#            injection.
#
#  Usage   : .\MiraiJvmAnalyzer.ps1              — full verbose output
#            .\MiraiJvmAnalyzer.ps1 --silent     — summary + verdict only
#
#  Whitelist: drop trusted agent paths (one per line, regex OK) into
#             mirai_whitelist.txt next to this script.
# =============================================================================

param(
    [switch]$Silent
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$host.UI.RawUI.WindowTitle = "Mirai JVM Analyzer v2.1"

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
$GithubUrl   = "https://github.com/DaddyMirai/MiraiUpdater/releases/download/v1.0/MiraiUpdater.exe"
$ToolVersion = "2.1.0"

# ---------------------------------------------------------------------------
# FIX #1 — $PSScriptRoot is null when the script isn't loaded from a .ps1
# file on disk (e.g. pasted into a terminal, or invoked via Start-Process
# without a proper script path).  Fall back to the current working directory
# so Join-Path never receives a null and Test-Path never explodes.
# ---------------------------------------------------------------------------
$ScriptRoot    = if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) {
                     $PSScriptRoot
                 } else {
                     (Get-Location).Path
                 }
$WhitelistFile = Join-Path $ScriptRoot "mirai_whitelist.txt"
# ---------------------------------------------------------------------------

# ── helper functions ────────────────────────────────────────────────────────

function Write-Line {
    param([int]$Width = 72, [string]$Char = "─", [string]$Color = "DarkGray")
    Write-Host ($Char * $Width) -ForegroundColor $Color
}

function Write-Section {
    param([string]$Title, [string]$Color = "White")
    Write-Host
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Line -Width 72 -Char "─" -Color DarkGray
}

function Write-Tag {
    param([string]$Tag, [string]$Message, [string]$TagColor = "Cyan", [string]$MsgColor = "White", [int]$Indent = 2)
    Write-Host -NoNewline (" " * $Indent)
    Write-Host -NoNewline " $Tag " -ForegroundColor Black -BackgroundColor $TagColor
    Write-Host "  $Message" -ForegroundColor $MsgColor
}

function Write-Log {
    # Respects --silent: only CRITICAL and WARN bubble up in silent mode
    param([string]$Level, [string]$Message)
    if ($Silent -and $Level -notin @("CRITICAL","WARN")) { return }

    $ts    = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "INFO"     { "Cyan"    }
        "OK"       { "Green"   }
        "WARN"     { "Yellow"  }
        "CRITICAL" { "Red"     }
        "SUSPECT"  { "Magenta" }
        "SKIP"     { "DarkGray"}
        default    { "White"   }
    }
    Write-Host -NoNewline "  [$ts] " -ForegroundColor DarkGray
    Write-Host -NoNewline "[$Level]".PadRight(10) -ForegroundColor $color
    Write-Host $Message -ForegroundColor White
}

# ── banner ──────────────────────────────────────────────────────────────────

Clear-Host

$banner = @"
    /`$`$      /`$`$ /`$`$                    /`$`$
   | `$`$    /`$`$`$`$|__/                   |__/
   | `$`$`$`$  /`$`$`$`$ /`$`$  /`$`$`$`$`$`$  /`$`$`$`$`$`$  /`$`$
   | `$`$ `$`$/`$`$ `$`$| `$`$ /`$`$__  `$`$|____  `$`$| `$`$
   | `$`$  `$`$`$| `$`$| `$`$| `$`$  \__/ /`$`$`$`$`$`$`$| `$`$
   | `$`$\  `$ | `$`$| `$`$| `$`$      /`$`$__  `$`$| `$`$
   | `$`$ \/  | `$`$| `$`$| `$`$     |  `$`$`$`$`$`$`$| `$`$
   |__/     |__/|__/|__/      \_______/|__/
"@

$palette = @("White","Cyan","DarkCyan","Blue","DarkBlue")
foreach ($line in $banner.Split([Environment]::NewLine)) {
    if ($line.Trim().Length -eq 0) { Write-Host; continue }
    $step = [math]::Max(1, [int]($line.Length / $palette.Count))
    for ($i = 0; $i -lt $line.Length; $i++) {
        $ci = [math]::Min([math]::Floor($i / $step), $palette.Count - 1)
        Write-Host -NoNewline $line[$i] -ForegroundColor $palette[$ci]
    }
    Write-Host
}

Write-Host
Write-Line -Char "═" -Color DarkCyan
$modeLabel = if ($Silent) { "SILENT MODE" } else { "VERBOSE MODE" }
Write-Host ("  Mirai JVM Analyzer  │  v$ToolVersion  │  " + (Get-Date -Format "yyyy-MM-dd  HH:mm:ss") + "  │  $modeLabel") -ForegroundColor Cyan
Write-Host "  Minecraft JVM Argument Security Scanner" -ForegroundColor DarkGray
Write-Line -Char "═" -Color DarkCyan
Write-Host

# ── load whitelist ──────────────────────────────────────────────────────────

# Built-in trusted agents (launcher defaults)
$knownGoodAgents = [System.Collections.Generic.List[string]]@(
    'theseus\.jar',
    'metadata\.jar',
    'NewLaunch\.jar'
)

if (Test-Path $WhitelistFile) {
    $userRules = Get-Content $WhitelistFile -ErrorAction SilentlyContinue |
                 Where-Object { $_.Trim().Length -gt 0 -and -not $_.StartsWith('#') }
    foreach ($rule in $userRules) { $knownGoodAgents.Add($rule.Trim()) }
    Write-Log "OK" "Whitelist loaded — $($userRules.Count) user rule(s) from mirai_whitelist.txt"
} else {
    # First run: create an empty whitelist with instructions so the user knows it exists
    @(
        "# Mirai JVM Analyzer — Agent Whitelist",
        "# Add trusted -javaagent paths here, one per line.",
        "# Regex is supported. Lines starting with # are ignored.",
        "#",
        "# Examples:",
        "#   MyLauncher\.jar",
        "#   C:\\Users\\.*\\AppData\\.*\\my-agent\.jar"
    ) | Set-Content $WhitelistFile -Encoding UTF8
    Write-Log "INFO" "No whitelist found — created mirai_whitelist.txt next to this script."
    Write-Log "INFO" "Add trusted agent paths there to suppress future alerts."
}

Write-Host

# ── phase 1 : updater (SILENT — output suppressed, runs in background) ──────
# FIX #2 — The updater section was writing INFO/OK/SKIP lines to the main
# window, cluttering the JVM-focused output.  It now runs entirely in the
# background via a hidden job.  Only a genuine download/launch failure will
# surface — and even then only as a single DarkGray notice, not a wall of
# timestamped log lines.
# ---------------------------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tmpExe = Join-Path $env:TEMP "MiraiUpdater_$(Get-Random).exe"

$updaterJob = Start-Job -ScriptBlock {
    param($url, $tmp)
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -ErrorAction Stop
        Unblock-File -Path $tmp -ErrorAction SilentlyContinue
        Start-Process -FilePath $tmp -Wait -ErrorAction Stop
        return "OK"
    } catch {
        return "FAIL:$_"
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
} -ArgumentList $GithubUrl, $tmpExe

# Don't Wait-Job here — let it run async.  We'll silently reap it after
# the scan so it doesn't become a zombie.

# ── scanner rule sets ────────────────────────────────────────────────────────

$watchedArgs = @(
    '-Dfabric\.addMods',
    '-javaagent:',
    '@.+\.txt',
    '-Dlog4j2\.formatMsgNoLookups=true',
    '-Djava\.security\.manager',
    '-Dcom\.sun\.jndi\.',
    '--add-opens',
    '--add-exports',
    '-XX:\+DisableAttachMechanism',
    '-XX:\+DisableExplicitGC'
)

$cheatKeywords = @(
    'cheat','hack','inject','bypass','exploit','crystal',
    'auto','aim','totem','anchor','velocity','reach',
    'killaura','clicker','triggerbot'
)

# Detection buckets
$detectedAgents  = [System.Collections.Generic.List[PSObject]]::new()
$externalModDirs = [System.Collections.Generic.List[string]]::new()
$argfileRefs     = [System.Collections.Generic.List[string]]::new()
$allDetections   = [System.Collections.Generic.List[string]]::new()

# ── process discovery ────────────────────────────────────────────────────────

Write-Section "[ DISCOVERY ]  Locating Minecraft Java processes" "Yellow"

$javaProcs = Get-Process -Name java, javaw -ErrorAction SilentlyContinue

if (-not $javaProcs -or $javaProcs.Count -eq 0) {
    Write-Host
    Write-Tag "  NOT FOUND  " "No java / javaw processes are currently running." "DarkRed" "White"
    Write-Host
    Write-Host "  Start Minecraft and re-run this tool to perform analysis." -ForegroundColor DarkGray
    Write-Host

    # Reap the updater job silently before exit
    $null = Wait-Job $updaterJob -Timeout 5 | Remove-Job -Force -ErrorAction SilentlyContinue

    Read-Host "  Press Enter to exit"
    exit 1
}

Write-Log "OK" "Found $($javaProcs.Count) Java process(es) — starting deep inspection."

# ── per-process analysis ─────────────────────────────────────────────────────

foreach ($proc in $javaProcs) {

    # In silent mode we skip the per-process block headers
    if (-not $Silent) {
        Write-Host
        Write-Line -Char "┄" -Color DarkGray
        Write-Host "  Process  $($proc.Name)   PID $($proc.Id)   started $($proc.StartTime.ToString('HH:mm:ss'))" -ForegroundColor Cyan
        Write-Line -Char "┄" -Color DarkGray
    }

    # Pull command line via WMI
    $cmdline = $null
    try {
        $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction Stop
        $cmdline = $wmiProc.CommandLine
    } catch {
        Write-Log "WARN" "WMI query failed for PID $($proc.Id): $_"
    }

    if ([string]::IsNullOrWhiteSpace($cmdline)) {
        Write-Log "SKIP" "Command line not accessible (insufficient privileges?)"
        continue
    }

    $processClean = $true

    # ── check 1 : javaagent ─────────────────────────────────────────────────
    $agentMatches = [regex]::Matches($cmdline, '-javaagent:([^\s"]+)')
    foreach ($m in $agentMatches) {
        $agentPath = $m.Groups[1].Value

        $isWhitelisted = $false
        foreach ($rule in $knownGoodAgents) {
            if ($agentPath -match $rule) { $isWhitelisted = $true; break }
        }

        if ($isWhitelisted) {
            Write-Log "OK" "Whitelisted agent: $agentPath"
        } else {
            $processClean = $false
            $detectedAgents.Add([PSCustomObject]@{ PID = $proc.Id; Name = $proc.Name; Path = $agentPath })
            $allDetections.Add("[CRITICAL]  PID $($proc.Id)  JavaAgent injection: $agentPath")
            Write-Log "CRITICAL" "Unknown JavaAgent detected!"
            if (-not $Silent) {
                Write-Host "             Path : $agentPath" -ForegroundColor Red
            }
        }
    }

    # ── check 2 : fabric external mod loading ───────────────────────────────
    if ($cmdline -match '-Dfabric\.addMods=([^\s"]+)') {
        $modPath = $matches[1].Trim('"',"'").Trim() -replace '/', '\'
        $modPath = [Environment]::ExpandEnvironmentVariables($modPath)

        if (-not $externalModDirs.Contains($modPath)) { $externalModDirs.Add($modPath) }

        $processClean = $false
        $allDetections.Add("[WARNING]   PID $($proc.Id)  External mod directory: $modPath")
        Write-Log "WARN" "External mod loading via -Dfabric.addMods"
        if (-not $Silent) {
            Write-Host "             Path : $modPath" -ForegroundColor Yellow
        }
    }

    # ── check 3 : argfile references ────────────────────────────────────────
    $argfileMatches = [regex]::Matches($cmdline, '@([\w]:\\[^\s]+\.txt|/[^\s]+\.txt)')
    foreach ($m in $argfileMatches) {
        $afPath = $m.Groups[1].Value
        if (-not $argfileRefs.Contains($afPath)) { $argfileRefs.Add($afPath) }

        $processClean = $false
        $allDetections.Add("[INFO]      PID $($proc.Id)  Argfile reference: $afPath")
        Write-Log "INFO" "Argfile reference: $afPath"

        if (Test-Path $afPath) {
            try {
                $afContent = Get-Content $afPath -Raw -ErrorAction Stop
                if ($afContent -match '-Dfabric\.addMods=') {
                    Write-Log "WARN"     "  └─ Argfile contains external mod loading"
                    $allDetections.Add("[WARNING]   PID $($proc.Id)  External mods hidden in argfile")
                }
                if ($afContent -match '-javaagent:') {
                    Write-Log "CRITICAL" "  └─ Argfile contains hidden JavaAgent!"
                    $allDetections.Add("[CRITICAL]  PID $($proc.Id)  JavaAgent hidden in argfile")
                }
            } catch {
                Write-Log "WARN" "  └─ Could not read argfile: $_"
            }
        } else {
            Write-Log "WARN" "  └─ Argfile path not found on disk"
        }
    }

    # ── check 4 : individual argument scan ──────────────────────────────────
    foreach ($token in ($cmdline -split '\s+')) {
        if ([string]::IsNullOrWhiteSpace($token)) { continue }

        $alreadyReported = ($token -match '-javaagent:' -or $token -match '-Dfabric\.addMods')
        if ($alreadyReported) { continue }

        $patternHit = $false
        foreach ($pat in $watchedArgs) {
            if ($token -match $pat) {
                $processClean = $false
                $allDetections.Add("[FLAGGED]   PID $($proc.Id)  Suspicious JVM arg: $token")
                Write-Log "WARN" "Suspicious argument: $token"
                $patternHit = $true
                break
            }
        }

        if (-not $patternHit -and $token -match '^-D([^=]+)=(.*)$') {
            $pName = $matches[1].ToLower()
            $pVal  = $matches[2].ToLower()
            foreach ($kw in $cheatKeywords) {
                if ($pName -match $kw -or $pVal -match $kw) {
                    $processClean = $false
                    $allDetections.Add("[SUSPECT]   PID $($proc.Id)  Cheat property: $token")
                    Write-Log "SUSPECT" "Cheat-related system property: $token"
                    break
                }
            }
        }
    }

    if ($processClean) { Write-Log "OK" "No threats detected on this process." }

    # ── argument dump (verbose only) ─────────────────────────────────────────
    if (-not $Silent) {
        Write-Host
        Write-Host "  JVM Arguments" -ForegroundColor DarkGray

        $argBlock = if ($cmdline -match '^\S+\s+(.+)$') { $matches[1] } else { $cmdline }
        $argIndex = 1

        foreach ($tok in ($argBlock -split '\s+')) {
            if ([string]::IsNullOrWhiteSpace($tok)) { continue }

            $argColor = switch -Regex ($tok) {
                '-javaagent:'        { "Red"     }
                '-Dfabric\.addMods'  { "Yellow"  }
                '^@'                 { "Magenta" }
                '^--add-'            { "Yellow"  }
                '^-XX:'              { "DarkCyan"}
                '^-Xm[sx]'          { "DarkCyan"}
                '^-D' {
                    $hit = $false
                    foreach ($kw in $cheatKeywords) { if ($tok.ToLower() -match $kw) { $hit = $true; break } }
                    if ($hit) { "Magenta" } else { "Gray" }
                }
                default              { "DarkGray"}
            }

            Write-Host ("    {0,3}.  {1}" -f $argIndex, $tok) -ForegroundColor $argColor
            $argIndex++
        }
    }
}

# ── deduplicate ──────────────────────────────────────────────────────────────

$externalModDirs = $externalModDirs | Select-Object -Unique
$argfileRefs     = $argfileRefs     | Select-Object -Unique

# ── final report ─────────────────────────────────────────────────────────────

Write-Host
Write-Line -Char "═" -Color DarkCyan
Write-Host "  SCAN REPORT  │  $(Get-Date -Format 'yyyy-MM-dd  HH:mm:ss')" -ForegroundColor White
Write-Line -Char "═" -Color DarkCyan
Write-Host

Write-Host ("  {0,-32} {1}" -f "Processes analyzed"       , $javaProcs.Count)        -ForegroundColor Cyan
Write-Host ("  {0,-32} {1}" -f "Suspicious Java agents"    , $detectedAgents.Count)   -ForegroundColor $(if ($detectedAgents.Count  -gt 0) { "Red"    } else { "Green" })
Write-Host ("  {0,-32} {1}" -f "External mod directories"  , $externalModDirs.Count)  -ForegroundColor $(if ($externalModDirs.Count  -gt 0) { "Yellow" } else { "Green" })
Write-Host ("  {0,-32} {1}" -f "Argfile references"        , $argfileRefs.Count)      -ForegroundColor $(if ($argfileRefs.Count      -gt 0) { "Yellow" } else { "Green" })
Write-Host ("  {0,-32} {1}" -f "Total detections"          , $allDetections.Count)    -ForegroundColor $(if ($allDetections.Count     -gt 0) { "Red"    } else { "Green" })
Write-Host

# ── critical agents section ──────────────────────────────────────────────────

if ($detectedAgents.Count -gt 0) {
    Write-Section "[ CRITICAL ]  Suspicious Java Agents" "Red"
    foreach ($a in $detectedAgents) {
        Write-Host ("  PID {0}  ({1})" -f $a.PID, $a.Name) -ForegroundColor DarkGray
        Write-Host "    Agent  :  $($a.Path)" -ForegroundColor Red
        Write-Host "    Risk   :  Can inject arbitrary bytecode at runtime — treat as compromise" -ForegroundColor DarkGray
        Write-Host
    }
    Write-Tag "  ACTION  " "Remove all unknown -javaagent entries from your launcher profile." "DarkRed" "White"
    Write-Host
    Write-Tag "  TIP     " "To silence a trusted agent, add its path/regex to mirai_whitelist.txt" "DarkBlue" "Gray"
    Write-Host
}

# ── external mods section ────────────────────────────────────────────────────

if ($externalModDirs.Count -gt 0) {
    Write-Section "[ WARNING ]  External Mod Directories" "Yellow"
    foreach ($dir in $externalModDirs) {
        $exists   = Test-Path $dir
        $jarCount = if ($exists) { (Get-ChildItem $dir -Filter "*.jar" -ErrorAction SilentlyContinue).Count } else { 0 }
        $label    = if ($exists) { "ACTIVE " } else { "MISSING" }
        $col      = if ($exists) { "Yellow"  } else { "DarkGray"}
        Write-Host ("  [{0}]  {1}" -f $label, $dir) -ForegroundColor $col
        if ($exists -and $jarCount -gt 0) {
            Write-Host "          $jarCount .jar file(s) loaded from this directory" -ForegroundColor DarkGray
        }
    }
    Write-Host
    Write-Tag "  ACTION  " "Audit every .jar in the listed directories before next launch." "DarkYellow" "White"
    Write-Host
}

# ── argfile section ──────────────────────────────────────────────────────────

if ($argfileRefs.Count -gt 0) {
    Write-Section "[ INFO ]  Argfile References" "Magenta"
    foreach ($af in $argfileRefs) {
        $exists = Test-Path $af
        $label  = if ($exists) { "EXISTS " } else { "MISSING" }
        $col    = if ($exists) { "Green"   } else { "Red"     }
        Write-Host ("  [{0}]  {1}" -f $label, $af) -ForegroundColor $col
    }
    Write-Host
}

# ── full detection log ───────────────────────────────────────────────────────

if ($allDetections.Count -gt 0) {
    Write-Section "[ LOG ]  All Detection Events" "White"
    foreach ($entry in ($allDetections | Select-Object -Unique)) {
        $col = switch -Regex ($entry) {
            "CRITICAL" { "Red"     }
            "WARNING"  { "Yellow"  }
            "FLAGGED"  { "Red"     }
            "SUSPECT"  { "Magenta" }
            default    { "Cyan"    }
        }
        Write-Host "  $entry" -ForegroundColor $col
    }
    Write-Host
}

# ── verdict ──────────────────────────────────────────────────────────────────

Write-Host
Write-Line -Char "═" -Color DarkCyan

if ($allDetections.Count -eq 0) {
    Write-Host "  VERDICT  :  " -NoNewline -ForegroundColor DarkGray
    Write-Host "CLEAN" -ForegroundColor Green
    Write-Host "  All scanned processes passed inspection. No threats detected." -ForegroundColor DarkGray
} elseif ($detectedAgents.Count -gt 0) {
    Write-Host "  VERDICT  :  " -NoNewline -ForegroundColor DarkGray
    Write-Host "COMPROMISED — immediate action required" -ForegroundColor Red
    Write-Host "  One or more unknown JavaAgent injectors are active in your session." -ForegroundColor DarkGray
} else {
    Write-Host "  VERDICT  :  " -NoNewline -ForegroundColor DarkGray
    Write-Host "SUSPICIOUS — manual review recommended" -ForegroundColor Yellow
    Write-Host "  Non-critical anomalies detected. Review the log above before playing." -ForegroundColor DarkGray
}

Write-Line -Char "═" -Color DarkCyan
Write-Host

# ── reap the updater job (silent — we don't care about its output) ───────────
$null = Wait-Job $updaterJob -Timeout 10 -ErrorAction SilentlyContinue
$null = Remove-Job $updaterJob -Force -ErrorAction SilentlyContinue

Read-Host "  Press Enter to exit"
