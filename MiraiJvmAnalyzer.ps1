# Mirai JVM Analyzer - Console Version
# Developed by: DaddyMirai
# Scans Minecraft JVM arguments and displays results directly in console

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ASCII Art Banner
$asciiArt = @"
    /$$      /$$ /$$                    /$$
   | $$    /$$$|__/                   |__/
   | $$$$  /$$$$ /$$  /$$$$$$  /$$$$$$  /$$
   | $$ $$/$$ $$| $$ /$$__  $$|____  $$| $$
   | $$  $$$| $$| $$| $$  \__/ /$$$$$$$| $$
   | $$\  $ | $$| $$| $$      /$$__  $$| $$
   | $$ \/  | $$| $$| $$     |  $$$$$$$| $$
   |__/     |__/|__/|__/      \_______/|__/
"@

# Display ASCII art with gradient colors
$gradientColors = @("White", "Cyan", "DarkCyan", "Blue", "DarkBlue")

$lines = $asciiArt.Split([System.Environment]::NewLine)
foreach ($line in $lines) {
    if ($line.Trim().Length -gt 0) {
        $colorStep = $line.Length / $gradientColors.Count
        for ($i = 0; $i -lt $line.Length; $i++) {
            $char = $line[$i]
            $colorIndex = [math]::Min([math]::Floor($i / $colorStep), $gradientColors.Count - 1)
            $charColor = $gradientColors[$colorIndex]
            Write-Host -NoNewline $char -ForegroundColor $charColor
        }
    }
    Write-Host
}

Write-Host
Write-Host "Mirai JVM Analyzer - Minecraft JVM Argument Security Scanner (Console Mode)" -ForegroundColor Cyan
Write-Host "========================================================================================" -ForegroundColor DarkGray
Write-Host

# ==================== JVM ARGUMENT SCANNER ====================

# Find all javaw.exe and java.exe processes
$javaProcesses = Get-Process -Name javaw, java -ErrorAction SilentlyContinue
$externalModDirectories = @()
$suspiciousJavaAgents = @()
$argfilesFound = @()
$allDetections = @()

# Known legitimate agent patterns
$legitimateAgentPatterns = @(
    'theseus\.jar',
    'metadata\.jar',
    'NewLaunch\.jar'
)

# Suspicious argument patterns to flag
$suspiciousArgPatterns = @(
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

# Suspicious system properties
$suspiciousProperties = @(
    'cheat', 'hack', 'inject', 'bypass', 'exploit', 'crystal', 'auto', 'aim',
    'totem', 'anchor', 'velocity', 'reach', 'killaura', 'clicker', 'triggerbot'
)

Write-Host "[SCAN] Looking for Minecraft Java processes..." -ForegroundColor Yellow
Write-Host

if ($javaProcesses.Count -eq 0) {
    Write-Host "[!] No Minecraft (java/javaw) processes found running." -ForegroundColor Red
    Write-Host "[!] Start Minecraft and run this script again for analysis." -ForegroundColor Yellow
    Write-Host
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "[+] Found $($javaProcesses.Count) Java process(es)" -ForegroundColor Green
Write-Host

foreach ($proc in $javaProcesses) {
    try {
        Write-Host "Analyzing Process ID: $($proc.Id) ($($proc.Name))" -ForegroundColor Cyan
        
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction Stop).CommandLine
        
        if (-not $commandLine) { 
            Write-Host "  [-] No command line accessible" -ForegroundColor DarkGray
            continue 
        }
        
        $hasIssues = $false
        
        # Check for javaagent arguments
        if ($commandLine -match '-javaagent:([^\s]+)') {
            $javaAgentPath = $matches[1]
            
            # Check if legitimate
            $isLegitimate = $false
            foreach ($pattern in $legitimateAgentPatterns) {
                if ($javaAgentPath -match $pattern) {
                    $isLegitimate = $true
                    break
                }
            }
            
            if (-not $isLegitimate) {
                $hasIssues = $true
                $suspiciousJavaAgents += [PSCustomObject]@{
                    ProcessId = $proc.Id
                    ProcessName = $proc.Name
                    AgentPath = $javaAgentPath
                }
                $allDetections += "[CRITICAL] Process $($proc.Id) - Suspicious JavaAgent: $javaAgentPath"
                Write-Host "  [CRITICAL] Suspicious JavaAgent detected!" -ForegroundColor Red
                Write-Host "             Path: $javaAgentPath" -ForegroundColor Red
            }
        }
        
        # Check for fabric.addMods
        if ($commandLine -match '-Dfabric\.addMods=([^\s"]+)') {
            $rawPath = $matches[1]
            $fabricAddModsValue = $rawPath.Trim('"', "'").Trim()
            $fabricAddModsValue = $fabricAddModsValue -replace '/', '\'
            $fabricAddModsValue = [Environment]::ExpandEnvironmentVariables($fabricAddModsValue)
            $externalModDirectories += $fabricAddModsValue
            $hasIssues = $true
            $allDetections += "[WARNING] Process $($proc.Id) - External Mod Loading: $fabricAddModsValue"
            Write-Host "  [WARNING] External mod loading detected!" -ForegroundColor Yellow
            Write-Host "            Path: $fabricAddModsValue" -ForegroundColor Yellow
        }
        
        # Check for argfile references
        if ($commandLine -match '@([\w]:\\[^\s]+\.txt|/[^\s]+\.txt)') {
            $argFilePath = $matches[1]
            $argfilesFound += $argFilePath
            $hasIssues = $true
            $allDetections += "[INFO] Process $($proc.Id) - Argfile Reference: $argFilePath"
            Write-Host "  [INFO] Argfile reference found: $argFilePath" -ForegroundColor Cyan
            
            if (Test-Path $argFilePath) {
                Write-Host "         [+] Argfile exists, scanning contents..." -ForegroundColor Green
                try {
                    $argFileContent = Get-Content -Path $argFilePath -Raw -ErrorAction SilentlyContinue
                    
                    if ($argFileContent -match '-Dfabric\.addMods=') {
                        Write-Host "         [WARNING] External mod loading inside argfile!" -ForegroundColor Yellow
                        $allDetections += "[WARNING] Process $($proc.Id) - External mod loading hidden in argfile"
                    }
                    
                    if ($argFileContent -match '-javaagent:') {
                        Write-Host "         [CRITICAL] JavaAgent hidden inside argfile!" -ForegroundColor Red
                        $allDetections += "[CRITICAL] Process $($proc.Id) - JavaAgent hidden in argfile"
                    }
                } catch {}
            } else {
                Write-Host "         [WARNING] Argfile not found: $argFilePath" -ForegroundColor Red
            }
        }
        
        # Scan individual JVM arguments
        $argsList = $commandLine -split '\s+'
        foreach ($arg in $argsList) {
            foreach ($pattern in $suspiciousArgPatterns) {
                if ($arg -match $pattern) {
                    $hasIssues = $true
                    $allDetections += "[FLAGGED] Process $($proc.Id) - Suspicious Argument: $arg"
                    Write-Host "  [FLAGGED] Suspicious argument: $arg" -ForegroundColor Red
                    break
                }
            }
            
            # Check for suspicious system properties
            if ($arg -match '^-D([^=]+)=(.*)$') {
                $propName = $matches[1].ToLower()
                $propValue = $matches[2].ToLower()
                foreach ($suspProp in $suspiciousProperties) {
                    if ($propName -match $suspProp -or $propValue -match $suspProp) {
                        $hasIssues = $true
                        $allDetections += "[SUSPECT] Process $($proc.Id) - Suspicious Property: $arg"
                        Write-Host "  [SUSPECT] Suspicious system property: $arg" -ForegroundColor Magenta
                        break
                    }
                }
            }
        }
        
        if (-not $hasIssues) {
            Write-Host "  [CLEAN] No suspicious JVM arguments detected" -ForegroundColor Green
        }
        
        Write-Host
        
    } catch {
        Write-Host "  [ERROR] Could not access process: $($_.Exception.Message)" -ForegroundColor DarkRed
        Write-Host
    }
}

# Remove duplicate external mod directories
$externalModDirectories = $externalModDirectories | Select-Object -Unique

# ==================== DISPLAY SUMMARY ====================

Write-Host "=" * 70 -ForegroundColor DarkGray
Write-Host "SCAN SUMMARY" -ForegroundColor White
Write-Host "=" * 70 -ForegroundColor DarkGray
Write-Host

Write-Host "Processes Analyzed: $($javaProcesses.Count)" -ForegroundColor Cyan
Write-Host "External Mod Directories: $($externalModDirectories.Count)" -ForegroundColor Yellow
Write-Host "Suspicious Java Agents: $($suspiciousJavaAgents.Count)" -ForegroundColor Red
Write-Host "Argfiles Found: $($argfilesFound.Count)" -ForegroundColor Magenta
Write-Host "Total Detections: $($allDetections.Count)" -ForegroundColor White
Write-Host

# Display Critical Alerts first
if ($suspiciousJavaAgents.Count -gt 0) {
    Write-Host "[CRITICAL ALERTS]" -ForegroundColor Red
    Write-Host "-" * 50 -ForegroundColor DarkGray
    foreach ($agent in $suspiciousJavaAgents) {
        Write-Host "  [!] JavaAgent in Process $($agent.ProcessId):" -ForegroundColor Red
        Write-Host "      $($agent.AgentPath)" -ForegroundColor Red
        Write-Host
    }
    Write-Host "  [REMEDIATION] Remove -javaagent arguments from your launcher!" -ForegroundColor Yellow
    Write-Host
}

if ($externalModDirectories.Count -gt 0) {
    Write-Host "[EXTERNAL MOD DETECTIONS]" -ForegroundColor Yellow
    Write-Host "-" * 50 -ForegroundColor DarkGray
    foreach ($modDir in $externalModDirectories) {
        $exists = Test-Path $modDir
        if ($exists) {
            Write-Host "  [ACTIVE] $modDir" -ForegroundColor Yellow
            $jarCount = (Get-ChildItem -Path $modDir -Filter "*.jar" -ErrorAction SilentlyContinue).Count
            if ($jarCount -gt 0) {
                Write-Host "           Contains $jarCount mod JAR file(s)" -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "  [MISSING] $modDir (Path not accessible)" -ForegroundColor DarkGray
        }
    }
    Write-Host
}

if ($argfilesFound.Count -gt 0) {
    Write-Host "[ARGFILE REFERENCES]" -ForegroundColor Magenta
    Write-Host "-" * 50 -ForegroundColor DarkGray
    foreach ($argfile in $argfilesFound) {
        $exists = Test-Path $argfile
        $status = if ($exists) { "EXISTS" } else { "MISSING" }
        $color = if ($exists) { "Green" } else { "Red" }
        Write-Host "  [$status] $argfile" -ForegroundColor $color
    }
    Write-Host
}

# Display all detections if any
if ($allDetections.Count -gt 0) {
    Write-Host "[ALL DETECTIONS]" -ForegroundColor White
    Write-Host "-" * 50 -ForegroundColor DarkGray
    foreach ($detection in $allDetections | Select-Object -Unique) {
        if ($detection -match "CRITICAL") {
            Write-Host "  $detection" -ForegroundColor Red
        } elseif ($detection -match "WARNING") {
            Write-Host "  $detection" -ForegroundColor Yellow
        } elseif ($detection -match "FLAGGED") {
            Write-Host "  $detection" -ForegroundColor Red
        } elseif ($detection -match "SUSPECT") {
            Write-Host "  $detection" -ForegroundColor Magenta
        } else {
            Write-Host "  $detection" -ForegroundColor Cyan
        }
    }
    Write-Host
}

# Display JVM Arguments in detail for each process
Write-Host "[JVM ARGUMENTS BY PROCESS]" -ForegroundColor White
Write-Host "-" * 70 -ForegroundColor DarkGray

foreach ($proc in $javaProcesses) {
    try {
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction Stop).CommandLine
        if ($commandLine) {
            Write-Host "`nProcess: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Cyan
            Write-Host "Start Time: $($proc.StartTime)" -ForegroundColor DarkGray
            
            # Extract only JVM arguments (skip java.exe path)
            if ($commandLine -match '^\S+\s+(.+)$') {
                $jvmArgs = $matches[1]
            } else {
                $jvmArgs = $commandLine
            }
            
            # Split and display arguments one per line
            $argsArray = $jvmArgs -split '\s+'
            Write-Host "JVM Arguments:" -ForegroundColor White
            $argNumber = 1
            foreach ($arg in $argsArray) {
                # Color-code different argument types
                if ($arg -match '-javaagent:') {
                    Write-Host "  $argNumber. $arg" -ForegroundColor Red
                } elseif ($arg -match '-Dfabric\.addMods') {
                    Write-Host "  $argNumber. $arg" -ForegroundColor Yellow
                } elseif ($arg -match '^@') {
                    Write-Host "  $argNumber. $arg" -ForegroundColor Magenta
                } elseif ($arg -match '^-D') {
                    # Check if property contains suspicious keywords
                    $isSuspicious = $false
                    foreach ($suspProp in $suspiciousProperties) {
                        if ($arg.ToLower() -match $suspProp) {
                            $isSuspicious = $true
                            break
                        }
                    }
                    if ($isSuspicious) {
                        Write-Host "  $argNumber. $arg" -ForegroundColor Magenta
                    } else {
                        Write-Host "  $argNumber. $arg" -ForegroundColor Gray
                    }
                } elseif ($arg -match '^-X') {
                    Write-Host "  $argNumber. $arg" -ForegroundColor DarkCyan
                } elseif ($arg -match '^--add-') {
                    Write-Host "  $argNumber. $arg" -ForegroundColor Yellow
                } else {
                    Write-Host "  $argNumber. $arg" -ForegroundColor DarkGray
                }
                $argNumber++
            }
        }
    } catch {}
}

Write-Host
Write-Host "=" * 70 -ForegroundColor DarkGray
Write-Host "ANALYSIS COMPLETE" -ForegroundColor Green
Write-Host "=" * 70 -ForegroundColor DarkGray
Write-Host

# Final recommendations
if ($suspiciousJavaAgents.Count -gt 0 -or $externalModDirectories.Count -gt 0) {
    Write-Host "RECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host "-" * 50 -ForegroundColor DarkGray
    if ($suspiciousJavaAgents.Count -gt 0) {
        Write-Host "  • Remove suspicious -javaagent arguments from your launcher" -ForegroundColor White
        Write-Host "  • These can inject malicious code and bypass security" -ForegroundColor DarkGray
    }
    if ($externalModDirectories.Count -gt 0) {
        Write-Host "  • Review external mods loaded via -Dfabric.addMods" -ForegroundColor White
        Write-Host "  • Consider moving mods to the standard mods folder" -ForegroundColor DarkGray
    }
    Write-Host
}

Read-Host "Press Enter to exit"
