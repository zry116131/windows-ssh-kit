# PowerShell 5.1 compatible. No private-key contents are exported.
$script:reportDir = $null
$script:repairNotes = New-Object 'System.Collections.Generic.List[string]'
$script:currentStep = 'initializing'
$script:failureMessage = ''
$script:failedStep = ''
$script:runStarted = Get-Date
$script:commandNumber = 0

function Save-ReportText([string]$Name, [string]$Text) {
    if ($script:reportDir) {
        [IO.File]::WriteAllText((Join-Path $script:reportDir $Name), $Text, (New-Object Text.UTF8Encoding($false)))
    }
}
function Initialize-Reports([string]$RequestedDirectory) {
    $script:runId = '{0}_{1}_{2}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0,8))
    if ($RequestedDirectory) { $candidate = $RequestedDirectory }
    else { $candidate = Join-Path (Join-Path $PSScriptRoot 'Logs') $script:runId }
    try {
        New-Item -ItemType Directory -Path $candidate -Force | Out-Null
        $probe = Join-Path $candidate ('.write-test-' + $PID)
        [IO.File]::WriteAllText($probe, 'test')
        Remove-Item -LiteralPath $probe -Force
        $script:reportDir = [IO.Path]::GetFullPath($candidate)
    } catch {
        $script:reportDir = Join-Path (Join-Path $env:TEMP 'Windows-SSH-Logs') $script:runId
        New-Item -ItemType Directory -Path $script:reportDir -Force | Out-Null
        Write-Warning "USB log directory is not writable. Logs will be saved locally: $script:reportDir"
    }
    $script:runId = Split-Path $script:reportDir -Leaf
    Write-Host "LOG DIRECTORY: $script:reportDir" -ForegroundColor Cyan
    Start-Transcript -Path (Join-Path $script:reportDir "console-$PID.log") -Force | Out-Null
    $script:transcribing = $true
}
function Set-RepairStep([string]$Step) {
    $script:currentStep = $Step
    Write-Host "[$(Get-Date -Format HH:mm:ss)] $Step" -ForegroundColor Cyan
    Save-ReportText 'progress.json' ([ordered]@{Step=$Step;Time=(Get-Date -Format o);Action=$Action} | ConvertTo-Json)
}
function Add-RepairNote([string]$Note) {
    $line = "$(Get-Date -Format o) $Note"
    $script:repairNotes.Add($line)
    Write-Host "REPAIR: $Note" -ForegroundColor Yellow
    Save-ReportText 'repairs.txt' ($script:repairNotes -join "`r`n")
}
function Quote-NativeArgument([string]$Value) {
    # CommandLineToArgvW quoting, including embedded quotes and trailing slashes.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}
function Invoke-CapturedNative {
    param([string]$File, [string[]]$Arguments = @(), [string]$Label = 'command', [int]$TimeoutSeconds = 20)
    $script:commandNumber++
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = ($Arguments | ForEach-Object { Quote-NativeArgument $_ }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    $out = ''; $err = ''; $code = -1; $timeout = $false
    try {
        [void]$process.Start()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timeout = $true
            $process.Kill()
            [void]$process.WaitForExit(5000)
        }
        $out = $outTask.GetAwaiter().GetResult()
        $err = $errTask.GetAwaiter().GetResult()
        $code = $process.ExitCode
    } catch { $err += "`r`n" + $_.Exception.ToString() }
    finally { $process.Dispose() }
    $result = [pscustomobject]@{ExitCode=$code;TimedOut=$timeout;Stdout=$out;Stderr=$err}
    Save-ReportText (('{0:D3}-{1}.txt' -f $script:commandNumber, $Label)) (
        "FILE: $File`r`nARGS: $($psi.Arguments)`r`nEXIT: $code`r`nTIMEOUT: $timeout`r`nSTDOUT:`r`n$out`r`nSTDERR:`r`n$err")
    return $result
}
function Assert-NativeSuccess($Result, [string]$Operation) {
    if ($Result.TimedOut -or $Result.ExitCode -ne 0) {
        throw "$Operation failed (exit=$($Result.ExitCode), timeout=$($Result.TimedOut)). $($Result.Stderr) $($Result.Stdout)"
    }
}
function Save-Probe([string]$Name, [scriptblock]$Probe) {
    try { Save-ReportText $Name ((& $Probe | Out-String -Width 240).TrimEnd()) }
    catch { Save-ReportText $Name ("DIAGNOSTIC UNAVAILABLE: " + $_.Exception.Message) }
}
function Collect-Diagnostics([string]$Stage) {
    if (-not $script:reportDir) { return }
    Save-Probe "$Stage-system.txt" {
        Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime | Format-List
        [pscustomobject]@{Computer=$env:COMPUTERNAME;Account=[Security.Principal.WindowsIdentity]::GetCurrent().Name;
            NativeArchitecture=[Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE','Machine');
            ProcessArchitecture=$env:PROCESSOR_ARCHITECTURE;PowerShell=$PSVersionTable.PSVersion.ToString();Step=$script:currentStep} | Format-List
    }
    Save-Probe "$Stage-service.txt" {
        Get-CimInstance Win32_Service -Filter "Name='sshd' OR Name='ssh-agent'" |
            Select-Object Name,State,StartMode,StartName,PathName,ProcessId,ExitCode,ServiceSpecificExitCode | Format-List
    }
    foreach ($verb in @('qc','queryex','qprivs','qsidtype','sdshow')) {
        [void](Invoke-CapturedNative "$env:SystemRoot\System32\sc.exe" @($verb,'sshd') "$Stage-sc-$verb" 10)
    }
    Save-Probe "$Stage-network.txt" {
        $ports = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue)
        $ports | Format-Table LocalAddress,LocalPort,OwningProcess -AutoSize
        foreach ($port in $ports) { Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,Path | Format-List }
        Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength | Format-Table -AutoSize
        Get-NetConnectionProfile | Select-Object InterfaceAlias,NetworkCategory,IPv4Connectivity | Format-Table -AutoSize
    }
    Save-Probe "$Stage-firewall.txt" {
        Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | Format-Table
        foreach ($name in @($ruleName,'OpenSSH-Server-In-TCP')) {
            $r = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
            if ($r) {
                $r | Select-Object Name,Enabled,Direction,Action,Profile | Format-List
                $r | Get-NetFirewallAddressFilter | Format-List LocalAddress,RemoteAddress
                $r | Get-NetFirewallApplicationFilter | Format-List Program
                $r | Get-NetFirewallPortFilter | Format-List Protocol,LocalPort,RemotePort
            }
        }
    }
    Save-Probe "$Stage-acls.txt" {
        $paths = @($sshRoot,(Join-Path $sshRoot 'logs'),$configPath,$keyPath,$binRoot)
        if (Test-Path $sshRoot) { $paths += @(Get-ChildItem -LiteralPath $sshRoot -File -Filter 'ssh_host_*' | ForEach-Object { $_.FullName }) }
        foreach ($path in $paths) {
            if (Test-Path -LiteralPath $path) { Get-Acl -LiteralPath $path | Select-Object Path,Owner,Sddl,AccessToString | Format-List }
        }
    }
    Save-Probe "$Stage-engine.txt" {
        foreach ($name in @('sshd.exe','sshd-auth.exe','sshd-session.exe','ssh-keygen.exe','libcrypto.dll')) {
            $path = Join-Path $binRoot $name
            if (Test-Path $path) {
                $file = Get-Item -LiteralPath $path
                [pscustomobject]@{File=$path;Bytes=$file.Length;FileVersion=$file.VersionInfo.FileVersion;
                    SHA256=(Get-FileHash -LiteralPath $path).Hash;Machine=(Read-PeMachine $path)} | Format-List
            } else { "MISSING: $path" }
        }
    }
    Save-Probe "$Stage-registry.txt" {
        Get-ItemProperty 'HKLM:\SOFTWARE\OpenSSH' -ErrorAction SilentlyContinue | Select-Object DefaultShell,DefaultShellCommandOption | Format-List
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd' -ErrorAction SilentlyContinue |
            Select-Object ImagePath,ObjectName,Start,RequiredPrivileges,ServiceSidType | Format-List
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sshd.exe' -ErrorAction SilentlyContinue |
            Select-Object MitigationOptions | Format-List
    }
    foreach ($item in @(@($configPath,'sshd_config.txt'),@($statePath,'state.json'))) {
        if (Test-Path -LiteralPath $item[0]) {
            $text = [IO.File]::ReadAllText($item[0])
            if ($text -match '-----BEGIN .*PRIVATE KEY-----') { $text = '[OMITTED: unexpected private-key material in configuration]' }
            Save-ReportText "$Stage-$($item[1])" $text
        }
    }
    if (Test-Path $sshd) {
        [void](Invoke-CapturedNative $sshd @('-ddd','-t','-f',$configPath) "$Stage-sshd-debug-config" 15)
    }
    Save-Probe "$Stage-events.txt" {
        $since = (Get-Date).AddHours(-4)
        foreach ($channel in @('System','Application','OpenSSH/Admin','OpenSSH/Operational')) {
            try {
                Get-WinEvent -FilterHashtable @{LogName=$channel;StartTime=$since} -MaxEvents 400 -ErrorAction Stop |
                    Where-Object { $channel -like 'OpenSSH/*' -or $_.Message -match '(?i)(sshd|openssh|ssh-agent|libcrypto)' } |
                    Select-Object TimeCreated,LogName,Id,LevelDisplayName,ProviderName,Message | Format-List
            } catch { "CHANNEL $channel : $($_.Exception.Message)" }
        }
    }
    Save-Probe "$Stage-sshd-log-tail.txt" {
        foreach ($name in @('sshd.log','sshd.log.1')) {
            $file = Join-Path (Join-Path $sshRoot 'logs') $name
            if (Test-Path $file) { "FILE: $file"; Get-Content -LiteralPath $file -Tail 300 }
        }
    }
}
function Assert-NoReparse([string]$Path) {
    if ((Test-Path -LiteralPath $Path) -and ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing to change a junction/symlink: $Path"
    }
}
function Repair-SSHPermissions {
    Set-RepairStep 'Repair SSH directory, config and host-key permissions'
    foreach ($directory in @($sshRoot,(Join-Path $sshRoot 'logs'))) {
        Assert-NoReparse $directory
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        # SYSTEM and Administrators write; ordinary users read/execute only.
        Protect-InstallDirectory $directory
        Add-RepairNote "Restored secure directory ACL: $directory"
    }
    foreach ($file in @($configPath,$keyPath,(Join-Path $sshRoot 'administrators_authorized_keys'))) {
        Assert-NoReparse $file
        if (Test-Path $file) { Protect-File $file; Add-RepairNote "Restored protected file ACL: $file" }
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $sshRoot -File -Filter 'ssh_host_*_key')) {
        Assert-NoReparse $file.FullName
        Protect-File $file.FullName
        Add-RepairNote "Restored host private-key ACL without changing its contents: $($file.Name)"
    }
}
function Ensure-OfflineFiles([hashtable]$Payload, [string]$InstallRoot) {
    Set-RepairStep 'Verify native payload and repair missing or damaged program files'
    $zip = Join-Path $PSScriptRoot ('payloads\' + $Payload.Folder + '.zip')
    if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ine $Payload.Hash) { throw 'Offline payload SHA-256 mismatch.' }
    Assert-NoReparse $InstallRoot
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    Protect-InstallDirectory $InstallRoot
    $destination = Join-Path $InstallRoot $Payload.Folder
    Assert-NoReparse $destination
    $stage = Join-Path $InstallRoot ('.stage-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    Protect-InstallDirectory $stage
    try {
        Expand-Archive -LiteralPath $zip -DestinationPath $stage
        $sourceRoot = Join-Path $stage $Payload.Folder
        $sources = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File)
        foreach ($file in $sources) {
            if ($file.Extension -in @('.exe','.dll') -and (Read-PeMachine $file.FullName) -ne $Payload.Machine) { throw "Incorrect payload architecture: $($file.Name)" }
        }
        $changes = @($sources | Where-Object {
            $relative = $_.FullName.Substring($sourceRoot.Length).TrimStart('\','/')
            $target = Join-Path $destination $relative
            Assert-NoReparse $target
            -not (Test-Path $target) -or ((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $_.FullName).Hash)
        })
        if ($changes.Count -gt 0) {
            Stop-SSHBounded
            $backupRoot = Join-Path (Join-Path $InstallRoot 'repair-backups') $script:runId
            foreach ($source in $changes) {
                $relative = $source.FullName.Substring($sourceRoot.Length).TrimStart('\','/')
                $target = Join-Path $destination $relative
                $parent = Split-Path $target
                Assert-NoReparse $parent
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
                if (Test-Path $target) {
                    $backup = Join-Path $backupRoot $relative
                    New-Item -ItemType Directory -Path (Split-Path $backup) -Force | Out-Null
                    Copy-Item -LiteralPath $target -Destination $backup -Force
                }
                Copy-Item -LiteralPath $source.FullName -Destination $target -Force
                Add-RepairNote "Restored verified offline file: $relative"
            }
        }
        # Reset every packaged subdirectory before its files inherit permissions.
        Protect-InstallDirectory $destination
        foreach ($folder in @(Get-ChildItem -LiteralPath $destination -Directory -Recurse)) {
            Assert-NoReparse $folder.FullName
            Protect-InstallDirectory $folder.FullName
        }
        foreach ($source in $sources) {
            $relative = $source.FullName.Substring($sourceRoot.Length).TrimStart('\','/')
            $target = Join-Path $destination $relative
            $r = Invoke-CapturedNative "$env:SystemRoot\System32\icacls.exe" @($target,'/reset') 'binary-acl' 10
            Assert-NativeSuccess $r 'Reset installed file ACL'
            if ((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $source.FullName).Hash) { throw "Installed file hash mismatch: $relative" }
        }
        Add-RepairNote 'Complete offline payload verified; partial installation repaired where needed.'
    } finally {
        if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    }
}
function Repair-ServiceRegistration {
    $service = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    if (-not $service) { throw 'sshd service is missing.' }
    if ($service.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')) {
        throw "sshd uses a custom service identity ($($service.StartName)); auto-repair will not replace its credentials."
    }
    $r = Invoke-CapturedNative "$env:SystemRoot\System32\sc.exe" @('config','sshd','binPath=',('"' + $sshd + '"')) 'repair-service-path'
    Assert-NativeSuccess $r 'Normalize sshd service executable path'
    $r = Invoke-CapturedNative "$env:SystemRoot\System32\sc.exe" @('privs','sshd','SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege') 'repair-service-privileges'
    Assert-NativeSuccess $r 'Set standard sshd service privileges'
    Set-Service sshd -StartupType Automatic
    Add-RepairNote 'Restored quoted service executable path, standard sshd privileges and automatic startup.'
}
function Stop-SSHBounded {
    $service = Get-Service sshd -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        $service.Stop()
        $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
    }
}
function Assert-PortAvailable {
    $service = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    $pidAllowed = 0
    if ($service) { $pidAllowed = $service.ProcessId }
    $other = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -ne $pidAllowed })
    if ($other.Count) { throw "TCP 22 is occupied by another process (PID $($other.OwningProcess -join ',')). It will not be killed automatically." }
}
function Start-SSHVerified {
    Set-RepairStep 'Start SSH and wait for a stable TCP 22 listener'
    Assert-PortAvailable
    Stop-SSHBounded
    $service = Get-Service sshd
    $service.Start()
    $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    $stable = 0
    for ($i=0; $i -lt 20; $i++) {
        $info = Get-CimInstance Win32_Service -Filter "Name='sshd'"
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $info.ProcessId })
        if ($info.State -eq 'Running' -and $listeners.Count -gt 0) { $stable++ } else { $stable=0 }
        if ($stable -ge 3) { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'sshd did not keep a stable TCP 22 listener. See service exit codes, debug output and events.'
}
function Get-RepairHints([string]$Evidence) {
    $hints = New-Object 'System.Collections.Generic.List[string]'
    if ($Evidence -match '(?i)(bad owner|bad ownership|bad.*permissions|permissions.*(denied|too open)|access is denied|拒绝访问)') { $hints.Add('Possible permission/ACL issue. Review before/after-acls and repairs.txt.') }
    if ($Evidence -match '(?i)(libcrypto.{0,100}(error|fail|missing|mismatch|not found)|(error|fail|missing).{0,100}libcrypto|0xc0000139|0xc000007b|bad image|not a valid win32)') { $hints.Add('Possible binary/dependency or architecture mismatch. Review engine hashes and Windows Application events.') }
    if ($Evidence -match '(?i)(address already in use|occupied by another|bind.*failed)') { $hints.Add('Port/binding conflict. Review network.txt; other processes were not terminated.') }
    if ($Evidence -match '(?i)(bad configuration|bad config|unsupported option|terminating.*configuration|directive.*not allowed)') { $hints.Add('Configuration syntax error. Original policies were retained; review sshd-debug-config output.') }
    if ($Evidence -match '(?i)(no hostkeys|no host keys|unable to load host key)') { $hints.Add('Host key unavailable. Existing private keys were not regenerated; review key ACLs and debug output.') }
    if ($Evidence -match '(?i)(1053|1067|7034)') { $hints.Add('Windows service startup/crash error. This code alone does not identify the cause; review events and debug output.') }
    if ($hints.Count -eq 0) { $hints.Add('No single cause established. Review error.txt, before/after snapshots and captured command outputs.') }
    return $hints.ToArray()
}
function Finish-Reports([int]$Code) {
    try { Collect-Diagnostics 'after' } catch { Save-ReportText 'collection-error.txt' $_.Exception.ToString() }
    $evidence = $script:failureMessage
    foreach ($f in @(Get-ChildItem -LiteralPath $script:reportDir -Filter '*.txt' -File | Where-Object {
        $_.Name -match '(^error\.txt$|^first-start-error\.txt$|-events\.txt$|-sshd-debug-config\.txt$|-validate-config\.txt$|effective-user-config\.txt$)'
    })) {
        if ($f.Length -lt 2MB) { $evidence += "`n" + [IO.File]::ReadAllText($f.FullName) }
    }
    $result = if ($Code -eq 0) { 'LOCAL_CHECK_PASSED_REMOTE_LOGIN_UNVERIFIED' } else { 'FAILED_NEEDS_REVIEW' }
    if ($Action -eq 'Revoke' -and $Code -eq 0) { $result = 'KEY_REVOKED' }
    $hints = @()
    if ($Code -ne 0) { $hints = @(Get-RepairHints $evidence) }
    $summary = [ordered]@{Result=$result;ExitCode=$Code;Action=$Action;Computer=$env:COMPUTERNAME;
        Start=$script:runStarted.ToString('o');End=(Get-Date -Format o);LastStep=$script:currentStep;FailedStep=$script:failedStep;
        Error=$script:failureMessage;Repairs=@($script:repairNotes.ToArray());
        Hints=$hints;RemoteLoginVerified=$false;LogDirectory=$script:reportDir}
    Save-ReportText 'summary.json' ($summary | ConvertTo-Json -Depth 6)
    Save-ReportText 'SUMMARY.txt' ("RESULT: $result`r`nSTEP: $script:currentStep`r`nERROR: $script:failureMessage`r`n`r`nREPAIRS:`r`n" + ($summary.Repairs -join "`r`n") + "`r`n`r`nHINTS (not a confirmed diagnosis):`r`n" + ($summary.Hints -join "`r`n") + "`r`n`r`nRemote public-key login and administrator token remain unverified.`r`nNo private-key files are included.`r`n")
    if ($script:transcribing) { Stop-Transcript | Out-Null; $script:transcribing=$false }
    $archive = $script:reportDir + '.zip'
    try {
        Compress-Archive -Path (Join-Path $script:reportDir '*') -DestinationPath $archive -Force
        Write-Host "DIAGNOSTIC REPORT ZIP: $archive" -ForegroundColor Cyan
    } catch { Write-Warning "Could not ZIP logs; copy the whole directory: $script:reportDir" }
    Write-Host "LOG DIRECTORY: $script:reportDir" -ForegroundColor Cyan
}
