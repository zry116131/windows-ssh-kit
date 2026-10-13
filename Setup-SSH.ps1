#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Install','Repair','Check','Revoke')][string]$Action = 'Install',
    [string]$LogDirectory = '',
    [switch]$NoPause
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$tag = 'WindowsSSH-20261012'
$ruleName = "$tag-LAN"
$sshRoot = Join-Path $env:ProgramData 'ssh'
$configPath = Join-Path $sshRoot 'sshd_config'
$keyPath = Join-Path $sshRoot "$tag.authorized_keys"
$statePath = Join-Path $sshRoot "$tag.state.json"
$binRoot = Join-Path $env:SystemRoot 'System32\OpenSSH'
$sshd = Join-Path $binRoot 'sshd.exe'
$keygen = Join-Path $binRoot 'ssh-keygen.exe'
$nativePS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$transcribing = $false
$exitCode = 0
$rollbackConfig = $null
$rollbackKey = $null
$keyExisted = $false
$changedConfig = $false
$serviceWasRunning = $false
$oldStartMode = $null
$ruleCreated = $false
$rollbackState = $null
$stateExisted = $false
$newServiceCreated = $false
$rulePrior = $null
$delegated = $false
. (Join-Path $PSScriptRoot 'Diagnostics.ps1')
. (Join-Path $PSScriptRoot 'KeyTools.ps1')

function Get-PayloadInfo([string]$Architecture) {
    switch ($Architecture) {
        'AMD64' { return @{ Folder='OpenSSH-Win64'; Machine=0x8664; Hash='23f50f3458c4c5d0b12217c6a5ddfde0137210a30fa870e98b29827f7b43aba5' } }
        'ARM64' { return @{ Folder='OpenSSH-ARM64'; Machine=0xAA64; Hash='698c6aec31c1dd0fb996206e8741f4531a97355686b5431ef347d531b07fcd42' } }
        default { throw "Unsupported OS architecture: $Architecture" }
    }
}
function Read-PeMachine([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Invalid MZ executable.' }
        $stream.Position = 0x3C
        $offset = $reader.ReadInt32()
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550) { throw 'Invalid PE executable.' }
        return $reader.ReadUInt16()
    } finally { $reader.Dispose(); $stream.Dispose() }
}
function Protect-InstallDirectory([string]$Path) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($admins, $system)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Install-OfflineServer([hashtable]$Payload, [string]$InstallRoot) {
    Ensure-OfflineFiles $Payload $InstallRoot
    $destination = Join-Path $InstallRoot $Payload.Folder
    # Server-only registration mirrors the required service privileges in the official installer.
    # Avoid replacing an existing Windows ssh-agent service or altering machine PATH.
    $serverPath = Join-Path $destination 'sshd.exe'
    New-Service -Name sshd -DisplayName 'OpenSSH SSH Server' -BinaryPathName ('"' + $serverPath + '"') `
        -Description 'OpenSSH server installed from the verified Windows SSH offline package.' -StartupType Manual | Out-Null
    $script:newServiceCreated = $true
    $r = Invoke-CapturedNative "$env:SystemRoot\System32\sc.exe" @('privs','sshd','SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege') 'new-service-privileges'
    Assert-NativeSuccess $r 'Set standard OpenSSH service privileges'
    # Same RedirectionGuard setting as the official install-sshd.ps1, preserving existing policies.
    $mitigation = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sshd.exe'
    New-Item -Path $mitigation -Force | Out-Null
    if (-not (Get-ItemProperty -Path $mitigation -Name MitigationOptions -ErrorAction SilentlyContinue)) {
        $bytes = New-Object byte[] 19
        $bytes[18] = 0x10
        New-ItemProperty -Path $mitigation -Name MitigationOptions -PropertyType Binary -Value $bytes | Out-Null
    }
}

function Write-Utf8([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}
function Protect-File([string]$Path) {
    # SID based ACLs also work on Chinese and other non-English Windows.
    $acl = New-Object Security.AccessControl.FileSecurity
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($admins, $system)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Remove-ManagedBlock([string]$Text) {
    $pattern = '(?ms)^# BEGIN ' + [regex]::Escape($tag) + '\r?\n.*?^# END ' + [regex]::Escape($tag) + '\r?\n?'
    return [regex]::Replace($Text, $pattern, '')
}
function New-ManagedConfig([string]$Text, [string]$UserName) {
    $clean = Remove-ManagedBlock $Text
    # Insert before the first Match, after all global-only directives.
    $match = [regex]::Match($clean, '(?im)^\s*Match\s+')
    $at = $clean.Length
    if ($match.Success) { $at = $match.Index }
    $block = "# BEGIN $tag`r`nMatch User `"$UserName`"`r`n    PubkeyAuthentication yes`r`n    AuthorizedKeysFile __PROGRAMDATA__/ssh/$tag.authorized_keys __PROGRAMDATA__/ssh/administrators_authorized_keys .ssh/authorized_keys`r`n# END $tag`r`n"
    $prefix = $clean.Substring(0, $at)
    if ($prefix.Length -gt 0 -and -not $prefix.EndsWith("`n")) { $prefix += "`r`n" }
    return $prefix + $block + $clean.Substring($at)
}
function Test-Config {
    $r = Invoke-CapturedNative $sshd @('-t','-f',$configPath) 'validate-config' 15
    Assert-NativeSuccess $r 'sshd configuration validation'
}
function Show-Status {
    Get-Service sshd | Format-Table Name, Status, StartType -AutoSize | Out-Host
    $sshdPid = (Get-CimInstance Win32_Service -Filter "Name='sshd'").ProcessId
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -eq $sshdPid })
    $listeners | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize | Out-Host
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
        Select-Object InterfaceAlias, IPAddress | Format-Table -AutoSize | Out-Host
    if (Test-Path $statePath) {
        $saved = Get-Content -Raw -Encoding UTF8 -LiteralPath $statePath | ConvertFrom-Json
        Write-Host "SSH login name: $($saved.UserName)"
        Write-Host "From your client: ssh -i PATH_TO_YOUR_PRIVATE_KEY -l '$($saved.UserName)' WINDOWS_IP"
    }
    $hostPublic = Join-Path $sshRoot 'ssh_host_ed25519_key.pub'
    if (Test-Path $hostPublic) { & $keygen -lf $hostPublic }
    if ((Get-Service sshd).Status -ne 'Running' -or $listeners.Count -eq 0) {
        throw 'SSH is not running/listening on TCP 22.'
    }
    Write-Host 'Local service check passed. Remote key login and admin token still require verification.' -ForegroundColor Yellow
}

try {
    Initialize-Reports $LogDirectory
    Set-RepairStep 'Initialize and request administrator rights'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Action ' + $Action
        $arguments += ' -LogDirectory "' + $script:reportDir + '"'
        if ($NoPause) { $arguments += ' -NoPause' }
        Stop-Transcript | Out-Null
        $transcribing = $false
        $child = Start-Process -FilePath $nativePS -Verb RunAs -ArgumentList $arguments -Wait -PassThru
        $delegated = $true
        exit $child.ExitCode
    }
    $arch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')
    Write-Host "OS architecture: $arch | Elevated account: $($identity.Name)"
    Set-RepairStep 'Collect original machine and SSH service state'
    if ($arch -notin @('AMD64','ARM64')) { throw 'This package supports x64 and ARM64 Windows only.' }
    $payload = Get-PayloadInfo $arch
    $registry64 = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $currentVersion = $registry64.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion')
        try { $programFilesNative = $currentVersion.GetValue('ProgramFilesDir') } finally { $currentVersion.Dispose() }
    } finally { $registry64.Dispose() }
    $installRoot = Join-Path $programFilesNative $tag
    $offlineBin = Join-Path $installRoot $payload.Folder
    $existingService = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    if ($existingService) {
        $serviceExe = [Environment]::ExpandEnvironmentVariables($existingService.PathName.Trim().Trim('"'))
        if ($serviceExe -ieq (Join-Path $offlineBin 'sshd.exe')) { $binRoot = $offlineBin }
        elseif ($serviceExe -ine $sshd) { throw "Custom SSH service detected: $($existingService.PathName). It requires a manual review." }
    } elseif ($Action -in @('Install','Repair')) { $binRoot = $offlineBin }
    elseif (Test-Path (Join-Path $offlineBin 'sshd.exe')) { $binRoot = $offlineBin }
    $sshd = Join-Path $binRoot 'sshd.exe'
    $keygen = Join-Path $binRoot 'ssh-keygen.exe'
    Collect-Diagnostics 'before'
    if ([Environment]::OSVersion.Version.Build -lt 17763) { throw 'Windows 10 1809 / Server 2019 or newer is required.' }
    if ($Action -in @('Install','Repair')) {
        Set-RepairStep 'Check account, installation path and port ownership'
        # Use the elevated LOCAL administrator account; never create hidden users or change UAC.
        $sidValue = $identity.User.Value
        $account = Get-CimInstance Win32_UserAccount -Filter "SID='$sidValue' AND LocalAccount=True"
        if (-not $account -or $account.Disabled) {
            throw 'Run with an enabled LOCAL administrator account. Entra/domain-only identities are not configured by this package.'
        }
        $loginName = $account.Name.ToLowerInvariant()
        if ($loginName -match '["\r\n*?!,]') { throw 'Account name cannot be safely represented as an exact SSH Match pattern.' }
        if (Test-Path $statePath) {
            $saved = Get-Content -Raw -Encoding UTF8 -LiteralPath $statePath | ConvertFrom-Json
            if ($saved.SID -ne $sidValue) { throw 'This package already targets a different account. Revoke that key first.' }
        }
        $publicKey = Read-LoginPublicKey (Join-Path $PSScriptRoot 'windows-admin.pub')
        $existingService = Get-CimInstance Win32_Service -Filter "Name='sshd'"
        if ($existingService -and ([Environment]::ExpandEnvironmentVariables($existingService.PathName.Trim().Trim('"')) -ine $sshd)) {
            throw "Existing custom SSH service detected: $($existingService.PathName). Refusing to overwrite a custom installation."
        }
        Assert-PortAvailable
        if ($existingService) {
            $serviceWasRunning = $existingService.State -eq 'Running'
            $oldStartMode = $existingService.StartMode
        }
        if (-not $existingService) {
            Write-Host "Installing bundled $($payload.Folder), version 10.0.0.0p2-Preview. No Windows Update download."
            Install-OfflineServer $payload $installRoot
        } else {
            Write-Host "Reusing existing OpenSSH: $sshd"
            if ($binRoot -eq $offlineBin) { Ensure-OfflineFiles $payload $installRoot }
        }
        if (-not (Test-Path $sshd) -or -not (Test-Path $keygen)) { throw 'OpenSSH server tools are missing; inspect the existing installation or re-extract the offline package.' }
        if ($binRoot -eq $offlineBin -and (Read-PeMachine $sshd) -ne $payload.Machine) { throw 'Installed server architecture does not match this Windows OS.' }
        $r = Invoke-CapturedNative $keygen @('-lf',(Join-Path $PSScriptRoot 'windows-admin.pub')) 'validate-public-key'
        Assert-NativeSuccess $r 'Validate login public key'
        Write-Host $r.Stdout
        New-Item -ItemType Directory -Path $sshRoot -Force | Out-Null
        if (-not (Test-Path $configPath)) {
            Copy-Item -LiteralPath (Join-Path $binRoot 'sshd_config_default') -Destination $configPath
            if ($binRoot -eq $offlineBin) {
                # File logs avoid changing an existing client's shared ETW provider.
                Write-Utf8 $configPath ("SyslogFacility LOCAL0`r`n" + [IO.File]::ReadAllText($configPath))
            }
            Protect-File $configPath
        }
        Repair-SSHPermissions
        Set-RepairStep 'Preserve SSH policies and install the dedicated public key'
        $oldText = [IO.File]::ReadAllText($configPath)
        if ($oldText -match '(?im)^\s*Include\s+') { throw 'Existing Include directives require a manual configuration review.' }
        $ports = @([regex]::Matches($oldText, '(?im)^\s*Port\s+(\d+)') | ForEach-Object { $_.Groups[1].Value })
        if ($ports.Count -gt 0 -and @($ports | Where-Object { $_ -ne '22' }).Count -gt 0) {
            throw 'Existing SSH uses a non-default port. This package will not change it.'
        }
        $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='sshd'"
        if (-not $existingService) { $oldStartMode = $serviceInfo.StartMode }
        $rollbackConfig = [IO.File]::ReadAllBytes($configPath)
        $keyExisted = Test-Path $keyPath
        if ($keyExisted) { $rollbackKey = [IO.File]::ReadAllBytes($keyPath) }
        $stateExisted = Test-Path $statePath
        if ($stateExisted) { $rollbackState = [IO.File]::ReadAllBytes($statePath) }
        $backup = "$configPath.$tag.$(Get-Date -Format 'yyyyMMdd-HHmmss-fff').bak"
        Copy-Item -LiteralPath $configPath -Destination $backup
        Protect-File $backup
        $changedConfig = $true
        Write-Utf8 $keyPath ($publicKey + "`r`n")
        Protect-File $keyPath
        Write-Utf8 $configPath (New-ManagedConfig $oldText $loginName)
        $r = Invoke-CapturedNative $keygen @('-A') 'generate-missing-host-keys' 30
        Assert-NativeSuccess $r 'Generate missing host keys'
        Repair-SSHPermissions
        Set-RepairStep 'Validate syntax, host keys and effective user configuration'
        Test-Config
        $r = Invoke-CapturedNative $sshd @('-T','-f',$configPath,'-C',"user=$loginName,host=localhost,addr=127.0.0.1") 'effective-user-config' 15
        Assert-NativeSuccess $r 'Read effective user configuration'
        $effective = @($r.Stdout -split '\r?\n')
        if (-not ($effective -match '^pubkeyauthentication yes$') -or
            -not ($effective -match ('^authorizedkeysfile .*' + [regex]::Escape("$tag.authorized_keys")))) {
            throw 'Effective SSH configuration did not enable this public key for the target account.'
        }
        $auth = @($effective | Where-Object { $_ -match '^authenticationmethods ' })
        if ($auth.Count -gt 0 -and $auth[0] -notin @('authenticationmethods any','authenticationmethods publickey')) {
            throw 'Existing authentication policy requires additional factors; it has been preserved.'
        }
        if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name $ruleName -DisplayName 'Windows SSH (local subnet)' -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort 22 -RemoteAddress LocalSubnet -Profile Any -Program $sshd | Out-Null
            $ruleCreated = $true
        } else {
            $currentRule = Get-NetFirewallRule -Name $ruleName
            $rulePrior = @{ Enabled=$currentRule.Enabled; Program=($currentRule | Get-NetFirewallApplicationFilter).Program }
            Set-NetFirewallRule -Name $ruleName -Program $sshd -Enabled True
        }
        Repair-ServiceRegistration
        try { Start-SSHVerified }
        catch {
            Save-ReportText 'first-start-error.txt' ($_ | Format-List * -Force | Out-String -Width 240)
            Collect-Diagnostics 'start-failed'
            Add-RepairNote 'First start failed; retrying once after refreshing permissions and service privileges.'
            Repair-SSHPermissions
            Repair-ServiceRegistration
            Test-Config
            Start-SSHVerified
        }
        $state = [ordered]@{ UserName=$loginName; SID=$sidValue; Architecture=$arch; Binary=$sshd; KeyFile=$keyPath; Backup=$backup; Updated=(Get-Date -Format o) }
        Write-Utf8 $statePath ($state | ConvertTo-Json)
        Protect-File $statePath
        Show-Status
        $changedConfig = $false
        Write-Host 'Setup completed. Administrator rights follow the selected account. UAC and account policies were not disabled.' -ForegroundColor Green
    }
    elseif ($Action -eq 'Check') {
        if (-not (Test-Path $sshd)) { throw 'OpenSSH Server has not been installed by this package or Windows.' }
        Test-Config
        Show-Status
        if (Test-Path $keyPath) { Get-Acl $keyPath | Format-List Owner, AccessToString | Out-Host }
        Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Format-Table Name, Enabled, Profile | Out-Host
    }
    else {
        # Delete only this dedicated key first: even a later service error cannot leave it authorized.
        if (Test-Path $keyPath) { Remove-Item -LiteralPath $keyPath -Force }
        if (Test-Path $configPath) {
            $previous = [IO.File]::ReadAllBytes($configPath)
            Write-Utf8 $configPath (Remove-ManagedBlock ([IO.File]::ReadAllText($configPath)))
            try { Test-Config } catch { [IO.File]::WriteAllBytes($configPath, $previous); throw }
            $revokeService = Get-Service sshd -ErrorAction SilentlyContinue
            if ($revokeService -and $revokeService.Status -eq 'Running') { Restart-Service sshd }
        }
        Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        if (Test-Path $statePath) { Remove-Item -LiteralPath $statePath -Force }
        Write-Host 'Dedicated key revoked. Existing SSH service, other keys and active sessions are retained.' -ForegroundColor Green
    }
}
catch {
    $exitCode = 1
    $script:failureMessage = $_.Exception.Message
    $script:failedStep = $script:currentStep
    Save-ReportText 'error.txt' ($_ | Format-List * -Force | Out-String -Width 240)
    try { Collect-Diagnostics 'failure-before-rollback' } catch { Write-Warning $_.Exception.Message }
    Write-Host ("ERROR: " + $script:failureMessage) -ForegroundColor Red
    if ($changedConfig -and $null -ne $rollbackConfig) {
        try {
            [IO.File]::WriteAllBytes($configPath, $rollbackConfig)
            if ($keyExisted) { [IO.File]::WriteAllBytes($keyPath, $rollbackKey) }
            elseif (Test-Path $keyPath) { Remove-Item -LiteralPath $keyPath -Force }
            if ($stateExisted) { [IO.File]::WriteAllBytes($statePath, $rollbackState) }
            elseif (Test-Path $statePath) { Remove-Item -LiteralPath $statePath -Force }
            if ($ruleCreated) { Remove-NetFirewallRule -Name $ruleName }
            elseif ($null -ne $rulePrior) { Set-NetFirewallRule -Name $ruleName -Program $rulePrior.Program -Enabled $rulePrior.Enabled }
            if ($oldStartMode -eq 'Auto') { Set-Service sshd -StartupType Automatic }
            elseif ($oldStartMode -eq 'Disabled') { Set-Service sshd -StartupType Disabled }
            elseif ($oldStartMode -eq 'Manual') { Set-Service sshd -StartupType Manual }
            if ($serviceWasRunning) { Start-SSHVerified } else { Stop-SSHBounded }
            Write-Host 'Previous SSH configuration restored; installed binaries and generated host keys are retained.'
        } catch { Write-Host ("Rollback needs attention: " + $_.Exception.Message) -ForegroundColor Red }
    }
    if ($newServiceCreated) {
        try {
            Stop-Service sshd -ErrorAction SilentlyContinue
            Set-Service sshd -StartupType Disabled
            Write-Host 'New SSH service disabled after failure. Inspect the log and retry after fixing the reported error.'
        } catch { Write-Host 'Unable to disable the newly created service; inspect it manually.' -ForegroundColor Red }
    }
    Write-Host 'See the log path above and README. This offline edition does not download Windows optional features.'
}
finally {
    if (-not $delegated -and $script:reportDir) {
        try { Finish-Reports $exitCode } catch { Write-Warning ("Log export needs attention: " + $_.Exception.Message) }
    }
    if ($transcribing) { Stop-Transcript | Out-Null }
}
Write-Host ''
if (-not $NoPause) { [void](Read-Host 'Press Enter to close') }
exit $exitCode
