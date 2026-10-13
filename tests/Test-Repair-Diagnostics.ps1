$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$temp = Join-Path ([IO.Path]::GetTempPath()) ('ssh-repair-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
. (Join-Path $root 'Diagnostics.ps1')
$Action = 'Repair'
$env:COMPUTERNAME = 'TEST-HOST'
$env:SystemRoot = '/nonexistent-test-windows'
$tag = 'WindowsSSH-20261012'; $ruleName = "$tag-LAN"
$sshRoot = Join-Path $temp 'ssh'; $binRoot = Join-Path $temp 'engine'
$configPath = Join-Path $sshRoot 'sshd_config'; $keyPath = Join-Path $sshRoot 'dedicated.authorized_keys'
$statePath = Join-Path $sshRoot 'state.json'; $sshd = Join-Path $binRoot 'sshd.exe'
$tokens=$null; $errors=$null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Setup-SSH.ps1'),[ref]$tokens,[ref]$errors)
foreach ($name in @('Get-PayloadInfo','Read-PeMachine')) {
    $function = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    Invoke-Expression $function.Extent.Text
}
try {
    Initialize-Reports (Join-Path $temp 'USB Logs Chinese space')
    Set-RepairStep 'test native command capture'
    $pwsh = Join-Path $PSHOME 'pwsh'
    $r = Invoke-CapturedNative $pwsh @('-NoProfile','-Command',"Write-Output 'stdout value'; [Console]::Error.WriteLine('stderr value'); exit 7") 'nonzero' 10
    if ($r.ExitCode -ne 7 -or $r.Stdout -notmatch 'stdout value' -or $r.Stderr -notmatch 'stderr value') { throw 'Native stdout/stderr/exit code not preserved.' }
    $r = Invoke-CapturedNative $pwsh @('-NoProfile','-Command','Start-Sleep -Seconds 8') 'timeout' 1
    if (-not $r.TimedOut) { throw 'Native command timeout was not enforced.' }
    Write-Output 'PASS: native stdout/stderr/nonzero exit and timeout captured.'

    New-Item -ItemType Directory -Path $sshRoot | Out-Null
    [IO.File]::WriteAllText($configPath,"Port 22`n")
    [IO.File]::WriteAllText((Join-Path $sshRoot 'ssh_host_ed25519_key'),'PRIVATE_HOST_KEY_MUST_NEVER_BE_EXPORTED')
    Collect-Diagnostics 'fixture'
    $script:failureMessage = 'Error 1067: service exited; bad ownership or permissions'
    Add-RepairNote 'simulated repair action'
    Finish-Reports 1
    $summary = Get-Content -Raw (Join-Path $script:reportDir 'summary.json') | ConvertFrom-Json
    if ($summary.Result -ne 'FAILED_NEEDS_REVIEW' -or $summary.RemoteLoginVerified) { throw 'False success in summary.' }
    if (-not (Test-Path ($script:reportDir + '.zip'))) { throw 'No portable diagnostic ZIP.' }
    foreach ($file in Get-ChildItem $script:reportDir -File) {
        if ([IO.File]::ReadAllText($file.FullName).Contains('PRIVATE_HOST_KEY_MUST_NEVER_BE_EXPORTED')) { throw 'Private host key content leaked.' }
    }
    $zipEntries = [IO.Compression.ZipFile]::OpenRead($script:reportDir + '.zip')
    try {
        foreach ($entry in $zipEntries.Entries) {
            if ($entry.Name -eq 'ssh_host_ed25519_key') { throw 'Private key file in report archive.' }
        }
    } finally { $zipEntries.Dispose() }
    if (-not ((Get-RepairHints 'libcrypto 0xc0000139') -match 'mismatch')) { throw 'Missing dependency hint.' }
    if (-not ((Get-RepairHints 'TCP 22 is occupied by another process') -match 'conflict')) { throw 'Missing port-conflict hint.' }
    Write-Output 'PASS: USB-style report folder, failure summary, ZIP export, diagnostic hints and private-key exclusion.'

    $env:TEMP = $temp
    $blockedPath = Join-Path $temp 'not-a-writable-directory'
    [IO.File]::WriteAllText($blockedPath,'fixture file blocks directory creation')
    Initialize-Reports $blockedPath
    if (-not $script:reportDir.StartsWith((Join-Path $temp 'Windows-SSH-Logs'))) { throw 'Unwritable USB path did not fall back to local TEMP.' }
    Stop-Transcript | Out-Null
    $script:transcribing = $false
    Write-Output 'PASS: unavailable USB directory falls back to a reported local TEMP directory.'

    # Mock only Windows mutation APIs. Actual archive, hashes, file repair, and PE parsing run.
    function Protect-InstallDirectory([string]$Path) { }
    function Stop-SSHBounded { }
    function Invoke-CapturedNative {
        param($File,$Arguments,$Label,$TimeoutSeconds)
        if ($File -notlike '*icacls.exe') { throw "Unexpected mutation command: $File" }
        return [pscustomobject]@{ExitCode=0;TimedOut=$false;Stdout='';Stderr=''}
    }
    $install = Join-Path $temp 'Program Files'
    $payload = Get-PayloadInfo 'ARM64'
    Ensure-OfflineFiles $payload $install
    $engine = Join-Path $install $payload.Folder
    $dll = Join-Path $engine 'libcrypto.dll'
    $expectedHash = (Get-FileHash $dll).Hash
    [IO.File]::WriteAllText($dll,'BROKEN-DLL-FIXTURE')
    Remove-Item (Join-Path $engine 'sshd-session.exe')
    Ensure-OfflineFiles $payload $install
    if ((Get-FileHash $dll).Hash -ne $expectedHash -or -not (Test-Path (Join-Path $engine 'sshd-session.exe'))) { throw 'Partial installation repair failed.' }
    $backup = Join-Path (Join-Path (Join-Path $install 'repair-backups') $script:runId) 'libcrypto.dll'
    if ([IO.File]::ReadAllText($backup) -ne 'BROKEN-DLL-FIXTURE') { throw 'Original damaged file was not backed up.' }
    $notesBefore = $script:repairNotes.Count
    Ensure-OfflineFiles $payload $install
    if ($script:repairNotes.Count -ne ($notesBefore + 1)) { throw 'Clean repeated run unexpectedly replaced files.' }
    Write-Output 'PASS: verified ARM64 payload installation, damaged DLL repair, missing helper repair, backup and idempotence (ACL/service APIs mocked).'

    function Get-CimInstance { [pscustomobject]@{ProcessId=123;StartName='LocalSystem'} }
    function Get-NetTCPConnection { [pscustomobject]@{OwningProcess=999;LocalPort=22} }
    $rejected=$false
    try { Assert-PortAvailable } catch { $rejected=$true }
    if (-not $rejected) { throw 'Foreign port owner was not rejected.' }
    Write-Output 'PASS: conflicting TCP 22 owner stops automatic startup without killing processes.'
    Write-Output 'NOT TESTED: real Windows UAC, SCM, ACLs, firewall, real sshd startup and remote login.'
} finally {
    if ($script:transcribing) { Stop-Transcript | Out-Null }
    Remove-Item -LiteralPath $temp -Recurse -Force
}
