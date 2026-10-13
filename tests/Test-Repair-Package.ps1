$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Setup-SSH.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { $errors | Format-List; throw 'Installer parse failed' }
[void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Verify-Admin.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Verifier parse failed' }
foreach ($file in @(Get-ChildItem $root -Filter '*.ps1')) {
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { $errors | Format-List; throw "Parse failure: $file" }
}
Write-Output 'PASS: All package scripts parsed with PowerShell.'
$tag = 'WindowsSSH-20261012'
foreach ($name in @('Remove-ManagedBlock','New-ManagedConfig','Get-PayloadInfo','Read-PeMachine')) {
    $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    Invoke-Expression $function.Extent.Text
}
$cases = @(
    "Port 22`r`nSubsystem sftp sftp-server.exe`r`nMatch Group administrators`r`n    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys`r`n",
    "# header`nPort 22`nSubsystem sftp sftp-server.exe`n",
    "Port 22`n`nMatch User existing`n    PasswordAuthentication no`nMatch Group administrators`n    AuthorizedKeysFile admin_keys`n"
)
foreach ($fixture in $cases) {
    $once = New-ManagedConfig $fixture 'testadmin'
    $twice = New-ManagedConfig $once 'testadmin'
    if ($once -cne $twice) { throw 'Repeated install is not idempotent.' }
    if ([regex]::Matches($once, '# BEGIN WindowsSSH-20261012').Count -ne 1) { throw 'Duplicate managed block.' }
    if ($once.IndexOf('Port 22') -gt $once.IndexOf('Match User "testadmin"')) { throw 'Global directive moved into Match.' }
    if ($once.Contains('Match Group administrators') -and $once.IndexOf('Match User "testadmin"') -gt $once.IndexOf('Match Group administrators')) { throw 'Admin match has precedence over dedicated key.' }
    if ((Remove-ManagedBlock $once).TrimEnd() -cne $fixture.TrimEnd()) { throw 'Revoke changed pre-existing configuration.' }
    $retargeted = New-ManagedConfig $once 'seconduser'
    if ($retargeted.Contains('Match User "testadmin"') -or -not $retargeted.Contains('Match User "seconduser"')) { throw 'Old managed target remained.' }
}
Write-Output 'PASS: 3 fixtures: idempotence, directive scope, match precedence, revoke preservation and replacement.'
if ([IO.File]::ReadAllText((Join-Path $root 'Setup-SSH.ps1')).Contains('LocalAccountTokenFilterPolicy')) { throw 'Unexpected UAC policy modification.' }
Write-Output 'PASS: No UAC policy modification.'
Write-Output 'NOT TESTED: Windows offline installation, UAC, ACL application, service/firewall, actual SSH login, ARM64 runtime.'

foreach ($architecture in @('AMD64','ARM64')) {
    $info = Get-PayloadInfo $architecture
    $archive = Join-Path $root ('payloads/' + $info.Folder + '.zip')
    if ((Get-FileHash $archive -Algorithm SHA256).Hash -ine $info.Hash) { throw 'Official archive hash mismatch.' }
    $tempDir = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    try {
        Expand-Archive -LiteralPath $archive -DestinationPath $tempDir
        $binaries = @(Get-ChildItem (Join-Path $tempDir $info.Folder) -File | Where-Object { $_.Extension -in @('.exe','.dll') })
        foreach ($binary in $binaries) {
            if ((Read-PeMachine $binary.FullName) -ne $info.Machine) { throw "Wrong architecture: $binary" }
        }
        Write-Output "PASS: $architecture official hash and PE architecture for $($binaries.Count) binaries."
    } finally { Remove-Item -LiteralPath $tempDir -Recurse -Force }
}
$rejected = $false
try { Get-PayloadInfo 'x86' } catch { $rejected = $true }
if (-not $rejected) { throw 'Unsupported architecture was accepted.' }
$source = [IO.File]::ReadAllText((Join-Path $root 'Setup-SSH.ps1'))
if ($source -match '(?i)(Add-WindowsCapability|Invoke-WebRequest|Start-BitsTransfer|DownloadFile\()') { throw 'Offline package contains an online install path.' }
Write-Output 'PASS: Unsupported architecture rejected; no online download or DISM installation path.'
