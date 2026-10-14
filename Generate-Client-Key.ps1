#requires -Version 5.1
[CmdletBinding()]
param([switch]$NoPassphrase)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'KeyTools.ps1')
$work = $null
$private = $null
try {
    $publicDestination = Join-Path $PSScriptRoot 'windows-admin.pub'
    $guide = Join-Path $PSScriptRoot 'CLIENT-CONNECTION.txt'
    if ((Test-Path -LiteralPath $publicDestination) -or (Test-Path -LiteralPath $guide)) {
        throw 'This kit is already paired or contains connection instructions. Use a fresh extracted kit to generate a different pair. Existing keys were not changed.'
    }
    # Probe before creating a private key, so a read-only USB fails early.
    $probe = Join-Path $PSScriptRoot ('.write-test-' + [guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText($probe, 'test')
    Remove-Item -LiteralPath $probe
    $clientHome = [Environment]::GetFolderPath('UserProfile')
    $pairName = 'windows-ssh-kit-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $keyDirectory = Join-Path (Join-Path $clientHome '.ssh') $pairName
    New-Item -ItemType Directory -Path $keyDirectory -ErrorAction Stop | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($owner, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    Set-Acl -LiteralPath $keyDirectory -AclObject $acl
    $private = Join-Path $keyDirectory 'id_ed25519'
    $keygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
    if (-not (Test-Path -LiteralPath $keygen)) {
        # Windows client optional feature is absent: use the verified native payload.
        $arch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE','Machine')
        $payloadName = switch ($arch) {
            'AMD64' { 'OpenSSH-Win64' }
            'ARM64' { 'OpenSSH-ARM64' }
            default { throw "Unsupported Windows client architecture: $arch" }
        }
        $manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'SOURCE.json') | ConvertFrom-Json
        $payload = @($manifest.payloads | Where-Object { $_.file -eq "$payloadName.zip" })
        if ($payload.Count -ne 1) { throw 'Missing payload manifest entry.' }
        $zip = Join-Path $PSScriptRoot ('payloads\' + $payload[0].file)
        if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ine $payload[0].sha256) { throw 'Client payload hash mismatch.' }
        $work = Join-Path $keyDirectory 'keygen-tools'
        Expand-Archive -LiteralPath $zip -DestinationPath $work
        $keygen = Join-Path (Join-Path $work $payloadName) 'ssh-keygen.exe'
    }
    Write-Host 'Run this on the computer you will connect FROM. Its private key stays in this user profile.'
    Write-Host "Private key destination: $private"
    Write-Host 'Choose a passphrase when prompted, or press Enter twice for no passphrase.'
    # ProcessStartInfo preserves -N "" on Windows PowerShell 5.1.
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $keygen
    $psi.UseShellExecute = $false
    $psi.Arguments = '-t ed25519 -f "' + $private + '" -C "' + $pairName + '"'
    if ($NoPassphrase) { $psi.Arguments += ' -N ""' }
    $process = [Diagnostics.Process]::Start($psi)
    try { $process.WaitForExit(); if ($process.ExitCode -ne 0) { throw 'ssh-keygen failed; no public key was paired.' } }
    finally { $process.Dispose() }
    $public = Read-LoginPublicKey ($private + '.pub')
    # CreateNew refuses to overwrite a concurrently imported key.
    $stream = [IO.File]::Open($publicDestination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($public + "`r`n"); $stream.Write($bytes,0,$bytes.Length) }
    finally { $stream.Dispose() }
    $instructions = "CLIENT PRIVATE KEY (path only; key stays on this computer):`r`n$private`r`n`r`n1. Take this kit to the TARGET Windows computer.`r`n2. Run 01-Enable-SSH.cmd there and note SSH login name, IP and host fingerprint.`r`n3. Return to THIS client and run:`r`nssh -i `"$private`" -l WINDOWS_USERNAME WINDOWS_IP`r`n"
    [IO.File]::WriteAllText($guide, $instructions, (New-Object Text.UTF8Encoding($true)))
    Write-Host 'PAIRED: windows-admin.pub and CLIENT-CONNECTION.txt are ready in the kit.' -ForegroundColor Green
    Write-Host 'Take the kit to the target Windows computer and run 01-Enable-SSH.cmd.'
} catch {
    Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
    if ($private -and (Test-Path -LiteralPath $private)) { Write-Host "Keep your generated private key here: $private" }
    exit 1
} finally {
    if ($work -and (Test-Path -LiteralPath $work)) { Remove-Item -LiteralPath $work -Recurse -Force }
}
