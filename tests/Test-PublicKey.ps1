$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
. (Join-Path $root 'KeyTools.ps1')
$temp = Join-Path ([IO.Path]::GetTempPath()) ('ssh-key-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $file = Join-Path $temp 'fixture.pub'
    # Synthetic structural fixture; never shipped as an authorized public key.
    $blob = [byte[]](0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32) + (New-Object byte[] 32)
    $valid = 'ssh-ed25519 ' + [Convert]::ToBase64String($blob) + ' test-only'
    [IO.File]::WriteAllText($file, $valid + "`r`n")
    if ((Read-LoginPublicKey $file) -cne $valid) { throw 'Valid public key rejected.' }
    foreach ($bad in @('ssh-ed25519 AAAA', '-----BEGIN OPENSSH PRIVATE KEY-----', ($valid + "`n" + $valid), ($valid + "`ncommand=bad"))) {
        [IO.File]::WriteAllText($file, $bad)
        $rejected = $false
        try { Read-LoginPublicKey $file | Out-Null } catch { $rejected = $true }
        if (-not $rejected) { throw 'Unsafe or malformed public key accepted.' }
    }
    $rejected = $false
    try { Read-LoginPublicKey (Join-Path $temp 'missing.pub') | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Missing public key accepted.' }
    Write-Output 'PASS: public-key structure, private-key/multiline rejection and missing-key handling.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
