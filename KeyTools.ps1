#requires -Version 5.1
# Read a single Ed25519 public key without printing rejected input.
function Read-LoginPublicKey([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Missing windows-admin.pub. On the CLIENT computer, run 00-Generate-Client-Key.cmd (Windows) or .command (Mac) first; then take the paired kit to this target. Existing keys: use 05-Import-Public-Key.cmd. Never copy the private key.'
    }
    if ((Get-Item -LiteralPath $Path).Length -gt 16KB) { throw 'Public-key file is too large.' }
    $text = [IO.File]::ReadAllText($Path).Trim()
    if ($text -notmatch '^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})( [^\r\n\x00-\x1f]+)?$') {
        throw 'Expected one ssh-ed25519 public-key line. Private keys, multiple keys and other formats are not accepted.'
    }
    try { $blob = [Convert]::FromBase64String($Matches[1]) }
    catch { throw 'Invalid public-key Base64.' }
    # SSH wire encoding: uint32 length, "ssh-ed25519", uint32 length, 32 bytes.
    $prefix = [byte[]](0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32)
    if ($blob.Length -ne 51) { throw 'Invalid Ed25519 public-key length.' }
    for ($i = 0; $i -lt $prefix.Length; $i++) {
        if ($blob[$i] -ne $prefix[$i]) { throw 'Invalid Ed25519 public-key structure.' }
    }
    return $text
}
