#requires -Version 5.1
[CmdletBinding()]
param([string]$Path = '')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'KeyTools.ps1')
try {
    if (-not $Path) {
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        try {
            $dialog.Title = 'Select the CLIENT Ed25519 public key (.pub). Never select a private key.'
            $dialog.Filter = 'SSH public key (*.pub)|*.pub'
            if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { exit 2 }
            $Path = $dialog.FileName
        } finally { $dialog.Dispose() }
    }
    $public = Read-LoginPublicKey $Path
    $destination = Join-Path $PSScriptRoot 'windows-admin.pub'
    if (Test-Path -LiteralPath $destination) {
        if ((Read-LoginPublicKey $destination) -ceq $public) {
            Write-Host 'This public key is already imported.'
            exit 0
        }
        throw 'windows-admin.pub already contains another key. Remove or rename it explicitly before importing a replacement.'
    }
    [IO.File]::WriteAllText($destination, ($public + "`r`n"), (New-Object Text.UTF8Encoding($false)))
    Write-Host 'Public key imported. Next, run 01-Enable-SSH.cmd (or 04-Repair-SSH.cmd).'
} catch {
    Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
