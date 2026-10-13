# Run this INSIDE the SSH session to verify the actual remote token.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
[pscustomobject]@{
    Computer = $env:COMPUTERNAME
    User = $identity.Name
    SID = $identity.User.Value
    AdministratorToken = $isAdmin
    OSArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')
    SSHConnection = $env:SSH_CONNECTION
} | Format-List
if (-not $env:SSH_CONNECTION) { Write-Warning 'Run inside SSH to verify remote rights; local execution is not remote proof.' }
if (-not $isAdmin) { Write-Error 'This session does not have an active administrator token.'; exit 1 }
Get-Service sshd | Format-Table Name, Status, StartType
Write-Host 'Administrator token confirmed. This is not SYSTEM or TrustedInstaller.'
