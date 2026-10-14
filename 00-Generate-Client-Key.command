#!/bin/bash
# Run on the macOS/Linux CLIENT. The target remains Windows x64/ARM64.
set -euo pipefail
umask 077
kit_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
key_path=''
probe=''
finish() {
    result=$?
    [ -z "$probe" ] || rm -f -- "$probe"
    if [ "$result" -ne 0 ] && [ -n "$key_path" ] && [ -f "$key_path" ]; then
        printf '\nKeep your generated private key here: %s\n' "$key_path"
    fi
    if [ -t 0 ]; then read -r -p 'Press Enter to close.' unused || true; fi
    exit "$result"
}
trap finish EXIT
if [ -e "$kit_dir/windows-admin.pub" ] || [ -e "$kit_dir/CLIENT-CONNECTION.txt" ]; then
    echo 'This kit is already paired. Use a fresh extracted kit for a different pair. Existing keys were not changed.' >&2
    exit 1
fi
command -v ssh-keygen >/dev/null
probe="$(mktemp "$kit_dir/.write-test-XXXXXX")"
rm -f -- "$probe"
probe=''
mkdir -p -- "$HOME/.ssh"
key_dir="$(mktemp -d "$HOME/.ssh/windows-ssh-kit-XXXXXXXX")"
key_path="$key_dir/id_ed25519"
printf 'Run this on the computer you will connect FROM.\nPrivate key stays here: %s\n' "$key_path"
echo 'Choose a passphrase when prompted, or press Enter twice for no passphrase.'
if [ "${1:-}" = '--no-passphrase' ]; then
    ssh-keygen -t ed25519 -f "$key_path" -C "$(basename "$key_dir")" -N ''
elif [ "$#" -eq 0 ]; then
    ssh-keygen -t ed25519 -f "$key_path" -C "$(basename "$key_dir")"
else
    echo 'Usage: bash 00-Generate-Client-Key.command [--no-passphrase]' >&2
    exit 1
fi
chmod 600 "$key_path"
ssh-keygen -lf "$key_path.pub"
# noclobber refuses to overwrite a concurrently imported public key.
(set -o noclobber; cat "$key_path.pub" > "$kit_dir/windows-admin.pub")
{
    printf 'CLIENT PRIVATE KEY (path only; key stays on this computer):\n%s\n\n' "$key_path"
    printf '1. Take this kit to the TARGET Windows computer.\n2. Run 01-Enable-SSH.cmd there and note SSH login name, IP and host fingerprint.\n3. Return to THIS client and run:\n'
    printf 'ssh -i %q -l WINDOWS_USERNAME WINDOWS_IP\n' "$key_path"
} > "$kit_dir/CLIENT-CONNECTION.txt"
echo 'PAIRED: windows-admin.pub and CLIENT-CONNECTION.txt are ready in the kit.'
echo 'Take the kit to the target Windows computer and run 01-Enable-SSH.cmd.'
