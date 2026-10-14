"""Exercise real key generation without installing or restarting an SSH service."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def run(args):
    env = os.environ.copy()
    # Actions runs Python under pwsh. A PS 5.1 child launched through Python
    # otherwise inherits PS 7's module path and may load incompatible modules.
    if os.name == 'nt' and Path(args[0]).name.lower() == 'powershell.exe':
        env.pop('PSModulePath', None)
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=60, env=env)


def main():
    private = None
    spec = importlib.util.spec_from_file_location('builder', ROOT / 'tools/build_release.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    try:
        with tempfile.TemporaryDirectory(prefix='ssh kit pairing ') as tmp:
            kit = Path(tmp) / 'USB kit'
            kit.mkdir()
            for name in builder.FILES:
                shutil.copyfile(ROOT / name, kit / name)
            shutil.copytree(ROOT / 'payloads', kit / 'payloads')
            if os.name == 'nt':
                command = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                           '-File', str(kit / 'Generate-Client-Key.ps1'), '-NoPassphrase']
            else:
                command = ['bash', str(kit / '00-Generate-Client-Key.command'), '--no-passphrase']
            result = run(command)
            assert result.returncode == 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace')
            guide = (kit / 'CLIENT-CONNECTION.txt').read_text(encoding='utf-8-sig')
            private = Path(guide.splitlines()[1])
            assert private.name == 'id_ed25519' and private.parent.name.startswith('windows-ssh-kit-')
            assert private.is_file() and kit not in private.parents
            keygen = shutil.which('ssh-keygen')
            assert keygen, 'Test runner needs an SSH client to independently verify the pair.'
            derived = run([keygen, '-y', '-f', str(private)])
            assert derived.returncode == 0
            assert derived.stdout.decode().split()[:2] == (kit / 'windows-admin.pub').read_text().split()[:2]
            assert Path(str(private) + '.pub').read_text().strip() == (kit / 'windows-admin.pub').read_text().strip()
            before = hashlib.sha256(private.read_bytes()).hexdigest()
            assert run(command).returncode != 0, 'Repeated generation unexpectedly succeeded.'
            assert hashlib.sha256(private.read_bytes()).hexdigest() == before
            if os.name == 'nt':
                expression = "$p='" + str(private).replace("'", "''") + "'; $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544'); foreach($a in (Get-Acl -LiteralPath $p).Access){if($a.AccessControlType -eq 'Allow' -and $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed){exit 1}}"
                assert run(['powershell.exe', '-NoProfile', '-Command', expression]).returncode == 0, 'Private key has excessive permissions.'
            else:
                assert private.stat().st_mode & 0o777 == 0o600
                assert private.parent.stat().st_mode & 0o777 == 0o700
            for file in kit.rglob('*'):
                if file.is_file() and file.suffix != '.zip':
                    assert b'-----BEGIN OPENSSH PRIVATE KEY-----' not in file.read_bytes()
            # Build from an already paired USB kit: neither key nor connection details may leak.
            builder.ROOT = kit
            builder.main()
            archive = next((kit / 'dist').glob('*.zip'))
            with zipfile.ZipFile(archive) as z:
                assert not any(n.endswith(('.pub', 'CLIENT-CONNECTION.txt', 'id_ed25519')) for n in z.namelist())
                for n in z.namelist():
                    if not n.endswith('.zip'):
                        assert str(private).encode() not in z.read(n)
            print('PASS: real key pairing, client-only private key, restricted permissions, repeat-run refusal and clean release.')
    finally:
        # Delete only the unique test key directory identified by this run's receipt.
        if private and private.name == 'id_ed25519' and private.parent.name.startswith('windows-ssh-kit-'):
            shutil.rmtree(private.parent)


if __name__ == '__main__':
    main()
