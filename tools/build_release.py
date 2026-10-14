#!/usr/bin/env python3
"""Build a credential-free offline ZIP using an explicit allowlist (Python 3.9+)."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    '00-Generate-Client-Key.cmd', '00-Generate-Client-Key.command',
    'Generate-Client-Key.ps1', '05-Import-Public-Key.cmd', '01-Enable-SSH.cmd', '02-Check-SSH.cmd',
    '03-Revoke-Key.cmd', '04-Repair-SSH.cmd', 'Setup-SSH.ps1',
    'Diagnostics.ps1', 'KeyTools.ps1', 'Import-Public-Key.ps1', 'Verify-Admin.ps1',
    'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'VALIDATION.md', 'SOURCE.json',
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download-payloads', action='store_true',
                        help='Download missing pinned official payloads on the build machine.')
    args = parser.parse_args()
    source = json.loads((ROOT / 'SOURCE.json').read_text())
    contents = {}
    for name in FILES:
        raw = (ROOT / name).read_bytes()
        if name.endswith(('.ps1', '.cmd')):
            # PS 5.1 needs UTF-8 BOM to decode non-ASCII diagnostics reliably.
            text = raw.decode('utf-8-sig').replace('\r\n', '\n').replace('\n', '\r\n')
            raw = text.encode('utf-8-sig' if name.endswith('.ps1') else 'ascii')
        contents[name] = raw
    for item in source['payloads']:
        path = ROOT / 'payloads' / item['file']
        if not path.exists() and args.download_payloads:
            path.parent.mkdir(exist_ok=True)
            request = urllib.request.Request(item['source'], headers={'User-Agent': 'windows-ssh-kit-builder'})
            with urllib.request.urlopen(request, timeout=90) as response:
                raw = response.read()
            if hashlib.sha256(raw).hexdigest() != item['sha256']:
                raise SystemExit('Downloaded payload hash mismatch: ' + item['file'])
            path.write_bytes(raw)
        if not path.exists():
            raise SystemExit('Missing payload. Use --download-payloads: ' + item['file'])
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise SystemExit('Payload hash mismatch: ' + item['file'])
        contents['payloads/' + item['file']] = raw
    contents['SHA256SUMS.txt'] = ''.join(
        hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
        for name, data in sorted(contents.items())
    ).encode()
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    archive = dist / ('Windows-SSH-Kit-' + source['package_version'] + '-x64-ARM64.zip')
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for name, raw in sorted(contents.items()):
            info = zipfile.ZipInfo('Windows-SSH-Kit/' + name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if name.endswith('.command') else 0o100644) << 16
            z.writestr(info, raw)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (dist / (archive.name + '.sha256')).write_text(digest + '  ' + archive.name + '\n')
    print(str(archive))
    print('SHA256 ' + digest)


if __name__ == '__main__':
    main()
