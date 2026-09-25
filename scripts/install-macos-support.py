#!/usr/bin/env python3
"""Atomically install the CLI, browser host and registrations, with rollback."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

BROWSERS = ('Google/Chrome', 'BraveSoftware/Brave-Browser', 'Microsoft Edge', 'Chromium')
HOST_NAME = 'no.sybr.vault'


def atomic_write(path, data, mode):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            os.fchmod(file.fileno(), mode)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def payloads(repo, cargo_output, home, host_only=False):
    home = Path(home)
    host = home / '.local/lib/arca/vault-native-host'
    files = {host: ((Path(cargo_output) / 'release/vault-native-host').read_bytes(), 0o755)}
    if not host_only:
        files[home / '.local/bin/arca'] = ((Path(cargo_output) / 'release/arca').read_bytes(), 0o755)
    manifest = json.loads((Path(repo) / 'extension/chromium/manifest.json').read_text())
    digest = hashlib.sha256(base64.b64decode(manifest['key'], validate=True)).hexdigest()[:32]
    extension_id = digest.translate(str.maketrans('0123456789abcdef', 'abcdefghijklmnop'))
    registration = {'name': HOST_NAME, 'description': 'Arca native messaging host',
                    'path': str(host), 'type': 'stdio',
                    'allowed_origins': [f'chrome-extension://{extension_id}/']}
    support = home / 'Library/Application Support'
    for browser in BROWSERS:
        base = support / browser
        if base.is_dir():
            files[base / 'NativeMessagingHosts' / (HOST_NAME + '.json')] = (
                (json.dumps(registration, indent=2) + '\n').encode(), 0o600)
    if (support / 'Mozilla').is_dir():
        firefox = json.loads((Path(repo) / 'extension/native-host/no.sybr.vault.firefox.json').read_text())
        firefox['path'] = str(host)
        files[support / 'Mozilla/NativeMessagingHosts' / (HOST_NAME + '.json')] = (
            (json.dumps(firefox, indent=2) + '\n').encode(), 0o600)
    return files


def capture(files, journal):
    journal = Path(journal)
    journal.mkdir(mode=0o700)  # Refuse to overwrite an earlier recovery journal.
    records = []
    for path in files:
        path = Path(path)
        record = {'path': str(path), 'exists': path.exists() or path.is_symlink()}
        if path.is_symlink():
            record['link'] = os.readlink(path)
        elif path.exists():
            if not path.is_file():
                raise ValueError(f'Refusing to replace a non-file: {path}')
            record['data'] = base64.b64encode(path.read_bytes()).decode()
            record['mode'] = stat.S_IMODE(path.stat().st_mode)
        records.append(record)
    atomic_write(journal / 'files.json', json.dumps(records).encode(), 0o600)


def rollback(journal):
    records = json.loads((Path(journal) / 'files.json').read_text())
    for record in reversed(records):
        path = Path(record['path'])
        if not record['exists']:
            path.unlink(missing_ok=True)
        elif 'link' in record:
            path.unlink(missing_ok=True)
            path.symlink_to(record['link'])
        else:
            atomic_write(path, base64.b64decode(record['data']), record['mode'])


def install(files, journal):
    capture(files, journal)
    try:
        for path, (data, mode) in files.items():
            atomic_write(path, data, mode)
    except BaseException:
        rollback(journal)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rollback', metavar='JOURNAL')
    parser.add_argument('--host-only', action='store_true')
    parser.add_argument('paths', nargs='*', metavar='PATH')
    args = parser.parse_args()
    if args.rollback:
        rollback(args.rollback)
    else:
        if len(args.paths) != 3:
            parser.error('Expected REPO CARGO_OUTPUT JOURNAL')
        repo, output, journal = args.paths
        files = payloads(repo, output, Path.home(), args.host_only)
        install(files, journal)
        for path in files:
            print(f'Installed: {path}')


if __name__ == '__main__':
    main()
