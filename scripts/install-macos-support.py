#!/usr/bin/env python3
"""Install the arca command line and retire the old browser host, with rollback.

The browser host travels inside Arca.app, and the app registers it with the
browsers when it starts (apps/desktop/src-tauri/src/browser_host.rs). So this
also records what the new app is about to change: the registrations, and the
host an older install left in ~/.local/lib/arca. A failed install puts all of
it back, and the browsers return to the host of the app the installer restores.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import stat
import tempfile

# CHROMIUM_BROWSERS in browser_host.rs, and Firefox.
BROWSERS = ('Google/Chrome', 'BraveSoftware/Brave-Browser', 'Microsoft Edge', 'Chromium', 'Mozilla')
HOST_NAME = 'no.sybr.vault'
# Recorded for a rollback and left for the app to write.
RECORD = 'record'
# Recorded, then removed.
REMOVE = 'remove'


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


def payloads(cargo_output, home):
    home = Path(home)
    support = home / 'Library/Application Support'
    files = {
        # Where the host lived before it moved into the app.
        home / '.local/lib/arca/vault-native-host': REMOVE,
        home / '.local/bin/arca': ((Path(cargo_output) / 'release/arca').read_bytes(), 0o755),
    }
    for browser in BROWSERS:
        files[support / browser / 'NativeMessagingHosts' / (HOST_NAME + '.json')] = RECORD
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
        for path, action in files.items():
            if action == RECORD:
                continue
            if action == REMOVE:
                Path(path).unlink(missing_ok=True)
            else:
                atomic_write(path, *action)
    except BaseException:
        rollback(journal)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rollback', metavar='JOURNAL')
    parser.add_argument('paths', nargs='*', metavar='PATH')
    args = parser.parse_args()
    if args.rollback:
        rollback(args.rollback)
    else:
        if len(args.paths) != 2:
            parser.error('Expected CARGO_OUTPUT JOURNAL')
        output, journal = args.paths
        files = payloads(output, Path.home())
        retired = [path for path, action in files.items()
                   if action == REMOVE and (path.exists() or path.is_symlink())]
        install(files, journal)
        for path, action in files.items():
            if action not in (RECORD, REMOVE):
                print(f'Installed: {path}')
        for path in retired:
            print(f'Removed the old browser host: {path}')


if __name__ == '__main__':
    main()
