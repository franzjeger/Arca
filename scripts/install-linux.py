#!/usr/bin/env python3
"""Transactional per-user installation. Never restore a vault automatically."""
import argparse
import base64
import contextlib
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parent.parent
HOST_NAME = "no.sybr.vault"


class Locations:
    def __init__(self, home=None, data=None, config=None):
        self.home = Path(home or Path.home())
        self.data = Path(data or os.environ.get("XDG_DATA_HOME") or self.home / ".local/share")
        self.config = Path(config or os.environ.get("XDG_CONFIG_HOME") or self.home / ".config")
        self.lib = self.home / ".local/lib/arca"
        self.app = self.lib / "arca"
        self.host = self.lib / "vault-native-host"
        self.launcher = self.home / ".local/bin/arca"
        self.icon = self.data / "icons/hicolor/scalable/apps/arca.svg"
        self.desktop = self.data / "applications/arca.desktop"
        self.manifest = self.lib / "install.json"
        self.pending = self.lib / "pending-update.json"
        self.vault = self.data / HOST_NAME / "default.vault"

    def browser_manifests(self):
        chromium = ["google-chrome", "google-chrome-beta", "chromium", "BraveSoftware/Brave-Browser", "microsoft-edge", "vivaldi"]
        paths = [(self.config / browser / "NativeMessagingHosts" / f"{HOST_NAME}.json", False)
                 for browser in chromium if (self.config / browser).is_dir()]
        if (self.home / ".mozilla").is_dir():
            paths.append((self.home / ".mozilla/native-messaging-hosts" / f"{HOST_NAME}.json", True))
        return paths

    def files(self):
        return [self.app, self.host, self.launcher, self.icon, self.desktop, self.manifest,
                *(path for path, _ in self.browser_manifests())]


def sha(path):
    with open(path, "rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as file:
            os.fchmod(file.fileno(), mode)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    atomic_write(path, (json.dumps(value, indent=2) + "\n").encode())


def capture(locations, destination):
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    records = []
    for index, path in enumerate(locations.files()):
        record = {"path": str(path), "exists": path.exists() or path.is_symlink()}
        if path.is_symlink():
            record["link"] = os.readlink(path)
        elif path.exists():
            if not path.is_file():
                raise RuntimeError(f"Refusing to replace a non-file: {path}")
            record.update(file=str(index), mode=stat.S_IMODE(path.stat().st_mode), sha256=sha(path))
            atomic_write(destination / str(index), path.read_bytes())
        records.append(record)
    # Migrate old registrations that pointed at a mutable Cargo cache. Keep
    # the previous host BEFORE the build can overwrite that cached binary.
    if not locations.host.exists():
        for path, _ in locations.browser_manifests():
            if path.is_file():
                old = Path(json.loads(path.read_text())["path"])
                if old.is_file():
                    atomic_write(destination / "legacy-native-host", old.read_bytes(), 0o700)
                    break
    write_json(destination / "transaction.json", records)
    return destination


def restore_files(locations, snapshot):
    allowed = {str(path) for path in locations.files()}
    records = json.loads((snapshot / "transaction.json").read_text())
    if any(record["path"] not in allowed for record in records):
        raise RuntimeError("The rollback contains paths outside this installation.")
    legacy = snapshot / "legacy-native-host"
    for record in records:
        path = Path(record["path"])
        if "file" in record:
            source = snapshot / record["file"]
            if sha(source) != record["sha256"]:
                raise RuntimeError("A rollback artifact failed its checksum.")
    for record in reversed(records):
        path = Path(record["path"])
        if not record["exists"]:
            path.unlink(missing_ok=True)
        elif "link" in record:
            temporary = path.with_name(f".{path.name}-rollback-{os.getpid()}")
            os.symlink(record["link"], temporary)
            os.replace(temporary, path)
        else:
            data = (snapshot / record["file"]).read_bytes()
            if legacy.exists() and path.name == f"{HOST_NAME}.json":
                manifest = json.loads(data)
                manifest["path"] = str(locations.host)
                data = json.dumps(manifest, indent=2).encode()
            atomic_write(path, data, record["mode"])
    if legacy.exists():
        atomic_write(locations.host, legacy.read_bytes(), 0o755)


def build_info(path):
    result = subprocess.run([str(path), "--build-info"], stdin=subprocess.DEVNULL,
                            capture_output=True, check=True, timeout=10)
    info = json.loads(result.stdout)
    if len(info.get("commit", "")) != 40 or "dirty" in info.get("build", ""):
        raise RuntimeError("Install requires artifacts from a clean, committed checkout.")
    return info


def native_hello(host):
    message = json.dumps({"type": "hello", "protocol": 1}).encode()
    result = subprocess.run([str(host)], input=struct.pack("<I", len(message)) + message,
                            capture_output=True, check=True, timeout=8)
    if len(result.stdout) < 4:
        raise RuntimeError("Native host returned no handshake.")
    length, = struct.unpack("<I", result.stdout[:4])
    return json.loads(result.stdout[4:4 + length])


def processes_for_paths(paths):
    processes = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            target = os.readlink(entry / "exe").removesuffix(" (deleted)")
            if entry.stat().st_uid == os.getuid() and target in {str(path) for path in paths}:
                processes.append(int(entry.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass
    return processes


def installed_processes(locations):
    return processes_for_paths([locations.app])


def stop_native_hosts(locations, snapshot):
    paths = [locations.host]
    for record in json.loads((snapshot / "transaction.json").read_text()):
        if Path(record["path"]).name == f"{HOST_NAME}.json" and "file" in record:
            try:
                old = json.loads((snapshot / record["file"]).read_text())
                old_path = Path(old["path"])
                if old_path.name == "vault-native-host":
                    paths.append(old_path)
            except (ValueError, KeyError, TypeError):
                pass
    for pid in processes_for_paths(paths):
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGTERM)


def stop_installed(locations, restart):
    processes = installed_processes(locations)
    if processes and not restart:
        raise RuntimeError("Close Arca first, or use --restart to allow restarting it. Save unfinished edits first.")
    for pid in processes:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 15
    while installed_processes(locations):
        if time.monotonic() >= deadline:
            raise RuntimeError("Arca did not close. Installation stopped before replacing any files.")
        time.sleep(0.1)
    return bool(processes)


def launch(locations):
    log = locations.lib / "startup.log"
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "ab") as file:
        return subprocess.Popen([str(locations.launcher)], stdin=subprocess.DEVNULL,
                                stdout=file, stderr=file, start_new_session=True)


def verify_running(locations, process, expected, legacy=False):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("The new app exited during startup.")
        try:
            response = native_hello(locations.host)
            identity_matches = (response.get("app_pid") == process.pid
                                and response.get("app_commit") == expected["commit"]
                                and response.get("app_build") == expected["build"])
            if legacy and response.get("app_pid") is None and response.get("app_commit") is None:
                identity_matches = True
            if (response.get("app_connected") is True and identity_matches
                    and response.get("app_version") == expected["version"]
                    and response.get("version") == expected["version"]):
                if sha(Path("/proc") / str(process.pid) / "exe") != sha(locations.app):
                    raise RuntimeError("The running executable differs from the installed file.")
                return response
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(0.3)
    raise RuntimeError("Could not verify the new app through its authenticated native bridge.")


def installation_files(locations, app, host):
    # The stable per-user host survives Cargo cache cleaning and future builds.
    files = [(locations.app, app.read_bytes(), 0o755), (locations.host, host.read_bytes(), 0o755)]
    import shlex
    launcher = '#!/bin/bash\nexport WEBKIT_DISABLE_DMABUF_RENDERER=1\nexport WEBKIT_DISABLE_COMPOSITING_MODE=1\nexec ' + shlex.quote(str(locations.app)) + ' "$@"\n'
    files += [(locations.launcher, launcher.encode(), 0o755), (locations.icon, (REPO / "assets/arca-icon.svg").read_bytes(), 0o644)]
    # Desktop Exec has its own quoting rules, independent of shell quoting.
    escaped = str(locations.launcher).replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$').replace('%', '%%')
    desktop = f'[Desktop Entry]\nType=Application\nName=Arca\nComment=Password manager\nExec="{escaped}"\nIcon=arca\nTerminal=false\nCategories=Utility;Security;\nStartupWMClass=arca\n'
    files.append((locations.desktop, desktop.encode(), 0o644))
    extension = json.loads((REPO / "extension/chromium/manifest.json").read_text())
    digest = hashlib.sha256(base64.b64decode(extension["key"])).hexdigest()[:32]
    extension_id = ''.join(chr(ord('a') + int(character, 16)) for character in digest)
    firefox_template = json.loads((REPO / "extension/native-host/no.sybr.vault.firefox.json").read_text())
    for path, firefox in locations.browser_manifests():
        manifest = {"name": HOST_NAME, "description": "Arca native messaging host", "path": str(locations.host), "type": "stdio"}
        if firefox:
            manifest["allowed_extensions"] = firefox_template["allowed_extensions"]
        else:
            manifest["allowed_origins"] = [f"chrome-extension://{extension_id}/"]
        files.append((path, json.dumps(manifest, indent=2).encode(), 0o600))
    return files


def apply(locations, snapshot, app, host, restart=False):
    if locations.pending.exists():
        raise RuntimeError("An earlier update was interrupted. Run install-linux.sh --rollback --restart first.")
    expected = build_info(app)
    if build_info(host) != expected:
        raise RuntimeError("App and native host were built from different source versions.")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    if head != expected["commit"]:
        raise RuntimeError("The build does not match the current Git commit.")
    # Another install or a manual change during compilation must not be
    # overwritten using a stale rollback snapshot.
    records = json.loads((snapshot / "transaction.json").read_text())
    if {record["path"] for record in records} != {str(path) for path in locations.files()}:
        raise RuntimeError("Browser configuration changed during the build. Retry the update.")
    for record in records:
        path = Path(record["path"])
        if "file" in record and (not path.is_file() or sha(path) != record["sha256"]):
            raise RuntimeError("The installed files changed during the build. Retry the update.")
        if "link" in record and (not path.is_symlink() or os.readlink(path) != record["link"]):
            raise RuntimeError("The installation links changed during the build. Retry the update.")
        if not record["exists"] and (path.exists() or path.is_symlink()):
            raise RuntimeError("The installation changed during the build. Retry the update.")
    files = installation_files(locations, app, host)
    previous = locations.lib / "previous" / f'{time.time_ns()}-{expected["commit"][:12]}'
    previous.parent.mkdir(parents=True, exist_ok=True)
    # Persist rollback artifacts before touching the working installation. A
    # journal survives SIGKILL/reboots even if the shell cleans its build stage.
    shutil.copytree(snapshot, previous)
    was_running = stop_installed(locations, restart)
    process = None
    try:
        stop_native_hosts(locations, previous)
        if locations.vault.is_file():
            atomic_write(previous / "vault-before-update.vault", locations.vault.read_bytes())
        write_json(locations.pending, {"previousInstall": str(previous)})
        for path, data, mode in files:
            atomic_write(path, data, mode)
        if sha(locations.app) != sha(app) or sha(locations.host) != sha(host):
            raise RuntimeError("Installed binaries failed checksum verification.")
        process = launch(locations)
        response = verify_running(locations, process, expected)
        second = subprocess.run([str(locations.launcher)], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        if second.returncode != 0:
            raise RuntimeError("Repeated launch did not focus the existing app.")
        verify_running(locations, process, expected)
        if installed_processes(locations) != [process.pid]:
            raise RuntimeError("Expected exactly one installed Arca process.")
        manifest = {**expected, "sha256": sha(locations.app), "nativeSha256": sha(locations.host),
                    "installedAt": datetime.now(timezone.utc).isoformat(), "previousInstall": str(previous),
                    "verifiedAppVersion": response["app_version"], "verifiedNativeHostVersion": response["version"],
                    "verifiedAppCommit": response["app_commit"], "singleInstanceVerified": True}
        write_json(locations.manifest, manifest)
        locations.pending.unlink()
        return manifest
    except BaseException:
        if process is not None:
            stop_installed(locations, True)
        stop_native_hosts(locations, previous)
        restore_files(locations, previous)
        locations.pending.unlink(missing_ok=True)
        if was_running and locations.app.exists():
            launch(locations)
        raise


def rollback(locations, restart=False):
    manifest = json.loads((locations.pending if locations.pending.exists() else locations.manifest).read_text())
    snapshot = Path(manifest["previousInstall"]).resolve()
    if snapshot.parent != (locations.lib / "previous").resolve():
        raise RuntimeError("Invalid previous-installation path.")
    was_running = stop_installed(locations, restart)
    write_json(locations.pending, {"previousInstall": str(snapshot)})
    stop_native_hosts(locations, snapshot)
    restore_files(locations, snapshot)
    if was_running and locations.app.exists():
        process = launch(locations)
        if locations.manifest.exists() and locations.host.exists():
            previous = json.loads(locations.manifest.read_text())
            verify_running(locations, process, previous, legacy="verifiedAppCommit" not in previous)
    locations.pending.unlink(missing_ok=True)
    print("Previous app and native host restored. Vault data was not rolled back.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "apply", "rollback"])
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--app", type=Path)
    parser.add_argument("--host", type=Path)
    parser.add_argument("--restart", action="store_true")
    args = parser.parse_args()
    locations = Locations()
    locations.lib.mkdir(parents=True, exist_ok=True)
    with open(locations.lib / ".install.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.operation == "prepare":
            if locations.pending.exists():
                raise RuntimeError("An earlier update was interrupted. Run install-linux.sh --rollback --restart first.")
            if not args.snapshot:
                parser.error("prepare requires --snapshot")
            capture(locations, args.snapshot)
        elif args.operation == "apply":
            if not all([args.snapshot, args.app, args.host]):
                parser.error("apply requires --snapshot, --app and --host")
            print(json.dumps(apply(locations, args.snapshot, args.app, args.host, args.restart), indent=2))
        else:
            rollback(locations, args.restart)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Install stopped: {error}") from None
