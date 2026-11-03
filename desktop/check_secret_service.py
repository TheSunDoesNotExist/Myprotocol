"""CI-only check inside a disposable dbus-run-session, never an existing session."""
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from desktop.vault import Vault

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        started = subprocess.run(["gnome-keyring-daemon", "--unlock", "--components=secrets"],
            input=b"disposable-ci-keyring-password", stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=15)
        if started.returncode:
            raise SystemExit("Could not start disposable Secret Service")
        key = secrets.token_hex(32)
        vault = Vault(directory)
        vault.save("a" * 24, key)
        assert vault.load("a" * 24) == key
        assert not list(pathlib.Path(directory).iterdir()), "Secret Service must not write a plaintext local key"
        print("Secret Service store/load verified without a plaintext configuration fallback")
