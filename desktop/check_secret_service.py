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
        runtime = pathlib.Path(directory) / "runtime"
        runtime.mkdir(mode=0o700)
        os.environ["XDG_RUNTIME_DIR"] = str(runtime)
        # Fedora containers have no user login to provide HOME or runtime state.
        home = pathlib.Path(directory) / "home"
        home.mkdir(mode=0o700)
        os.environ["HOME"] = str(home)
        started = subprocess.run(["gnome-keyring-daemon", "--unlock", "--components=secrets"],
            input=b"disposable-ci-keyring-password", stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=15)
        if started.returncode:
            print(started.stderr.decode("utf-8", "replace"))
            raise SystemExit("Could not start disposable Secret Service")
        key = secrets.token_hex(32)
        vault = Vault(directory)
        vault.save("a" * 24, key)
        assert vault.load("a" * 24) == key
        assert not list(pathlib.Path(directory).glob("*.dpapi")), "No local key-file fallback on Linux"
        for item in (home / ".local/share/keyrings").glob("*"):
            if item.is_file():
                assert key.encode() not in item.read_bytes(), "Secret Service wrote an unencrypted test key"
        print("Secret Service store/load verified without a plaintext configuration fallback")
