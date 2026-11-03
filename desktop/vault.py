"""OS-protected access keys. No plaintext-file fallback and no secret CLI args."""

import ctypes
import os
import pathlib
import shutil
import subprocess

from desktop.profiles import valid_key, write_private


class VaultError(RuntimeError):
    pass


def dpapi(data, decrypt=False):
    from ctypes import wintypes
    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    result = Blob()
    if decrypt:
        operation = crypt.CryptUnprotectData
        operation.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result))
    else:
        operation = crypt.CryptProtectData
        operation.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = operation(ctypes.byref(source), "Myownvpn access key", None, None, None, 1, ctypes.byref(result))
    operation.restype = wintypes.BOOL
    if not ok:
        raise VaultError("Windows не разрешила доступ к хранилищу ключей")
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        ctypes.memset(result.data, 0, result.size)
        kernel.LocalFree(result.data)


class Vault:
    def __init__(self, root):
        self.root = pathlib.Path(root)

    def _path(self, identity):
        if len(identity) != 24 or any(c not in "0123456789abcdef" for c in identity):
            raise VaultError("Неверный идентификатор ключа")
        return self.root / (identity + ".dpapi")

    def _secret_tool(self, verb, identity, data=None):
        self._path(identity)
        tool = shutil.which("secret-tool")
        if tool is None:
            raise VaultError("Нужны libsecret и разблокированное системное хранилище ключей")
        command = [tool, verb]
        if verb == "store":
            command += ["--label=Myownvpn · ключ подключения"]
        command += ["application", "org.myownvpn.Client", "profile", identity]
        try:
            result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise VaultError("Системное хранилище ключей недоступно или заблокировано") from None
        if result.returncode:
            raise VaultError("Разблокируйте системное хранилище ключей или импортируйте пакет заново")
        return result.stdout

    def save(self, identity, key):
        raw = valid_key(key).encode("ascii")
        if os.name == "nt":
            write_private(self._path(identity), dpapi(raw))
        else:
            self._secret_tool("store", identity, raw)

    def load(self, identity):
        if os.name == "nt":
            path = self._path(identity)
            if not path.exists():
                raise VaultError("Импортируйте клиентский пакет: ключ доступа не сохранён")
            try:
                raw = dpapi(path.read_bytes(), decrypt=True)
            except OSError:
                raise VaultError("Не удалось прочитать защищённый ключ") from None
        else:
            raw = self._secret_tool("lookup", identity)
        try:
            return valid_key(raw.decode("ascii").strip())
        except (UnicodeError, ValueError):
            raise VaultError("Ключ в хранилище повреждён: импортируйте пакет заново") from None
