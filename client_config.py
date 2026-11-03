"""Portable connection text. Base64 is an encoding, never encryption."""

import base64
import binascii
import json

PREFIX = "myownvpn://"
LIMIT = 32768


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Повторяющееся поле конфигурации")
        result[key] = value
    return result


def encode(server, ca, key, name):
    raw = json.dumps(dict(schema=1, protocol=5, server=server, ca=ca.decode("ascii"),
                         key=key, name=name, srtl=False), ensure_ascii=True, separators=(",", ":")).encode()
    token = PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")
    if len(token) > LIMIT:
        raise ValueError("Конфигурация слишком большая")
    return token


def decode(text):
    try:
        if not isinstance(text, str) or len(text) > LIMIT:
            raise ValueError
        text = text.strip()
        if not text.startswith(PREFIX):
            raise ValueError
        payload = text[len(PREFIX):]
        if not payload or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in payload):
            raise ValueError
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
        cfg = json.loads(raw, object_pairs_hook=_object)
        if (not isinstance(cfg, dict) or set(cfg) != {"schema", "protocol", "server", "ca", "key", "name", "srtl"}
                or type(cfg["schema"]) is not int or cfg["schema"] != 1
                or type(cfg["protocol"]) is not int or cfg["protocol"] != 5
                or type(cfg["srtl"]) is not bool or not isinstance(cfg["name"], str)
                or not 1 <= len(cfg["name"]) <= 80 or not all(c.isprintable() for c in cfg["name"])
                or not isinstance(cfg["ca"], str) or len(cfg["ca"]) > 16384):
            raise ValueError
        return cfg
    except (ValueError, TypeError, UnicodeError, RecursionError, binascii.Error):
        raise ValueError("Не удалось прочитать конфигурацию. Скопируйте строку myownvpn:// целиком") from None
