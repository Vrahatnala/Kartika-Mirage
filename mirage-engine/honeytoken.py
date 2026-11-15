"""Honeytoken: kredensial umpan unik per sesi.

Kredensial ini tidak valid di sistem mana pun. Satu-satunya tempat ia muncul adalah di dokumen umpan
sesi tertentu, jadi kalau dipakai (portal atau gateway) berarti seseorang membuka dokumen itu dan
mencoba memakai isinya. Nilainya diturunkan dari HMAC(LEDGER_KEY, sesi) sehingga tidak bisa ditebak.
Pencocokan hanya dilakukan di server kita sendiri (pasif): tidak ada kode yang berjalan di sisi penyerang.
"""
import hashlib
import hmac

from security_core import LEDGER_KEY

# nilai kredensial -> session_id. Hanya di memori; dikosongkan saat reset.
_registry: dict = {}

_ALPHA = "abcdefghjkmnpqrstuvwxyz23456789"


def _derive(session_id: str, label: str, n: int) -> str:
    d = hmac.new(LEDGER_KEY.encode(), f"honey|{label}|{session_id}".encode(), hashlib.sha256).digest()
    return "".join(_ALPHA[b % len(_ALPHA)] for b in d[:n])


def mint(session_id: str) -> dict:
    cred = {
        "username": f"siops.{_derive(session_id, 'u', 4)}",
        "password": f"{_derive(session_id, 'p1', 5).capitalize()}-{_derive(session_id, 'p2', 4)}-{sum(_derive(session_id, 'p3', 6).encode()) % 900 + 100}",
        "api_key": f"kd-{_derive(session_id, 'k', 24)}",
    }
    for key in ("username", "password", "api_key"):
        _registry[cred[key]] = session_id
    return cred


def lookup(value: str):
    """Kembalikan session_id jika value adalah honeytoken (username/password/api_key), selain itu None."""
    if not value:
        return None
    return _registry.get(value.strip()[:80])


def clear():
    _registry.clear()
