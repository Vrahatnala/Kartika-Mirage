"""Tar-pit adaptif: menahan pemakai honeytoken di dalam portal umpan.

Hanya dipakai setelah kredensial umpan terbukti dipakai. Semua terjadi di server kita sendiri
(respons lambat + direktori/berkas palsu tanpa ujung); tidak ada kode yang berjalan di perangkat penyerang.

Batas keamanan (supaya server kita tidak ikut kewalahan):
  TARPIT_MAX_CONNECTIONS (50)  koneksi tertahan bersamaan, global
  TARPIT_MAX_PER_IP      (5)   koneksi tertahan bersamaan per IP
  TARPIT_MAX_SECONDS     (300) durasi maksimum satu koneksi
  TARPIT_SPEED           (1.0) pengali jeda; <1 hanya untuk tes
"""
import asyncio
import hashlib
import os
import random
import re
import secrets
import time
from collections import deque
from html import escape

MAX_CONN = int(os.getenv("TARPIT_MAX_CONNECTIONS", "50"))
MAX_PER_IP = int(os.getenv("TARPIT_MAX_PER_IP", "5"))
MAX_SECONDS = float(os.getenv("TARPIT_MAX_SECONDS", "300"))
SPEED = float(os.getenv("TARPIT_SPEED", "1.0"))

BOT_DELAY = 4.0      # detik antar baris untuk skrip otomatis
HUMAN_DELAY = 0.4    # detik antar baris untuk pengguna manusia
HUMAN_MAX_SECONDS = 30.0
BOT_GAP = 2.0        # rata-rata jeda antar request < ini => perilaku skrip
MAX_SESSIONS = 500

_BOT_UA = re.compile(r"curl|wget|python|httpx|requests|aiohttp|scrapy|go-http|java/|libwww|bot|spider|crawl|scan", re.I)

sessions: dict = {}
ip_active: dict = {}
stats = {"active": 0, "seconds_wasted": 0.0, "requests": 0}

_FOLDERS = ["KOMUNIKASI", "OPERASI", "LOGISTIK", "INTELIJEN", "ARSIP", "PERSONEL", "JARINGAN", "SANDI",
            "LAPORAN", "PERENCANAAN", "PENGAMANAN", "SATKOM", "DISTRIBUSI", "EVALUASI"]
_QUAL = ["2024", "2025", "2026", "TW1", "TW2", "TW3", "TW4", "REGIONAL", "PUSAT", "CADANGAN"]
_FILES = ["Rekap", "Telegram", "Matriks", "Jadwal", "Notulen", "Daftar", "Rencana", "Evaluasi", "Disposisi"]
_EXT = ["pdf", "docx", "xlsx", "txt"]


def open_session(honey_sid: str) -> str:
    if len(sessions) >= MAX_SESSIONS:
        sessions.pop(next(iter(sessions)))
    token = secrets.token_urlsafe(18)
    sessions[token] = {"sid": honey_sid, "gaps": deque(maxlen=6), "last": None, "requests": 0,
                       "wasted": 0.0, "announced": False}
    return token


def get_session(token: str):
    return sessions.get(token or "")


def clear():
    sessions.clear()
    ip_active.clear()
    stats.update({"active": 0, "seconds_wasted": 0.0, "requests": 0})


def snapshot() -> dict:
    return {
        "active": stats["active"],
        "seconds_wasted": round(stats["seconds_wasted"], 1),
        "requests": stats["requests"],
        "sessions": len(sessions),
        "limits": {"connections": MAX_CONN, "per_ip": MAX_PER_IP, "max_seconds": MAX_SECONDS},
    }


def classify(sess: dict, user_agent: str) -> str:
    """'bot' bila UA khas skrip atau rata-rata jeda antar request pendek; selain itu 'human'."""
    now = time.monotonic()
    if sess["last"] is not None:
        sess["gaps"].append(now - sess["last"])
    sess["last"] = now
    sess["requests"] += 1
    stats["requests"] += 1
    if _BOT_UA.search(user_agent or ""):
        return "bot"
    if len(sess["gaps"]) >= 2 and sum(sess["gaps"]) / len(sess["gaps"]) < BOT_GAP:
        return "bot"
    return "human"


def try_acquire(ip: str) -> bool:
    if stats["active"] >= MAX_CONN or ip_active.get(ip, 0) >= MAX_PER_IP:
        return False
    stats["active"] += 1
    ip_active[ip] = ip_active.get(ip, 0) + 1
    return True


def release(ip: str):
    stats["active"] = max(0, stats["active"] - 1)
    n = ip_active.get(ip, 0) - 1
    if n <= 0:
        ip_active.pop(ip, None)
    else:
        ip_active[ip] = n


def _rng(sid: str, path: str) -> random.Random:
    return random.Random(int(hashlib.sha256(f"{sid}|{path}".encode()).hexdigest()[:16], 16))


def _row(rng: random.Random, base: str):
    if rng.random() < 0.55:
        name = f"{rng.choice(_FOLDERS)}_{rng.choice(_QUAL)}"
        return f'<li>[DIR] <a href="{escape(base)}/{name}/">{name}/</a></li>\n'
    name = f"{rng.choice(_FILES)}_{rng.choice(_FOLDERS)}_{rng.randint(1, 99):02d}.{rng.choice(_EXT)}"
    return f'<li>{rng.randint(12, 980)} KB <a href="{escape(base)}/{name}">{name}</a></li>\n'


def _is_file(path: str) -> bool:
    return bool(re.search(r"\.(pdf|docx|xlsx|txt)$", path, re.I))


def page_lines(sid: str, path: str, mode: str):
    """Generator baris HTML. Mode 'bot': tanpa akhir (dibatasi durasi). Mode 'human': halaman wajar."""
    rng = _rng(sid, path)
    base = "/portal/files" + (("/" + path.strip("/")) if path.strip("/") else "")
    yield f"<!doctype html><html lang=\"id\"><head><meta charset=\"utf-8\"><title>Portal Koordinasi - Berkas</title></head><body>\n"
    yield f"<h3>/{escape(path.strip('/'))}</h3>\n"
    if _is_file(path):
        n = 0
        while mode == "bot" or n < 40:
            n += 1
            yield f"<pre>{n:04d}  {rng.choice(_FILES).upper()} {rng.randint(100000, 999999)} ... {secrets.token_hex(6)}</pre>\n"
        yield "</body></html>\n"
        return
    yield "<ul>\n"
    n = 0
    while mode == "bot" or n < rng.randint(12, 22):
        n += 1
        yield _row(rng, base)
    yield "</ul></body></html>\n"


async def slow_stream(sess: dict, ip: str, lines, mode: str, on_end=None):
    """Kirim baris demi baris dengan jeda; hitung waktu terbuang secara langsung."""
    delay = (BOT_DELAY if mode == "bot" else HUMAN_DELAY) * SPEED
    limit = (MAX_SECONDS if mode == "bot" else min(HUMAN_MAX_SECONDS, MAX_SECONDS)) * (SPEED if SPEED < 1 else 1)
    start = last = time.monotonic()

    def credit():
        nonlocal last
        now = time.monotonic()
        dt = now - last
        last = now
        sess["wasted"] += dt
        stats["seconds_wasted"] += dt

    try:
        for line in lines:
            if time.monotonic() - start >= limit:
                break
            yield line
            await asyncio.sleep(delay)
            credit()
    finally:
        credit()
        release(ip)
        if on_end:
            try:
                on_end(sess, mode, time.monotonic() - start)
            except Exception:
                pass
