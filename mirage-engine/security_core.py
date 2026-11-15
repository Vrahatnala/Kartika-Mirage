import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
import jwt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "forensic_vault.db")
SECRETS_PATH = os.path.join(DATA_DIR, ".mirage_secrets.json")
JWT_ALGO = "HS256"
MAX_PENDING_REQUESTS = 25
PENDING_TTL_SECONDS = 15 * 60

# Prinsip minimisasi/proporsionalitas data: warrant untuk METADATA_ONLY (mis. lokasi,
# status koneksi -- yang berhasil didapat di kasus penyadapan SBY 2013) TIDAK otomatis
# mengizinkan akses FULL_CONTENT (isi komunikasi). Warrant kategori lebih tinggi
# mencakup kategori di bawahnya, tapi tidak sebaliknya.
CATEGORY_RANK = {"METADATA_ONLY": 1, "FULL_CONTENT": 2}
DEFAULT_DATA_CATEGORY = "METADATA_ONLY"


def _load_secrets() -> dict:
    """Secret dibuat acak saat pertama jalan dan disimpan lokal (bukan di source code).
    Env var tetap bisa menimpa (untuk deployment)."""
    data = {}
    if os.path.exists(SECRETS_PATH):
        try:
            with open(SECRETS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
    changed = False
    for key, nbytes in (("jwt_secret", 32), ("ledger_key", 32), ("admin_key", 24), ("vip_token", 18)):
        if not data.get(key):
            data[key] = secrets.token_urlsafe(nbytes)
            changed = True
    if changed:
        fd = os.open(SECRETS_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
    return data


_SECRETS = _load_secrets()
JWT_SECRET = os.getenv("MIRAGE_JWT_SECRET") or _SECRETS["jwt_secret"]
LEDGER_KEY = os.getenv("MIRAGE_LEDGER_KEY") or _SECRETS["ledger_key"]
ADMIN_KEY = os.getenv("MIRAGE_ADMIN_KEY") or _SECRETS["admin_key"]
VIP_STATIC_TOKEN = os.getenv("VIP_GATEWAY_TOKEN") or _SECRETS["vip_token"]


def _norm_identity(name: str) -> str:
    """Normalisasi nama agar 'Budi', 'budi.' dan ' BUDI ' dianggap orang yang sama."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _block_hash(raw: bytes) -> str:
    """Hash berkunci (HMAC): tanpa LEDGER_KEY, rantai tidak bisa dihitung ulang setelah dimodifikasi."""
    return hmac.new(LEDGER_KEY.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def init_forensic_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS adversary_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            curr_hash TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS warrant_registry (
            warrant_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            issued_by TEXT NOT NULL,
            purpose TEXT NOT NULL,
            scope TEXT NOT NULL,
            data_category TEXT NOT NULL DEFAULT 'METADATA_ONLY',
            issued_at TEXT NOT NULL,
            valid_until TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            revoked_by TEXT,
            revoked_at TEXT,
            revocation_reason TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS warrant_requests (
            request_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            scope TEXT NOT NULL,
            data_category TEXT NOT NULL DEFAULT 'METADATA_ONLY',
            requested_by TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            decided_by TEXT,
            decided_at TEXT,
            decision_note TEXT,
            warrant_id TEXT
        )
    """)
    # Migrasi ringan: database lama (sebelum kolom ini ada) otomatis ditambahkan
    # kolomnya tanpa kehilangan data yang sudah tercatat.
    for table, col, decl in [
        ("warrant_registry", "data_category", "TEXT NOT NULL DEFAULT 'METADATA_ONLY'"),
        ("warrant_registry", "revoked_by", "TEXT"),
        ("warrant_registry", "revoked_at", "TEXT"),
        ("warrant_registry", "revocation_reason", "TEXT"),
        ("warrant_requests", "data_category", "TEXT NOT NULL DEFAULT 'METADATA_ONLY'"),
    ]:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        except sqlite3.OperationalError:
            pass  # kolom sudah ada
    conn.commit()
    conn.close()


def issue_warrant(
    device_id: str, issued_by: str, purpose: str, scope: str = "VIP_COMM_DATA",
    data_category: str = DEFAULT_DATA_CATEGORY, ttl_minutes: int = 60,
) -> dict:
    """
    Menerbitkan 'surat izin' akses ke data VVIP -- mensimulasikan otorisasi
    pengadilan/atasan berwenang sesuai SOP (Perkap No. 5/2010), BUKAN sekadar
    kredensial login. Dipanggil lewat endpoint admin saat demo untuk
    membuktikan jalur akses yang sah.

    data_category membatasi SEBERAPA DALAM data yang boleh diakses warrant ini
    (prinsip minimisasi/proporsionalitas): METADATA_ONLY (lokasi, status koneksi)
    atau FULL_CONTENT (isi komunikasi). Warrant tidak otomatis "akses penuh".
    """
    init_forensic_db()
    if data_category not in CATEGORY_RANK:
        data_category = DEFAULT_DATA_CATEGORY
    warrant_id = "WARRANT-" + hashlib.sha256(
        f"{device_id}{issued_by}{time.time()}".encode()
    ).hexdigest()[:10].upper()
    issued_at = datetime.now().isoformat()
    valid_until = datetime.fromtimestamp(time.time() + ttl_minutes * 60).isoformat()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO warrant_registry (warrant_id, device_id, issued_by, purpose, scope, data_category, issued_at, valid_until, revoked) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (warrant_id, device_id, issued_by, purpose, scope, data_category, issued_at, valid_until),
    )
    conn.commit()
    conn.close()

    return {
        "warrant_id": warrant_id,
        "device_id": device_id,
        "issued_by": issued_by,
        "purpose": purpose,
        "scope": scope,
        "data_category": data_category,
        "issued_at": issued_at,
        "valid_until": valid_until,
    }


def request_warrant(
    device_id: str, purpose: str, requested_by: str, scope: str = "VIP_COMM_DATA",
    data_category: str = DEFAULT_DATA_CATEGORY,
) -> dict:
    """
    Langkah 1 dari alur dual-control: pihak yang BUTUH akses mengajukan
    permintaan (belum aktif, status PENDING). Mengajukan permintaan TIDAK
    memberi akses apapun -- harus disetujui pihak independen lewat
    approve_warrant_request(). Ini mencegah 1 orang bisa sekaligus
    "meminta" dan "mengotorisasi" akses dirinya sendiri.
    """
    init_forensic_db()
    if data_category not in CATEGORY_RANK:
        data_category = DEFAULT_DATA_CATEGORY
    requested_by = (requested_by or "")[:60]
    purpose = (purpose or "")[:120]
    request_id = "REQ-" + hashlib.sha256(
        f"{device_id}{requested_by}{time.time()}".encode()
    ).hexdigest()[:10].upper()
    requested_at = datetime.now().isoformat()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Permintaan PENDING yang tak diproses kedaluwarsa otomatis (spam tidak bisa memblokir antrean selamanya).
    cutoff = datetime.fromtimestamp(time.time() - PENDING_TTL_SECONDS).isoformat()
    c.execute(
        "UPDATE warrant_requests SET status = 'EXPIRED', decision_note = 'Kedaluwarsa otomatis' "
        "WHERE status = 'PENDING' AND requested_at < ?", (cutoff,),
    )
    conn.commit()
    c.execute("SELECT COUNT(*) FROM warrant_requests WHERE status = 'PENDING'")
    if c.fetchone()[0] >= MAX_PENDING_REQUESTS:
        conn.close()
        return {"status": "QUEUE_FULL", "reason": "Antrian permintaan warrant penuh"}
    c.execute(
        "INSERT INTO warrant_requests (request_id, device_id, purpose, scope, data_category, requested_by, requested_at, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')",
        (request_id, device_id, purpose, scope, data_category, requested_by, requested_at),
    )
    conn.commit()
    conn.close()

    return {
        "request_id": request_id,
        "device_id": device_id,
        "purpose": purpose,
        "scope": scope,
        "data_category": data_category,
        "requested_by": requested_by,
        "requested_at": requested_at,
        "status": "PENDING",
    }


def expire_all_pending() -> int:
    """Dipakai saat reset demo: kosongkan antrean permintaan yang menggantung."""
    init_forensic_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE warrant_requests SET status = 'EXPIRED', decision_note = 'Dibersihkan saat reset' WHERE status = 'PENDING'")
    n = c.rowcount
    conn.commit()
    conn.close()
    return n


def list_pending_warrant_requests() -> list[dict]:
    init_forensic_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT request_id, device_id, purpose, scope, data_category, requested_by, requested_at "
        "FROM warrant_requests WHERE status = 'PENDING' ORDER BY requested_at DESC"
    )
    rows = c.fetchall()
    conn.close()
    return [
        {
            "request_id": r[0], "device_id": r[1], "purpose": r[2],
            "scope": r[3], "data_category": r[4], "requested_by": r[5], "requested_at": r[6],
        }
        for r in rows
    ]


def approve_warrant_request(request_id: str, decided_by: str, ttl_minutes: int = 60) -> dict:
    """
    Langkah 2: pihak INDEPENDEN (bukan peminta) menyetujui permintaan.
    Enforcement pemisahan wewenang (separation of duty) ada di sini:
    decided_by TIDAK BOLEH sama dengan requested_by -- kalau sama, ditolak
    otomatis. Ini mencegah 1 orang berperan ganda sebagai peminta sekaligus
    pemberi izin, persis celah yang dieksploitasi di kasus penyalahgunaan
    LIMS/PenLink (perintah lisan dari 1 pihak berkuasa, tanpa pihak kedua
    yang independen mengotorisasi).
    """
    init_forensic_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT device_id, purpose, scope, data_category, requested_by, status FROM warrant_requests WHERE request_id = ?",
        (request_id,),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "ERROR", "reason": f"Request '{request_id}' tidak ditemukan"}

    device_id, purpose, scope, data_category, requested_by, status = row

    if status != "PENDING":
        conn.close()
        return {"status": "ERROR", "reason": f"Request '{request_id}' sudah diputuskan sebelumnya ({status})"}

    if _norm_identity(decided_by) == _norm_identity(requested_by):
        decided_at = datetime.now().isoformat()
        c.execute(
            "UPDATE warrant_requests SET status = 'REJECTED', decided_by = ?, decided_at = ?, decision_note = ? WHERE request_id = ?",
            (decided_by, decided_at, "Ditolak otomatis: peminta dan penyetuju adalah pihak yang sama (pelanggaran separation-of-duty)", request_id),
        )
        conn.commit()
        conn.close()
        return {
            "status": "REJECTED_SEPARATION_OF_DUTY",
            "reason": f"'{decided_by}' tidak boleh menyetujui permintaan yang diajukan oleh dirinya sendiri",
        }

    conn.close()

    warrant = issue_warrant(
        device_id=device_id, issued_by=decided_by, purpose=purpose, scope=scope,
        data_category=data_category, ttl_minutes=ttl_minutes,
    )

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    decided_at = datetime.now().isoformat()
    c.execute(
        "UPDATE warrant_requests SET status = 'APPROVED', decided_by = ?, decided_at = ?, decision_note = ?, warrant_id = ? WHERE request_id = ?",
        (decided_by, decided_at, f"Disetujui oleh {decided_by}", warrant["warrant_id"], request_id),
    )
    conn.commit()
    conn.close()

    return {"status": "APPROVED", "warrant": warrant}


def reject_warrant_request(request_id: str, decided_by: str, reason: str = "Tidak memenuhi syarat") -> dict:
    init_forensic_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT status FROM warrant_requests WHERE request_id = ?", (request_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "ERROR", "reason": f"Request '{request_id}' tidak ditemukan"}
    if row[0] != "PENDING":
        conn.close()
        return {"status": "ERROR", "reason": f"Request '{request_id}' sudah diputuskan sebelumnya ({row[0]})"}

    decided_at = datetime.now().isoformat()
    c.execute(
        "UPDATE warrant_requests SET status = 'REJECTED', decided_by = ?, decided_at = ?, decision_note = ? WHERE request_id = ?",
        (decided_by, decided_at, reason, request_id),
    )
    conn.commit()
    conn.close()
    return {"status": "REJECTED", "reason": reason}


def verify_warrant(
    warrant_id: str, device_id: str, scope: str = "VIP_COMM_DATA",
    requested_category: str = DEFAULT_DATA_CATEGORY,
) -> tuple[bool, str]:
    """
    Memverifikasi apakah akses ke data VVIP didasari otorisasi yang sah.
    Ini lapisan terpisah dari autentikasi (token/JWT) -- device/token bisa
    saja sah, tapi tanpa warrant valid, akses tetap dianggap
    PENYALAHGUNAAN AKSES OLEH PIHAK BERWENANG (insider abuse), persis pola
    kasus nyata penyalahgunaan LIMS/PenLink tanpa izin pengadilan.

    requested_category diperiksa terhadap data_category yang tertera di
    warrant -- warrant METADATA_ONLY tidak bisa dipakai untuk minta
    FULL_CONTENT (prinsip minimisasi data), walau device & scope-nya cocok.
    """
    init_forensic_db()
    if requested_category not in CATEGORY_RANK:
        requested_category = DEFAULT_DATA_CATEGORY
    if not warrant_id:
        return False, "Tidak ada Warrant-ID disertakan pada request"

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT device_id, scope, data_category, valid_until, revoked, issued_by, revoked_by, revocation_reason "
        "FROM warrant_registry WHERE warrant_id = ?",
        (warrant_id,),
    )
    row = c.fetchone()
    conn.close()

    if not row:
        return False, f"Warrant-ID '{warrant_id}' tidak terdaftar di registry"

    reg_device_id, reg_scope, reg_category, valid_until, revoked, issued_by, revoked_by, revocation_reason = row

    if revoked:
        who = revoked_by or "otoritas penerbit"
        why = revocation_reason or "tanpa alasan tercatat"
        return False, f"Warrant '{warrant_id}' telah dicabut oleh {who} ({why})"

    if datetime.now() > datetime.fromisoformat(valid_until):
        return False, f"Warrant '{warrant_id}' kedaluwarsa pada {valid_until}"

    if reg_device_id != device_id:
        return False, f"Warrant '{warrant_id}' diterbitkan untuk device lain, bukan '{device_id}' (scope mismatch)"

    if reg_scope != scope:
        return False, f"Warrant '{warrant_id}' tidak mencakup scope '{scope}'"

    if CATEGORY_RANK.get(reg_category, 0) < CATEGORY_RANK.get(requested_category, 0):
        return False, (
            f"Warrant '{warrant_id}' hanya mengizinkan kategori '{reg_category}', "
            f"tapi yang diminta '{requested_category}' (pelanggaran prinsip minimisasi/proporsionalitas data)"
        )

    return True, f"Warrant sah ({reg_category}), diterbitkan oleh {issued_by}"


def revoke_warrant(warrant_id: str, revoked_by: str, reason: str) -> dict:
    """
    Mencabut warrant yang sudah terbit SEBELUM masa berlakunya habis sendiri --
    dipakai saat penyalahgunaan terdeteksi di tengah operasi. Setelah dicabut,
    warrant ini langsung ditolak oleh verify_warrant di permintaan berikutnya,
    walau secara waktu (valid_until) masih belum kedaluwarsa.
    """
    init_forensic_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT revoked FROM warrant_registry WHERE warrant_id = ?", (warrant_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "ERROR", "reason": f"Warrant '{warrant_id}' tidak ditemukan"}
    if row[0]:
        conn.close()
        return {"status": "ERROR", "reason": f"Warrant '{warrant_id}' sudah dicabut sebelumnya"}

    revoked_at = datetime.now().isoformat()
    c.execute(
        "UPDATE warrant_registry SET revoked = 1, revoked_by = ?, revoked_at = ?, revocation_reason = ? WHERE warrant_id = ?",
        (revoked_by[:60], revoked_at, reason[:200], warrant_id),
    )
    conn.commit()
    conn.close()
    return {
        "status": "REVOKED", "warrant_id": warrant_id,
        "revoked_by": revoked_by[:60], "revoked_at": revoked_at, "reason": reason[:200],
    }


def issue_vip_jwt(device_id: str, unit_code: str = "SATCOM-VVIP-01", ttl_seconds: int = 60) -> str:
    now = int(time.time())
    payload = {
        "sub": device_id,
        "unit": unit_code,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def verify_vip_jwt(token: str, expected_device_id: str | None = None) -> tuple[bool, str]:
    if not token:
        return False, "Token JWT tidak ditemukan"
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        if expected_device_id and decoded.get("sub") != expected_device_id:
            return False, "Device ID tidak cocok dengan tanda tangan token"
        return True, f"Valid ({decoded.get('unit')})"
    except jwt.ExpiredSignatureError:
        return False, "Token JWT kedaluwarsa (Replay Attack terdeteksi)"
    except jwt.InvalidTokenError:
        return False, "Tanda tangan JWT tidak sah"


def record_tamper_evident_dossier(session_id: str, dossier: dict) -> dict:
    init_forensic_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT curr_hash FROM adversary_ledger ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    prev_hash = row[0] if row else "0" * 64

    ts = datetime.now().isoformat()
    serialized = json.dumps(dossier, sort_keys=True)
    raw_block = f"{session_id}|{ts}|{serialized}|{prev_hash}".encode("utf-8")
    curr_hash = _block_hash(raw_block)

    c.execute(
        "INSERT INTO adversary_ledger (session_id, timestamp, payload_json, prev_hash, curr_hash) VALUES (?, ?, ?, ?, ?)",
        (session_id, ts, serialized, prev_hash, curr_hash),
    )
    conn.commit()
    conn.close()

    return {
        "session_id": session_id,
        "prev_hash": prev_hash[:16] + "...",
        "curr_hash": curr_hash,
        "integrity": "VERIFIED_CHAIN",
    }


def _verify_rows(rows) -> dict:
    expected_prev = "0" * 64
    for row_id, session_id, ts, serialized, prev_hash, curr_hash in rows:
        if prev_hash != expected_prev:
            return {"valid": False, "corrupted_id": row_id, "reason": "Rantai prev_hash terputus"}
        recomputed = _block_hash(f"{session_id}|{ts}|{serialized}|{prev_hash}".encode("utf-8"))
        if recomputed != curr_hash:
            return {"valid": False, "corrupted_id": row_id, "reason": "Payload forensik telah dimodifikasi"}
        expected_prev = curr_hash
    return {"valid": True, "total_blocks": len(rows), "head_hash": expected_prev}


def _read_ledger_rows():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, session_id, timestamp, payload_json, prev_hash, curr_hash FROM adversary_ledger ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    return rows


def verify_ledger_integrity() -> dict:
    init_forensic_db()
    return _verify_rows(_read_ledger_rows())


def simulate_tamper_check() -> dict:
    """Demo NON-DESTRUKTIF: salinan ledger di memori dimanipulasi, lalu diverifikasi.
    Database asli tidak disentuh."""
    init_forensic_db()
    rows = _read_ledger_rows()
    if not rows:
        return {"error": "Ledger masih kosong. Jalankan Tahap 03 dulu agar ada bukti yang bisa diuji."}

    idx = len(rows) - 1
    rid, sid, ts, payload, prev, curr = rows[idx]
    data = json.loads(payload)
    data["attacker_ip"] = "203.0.113.66"
    forged = json.dumps(data, sort_keys=True)

    # Skenario 1: isi diubah, hash dibiarkan.
    naive = rows[:idx] + [(rid, sid, ts, forged, prev, curr)]
    # Skenario 2: isi diubah DAN hash dihitung ulang dengan SHA-256 biasa (tanpa kunci ledger).
    plain = hashlib.sha256(f"{sid}|{ts}|{forged}|{prev}".encode("utf-8")).hexdigest()
    recomputed = rows[:idx] + [(rid, sid, ts, forged, prev, plain)]

    return {
        "block_id": rid,
        "original": _verify_rows(rows),
        "edited_payload": _verify_rows(naive),
        "edited_and_rehashed_without_key": _verify_rows(recomputed),
    }


def recent_warrant_requests(limit: int = 6) -> list[dict]:
    init_forensic_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT request_id, device_id, data_category, requested_by, decided_by, status, warrant_id, requested_at, decision_note "
        "FROM warrant_requests ORDER BY requested_at DESC LIMIT ?", (limit,),
    )
    rows = c.fetchall()
    conn.close()
    keys = ["request_id", "device_id", "data_category", "requested_by", "decided_by", "status", "warrant_id", "requested_at", "decision_note"]
    return [dict(zip(keys, r)) for r in rows]
