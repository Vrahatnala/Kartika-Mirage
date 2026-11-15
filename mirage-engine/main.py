from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import httpx
import uuid
import os
import glob
import hmac
import ipaddress
import re
import html
from urllib.parse import urlparse
from datetime import datetime
from deception import create_poisoned_pdf, create_poisoned_html_decoy, create_poisoned_docx, GEN_DIR
from ml_detector import BehavioralAnomalyDetector
from security_core import (
    BASE_DIR,
    ADMIN_KEY,
    VIP_STATIC_TOKEN,
    init_forensic_db,
    issue_vip_jwt,
    verify_vip_jwt,
    record_tamper_evident_dossier,
    verify_ledger_integrity,
    issue_warrant,
    verify_warrant,
    request_warrant,
    approve_warrant_request,
    reject_warrant_request,
    list_pending_warrant_requests,
    expire_all_pending,
    simulate_tamper_check,
    recent_warrant_requests,
    revoke_warrant,
    CATEGORY_RANK,
    DEFAULT_DATA_CATEGORY,
)
import honeytoken
import tarpit
from intel_enrichment import enrich_adversary_ip, create_tactical_audio_decoy
import uvicorn

# Catatan: TIDAK memakai CORSMiddleware global. Hanya /api/telemetry yang boleh dipanggil
# lintas-origin (beacon dari file:// di perangkat penyadap). Endpoint admin tidak boleh.
app = FastAPI(title="KARTIKA-MIRAGE Active Counter-Surveillance")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
detector = BehavioralAnomalyDetector()
init_forensic_db()

VIP_GATEWAY_URL = "http://127.0.0.1:8001/api/vip/comm-status"
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

SESSION_ID_REGEX = re.compile(r"^[A-F0-9]{8}$")
DEVICE_ID_REGEX = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
HOST_REGEX = re.compile(r"^[A-Za-z0-9.\-]{1,100}(:\d{1,5})?$")
MAX_TELEMETRY_PER_SESSION = 30

events_log = []
captured_adversaries = []
active_decoy_sessions = set()
telemetry_counts = {}
last_session_id = None
latest_threat_score = 18


def _validate_session_id(session_id: str):
    if not session_id or not SESSION_ID_REGEX.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session format")


def _clean_device_id(value, default=None):
    if value and DEVICE_ID_REGEX.match(value):
        return value
    return default


def _clean_category(value):
    return value if value in CATEGORY_RANK else DEFAULT_DATA_CATEGORY


def _trim_storage():
    if len(events_log) > 50:
        del events_log[:-50]
    if len(captured_adversaries) > 50:
        del captured_adversaries[:-50]
    files = sorted(glob.glob(os.path.join(GEN_DIR, "*")), key=os.path.getmtime)
    for old_file in files[:-45]:
        try:
            os.remove(old_file)
        except OSError:
            pass


def _get_real_ip(request: Request) -> str:
    if TRUST_PROXY:
        ip = (
            request.headers.get("cf-connecting-ip")
            or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        )
        if ip:
            return ip
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def _is_local(request: Request) -> bool:
    """Lokal = koneksi langsung dari loopback DAN tidak lewat proxy/tunnel.
    Request yang membawa header proxy (cf-connecting-ip, x-forwarded-for, forwarded)
    tidak pernah dianggap lokal, jadi tunnel tidak otomatis mendapat hak admin."""
    if any(request.headers.get(h) for h in ("cf-connecting-ip", "x-forwarded-for", "forwarded")):
        return False
    host = request.client.host if request.client else ""
    return host in ("127.0.0.1", "::1", "testclient")


def _verify_admin(request: Request, x_admin_key: str = ""):
    key = x_admin_key or request.headers.get("x-admin-key", "")
    if key and hmac.compare_digest(key, ADMIN_KEY):
        return True
    if _is_local(request):
        # Tolak request lintas-origin dari browser operator (CSRF / situs jahat).
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host", ""):
            raise HTTPException(status_code=403, detail="Cross-origin admin request ditolak")
        return True
    raise HTTPException(status_code=403, detail="Unauthorized: Admin key required")


def _host_allowed(host: str) -> bool:
    """Tanpa PUBLIC_BASE_URL, hanya Host berupa localhost / alamat IP yang dipercaya
    (mencegah penyerang menyuntikkan domain sendiri ke URL beacon)."""
    if not HOST_REGEX.match(host):
        return False
    name = host.rsplit(":", 1)[0] if re.search(r":\d+$", host) else host
    if name == "localhost":
        return True
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def _base_url(request: Request) -> str:
    """URL dasar untuk beacon. Saat memakai tunnel/domain, WAJIB set PUBLIC_BASE_URL."""
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    host = request.headers.get("host", "")
    if not _host_allowed(host):
        print(f"[PERINGATAN] Host '{host[:60]}' tidak dipercaya; beacon memakai 127.0.0.1:8000. "
              f"Set PUBLIC_BASE_URL jika memakai tunnel/domain.")
        host = "127.0.0.1:8000"
    return f"{request.url.scheme}://{host}"


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Kunci admin hanya disuntikkan ke dashboard untuk operator lokal.
    admin_key = ADMIN_KEY if _is_local(request) else ""
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"admin_key": admin_key})


@app.post("/api/auth/issue-token")
async def generate_ephemeral_token(request: Request, device_id: str = "VIP-HANDSET-01", ttl: int = 60, x_admin_key: str = Header(default="")):
    _verify_admin(request, x_admin_key)
    device_id = _clean_device_id(device_id)
    if not device_id:
        raise HTTPException(status_code=400, detail="Invalid device_id")
    ttl_clamped = max(15, min(ttl, 300))
    token = issue_vip_jwt(device_id=device_id, ttl_seconds=ttl_clamped)
    return {
        "status": "ISSUED",
        "device_id": device_id,
        "expires_in_seconds": ttl_clamped,
        "token": token,
    }


@app.get("/api/forensics/verify-chain")
async def check_forensic_chain(request: Request, x_admin_key: str = Header(default="")):
    _verify_admin(request, x_admin_key)
    return verify_ledger_integrity()


@app.post("/api/forensics/simulate-tamper")
async def forensic_tamper_demo(request: Request, x_admin_key: str = Header(default="")):
    """Demo non-destruktif: memanipulasi SALINAN ledger di memori dan memverifikasinya."""
    _verify_admin(request, x_admin_key)
    return simulate_tamper_check()


@app.post("/api/warrant/issue")
async def admin_issue_warrant(
    request: Request,
    device_id: str = "VIP-HANDSET-01",
    issued_by: str = "Pengadilan Negeri Jakarta Pusat",
    purpose: str = "Pengamanan VVIP",
    data_category: str = DEFAULT_DATA_CATEGORY,
    ttl_minutes: int = 60,
    x_admin_key: str = Header(default=""),
):
    """Simulasi penerbitan surat izin akses resmi (warrant). Hanya admin."""
    _verify_admin(request, x_admin_key)
    device_id = _clean_device_id(device_id)
    if not device_id:
        raise HTTPException(status_code=400, detail="Invalid device_id")
    warrant = issue_warrant(
        device_id=device_id, issued_by=issued_by[:60], purpose=purpose[:120],
        data_category=_clean_category(data_category),
        ttl_minutes=max(1, min(ttl_minutes, 1440)),
    )
    return {"status": "WARRANT_ISSUED", **warrant}


@app.post("/api/warrant/revoke")
async def admin_revoke_warrant(
    request: Request,
    warrant_id: str,
    revoked_by: str,
    reason: str = "Dugaan penyalahgunaan terdeteksi",
    x_admin_key: str = Header(default=""),
):
    """
    Mencabut warrant yang sudah terbit SEBELUM masa berlakunya habis --
    dipakai saat penyalahgunaan terdeteksi di tengah operasi berjalan.
    """
    _verify_admin(request, x_admin_key)
    return revoke_warrant(warrant_id=warrant_id, revoked_by=revoked_by, reason=reason)


@app.post("/api/warrant/request")
async def submit_warrant_request(
    device_id: str = "VIP-HANDSET-01",
    purpose: str = "Pengamanan VVIP",
    data_category: str = DEFAULT_DATA_CATEGORY,
    requested_by: str = "Operator",
):
    """Langkah 1 (dual-control): pengajuan berstatus PENDING, tidak memberi akses apa pun."""
    device_id = _clean_device_id(device_id)
    if not device_id:
        raise HTTPException(status_code=400, detail="Invalid device_id")
    req = request_warrant(
        device_id=device_id, purpose=purpose, requested_by=requested_by,
        data_category=_clean_category(data_category),
    )
    if req.get("status") == "QUEUE_FULL":
        raise HTTPException(status_code=429, detail=req["reason"])
    return {"status": "REQUEST_SUBMITTED", **req}


@app.get("/api/warrant/pending")
async def admin_list_pending(request: Request, x_admin_key: str = Header(default="")):
    _verify_admin(request, x_admin_key)
    return {"pending_requests": list_pending_warrant_requests()}


@app.post("/api/warrant/approve")
async def admin_approve_warrant(
    request: Request,
    request_id: str,
    decided_by: str,
    ttl_minutes: int = 60,
    x_admin_key: str = Header(default=""),
):
    """Langkah 2: pihak independen menyetujui. decided_by harus berbeda dari requested_by
    (dibandingkan setelah normalisasi; kontrol tingkat demo, bukan identitas terverifikasi)."""
    _verify_admin(request, x_admin_key)
    return approve_warrant_request(
        request_id=request_id, decided_by=decided_by[:60], ttl_minutes=max(1, min(ttl_minutes, 1440))
    )


@app.post("/api/warrant/reject")
async def admin_reject_warrant(
    request: Request,
    request_id: str,
    decided_by: str,
    reason: str = "Tidak memenuhi syarat",
    x_admin_key: str = Header(default=""),
):
    _verify_admin(request, x_admin_key)
    return reject_warrant_request(request_id=request_id, decided_by=decided_by[:60], reason=reason[:200])



_CONFIDENCE = {
    "honeytoken_portal": "TINGGI: kredensial unik sesi dipakai di portal",
    "honeytoken_gateway": "TINGGI: kredensial unik sesi dipakai di gateway",
    "pdf_link": "TINGGI: tautan lampiran diklik manual",
    "docx_link": "TINGGI: tautan lampiran diklik manual",
    "img_pixel": "SEDANG: bisa pratinjau/pemindai otomatis",
    "js_telemetry": "SEDANG: skrip jalan di peramban (dokumen dibuka)",
}


async def _record_hit(request: Request, session_id: str, channel: str, tz: str = "Unknown", res: str = "Unknown"):
    """Catat satu pemicu umpan (beacon / honeytoken): dossier, ledger, event. Mengembalikan chain_proof,
    atau None jika batas per sesi terlampaui."""
    global latest_threat_score
    telemetry_counts[session_id] = telemetry_counts.get(session_id, 0) + 1
    if telemetry_counts[session_id] > MAX_TELEMETRY_PER_SESSION:
        return None
    safe_channel = html.escape(channel)[:40]
    safe_tz = html.escape(tz)[:40]
    safe_res = html.escape(res)[:20]
    latest_threat_score = 99
    attacker_ip = _get_real_ip(request)
    intel = await enrich_adversary_ip(attacker_ip)
    confidence = _CONFIDENCE.get(channel, "N/A: uji internal / langsung")
    adversary_info = {
        "session_id": session_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip": attacker_ip,
        "isp": intel["isp"],
        "asn": intel["asn"],
        "network_type": intel["network_type"],
        "location": intel["location"],
        "user_agent": html.escape(request.headers.get("user-agent", "Unknown"))[:140],
        "channel": safe_channel,
        "confidence": confidence,
        "timezone": safe_tz,
        "screen_res": safe_res,
    }
    chain_proof = record_tamper_evident_dossier(session_id, adversary_info)
    adversary_info["forensic_hash"] = chain_proof["curr_hash"][:16] + "..."
    captured_adversaries.append(adversary_info)
    events_log.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": "COUNTER_INTEL",
        "score": 99,
        "detail": f"TELEMETRI [{safe_channel.upper()}] sesi [{session_id}] | IP: {attacker_ip} ({intel['isp']} - {intel['network_type']}) | Keyakinan: {confidence} | Hash: {adversary_info['forensic_hash']}"
    })
    _trim_storage()
    return chain_proof


@app.get("/gateway/vip-stream")
async def inspect_traffic(request: Request, format: str = "pdf"):
    global latest_threat_score, last_session_id
    client_ip = _get_real_ip(request)
    headers_dict = dict(request.headers)
    token = headers_dict.get("x-vip-token", "")
    device_id = _clean_device_id(headers_dict.get("x-device-id"))
    simulated_burst = headers_dict.get("x-simulated-burst") == "1"  # hook demo

    # Honeytoken: kredensial umpan dari dokumen yang bocor dipakai di gateway.
    bearer = headers_dict.get("authorization", "")
    bearer = bearer[7:] if bearer.lower().startswith("bearer ") else bearer
    hit_sid = honeytoken.lookup(token) or honeytoken.lookup(bearer)
    if hit_sid:
        await _record_hit(request, hit_sid, "honeytoken_gateway")
        return JSONResponse(status_code=200, content={
            "status": "AUTHENTICATED_CHANNEL", "channel": "SATCOM-KARTIKA-01",
            "message": "Sesi terverifikasi.",
        })

    # Layer 2: Evaluasi perilaku (Isolation Forest + aturan) secara independen
    ai_result = detector.evaluate(client_ip, headers_dict, simulated_burst=simulated_burst)
    ai_score = ai_result["threat_score"]
    why = "; ".join(ai_result["reasons"]) or "perilaku normal"

    # Layer 1: JWT berumur pendek atau kunci statis (legacy)
    jwt_valid, jwt_msg = verify_vip_jwt(token, expected_device_id=device_id)
    static_valid = hmac.compare_digest(token, VIP_STATIC_TOKEN)
    token_valid = jwt_valid or static_valid
    auth_mode = f"JWT ({jwt_msg})" if jwt_valid else ("Static-VIP-Key" if static_valid else jwt_msg)

    # Layer 3: Warrant -- hanya dicek kalau Layer 1 & 2 lolos. Kategori data yang
    # DIMINTA (dari header klien) dicocokkan dengan kategori yang DIIZINKAN warrant.
    warrant_id = headers_dict.get("x-warrant-id", "")[:40]
    requested_category = _clean_category(headers_dict.get("x-data-category", DEFAULT_DATA_CATEGORY))
    warrant_valid, warrant_msg = (False, "Belum dicek (auth/AI gagal lebih dulu)")
    if token_valid and not ai_result["is_anomaly"]:
        warrant_valid, warrant_msg = verify_warrant(
            warrant_id, device_id or "UNKNOWN_DEVICE", requested_category=requested_category
        )

    if token_valid and not ai_result["is_anomaly"] and warrant_valid:
        latest_threat_score = ai_score
        fallback = {
            "status": "AUTHENTICATED_CHANNEL",
            "channel": "SATCOM-KARTIKA-01",
            "auth_method": auth_mode,
            "warrant": warrant_msg,
            "message": "Sesi VIP terverifikasi, AI Risk rendah, & Warrant sah. Diteruskan ke Gateway.",
        }
        vip_data = fallback
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                # Ke gateway internal memakai kunci layanan, bukan token milik pengguna.
                resp = await client.get(
                    VIP_GATEWAY_URL,
                    headers={"x-vip-token": VIP_STATIC_TOKEN, "x-data-category": requested_category},
                )
            if resp.status_code == 200:
                vip_data = {**resp.json(), "auth_method": auth_mode, "warrant": warrant_msg,
                            "data_category": requested_category,
                            "message": "Sesi VIP terverifikasi, AI Risk rendah, & Warrant sah. " + resp.json().get("message", "")}
        except Exception:
            pass

        events_log.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "LEGITIMATE",
            "score": ai_score,
            "detail": f"Auth: {auth_mode} | AI Risk: {ai_score}% | Kategori: {requested_category} | Warrant: {warrant_msg}"
        })
        _trim_storage()
        return JSONResponse(status_code=200, content=vip_data)

    # Skor komposit untuk insiden: penolakan Layer-1 / pelanggaran otorisasi tidak boleh tampil "rendah".
    if not token_valid:
        incident_type = "EXTERNAL_INTRUSION"
        event_score = max(ai_score, 75)
        reason = f"[EXTERNAL_INTRUSION] Layer-1 ditolak [{jwt_msg}] | skor AI {ai_score}% ({why})"
    elif ai_result["is_anomaly"]:
        incident_type = "EXTERNAL_INTRUSION"
        event_score = ai_score
        reason = f"[EXTERNAL_INTRUSION] Layer-2 AI menangkap meski auth sah | AI Risk {ai_score}% ({why})"
    else:
        incident_type = "INSIDER_ABUSE_SUSPECTED"
        event_score = max(ai_score, 80)
        reason = f"[INSIDER_ABUSE_SUSPECTED] Auth & AI lolos (AI {ai_score}%), tapi Warrant ditolak: {warrant_msg}"
    latest_threat_score = event_score

    session_id = str(uuid.uuid4())[:8].upper()
    active_decoy_sessions.add(session_id)
    last_session_id = session_id

    base_url = _base_url(request)

    pdf_path = create_poisoned_pdf(session_id, base_url)
    html_path = create_poisoned_html_decoy(session_id, base_url)
    docx_path = create_poisoned_docx(session_id, base_url)
    wav_path = create_tactical_audio_decoy(session_id)

    fmt = format.lower()
    if fmt == "html":
        chosen_path, chosen_name, chosen_mime = html_path, f"INTERCEPTED_BRIEFING_{session_id}.html", "text/html"
    elif fmt == "docx":
        chosen_path, chosen_name, chosen_mime = docx_path, f"RAHASIA_OPERASI_VVIP_{session_id}.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    elif fmt in ["wav", "audio"]:
        chosen_path, chosen_name, chosen_mime = wav_path, f"SATCOM_VOICE_INTERCEPT_{session_id}.wav", "audio/wav"
    else:
        fmt = "pdf"
        chosen_path, chosen_name, chosen_mime = pdf_path, f"RAHASIA_PERGERAKAN_VVIP_{session_id}.pdf", "application/pdf"

    events_log.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": "MIRAGE_ENGAGED",
        "incident_type": incident_type,
        "score": event_score,
        "detail": f"{reason} -> Mengirim Umpan {fmt.upper()} [{session_id}]."
    })
    _trim_storage()

    return FileResponse(
        path=chosen_path,
        filename=chosen_name,
        media_type=chosen_mime,
        headers={
            "X-Mirage-Session": session_id,
            "X-Mirage-Incident": incident_type,
            "Access-Control-Expose-Headers": "X-Mirage-Session, X-Mirage-Incident",
        },
    )


@app.post("/portal/login")
async def portal_login(request: Request):
    """Portal umpan. Kredensial benar-benar hanya ada di dokumen umpan; pemakaiannya = pemicu berkeyakinan tinggi."""
    try:
        body = await request.json()
    except Exception:
        form = await request.form()
        body = dict(form)
    user = str(body.get("username", ""))[:80]
    pw = str(body.get("password", ""))[:80]
    sid = honeytoken.lookup(pw) or honeytoken.lookup(user)
    if sid:
        await _record_hit(request, sid, "honeytoken_portal")
        tp = tarpit.open_session(sid)
        resp = JSONResponse({"status": "ok", "message": "Sesi koordinasi dibuka", "next": "/portal/files", "token": tp})
        resp.set_cookie("tp", tp, httponly=True, samesite="lax", path="/portal")
        return resp
    return JSONResponse(status_code=401, content={"status": "error", "message": "Pengguna atau sandi salah"})


def _tarpit_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get("tp") or request.query_params.get("t", "")


def _tarpit_finished(sess: dict, mode: str, seconds: float):
    """Callback saat satu koneksi tertahan berakhir: catat ringkasan ke ledger berantai."""
    if seconds < 1:
        return
    chain = record_tamper_evident_dossier(sess["sid"], {
        "channel": "tarpit", "mode": mode, "seconds_held": round(seconds, 1),
        "session_total_seconds": round(sess["wasted"], 1), "requests": sess["requests"],
    })
    events_log.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": "TARPIT",
        "score": 99,
        "detail": f"TAR-PIT sesi [{sess['sid']}] mode {mode.upper()}: penyerang tertahan {seconds:.0f} dtk "
                  f"(total sesi {sess['wasted']:.0f} dtk) | Hash: {chain['curr_hash'][:16]}...",
    })
    _trim_storage()


@app.get("/portal/files")
@app.get("/portal/files/{path:path}")
async def portal_files(request: Request, path: str = ""):
    sess = tarpit.get_session(_tarpit_token(request))
    if not sess:
        raise HTTPException(status_code=401, detail="Sesi tidak valid")
    ip = _get_real_ip(request)
    mode = tarpit.classify(sess, request.headers.get("user-agent", ""))
    if not tarpit.try_acquire(ip):
        # Batas pelindung server tercapai: jawab cepat dan biasa saja (tanpa menahan koneksi).
        raise HTTPException(status_code=503, detail="Layanan sibuk, coba lagi nanti")
    if not sess["announced"]:
        sess["announced"] = True
        events_log.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "TARPIT",
            "score": 99,
            "detail": f"TAR-PIT aktif untuk sesi [{sess['sid']}] ({ip}): penyerang masuk portal umpan; perilakunya dinilai secara adaptif.",
        })
        _trim_storage()
    lines = tarpit.page_lines(sess["sid"], path, mode)
    return StreamingResponse(
        tarpit.slow_stream(sess, ip, lines, mode, on_end=_tarpit_finished),
        media_type="text/html; charset=utf-8",
    )


@app.get("/sandbox/open/{session_id}", response_class=HTMLResponse)
async def open_decoy_in_sandbox(session_id: str, request: Request):
    _validate_session_id(session_id)
    if session_id not in active_decoy_sessions:
        raise HTTPException(status_code=404, detail="Decoy session not found or expired")
    filepath = os.path.join(GEN_DIR, f"BRIEFING_VVIP_{session_id}.html")
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Decoy artifact file missing")
    with open(filepath, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/assets/{session_id}")
@app.get("/api/telemetry/{session_id}")
async def track_adversary(session_id: str, request: Request, channel: str = "direct", tz: str = "Unknown", res: str = "Unknown"):
    _validate_session_id(session_id)
    if session_id not in active_decoy_sessions:
        raise HTTPException(status_code=404, detail="Invalid session ID")
    chain_proof = await _record_hit(request, session_id, channel, tz, res)
    if chain_proof is None:
        raise HTTPException(status_code=429, detail="Telemetry limit per session")
    return JSONResponse(
        content={
            "status": "TELEMETRY_CAPTURED",
            "session_id": session_id,
            "forensic_chain": chain_proof,
        },
        headers={"Access-Control-Allow-Origin": "*"},
    )


@app.get("/api/state")
async def get_state(request: Request, x_admin_key: str = Header(default="")):
    _verify_admin(request, x_admin_key)
    return {
        "events": events_log[::-1],
        "adversaries": captured_adversaries[::-1],
        "latest_score": latest_threat_score,
        "latest_session_id": last_session_id,
        "forensic_chain": verify_ledger_integrity(),
        "warrants": recent_warrant_requests(),
        "tarpit": tarpit.snapshot(),
    }


@app.post("/api/reset")
async def reset_state(request: Request, x_admin_key: str = Header(default="")):
    global last_session_id
    _verify_admin(request, x_admin_key)
    events_log.clear()
    captured_adversaries.clear()
    active_decoy_sessions.clear()
    telemetry_counts.clear()
    honeytoken.clear()
    tarpit.clear()
    expire_all_pending()
    last_session_id = None
    for f in glob.glob(os.path.join(GEN_DIR, "*")):
        try:
            os.remove(f)
        except OSError:
            pass
    return {"status": "RESET_OK", "message": "Log audit dan profil penyadap berhasil dibersihkan. (Ledger forensik sengaja tidak dihapus.)"}


if __name__ == "__main__":
    print("KARTIKA-MIRAGE siap. Buka http://127.0.0.1:8000 (kunci admin: data/.mirage_secrets.json)")
    uvicorn.run(app, host="127.0.0.1", port=8000, proxy_headers=False)
