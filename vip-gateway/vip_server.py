import hmac
import json
import os
import time

from fastapi import FastAPI, Header, HTTPException
import uvicorn

app = FastAPI(title="VIP Tactical Comm Gateway")

SECRETS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mirage-engine", "data", ".mirage_secrets.json")


def _load_service_key() -> str:
    """Kunci layanan internal (bukan token pengguna). Sumber: env, atau file secret milik engine.
    Menunggu sampai 30 detik agar urutan start engine/gateway tidak penting."""
    key = os.getenv("VIP_GATEWAY_TOKEN")
    if key:
        return key
    for _ in range(60):
        try:
            with open(SECRETS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)["vip_token"]
        except (OSError, KeyError, ValueError):
            time.sleep(0.5)
    raise SystemExit("Kunci layanan tidak ditemukan. Jalankan mirage-engine/main.py (membuat "
                     "data/.mirage_secrets.json) atau set VIP_GATEWAY_TOKEN.")


SERVICE_KEY = _load_service_key()


@app.get("/api/vip/comm-status")
async def get_vip_comm(x_vip_token: str = Header(default=""), x_data_category: str = Header(default="METADATA_ONLY")):
    if not hmac.compare_digest(x_vip_token, SERVICE_KEY):
        raise HTTPException(status_code=403, detail="Unauthorized Access")

    # Prinsip minimisasi data: endpoint internal ini pun TIDAK membalas isi
    # komunikasi penuh kecuali kategori yang diminta memang FULL_CONTENT --
    # gateway (main.py) hanya meneruskan kategori yang sudah diizinkan warrant,
    # tapi endpoint ini tetap jaga-jaga menahan diri sesuai kategori yang diminta.
    base = {
        "status": "ENCRYPTED_ACTIVE",
        "channel": "SATCOM-KARTIKA-01",
        "location_status": "Dalam area aman, pergerakan terakhir 14:02 WIB",
    }
    if x_data_category == "FULL_CONTENT":
        base["content_excerpt"] = "[SIMULASI DEMO] Isi komunikasi taktis -- placeholder, bukan data sungguhan."
        base["message"] = "Koordinat & isi komunikasi VVIP terenkripsi AES-256. Aman."
    else:
        base["message"] = "Koordinat pergerakan VVIP terenkripsi AES-256. Aman. (Isi komunikasi tidak disertakan -- di luar scope METADATA_ONLY.)"
    return base


if __name__ == "__main__":
    # Hanya menerima koneksi dari mesin yang sama (engine memanggilnya).
    uvicorn.run(app, host="127.0.0.1", port=8001)
