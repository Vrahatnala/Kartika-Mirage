"""
KARTIKA-MIRAGE :: Automated Self-Red-Team Agent
================================================
Script pengujian ofensif OTOMATIS yang menjalankan serangkaian skenario
terstruktur terhadap instance KARTIKA-MIRAGE milik SENDIRI, lalu
menghasilkan laporan pass/fail yang bisa langsung dipakai sebagai bukti
di dokumentasi/video demo hackathon (kategori Penindakan).

BATASAN KERAS -- DIBACA DULU SEBELUM MENJALANKAN:
--------------------------------------------------
Script ini HANYA BOLEH menyerang instance KARTIKA-MIRAGE yang berjalan di
localhost (127.0.0.1 / localhost / ::1). Ini BUKAN alat untuk menyerang
sistem, jaringan, atau infrastruktur milik pihak lain -- script ini akan
MENOLAK berjalan (exit) kalau --target diarahkan ke host selain localhost.

Ini bukan pembatasan teknis sembarangan: ini yang menjaga agar
KARTIKA-MIRAGE tetap murni "self red-teaming" (menguji ketahanan sistem
sendiri secara aktif), bukan tool serangan terhadap pihak ketiga --
sesuai larangan eksplisit di rulebook hackathon soal karya yang
mengandung "malware aktif yang ditujukan untuk merusak pihak ketiga di
luar konteks demo".

Cara pakai:
    pip install httpx   (biasanya sudah ada karena dipakai mirage-engine)
    python red_team_agent.py
    python red_team_agent.py --target http://127.0.0.1:8000   (default, boleh ditulis eksplisit)

Prasyarat: vip_server.py (port 8001) dan main.py (port 8000) sudah berjalan.
"""

import argparse
import json
import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
REPORT_DIR = Path(__file__).resolve().parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)

# User-Agent "browser" dipakai untuk skenario yang MESTINYA terlihat sah (bukan bot).
# User-Agent "bot" sengaja mengandung kata kunci yang dikenali ml_detector.py sebagai
# ciri tool otomatis (curl/python/httpx/bot/dst) untuk memicu deteksi anomali perilaku.
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept-Language": "id-ID",
}
BOT_HEADERS = {"User-Agent": "python-redteam-autoscan/1.0"}


def _assert_target_is_local(base_url: str) -> None:
    host = urlparse(base_url).hostname or ""
    if host not in ALLOWED_HOSTS:
        print(f"[DITOLAK] Target '{host}' bukan localhost.")
        print("Script ini HANYA boleh menguji instance KARTIKA-MIRAGE milik sendiri (127.0.0.1).")
        print("Menyerang host lain di luar batas ini melanggar rulebook hackathon & etika pengujian.")
        sys.exit(1)


class RedTeamAgent:
    def __init__(self, base_url: str):
        _assert_target_is_local(base_url)
        self.base = base_url.rstrip("/")
        self.client = httpx.Client(timeout=5.0)
        self.results = []

    # ---------- util ----------

    def _log(self, name: str, expected: str, actual: str, passed: bool, detail: str = "") -> None:
        entry = {
            "scenario": name,
            "expected": expected,
            "actual": actual,
            "passed": passed,
            "detail": detail,
            "time": datetime.now().strftime("%H:%M:%S"),
        }
        self.results.append(entry)
        mark = "LOLOS" if passed else "GAGAL"
        print(f"[{mark:>5}] {name:<48} expected={expected:<26} actual={actual}")
        if detail and not passed:
            print(f"          detail: {detail}")

    # ---------- panggilan API ----------

    def issue_token(self, device_id: str, ttl: int = 60) -> str:
        r = self.client.post(
            f"{self.base}/api/auth/issue-token",
            params={"device_id": device_id, "ttl": ttl},
            headers=BROWSER_HEADERS,
        )
        r.raise_for_status()
        return r.json()["token"]

    def request_warrant(self, device_id: str, requested_by: str, data_category: str = "METADATA_ONLY") -> dict:
        r = self.client.post(
            f"{self.base}/api/warrant/request",
            params={
                "device_id": device_id, "purpose": "Red-team self-test",
                "requested_by": requested_by, "data_category": data_category,
            },
            headers=BROWSER_HEADERS,
        )
        return r.json()

    def approve_warrant(self, request_id: str, decided_by: str) -> dict:
        r = self.client.post(
            f"{self.base}/api/warrant/approve",
            params={"request_id": request_id, "decided_by": decided_by},
            headers=BROWSER_HEADERS,
        )
        return r.json()

    def revoke_warrant(self, warrant_id: str, revoked_by: str, reason: str) -> dict:
        r = self.client.post(
            f"{self.base}/api/warrant/revoke",
            params={"warrant_id": warrant_id, "revoked_by": revoked_by, "reason": reason},
            headers=BROWSER_HEADERS,
        )
        return r.json()

    def get_approved_warrant(self, device_id: str, requested_by: str, approver: str) -> str | None:
        """Helper: ajukan + setujui 1 warrant METADATA_ONLY, kembalikan warrant_id-nya."""
        req = self.request_warrant(device_id, requested_by=requested_by)
        approval = self.approve_warrant(req["request_id"], decided_by=approver)
        if approval.get("status") != "APPROVED":
            return None
        return approval["warrant"]["warrant_id"]

    def hit_gateway(self, headers: dict, simulated_burst: bool = False):
        # Jeda ini penting: detektor AI mengukur interval waktu antar-request dari
        # IP yang sama. Tanpa jeda, panggilan beruntun dari script ini sendiri bisa
        # salah terdeteksi sebagai "burst" walau skenarionya memang mau diuji sebagai
        # perilaku normal. Untuk skenario yang MEMANG ingin memicu burst, dipakai
        # header X-Simulated-Burst (hook demo yang sudah disediakan main.py), bukan
        # mengandalkan timing yang rapuh.
        time.sleep(0.6)
        h = dict(headers)
        if simulated_burst:
            h["X-Simulated-Burst"] = "1"
        r = self.client.get(f"{self.base}/gateway/vip-stream", headers=h)
        incident = r.headers.get("X-Mirage-Incident")
        if incident:
            # Hanya respons decoy (MIRAGE_ENGAGED) yang membawa header ini.
            return incident
        if r.status_code == 200:
            # 200 TANPA header insiden = request diteruskan ke VIP gateway asli
            # (lolos ketiga lapis). Isi body-nya datang dari vip_server.py, bukan
            # selalu "AUTHENTICATED_CHANNEL" -- itu cuma nilai fallback kalau
            # vip_server.py sedang tidak bisa dihubungi, jadi tidak boleh dijadikan
            # satu-satunya penanda sukses.
            return "LEGITIMATE"
        return f"HTTP_{r.status_code}"

    # ---------- skenario ----------

    def scenario_1_no_token(self) -> None:
        incident = self.hit_gateway(headers=BROWSER_HEADERS)
        self._log(
            "1. Tanpa token sama sekali (penyusup eksternal)",
            "EXTERNAL_INTRUSION", incident, incident == "EXTERNAL_INTRUSION",
        )

    def scenario_2_bot_ua_with_token(self, device_id: str) -> None:
        token = self.issue_token(device_id)
        headers = {**BOT_HEADERS, "X-VIP-Token": token, "X-Device-ID": device_id}
        incident = self.hit_gateway(headers=headers, simulated_burst=True)
        self._log(
            "2. Token sah, tapi perilaku/User-Agent bot",
            "EXTERNAL_INTRUSION", incident, incident == "EXTERNAL_INTRUSION",
        )

    def scenario_3_valid_no_warrant(self, device_id: str) -> None:
        token = self.issue_token(device_id)
        headers = {**BROWSER_HEADERS, "X-VIP-Token": token, "X-Device-ID": device_id}
        incident = self.hit_gateway(headers=headers)
        self._log(
            "3. Token & perilaku sah, TANPA warrant (insider abuse)",
            "INSIDER_ABUSE_SUSPECTED", incident, incident == "INSIDER_ABUSE_SUSPECTED",
        )

    def scenario_4_self_approval_blocked(self, device_id: str) -> None:
        req = self.request_warrant(device_id, requested_by="Agen-RedTeam")
        result = self.approve_warrant(req["request_id"], decided_by="Agen-RedTeam")
        status = result.get("status", "UNKNOWN")
        self._log(
            "4. Coba setujui warrant sendiri (separation-of-duty)",
            "REJECTED_SEPARATION_OF_DUTY", status, status == "REJECTED_SEPARATION_OF_DUTY",
            detail=json.dumps(result, ensure_ascii=False),
        )

    def scenario_5_valid_warrant_legitimate(self, device_id: str) -> None:
        req = self.request_warrant(device_id, requested_by="Agen-RedTeam")
        approval = self.approve_warrant(req["request_id"], decided_by="Komandan-Independen")
        if approval.get("status") != "APPROVED":
            self._log(
                "5. Token+AI+Warrant (pihak independen) sah -> lolos",
                "LEGITIMATE", f"approval_gagal:{approval.get('status')}", False,
                detail=json.dumps(approval, ensure_ascii=False),
            )
            return
        warrant_id = approval["warrant"]["warrant_id"]
        token = self.issue_token(device_id)
        headers = {
            **BROWSER_HEADERS, "X-VIP-Token": token,
            "X-Device-ID": device_id, "X-Warrant-ID": warrant_id,
        }
        incident = self.hit_gateway(headers=headers)
        self._log(
            "5. Token+AI+Warrant (pihak independen) sah -> lolos",
            "LEGITIMATE", incident, incident == "LEGITIMATE",
        )

    def scenario_7_category_violation(self, device_id: str) -> None:
        # Warrant diajukan & disetujui HANYA untuk METADATA_ONLY, tapi requester
        # lalu mencoba minta FULL_CONTENT lewat header X-Data-Category -- harus
        # tetap ditolak sebagai insider abuse (pelanggaran minimisasi data),
        # walau device, token, dan perilaku semuanya sah.
        warrant_id = self.get_approved_warrant(device_id, requested_by="Agen-RedTeam", approver="Komandan-Independen")
        if not warrant_id:
            self._log("7. Warrant METADATA_ONLY dipakai minta FULL_CONTENT", "INSIDER_ABUSE_SUSPECTED", "GAGAL_SETUP_WARRANT", False)
            return
        token = self.issue_token(device_id)
        headers = {
            **BROWSER_HEADERS, "X-VIP-Token": token, "X-Device-ID": device_id,
            "X-Warrant-ID": warrant_id, "X-Data-Category": "FULL_CONTENT",
        }
        incident = self.hit_gateway(headers=headers)
        self._log(
            "7. Warrant METADATA_ONLY dipakai minta FULL_CONTENT (minimisasi data)",
            "INSIDER_ABUSE_SUSPECTED", incident, incident == "INSIDER_ABUSE_SUSPECTED",
        )

    def scenario_8_revoked_warrant_rejected(self, device_id: str) -> None:
        # Warrant sah diterbitkan, lalu DICABUT di tengah jalan (mis. penyalahgunaan
        # terdeteksi) -- percobaan akses berikutnya dengan warrant yang sama harus
        # tetap ditolak walau secara waktu warrant belum kedaluwarsa.
        warrant_id = self.get_approved_warrant(device_id, requested_by="Agen-RedTeam", approver="Komandan-Independen")
        if not warrant_id:
            self._log("8. Warrant yang sudah dicabut dipakai lagi", "INSIDER_ABUSE_SUSPECTED", "GAGAL_SETUP_WARRANT", False)
            return
        revoke_result = self.revoke_warrant(warrant_id, revoked_by="Inspektorat", reason="Simulasi: dugaan penyalahgunaan di tengah operasi")
        if revoke_result.get("status") != "REVOKED":
            self._log("8. Warrant yang sudah dicabut dipakai lagi", "INSIDER_ABUSE_SUSPECTED", f"GAGAL_REVOKE:{revoke_result}", False)
            return
        token = self.issue_token(device_id)
        headers = {
            **BROWSER_HEADERS, "X-VIP-Token": token,
            "X-Device-ID": device_id, "X-Warrant-ID": warrant_id,
        }
        incident = self.hit_gateway(headers=headers)
        self._log(
            "8. Warrant yang sudah dicabut dipakai lagi (revoke)",
            "INSIDER_ABUSE_SUSPECTED", incident, incident == "INSIDER_ABUSE_SUSPECTED",
        )

    def _decoy_html(self):
        """Pancing umpan HTML (tanpa token => Layer 1 menolak) dan kembalikan (session_id, isi_html)."""
        time.sleep(0.6)
        r = self.client.get(f"{self.base}/gateway/vip-stream", params={"format": "html"}, headers=BROWSER_HEADERS)
        return r.headers.get("X-Mirage-Session"), r.text

    def scenario_9_beacon_asset_path(self) -> None:
        sid, _ = self._decoy_html()
        r = self.client.get(f"{self.base}/assets/{sid}", params={"channel": "pdf_link"}, headers=BROWSER_HEADERS)
        ok = r.status_code == 200 and r.json().get("status") == "TELEMETRY_CAPTURED"
        self._log("9. Beacon lewat path /assets (tampak biasa) tercatat",
                  "TELEMETRY_CAPTURED", r.json().get("status", str(r.status_code)) if r.status_code == 200 else str(r.status_code), ok)

    def scenario_10_honeytoken(self) -> None:
        sid, body = self._decoy_html()
        user = re.search(r"Pengguna</td><td>: (\S+?)</td>", body)
        pw = re.search(r"Kata sandi</td><td>: (\S+?)</td>", body)
        name = "10. Kredensial umpan dipakai di portal -> tercatat berkeyakinan tinggi"
        if not (user and pw):
            self._log(name, "HONEYTOKEN_TERCATAT", "KREDENSIAL_TIDAK_ADA_DI_UMPAN", False)
            return
        bad = self.client.post(f"{self.base}/portal/login", json={"username": "admin", "password": "admin123"})
        good = self.client.post(f"{self.base}/portal/login", json={"username": user.group(1), "password": pw.group(1)})
        state = self.client.get(f"{self.base}/api/state", headers=BROWSER_HEADERS).json()
        hit = [a for a in state.get("adversaries", []) if a.get("session_id") == sid and a.get("channel") == "honeytoken_portal"]
        ok = bad.status_code == 401 and good.status_code == 200 and bool(hit) and str(hit[0].get("confidence", "")).startswith("TINGGI")
        self._log(name, "HONEYTOKEN_TERCATAT",
                  "HONEYTOKEN_TERCATAT" if ok else f"salah={bad.status_code} benar={good.status_code} hit={bool(hit)}", ok)

    def scenario_11_tarpit_holds_attacker(self) -> None:
        sid, body = self._decoy_html()
        name = "11. Tar-pit menahan pemakai honeytoken & waktu terbuang tercatat"
        user = re.search(r"Pengguna</td><td>: (\S+?)</td>", body)
        pw = re.search(r"Kata sandi</td><td>: (\S+?)</td>", body)
        if not (user and pw):
            self._log(name, "TERTAHAN", "KREDENSIAL_TIDAK_ADA_DI_UMPAN", False)
            return
        tok = self.client.post(f"{self.base}/portal/login", json={"username": user.group(1), "password": pw.group(1)}).json().get("token")
        before = self.client.get(f"{self.base}/api/state", headers=BROWSER_HEADERS).json()["tarpit"]["seconds_wasted"]
        t0 = time.time()
        got = 0
        with httpx.stream("GET", f"{self.base}/portal/files", timeout=30,
                          headers={"Authorization": f"Bearer {tok}", "User-Agent": "python-redteam-autoscan/1.0"}) as resp:
            for chunk in resp.iter_text():
                got += chunk.count("\n")
                if time.time() - t0 > 6:      # penyerang "menyerah" setelah 6 detik
                    break
        time.sleep(1.5)
        after = self.client.get(f"{self.base}/api/state", headers=BROWSER_HEADERS).json()["tarpit"]
        gained = after["seconds_wasted"] - before
        ok = gained >= 4 and after["active"] == 0 and got <= 4
        self._log(name, "TERTAHAN", "TERTAHAN" if ok else f"terbuang={gained:.1f}s aktif={after['active']} baris={got}", ok,
                  detail="Bot harus tertahan >=4 dtk, hanya menerima sedikit baris, dan koneksi dilepas setelah putus.")

    def scenario_6_tamper_evident_log(self) -> None:
        tamper = self.client.post(f"{self.base}/api/forensics/simulate-tamper", headers=BROWSER_HEADERS).json()
        if "error" in tamper:
            # Ledger kosong: isi dulu lewat satu pemicu beacon, lalu coba lagi.
            sid, _ = self._decoy_html()
            self.client.get(f"{self.base}/assets/{sid}", params={"channel": "img_pixel"}, headers=BROWSER_HEADERS)
            tamper = self.client.post(f"{self.base}/api/forensics/simulate-tamper", headers=BROWSER_HEADERS).json()
        if "error" in tamper:
            self._log(
                "6. Manipulasi forensic log terdeteksi",
                "edited=ketahuan, rehash_tanpa_kunci=ketahuan", "LEDGER_MASIH_KOSONG", False,
                detail=tamper["error"],
            )
            return
        edited_caught = tamper["edited_payload"]["valid"] is False
        rehashed_caught = tamper["edited_and_rehashed_without_key"]["valid"] is False
        actual = f"edited={'ketahuan' if edited_caught else 'LOLOS!'}, rehash_tanpa_kunci={'ketahuan' if rehashed_caught else 'LOLOS!'}"
        self._log(
            "6. Manipulasi forensic log terdeteksi (HMAC chain)",
            "edited=ketahuan, rehash_tanpa_kunci=ketahuan", actual,
            edited_caught and rehashed_caught,
        )

    # ---------- runner ----------

    def run_all(self) -> None:
        print(f"\n=== KARTIKA-MIRAGE :: Automated Self-Red-Team Agent ===")
        print(f"Target (wajib localhost): {self.base}\n")

        uid = uuid.uuid4().hex[:6].upper()
        d = f"REDTEAM-{uid}"

        self.scenario_1_no_token()
        self.scenario_2_bot_ua_with_token(f"{d}-A")
        self.scenario_3_valid_no_warrant(f"{d}-B")
        self.scenario_4_self_approval_blocked(f"{d}-C")
        self.scenario_5_valid_warrant_legitimate(f"{d}-D")
        self.scenario_7_category_violation(f"{d}-E")
        self.scenario_8_revoked_warrant_rejected(f"{d}-F")
        self.scenario_9_beacon_asset_path()
        self.scenario_10_honeytoken()
        self.scenario_11_tarpit_holds_attacker()
        self.scenario_6_tamper_evident_log()

        self._write_report()

    def _write_report(self) -> None:
        total = len(self.results)
        passed = sum(1 for r in self.results if r["passed"])
        report = {
            "generated_at": datetime.now().isoformat(),
            "target": self.base,
            "total_scenarios": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate_pct": round(passed / total * 100, 1) if total else 0,
            "results": self.results,
        }
        out_path = REPORT_DIR / f"redteam_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"\n=== RINGKASAN: {passed}/{total} skenario sesuai ekspektasi ({report['pass_rate_pct']}%) ===")
        print(f"Laporan lengkap: {out_path}\n")
        if passed < total:
            print("Beberapa skenario TIDAK sesuai ekspektasi -- ini sinyal ada regresi atau")
            print("server belum di-restart dengan kode terbaru. Cek detail di atas sebelum demo.\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="KARTIKA-MIRAGE Self Red-Team Agent (localhost only)")
    parser.add_argument(
        "--target", default="http://127.0.0.1:8000",
        help="HARUS localhost/127.0.0.1/::1. Default: http://127.0.0.1:8000",
    )
    args = parser.parse_args()
    agent = RedTeamAgent(args.target)
    agent.run_all()


if __name__ == "__main__":
    main()
