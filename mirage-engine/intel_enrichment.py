import ipaddress
import math
import os
import struct
import wave
import httpx

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GEN_DIR = os.path.join(BASE_DIR, "generated_decoys")
os.makedirs(GEN_DIR, exist_ok=True)

# Lookup online MENGIRIM IP penyadap ke pihak ketiga (HTTP polos) -> default MATI.
# Aktifkan hanya untuk eksperimen: ENRICH_ONLINE=1. Produksi: GeoLite2 lokal.
ENRICH_ONLINE = os.getenv("ENRICH_ONLINE", "0") == "1"


async def enrich_adversary_ip(ip_str: str) -> dict:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {
                "network_type": "INTERNAL / LOCAL SANDBOX",
                "isp": "Local Loopback / Intranet Segment",
                "asn": "AS0000-LOCAL",
                "location": "Local Test Environment",
                "is_datacenter": False,
            }
    except ValueError:
        return {
            "network_type": "UNKNOWN",
            "isp": "Unresolved",
            "asn": "N/A",
            "location": "Unknown",
            "is_datacenter": False,
        }

    if not ENRICH_ONLINE:
        return {
            "network_type": "PUBLIC EXTERNAL",
            "isp": "Belum diperkaya (lookup online dimatikan demi OPSEC)",
            "asn": "N/A",
            "location": "Belum diperkaya (butuh GeoIP lokal)",
            "is_datacenter": False,
        }

    # Lookup IP publik via ip-api.com (opsional, ENRICH_ONLINE=1)
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip_str}?fields=status,country,city,isp,as,hosting"
            )
            data = resp.json()
            if data.get("status") == "success":
                is_dc = bool(data.get("hosting", False))
                return {
                    "network_type": "DATACENTER / VPN / PROXY" if is_dc else "RESIDENTIAL / MOBILE CARRIER",
                    "isp": data.get("isp", "Unknown ISP"),
                    "asn": data.get("as", "Unknown ASN"),
                    "location": f"{data.get('city', '-')}, {data.get('country', '-')}",
                    "is_datacenter": is_dc,
                }
    except Exception:
        pass

    return {
        "network_type": "PUBLIC EXTERNAL",
        "isp": "External Carrier (Offline Lookup)",
        "asn": "N/A",
        "location": "External Network",
        "is_datacenter": False,
    }


def create_tactical_audio_decoy(session_id: str) -> str:
    """
    Menghasilkan file audio umpan transmisi SATCOM (modulasi nada sandi Morse + carrier tone)
    tanpa dependensi eksternal agar penyadap yang mencegat voice stream mendapat sinyal palsu.
    """
    filepath = os.path.join(GEN_DIR, f"SATCOM_VOICE_DECOY_{session_id}.wav")
    sample_rate = 16000
    duration_sec = 4.0
    total_samples = int(sample_rate * duration_sec)

    # Pola ketukan sandi palsu (frekuensi 780 Hz + carrier 220 Hz)
    morse_pattern = [
        (0.1, 0.4), (0.5, 0.7), (0.8, 1.2),
        (1.5, 1.8), (1.9, 2.1), (2.3, 2.7),
        (3.0, 3.2), (3.3, 3.7)
    ]

    with wave.open(filepath, "w") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)

        frames = bytearray()
        for i in range(total_samples):
            t = i / sample_rate
            # Suara carrier radio pelan
            sample = 0.08 * math.sin(2 * math.pi * 220.0 * t)
            # Tambahkan bip sandi transmisi
            for start_t, end_t in morse_pattern:
                if start_t <= t <= end_t:
                    sample += 0.45 * math.sin(2 * math.pi * 780.0 * t)
                    break
            packed = struct.pack("<h", int(max(-1.0, min(1.0, sample)) * 32767))
            frames.extend(packed)

        wav_file.writeframes(bytes(frames))

    return filepath