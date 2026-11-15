import os
import math
import time
import joblib
import numpy as np
from train_ml_model import train_and_export, MODEL_PATH


class BehavioralAnomalyDetector:
    def __init__(self):
        if not os.path.exists(MODEL_PATH):
            train_and_export()
        artifact = joblib.load(MODEL_PATH)
        self.scaler = artifact["scaler"]
        self.model = artifact["model"]
        self.roc_auc = artifact.get("roc_auc", 0.99)
        self.client_timers = {}

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        probs = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum(p * math.log(p, 2) for p in probs)

    def get_interval_ms(self, client_ip: str) -> float:
        now_ms = time.time() * 1000
        last_ms = self.client_timers.get(client_ip, now_ms - 1600.0)
        self.client_timers[client_ip] = now_ms
        return min(now_ms - last_ms, 5000.0)

    def evaluate(self, client_ip: str, headers: dict, simulated_burst: bool = False) -> dict:
        interval_ms = 25.0 if simulated_burst else self.get_interval_ms(client_ip)
        lower_headers = {k.lower(): v for k, v in headers.items()}

        header_count = len(lower_headers)
        # Nilai rahasia (JWT, warrant, cookie) acak dan mendominasi entropi: dikecualikan agar
        # entropi mengukur "gaya" header klien, bukan panjang token.
        secret_keys = {"x-vip-token", "x-warrant-id", "authorization", "cookie", "x-admin-key"}
        raw_header_str = "".join(f"{k}:{v}" for k, v in lower_headers.items() if k not in secret_keys)
        entropy = self._shannon_entropy(raw_header_str)
        has_vip_header = 1 if "x-vip-token" in lower_headers else 0

        ua = lower_headers.get("user-agent", "").lower()
        is_bot = 1 if any(k in ua for k in ["curl", "python", "httpx", "sniffer", "interceptor", "bot", "sqlmap", "ffuf"]) else 0
        has_standard_accept = 1 if ("accept-language" in lower_headers or "sec-fetch-mode" in lower_headers) else 0

        features = np.array([[
            interval_ms,
            header_count,
            entropy,
            has_vip_header,
            is_bot,
            has_standard_accept
        ]])
        features_scaled = self.scaler.transform(features)
        raw_score = self.model.decision_function(features_scaled)[0]

        # Hybrid: Isolation Forest menangkap deviasi GABUNGAN beberapa fitur, sedangkan
        # anomali satu fitur (mis. interval) tidak bisa diekstrapolasi IF -> ditangani aturan.
        # Kalibrasi terukur: normal raw >= -0.004 (persentil-5), burst browser ~ +0.025,
        # curl+token ~ -0.021, bot python burst ~ -0.066.
        base_risk = int(np.clip((0.06 - raw_score) * 550, 8, 60))
        penalty = 0
        reasons = []
        if interval_ms < 250:
            penalty += 50
            reasons.append(f"interval {interval_ms:.0f}ms (burst, manusia >750ms)")
        if is_bot == 1:
            penalty += 50
            reasons.append("User-Agent bot/tool")
        if has_vip_header == 0:
            penalty += 18
            reasons.append("tanpa token VIP")
        if has_standard_accept == 0:
            penalty += 8
            reasons.append("header browser standar tidak ada")
        if base_risk >= 35:
            reasons.append(f"pola header menyimpang dari baseline (model {base_risk}%)")

        threat_score = min(base_risk + penalty, 98)
        is_anomaly = bool(threat_score >= 65)

        if len(self.client_timers) > 2000:
            self.client_timers.clear()

        return {
            "threat_score": threat_score,
            "is_anomaly": is_anomaly,
            "interval_ms": round(interval_ms, 1),
            "is_bot_ua": bool(is_bot),
            "reasons": reasons,
            "model_roc_auc_synthetic": self.roc_auc
        }