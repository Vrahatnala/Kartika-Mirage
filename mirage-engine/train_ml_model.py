import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "mirage_behavior_model.joblib")


def generate_training_dataset(seed: int = 42):
    rng = np.random.default_rng(seed)

    # 800 sampel trafik klien VIP sah (human/handset interval, header lengkap, token ada, bukan bot)
    n_normal = 800
    # 30% sampel = jeda panjang (>=5 dtk, di-cap 5000 oleh detektor), sisanya 0.75-5 dtk
    norm_interval = np.where(rng.random((n_normal, 1)) < 0.3, 5000.0, rng.uniform(750.0, 5000.0, size=(n_normal, 1)))
    norm_headers = rng.integers(7, 20, size=(n_normal, 1))  # app Android ~8, browser ~16 (termasuk x-device-id, x-warrant-id)
    norm_entropy = rng.uniform(4.9, 5.7, size=(n_normal, 1))  # diukur dari profil Chrome/Android, TANPA nilai rahasia
    norm_token = np.ones((n_normal, 1))
    norm_bot = np.zeros((n_normal, 1))
    norm_accept_present = np.ones((n_normal, 1))

    X_normal = np.hstack([
        norm_interval, norm_headers, norm_entropy,
        norm_token, norm_bot, norm_accept_present
    ])

    # 200 sampel trafik serangan (automated script, replay burst, missing headers, token bocor dipakai bot)
    n_attack = 200
    att_interval = rng.uniform(5.0, 220.0, size=(n_attack, 1))
    att_headers = rng.integers(2, 7, size=(n_attack, 1))
    att_entropy = rng.uniform(3.6, 4.85, size=(n_attack, 1))  # diukur dari curl/httpx/tool penyadap
    att_token = rng.choice([0, 1], p=[0.7, 0.3], size=(n_attack, 1))
    att_bot = rng.choice([0, 1], p=[0.2, 0.8], size=(n_attack, 1))
    att_accept_present = rng.choice([0, 1], p=[0.6, 0.4], size=(n_attack, 1))

    X_attack = np.hstack([
        att_interval, att_headers, att_entropy,
        att_token, att_bot, att_accept_present
    ])

    X = np.vstack([X_normal, X_attack])
    y_true = np.array([0] * n_normal + [1] * n_attack)  # 0 = Normal, 1 = Anomaly
    return X_normal, X, y_true


def train_and_export():
    X_normal, X_all, y_true = generate_training_dataset()

    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)
    X_all_scaled = scaler.transform(X_all)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_samples="auto",
        random_state=42
    )
    model.fit(X_normal_scaled)

    # Prediksi: IsolationForest mengembalikan -1 untuk anomali dan 1 untuk normal
    raw_preds = model.predict(X_all_scaled)
    y_pred = np.where(raw_preds == -1, 1, 0)
    anomaly_scores = -model.decision_function(X_all_scaled)

    print("=== KARTIKA-MIRAGE ML BEHAVIORAL ENGINE EVALUATION ===")
    print(classification_report(y_true, y_pred, target_names=["VIP_LEGITIMATE", "ADVERSARY_ANOMALY"]))
    print(f"ROC-AUC Score : {roc_auc_score(y_true, anomaly_scores):.4f}  (data SINTETIS dari generator yang sama: bukan klaim akurasi di dunia nyata)")

    artifact = {
        "scaler": scaler,
        "model": model,
        "features": [
            "interval_ms",
            "header_count",
            "header_entropy",
            "has_vip_token",
            "is_bot_ua",
            "has_standard_accept"
        ],
        "roc_auc": round(float(roc_auc_score(y_true, anomaly_scores)), 4)
    }
    joblib.dump(artifact, MODEL_PATH)
    print(f"Model berhasil diekspor ke: {MODEL_PATH}")


if __name__ == "__main__":
    train_and_export()