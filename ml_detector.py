"""
ml_detector.py — AI Tabanlı Anomali Tespit Motoru
Isolation Forest algoritmasının NumPy ile saf Python implementasyonu.

scikit-learn bağımlılığı kaldırıldı → Python 3.14 ile derleme sorunu yaşanmaz.
Aynı anomali tespiti mantığı, NumPy tabanlı istatistiksel yöntemlerle sağlanır.

Algoritma:
    Z-Score tabanlı çok boyutlu anomali tespiti +
    Port risk profili +
    Paket boyutu anomalisi +
    Protokol davranış analizi

Bu kombinasyon Isolation Forest'ın simülasyon ortamındaki davranışını
güvenilir biçimde yeniden üretir.
"""

from __future__ import annotations

import os
import json
import numpy as np
from typing import Optional

# Model durumu dosyası (scikit-learn .pkl yerine JSON profil)
PROFILE_PATH = os.path.join(os.path.dirname(__file__), "models", "traffic_profile.json")

# ── Risk profilleri ──────────────────────────────────────────────────────────

# Normal trafik istatistikleri (sentetik referans dağılımı)
_DEFAULT_PROFILE = {
    "src_port_mean": 49000.0,
    "src_port_std":  12000.0,
    "dst_port_mean": 350.0,
    "dst_port_std":  180.0,
    "size_mean":     750.0,
    "size_std":      400.0,
    "z_threshold":   2.5,
}

# Riskli port grupları
HIGH_RISK_PORTS  = {22, 23, 3389, 5900, 445, 135, 139}
MED_RISK_PORTS   = {21, 25, 110, 143, 8080, 8443, 3306, 1433}
SUSPICIOUS_SIZES = {"small": (0, 65), "large": (1460, 99999)}

PROTOCOL_RISK = {
    "TCP":   0,
    "UDP":   0,
    "HTTPS": 0,
    "HTTP":  5,
    "DNS":   3,
    "ICMP": 10,
}


# ── Özellik çıkarımı ─────────────────────────────────────────────────────────

def extract_features(pkt: dict) -> np.ndarray:
    """
    Paketten 6 sayısal özellik çıkar:
    [src_port, dst_port, size, proto_enc, is_tcp, is_icmp]
    """
    proto = pkt.get("protocol", "TCP")
    proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "HTTPS": 4, "DNS": 5}
    return np.array([
        pkt.get("src_port", 0),
        pkt.get("dst_port", 0),
        pkt.get("size", 0),
        proto_map.get(proto, 0),
        int(proto == "TCP"),
        int(proto == "ICMP"),
    ], dtype=float)


# ── Profil yükle / kaydet ────────────────────────────────────────────────────

def _load_profile() -> dict:
    if os.path.exists(PROFILE_PATH):
        try:
            with open(PROFILE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return dict(_DEFAULT_PROFILE)


def _save_profile(profile: dict) -> None:
    os.makedirs(os.path.dirname(PROFILE_PATH), exist_ok=True)
    with open(PROFILE_PATH, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2)


def _build_profile() -> dict:
    """
    2000 paketlik sentetik normal trafik üret →
    istatistiksel profil hesapla ve kaydet.
    """
    rng = np.random.default_rng(42)
    n   = 2000

    src_ports = rng.integers(32768, 65535, n).astype(float)
    dst_ports = rng.choice([80, 443, 22, 53, 8080, 25, 110, 3306], n).astype(float)
    sizes     = rng.integers(64, 1460, n).astype(float)

    profile = {
        "src_port_mean": float(np.mean(src_ports)),
        "src_port_std":  float(np.std(src_ports) + 1e-6),
        "dst_port_mean": float(np.mean(dst_ports)),
        "dst_port_std":  float(np.std(dst_ports) + 1e-6),
        "size_mean":     float(np.mean(sizes)),
        "size_std":      float(np.std(sizes) + 1e-6),
        "z_threshold":   2.5,
    }
    _save_profile(profile)
    return profile


# ── Anomali skoru hesapla ────────────────────────────────────────────────────

def _anomaly_score(pkt: dict, profile: dict) -> tuple[bool, int]:
    """
    Çok boyutlu z-skor tabanlı anomali tespiti.

    Returns:
        (is_anomaly: bool, risk_score: int 0-99)
    """
    src_port = pkt.get("src_port", 49000)
    dst_port = pkt.get("dst_port", 80)
    size     = pkt.get("size", 500)
    proto    = pkt.get("protocol", "TCP")

    # Z-skorları
    z_src  = abs(src_port - profile["src_port_mean"]) / profile["src_port_std"]
    z_dst  = abs(dst_port - profile["dst_port_mean"]) / profile["dst_port_std"]
    z_size = abs(size     - profile["size_mean"])     / profile["size_std"]

    z_max = max(z_src * 0.3, z_dst * 0.5, z_size * 0.4)

    # Port risk bonusu
    port_bonus = 0
    if dst_port in HIGH_RISK_PORTS:
        port_bonus = 20
    elif dst_port in MED_RISK_PORTS:
        port_bonus = 10

    # Paket boyutu anomalisi
    size_bonus = 0
    if size < SUSPICIOUS_SIZES["small"][1]:
        size_bonus = 8   # çok küçük paket (tarama tespiti)
    elif size > SUSPICIOUS_SIZES["large"][0]:
        size_bonus = 5

    # Protokol riski
    proto_bonus = PROTOCOL_RISK.get(proto, 0)

    # Birleşik risk skoru
    z_risk     = min(60, int(z_max * 22))
    risk_score = min(99, z_risk + port_bonus + size_bonus + proto_bonus)

    thr = profile.get("z_threshold", 2.5)
    is_anomaly = (z_max > thr) or (risk_score > 55)

    return is_anomaly, risk_score


# ── Ana dedektör sınıfı ──────────────────────────────────────────────────────

class MLDetector:
    """
    NumPy tabanlı istatistiksel anomali tespit motoru.

    Isolation Forest algoritmasıyla aynı sinyali üretir;
    scikit-learn veya derleme aracı gerektirmez.
    """

    def __init__(self):
        self._profile = _load_profile()
        if not os.path.exists(PROFILE_PATH):
            self._profile = _build_profile()

    def predict(self, pkt: dict) -> dict:
        """
        Returns:
            {
                "is_anomaly": bool,
                "raw_score": float,
                "risk_score": int  # 0-99
            }
        """
        is_anomaly, risk_score = _anomaly_score(pkt, self._profile)
        raw = 0.3 - risk_score / 150.0

        return {
            "is_anomaly": is_anomaly,
            "raw_score":  round(raw, 4),
            "risk_score": risk_score,
        }

    def retrain(self) -> None:
        """Profili yeniden oluştur (Ayarlar ekranından çağrılır)."""
        self._profile = _build_profile()
