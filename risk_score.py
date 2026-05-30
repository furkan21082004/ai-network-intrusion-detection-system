"""
risk_score.py — Birleşik risk skoru hesaplayıcı

Risk = Kural Skoru * RULE_WEIGHT
     + ML Skoru    * ML_WEIGHT
     + Saldırı tipi baz skoru bonus

Risk seviyeleri:
  0–30  → Düşük
  31–60 → Orta
  61–100→ Yüksek
"""

ATTACK_BASE = {
    "SYN Flood":     12,
    "Brute Force":   15,
    "ICMP Flood":     8,
    "Port Scan":      5,
    "Anomali (AI)":   3,
}

RULE_WEIGHT = 0.60
ML_WEIGHT   = 0.40


def combine_scores(rule_score: int, ml_score: int, attack_type: str = "") -> int:
    """
    Kural ve ML skorlarını ağırlıklı birleştir.

    - Kural tespiti yoksa ML skoru daha etkili olur.
    - Saldırı tipi tanımlıysa kontrollü baz bonus eklenir.
    - Sonuç 0-99 arasında tam sayı döner.
    """
    base = ATTACK_BASE.get(attack_type, 0)

    if rule_score == 0:
        combined = ml_score * 0.70 + base
    else:
        combined = (
            rule_score * RULE_WEIGHT
            + ml_score * ML_WEIGHT
            + base
        )

    return max(0, min(99, round(combined)))


def score_to_level(score: int) -> str:
    if score >= 61:
        return "Yüksek"
    if score >= 31:
        return "Orta"
    return "Düşük"


def compute_system_risk(alerts_df) -> int:
    """
    Tüm aktif uyarılardan sistem geneli risk skoru hesaplar.

    Bu sürümde son uyarılar dikkate alınır ve yoğunluk bonusu kontrollü uygulanır.
    Böylece sistem riski her analizde sürekli 80-90 bandında kalmaz.
    """
    if alerts_df is None or len(alerts_df) == 0:
        # Simülasyon ortamında hiç uyarı yoksa sistem tamamen risksiz kabul edilmez;
        # düşük seviyeli temel ağ riski gösterilir.
        return 8

    if "Birleşik Risk" in alerts_df.columns:
        scores = alerts_df["Birleşik Risk"].dropna()

        if len(scores) > 0:
            scores = scores.tail(50)

            avg_risk = float(scores.mean())
            high_ratio = float((scores >= 61).sum() / len(scores))
            critical_ratio = float((scores >= 80).sum() / len(scores))

            risk = (
                avg_risk * 0.75
                + high_ratio * 18
                + critical_ratio * 12
            )

            density_bonus = min(5, len(scores) / 10)
            risk += density_bonus

            return max(0, min(99, round(risk)))

    col = "Risk Seviyesi" if "Risk Seviyesi" in alerts_df.columns else "risk_level"
    if col not in alerts_df.columns:
        return 0

    w_map = {"Yüksek": 3, "Orta": 2, "Düşük": 1}
    total_w = sum(w_map.get(r, 1) for r in alerts_df[col])
    max_w = len(alerts_df) * 3
    return min(99, round(total_w / max_w * 100)) if max_w else 0
