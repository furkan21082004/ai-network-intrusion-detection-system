"""
analysis_engine.py — AI-Powered Intrusion Detection System
Analiz Motoru

Pipeline:
    Simülasyon Paketi (dict)
        ↓
    RuleDetector  (SYN Flood, Port Scan, Brute Force, ICMP Flood)
        ↓
    MLDetector    (Z-Score tabanlı anomali skoru)
        ↓
    combine_scores (ağırlıklı risk birleştirme)
        ↓
    AnalysisResult
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Optional

import pandas as pd

import utils
from rule_detector import RuleDetector
from ml_detector   import MLDetector
from risk_score    import combine_scores, score_to_level


class AnalysisResult:
    """Bir pakete ait tüm analiz sonuçlarını taşır."""

    def __init__(
        self,
        packet:     dict,
        rule_hit:   Optional[str],
        rule_score: int,
        is_anomaly: bool,
        ml_score:   int,
        combined:   int,
    ):
        self.packet     = packet
        self.rule_hit   = rule_hit
        self.rule_score = rule_score
        self.is_anomaly = is_anomaly
        self.ml_score   = ml_score
        self.combined   = combined
        self.level      = score_to_level(combined)
        self.timestamp  = datetime.now()

    @property
    def rule_label(self) -> str:
        return self.rule_hit if self.rule_hit else "—"

    @property
    def anomaly_label(self) -> str:
        return "⚠ Anomali" if self.is_anomaly else "✓ Normal"

    @property
    def verdict(self) -> str:
        if self.rule_hit:
            return f"🚨 {self.rule_hit}"
        if self.is_anomaly:
            return "🤖 AI Anomali"
        return "✅ Temiz"

    def to_traffic_row(self) -> dict:
        p = self.packet
        return {
            "Zaman":         p.get("timestamp", self.timestamp.strftime("%H:%M:%S")),
            "Kaynak IP":     p.get("src_ip", "—"),
            "Hedef IP":      p.get("dst_ip", "—"),
            "Protokol":      p.get("protocol", "—"),
            "Kaynak Port":   p.get("src_port", 0),
            "Hedef Port":    p.get("dst_port", 0),
            "Boyut (B)":     p.get("size", 0),
            "Kural Tespiti": self.rule_label,
            "AI Anomali":    self.anomaly_label,
            "AI Skoru":      self.ml_score,
            "Birleşik Risk": self.combined,
            "Sonuç":         self.verdict,
        }

    def to_alert_row(self) -> Optional[dict]:
        if not self.rule_hit and not self.is_anomaly:
            return None
        p = self.packet
        return {
            "Zaman":         self.timestamp.strftime("%d/%m/%Y %H:%M:%S"),
            "Saldırı Türü":  self.rule_hit if self.rule_hit else "Anomali (AI)",
            "Kaynak IP":     p.get("src_ip", "—"),
            "Hedef IP":      p.get("dst_ip", "—"),
            "Risk Seviyesi": self.level,
            "AI Skoru":      self.ml_score,
            "Birleşik Risk": self.combined,
            "Durum": (
                "Engellendi"     if self.combined >= 80 else
                "İzleniyor"      if self.combined >= 50 else
                "Tespit Edildi"
            ),
        }


class AnalysisEngine:
    """
    RuleDetector + MLDetector birleşimi.

    run_batch() her yeni analizde sayaçları sıfırlar. Böylece dashboard metrikleri
    eski analizlerden birikerek sürekli yüksek risk üretmez.
    """

    def __init__(self):
        self._rule = RuleDetector()
        self._ml   = MLDetector()
        self.reset()

    def analyze_packet(self, pkt: dict) -> AnalysisResult:
        rule_result = self._rule.analyze(pkt)
        if rule_result:
            rule_hit   = rule_result["attack_type"]
            rule_score = rule_result["risk_score"]
        else:
            rule_hit   = None
            rule_score = 0

        ml_result  = self._ml.predict(pkt)
        is_anomaly = ml_result["is_anomaly"]
        ml_score   = ml_result["risk_score"]

        combined = combine_scores(rule_score, ml_score, rule_hit or "")

        self.total_analyzed += 1
        self._ml_score_sum  += ml_score
        self._risk_sum      += combined

        if is_anomaly:
            self.total_anomalies += 1
        if rule_hit or is_anomaly:
            self.total_alerts += 1
        if combined >= 61 and (rule_hit or is_anomaly):
            self._critical_count += 1

        return AnalysisResult(
            packet     = pkt,
            rule_hit   = rule_hit,
            rule_score = rule_score,
            is_anomaly = is_anomaly,
            ml_score   = ml_score,
            combined   = combined,
        )

    def run_batch(self, n: int = 120) -> list[AnalysisResult]:
        self.reset()
        results = []
        sim_df  = utils.generate_packets(n)

        for _, row in sim_df.iterrows():
            pkt = {
                "timestamp":   row["Zaman"],
                "src_ip":      row["Kaynak IP"],
                "dst_ip":      row["Hedef IP"],
                "protocol":    row["Protokol"],
                "flags":       _infer_flags(row["Protokol"], int(row["Hedef Port"])),
                "src_port":    int(row["Kaynak Port"]),
                "dst_port":    int(row["Hedef Port"]),
                "size":        int(row["Boyut (B)"]),
                "_category":   row.get("_category", "normal"),
            }
            results.append(self.analyze_packet(pkt))

        return results

    def stats(self) -> dict:
        n = max(self.total_analyzed, 1)
        return {
            "total_analyzed":  self.total_analyzed,
            "total_anomalies": self.total_anomalies,
            "total_alerts":    self.total_alerts,
            "avg_ml_score":    round(self._ml_score_sum / n),
            "avg_risk":        round(self._risk_sum / n),
            "critical_count":  self._critical_count,
        }

    def reset(self):
        self.total_analyzed  = 0
        self.total_anomalies = 0
        self.total_alerts    = 0
        self._ml_score_sum   = 0
        self._risk_sum       = 0
        self._critical_count = 0

        try:
            self._rule = RuleDetector()
        except Exception:
            pass


def _infer_flags(protocol: str, dst_port: int) -> str:
    if protocol not in ("TCP",):
        return ""
    if dst_port in (22, 3389, 21, 5900, 23):
        return random.choices(["SYN", "SYN-ACK", "ACK"], weights=[60, 20, 20])[0]
    if dst_port in (80, 443, 8080):
        return random.choices(["ACK", "PSH", "SYN", "FIN"], weights=[50, 25, 15, 10])[0]
    return random.choices(["SYN", "ACK", "PSH", "FIN"], weights=[30, 40, 20, 10])[0]


def results_to_traffic_df(results: list[AnalysisResult]) -> pd.DataFrame:
    return pd.DataFrame([r.to_traffic_row() for r in results])


def results_to_alerts_df(results: list[AnalysisResult]) -> pd.DataFrame:
    rows = [r.to_alert_row() for r in results if r.to_alert_row() is not None]
    if not rows:
        return pd.DataFrame(columns=[
            "Zaman", "Saldırı Türü", "Kaynak IP", "Hedef IP",
            "Risk Seviyesi", "AI Skoru", "Birleşik Risk", "Durum",
        ])
    return pd.DataFrame(rows)
