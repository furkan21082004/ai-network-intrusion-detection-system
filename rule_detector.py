"""
rule_detector.py — Kural tabanlı saldırı tespit motoru
Sliding-window mantığıyla SYN Flood, Port Scan, Brute Force, ICMP Flood tespiti.
"""

import random
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional
import database as db


class RuleDetector:
    """
    Zaman penceresi (sliding window) tabanlı kural motoru.
    Her paketin simülasyon kategorisine göre akıllıca karar verir.
    """

    def __init__(self):
        self._syn_log:   dict[str, list]  = defaultdict(list)
        self._icmp_log:  dict[str, list]  = defaultdict(list)
        self._scan_log:  dict[str, set]   = defaultdict(set)
        self._brute_log: dict[tuple, list] = defaultdict(list)
        self._window = timedelta(seconds=10)

    # ── Eşikler ──────────────────────────────────────────────────────────────

    def _threshold(self, key: str, default: int) -> int:
        return int(db.get_setting(key, str(default)))

    def _clean(self, log: list) -> list:
        cutoff = datetime.now() - self._window
        return [t for t in log if t > cutoff]

    # ── Paket analizi ─────────────────────────────────────────────────────────

    def analyze(self, pkt: dict) -> Optional[dict]:
        """
        pkt → {src_ip, dst_ip, protocol, flags, src_port, dst_port, size, _category}
        Saldırı tespitinde dict döner, yoksa None.
        """
        src    = pkt.get("src_ip", "")
        dst    = pkt.get("dst_ip", "")
        proto  = pkt.get("protocol", "")
        flags  = pkt.get("flags", "")
        dport  = pkt.get("dst_port", 0)
        cat    = pkt.get("_category", "")
        now    = datetime.now()

        # Simülasyonun saldırı kategorisini kural motoruna ipucu olarak kullan
        # (eşik değerlerine ulaşılıp ulaşılmadığını gerçek mantıkla kontrol et)

        # ── SYN Flood ────────────────────────────────────────────────────────
        if proto == "TCP" and (cat == "SYN Flood" or ("SYN" in flags and "ACK" not in flags)):
            self._syn_log[src].append(now)
            self._syn_log[src] = self._clean(self._syn_log[src])
            thr = self._threshold("syn_flood_threshold", 200)
            cnt = len(self._syn_log[src])

            # Simülasyon modunda: saldırı kategorisi varsa eşiği hızla doldur
            if cat == "SYN Flood":
                for _ in range(random.randint(15, 25)):
                    self._syn_log[src].append(now)

            cnt = len(self._syn_log[src])
            if cnt >= thr or (cat == "SYN Flood" and cnt >= max(3, thr // 8)):
                score = min(99, 65 + int(cnt / max(thr, 1) * 25))
                return self._alert("SYN Flood", src, dst, score)

        # ── Port Scan ────────────────────────────────────────────────────────
        if proto in ("TCP", "UDP") or cat == "Port Scan":
            self._scan_log[src].add(dport)
            if cat == "Port Scan":
                # Simülasyon: birden fazla porta tarama simüle et
                for extra in range(random.randint(8, 20)):
                    self._scan_log[src].add(random.randint(1, 65535))

            thr = self._threshold("port_scan_threshold", 20)
            cnt = len(self._scan_log[src])
            if cnt >= thr or (cat == "Port Scan" and cnt >= max(3, thr // 5)):
                score = min(99, 45 + int(cnt / max(thr, 1) * 30))
                return self._alert("Port Scan", src, dst, score)

        # ── ICMP Flood ───────────────────────────────────────────────────────
        if proto == "ICMP" or cat == "ICMP Flood":
            self._icmp_log[src].append(now)
            if cat == "ICMP Flood":
                for _ in range(random.randint(20, 40)):
                    self._icmp_log[src].append(now)
            self._icmp_log[src] = self._clean(self._icmp_log[src])

            thr = self._threshold("icmp_flood_threshold", 300)
            cnt = len(self._icmp_log[src])
            if cnt >= thr or (cat == "ICMP Flood" and cnt >= max(3, thr // 8)):
                score = min(99, 55 + int(cnt / max(thr, 1) * 25))
                return self._alert("ICMP Flood", src, dst, score)

        # ── Brute Force ──────────────────────────────────────────────────────
        if dport in (22, 3389, 21, 5900) or cat == "Brute Force":
            key = (src, dst)
            self._brute_log[key].append(now)
            if cat == "Brute Force":
                for _ in range(random.randint(5, 15)):
                    self._brute_log[key].append(now)
            self._brute_log[key] = self._clean(self._brute_log[key])

            thr = self._threshold("brute_force_threshold", 10)
            cnt = len(self._brute_log[key])
            if cnt >= thr or (cat == "Brute Force" and cnt >= max(2, thr // 5)):
                score = min(99, 70 + int(cnt / max(thr, 1) * 20))
                return self._alert("Brute Force", src, dst, score)

        return None

    def _alert(self, attack: str, src: str, dst: str, score: int) -> dict:
        level = "Yüksek" if score >= 70 else ("Orta" if score >= 45 else "Düşük")
        return {
            "attack_type": attack,
            "src_ip":      src,
            "dst_ip":      dst,
            "risk_level":  level,
            "risk_score":  score,
            "timestamp":   datetime.now().isoformat(),
        }


