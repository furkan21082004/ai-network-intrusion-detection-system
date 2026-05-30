"""
utils.py — Simülasyon veri üreteci
Gerçek ağ davranışını taklit eden trafik simülasyonu.

Dağılım:
  %72 Normal kullanıcı trafiği
  %12 Web trafiği
  %6  DNS trafiği
  %10 Saldırı trafiği
"""

import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

ATTACK_TYPES = ["SYN Flood", "Port Scan", "Brute Force", "ICMP Flood"]
PROTOCOLS    = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
RISK_LEVELS  = ["Yüksek", "Orta", "Düşük"]

RISK_COLOR = {
    "Yüksek": "#E53E3E",
    "Orta":   "#DD6B20",
    "Düşük":  "#718096",
}

INTERNAL_IPS = [
    "192.168.1.1", "192.168.1.10", "192.168.1.30",
    "10.0.0.1",    "172.16.5.1",
]

NORMAL_SOURCE_IPS = [
    "203.0.113.15", "198.51.100.44", "8.8.8.8",
    "1.1.1.1",      "93.184.216.34", "151.101.1.140",
    "140.82.113.4",  "185.199.108.153",
]

ATTACKER_IPS = [
    "192.168.1.55",
    "10.0.0.23",
    "172.16.5.8",
    "45.33.32.156",
    "198.51.100.24",
    "203.0.113.7",
]

ALL_SOURCE_IPS = NORMAL_SOURCE_IPS + ATTACKER_IPS
DEST_IPS = INTERNAL_IPS

NORMAL_PORTS  = [80, 443, 25, 143, 110, 993, 995, 587]
WEB_PORTS     = [80, 443, 8080, 8443]
DNS_PORTS     = [53]
ATTACK_PORTS  = [22, 3389, 21, 5900, 23, 8080, 445]

NORMAL_PROTO_WEIGHTS = {
    "TCP":   50, "UDP": 20, "ICMP": 5,
    "HTTPS": 15, "HTTP": 7, "DNS": 3,
}


def generate_packets(n: int = 120) -> pd.DataFrame:
    """
    Gerçekçi ağ trafiği simülasyonu.
    Saldırı oranı %10 seviyesinde tutulur; dashboard düşük/orta/yüksek
    riskleri dengeli ama abartısız üretir.
    """
    now  = datetime.now()
    rows = []

    for i in range(n):
        ts       = now - timedelta(seconds=random.randint(0, 3600))
        category = _pick_category()

        if category == "normal":
            row = _normal_packet(ts)
        elif category == "web":
            row = _web_packet(ts)
        elif category == "dns":
            row = _dns_packet(ts)
        else:
            row = _attack_packet(ts)

        rows.append(row)

    df = pd.DataFrame(rows)
    df = df.sort_values("Zaman", ascending=False).reset_index(drop=True)
    return df


def _pick_category() -> str:
    return random.choices(
        ["normal", "web", "dns", "attack"],
        weights=[72, 12, 6, 10],
    )[0]


def _normal_packet(ts: datetime) -> dict:
    proto = random.choices(
        ["TCP", "UDP", "HTTPS", "HTTP"],
        weights=[50, 20, 20, 10],
    )[0]
    port_map = {
        "TCP":   random.choice([443, 80, 587, 993, 25]),
        "UDP":   random.choice([123, 161, 500]),
        "HTTPS": 443,
        "HTTP":  80,
    }
    return {
        "Zaman":       ts.strftime("%H:%M:%S.%f")[:-3],
        "Kaynak IP":   random.choice(NORMAL_SOURCE_IPS),
        "Hedef IP":    random.choice(DEST_IPS),
        "Protokol":    proto,
        "Kaynak Port": random.randint(32768, 65535),
        "Hedef Port":  port_map.get(proto, 443),
        "Boyut (B)":   random.randint(64, 1460),
        "_category":   "normal",
    }


def _web_packet(ts: datetime) -> dict:
    return {
        "Zaman":       ts.strftime("%H:%M:%S.%f")[:-3],
        "Kaynak IP":   random.choice(NORMAL_SOURCE_IPS + ATTACKER_IPS[:1]),
        "Hedef IP":    random.choice(DEST_IPS),
        "Protokol":    random.choice(["HTTPS", "HTTP", "TCP"]),
        "Kaynak Port": random.randint(32768, 65535),
        "Hedef Port":  random.choice(WEB_PORTS),
        "Boyut (B)":   random.randint(200, 1500),
        "_category":   "web",
    }


def _dns_packet(ts: datetime) -> dict:
    return {
        "Zaman":       ts.strftime("%H:%M:%S.%f")[:-3],
        "Kaynak IP":   random.choice(NORMAL_SOURCE_IPS),
        "Hedef IP":    random.choice(DEST_IPS),
        "Protokol":    "DNS",
        "Kaynak Port": random.randint(1024, 65535),
        "Hedef Port":  53,
        "Boyut (B)":   random.randint(40, 120),
        "_category":   "dns",
    }


def _attack_packet(ts: datetime) -> dict:
    attack = random.choices(
        ["Port Scan", "SYN Flood", "Brute Force", "ICMP Flood"],
        weights=[35, 30, 20, 15],
    )[0]

    proto_map = {
        "Port Scan":   "TCP",
        "SYN Flood":   "TCP",
        "Brute Force": "TCP",
        "ICMP Flood":  "ICMP",
    }
    port_map = {
        "Port Scan":   random.randint(1, 65535),
        "SYN Flood":   random.choice([80, 443, 8080]),
        "Brute Force": random.choice([22, 3389, 21]),
        "ICMP Flood":  0,
    }
    size_map = {
        "Port Scan":   random.randint(40, 60),
        "SYN Flood":   random.randint(40, 80),
        "Brute Force": random.randint(200, 600),
        "ICMP Flood":  random.randint(64, 1024),
    }

    return {
        "Zaman":       ts.strftime("%H:%M:%S.%f")[:-3],
        "Kaynak IP":   random.choice(ATTACKER_IPS),
        "Hedef IP":    random.choice(DEST_IPS),
        "Protokol":    proto_map[attack],
        "Kaynak Port": random.randint(1024, 65535),
        "Hedef Port":  port_map[attack],
        "Boyut (B)":   size_map[attack],
        "_category":   attack,
    }


def generate_alerts(n: int = 20) -> pd.DataFrame:
    """Yedek: doğrudan uyarı verisi üret."""
    now  = datetime.now()
    rows = []
    for _ in range(n):
        attack = random.choice(ATTACK_TYPES)
        risk   = random.choices(RISK_LEVELS, weights=[15, 35, 50])[0]
        ts     = now - timedelta(minutes=random.randint(0, 1440))
        rows.append({
            "Zaman":        ts.strftime("%d/%m/%Y %H:%M:%S"),
            "Saldırı Türü": attack,
            "Kaynak IP":    random.choice(ATTACKER_IPS),
            "Hedef IP":     random.choice(DEST_IPS),
            "Risk Seviyesi": risk,
            "AI Skoru":     random.randint(20, 80),
            "Birleşik Risk": random.randint(20, 85),
            "Durum":        random.choice(["Tespit Edildi", "İzleniyor", "Engellendi"]),
        })
    df = pd.DataFrame(rows)
    df = df.sort_values("Zaman", ascending=False).reset_index(drop=True)
    return df


def generate_protocol_dist() -> dict:
    return {"TCP": 48, "UDP": 17, "HTTPS": 20, "HTTP": 8, "DNS": 5, "ICMP": 2}


def generate_attack_dist() -> dict:
    return {
        "Port Scan":   35,
        "SYN Flood":   30,
        "Brute Force": 20,
        "ICMP Flood":  15,
    }


def generate_top_ips() -> pd.DataFrame:
    data = [
        {"IP Adresi": "45.33.32.156",  "Ort. Risk": 66, "Uyarı Sayısı": 8},
        {"IP Adresi": "192.168.1.55",  "Ort. Risk": 58, "Uyarı Sayısı": 6},
        {"IP Adresi": "10.0.0.23",     "Ort. Risk": 52, "Uyarı Sayısı": 5},
        {"IP Adresi": "172.16.5.8",    "Ort. Risk": 45, "Uyarı Sayısı": 3},
        {"IP Adresi": "198.51.100.24", "Ort. Risk": 39, "Uyarı Sayısı": 2},
    ]
    return pd.DataFrame(data)


def generate_world_attacks(n: int = 40) -> pd.DataFrame:
    coords = [
        (51.5074,  -0.1278,  "Londra"),
        (40.7128,  -74.0060, "New York"),
        (35.6762,  139.6503, "Tokyo"),
        (48.8566,   2.3522,  "Paris"),
        (55.7558,   37.6173, "Moskova"),
        (39.9042,  116.4074, "Pekin"),
        (28.6139,   77.2090, "Delhi"),
        (-23.5505, -46.6333, "São Paulo"),
        (37.7749, -122.4194, "San Francisco"),
        (1.3521,   103.8198, "Singapur"),
        (52.3676,    4.9041, "Amsterdam"),
        (37.9838,   23.7275, "Atina"),
    ]
    rows = []
    for _ in range(n):
        lat, lon, city = random.choice(coords)
        lat += random.uniform(-2, 2)
        lon += random.uniform(-2, 2)
        rows.append({
            "lat":    lat,
            "lon":    lon,
            "city":   city,
            "count":  random.randint(1, 10),
            "attack": random.choice(ATTACK_TYPES),
        })
    return pd.DataFrame(rows)


def format_number(n: int) -> str:
    return f"{n:,}".replace(",", ".")


def risk_badge_html(risk: str) -> str:
    color = RISK_COLOR.get(risk, "#718096")
    bg    = color + "22"
    return (
        f'<span style="background:{bg};color:{color};padding:2px 10px;'
        f'border-radius:12px;font-size:12px;font-weight:600;'
        f'border:1px solid {color}44;">{risk}</span>'
    )
