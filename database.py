"""
database.py — SQLite veri tabanı işlemleri
"""

import sqlite3
import os
import pandas as pd
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "traffic_logs.db")


def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    """Tablolar yoksa oluştur."""
    con = get_connection()
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            protocol    TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            size        INTEGER
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT,
            attack_type  TEXT,
            src_ip       TEXT,
            dst_ip       TEXT,
            risk_level   TEXT,
            risk_score   INTEGER,
            status       TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # Varsayılan ayarlar
    defaults = [
        ("syn_flood_threshold",  "200"),
        ("port_scan_threshold",  "20"),
        ("icmp_flood_threshold", "300"),
        ("brute_force_threshold","10"),
        ("risk_threshold",       "70"),
        ("auto_block",           "0"),
        ("log_active",           "1"),
        ("capture_mode",         "Simülasyon"),
        ("interface",            "eth0"),
        ("retention_days",       "30"),
        ("packet_size_limit",    "65535"),
    ]
    cur.executemany(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", defaults
    )

    con.commit()
    con.close()


# ── CRUD ──────────────────────────────────────────────────────────────────────

def insert_packet(src_ip, dst_ip, protocol, src_port, dst_port, size):
    con = get_connection()
    con.execute(
        "INSERT INTO packets (timestamp,src_ip,dst_ip,protocol,src_port,dst_port,size) "
        "VALUES (?,?,?,?,?,?,?)",
        (datetime.now().isoformat(), src_ip, dst_ip, protocol, src_port, dst_port, size)
    )
    con.commit(); con.close()


def insert_alert(attack_type, src_ip, dst_ip, risk_level, risk_score, status="Tespit Edildi"):
    con = get_connection()
    con.execute(
        "INSERT INTO alerts (timestamp,attack_type,src_ip,dst_ip,risk_level,risk_score,status) "
        "VALUES (?,?,?,?,?,?,?)",
        (datetime.now().isoformat(), attack_type, src_ip, dst_ip, risk_level, risk_score, status)
    )
    con.commit(); con.close()


def get_alerts(limit: int = 200) -> pd.DataFrame:
    con = get_connection()
    df = pd.read_sql_query(
        f"SELECT * FROM alerts ORDER BY timestamp DESC LIMIT {limit}", con
    )
    con.close()
    return df


def get_packets(limit: int = 500) -> pd.DataFrame:
    con = get_connection()
    df = pd.read_sql_query(
        f"SELECT * FROM packets ORDER BY timestamp DESC LIMIT {limit}", con
    )
    con.close()
    return df


def get_setting(key: str, default: str = "") -> str:
    con = get_connection()
    cur = con.cursor()
    cur.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = cur.fetchone()
    con.close()
    return row[0] if row else default


def save_setting(key: str, value: str):
    con = get_connection()
    con.execute(
        "INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, value)
    )
    con.commit(); con.close()


def get_stats() -> dict:
    con = get_connection()
    cur = con.cursor()
    total_packets  = cur.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    total_alerts   = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    blocked_ips    = cur.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM alerts WHERE status='Engellendi'"
    ).fetchone()[0]
    avg_risk       = cur.execute("SELECT AVG(risk_score) FROM alerts").fetchone()[0] or 0
    con.close()
    return {
        "total_packets": total_packets,
        "total_alerts":  total_alerts,
        "blocked_ips":   blocked_ips,
        "avg_risk":      round(avg_risk),
    }
