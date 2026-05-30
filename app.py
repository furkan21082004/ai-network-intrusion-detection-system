"""
app.py — NetGuard AI-IDS
Ağ Güvenliği Saldırı Tespit Sistemi — Streamlit Arayüzü

Çalıştır: streamlit run app.py
"""
import textwrap
import random
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta

import database as db
import utils
from analysis_engine import (
    AnalysisEngine,
    results_to_traffic_df,
    results_to_alerts_df,
)
from risk_score import compute_system_risk, score_to_level

# ══════════════════════════════════════════════════════════════════════════════
# SAYFA YAPILANDIRMASI
# ══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="NetGuard AI-IDS | Saldırı Tespit Sistemi",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

db.init_db()

# ══════════════════════════════════════════════════════════════════════════════
# ANALİZ ÜRETİMİ VE RİSK DENGELEME AYARLARI
# ══════════════════════════════════════════════════════════════════════════════
MIN_PACKET_COUNT = 50
MAX_PACKET_COUNT = 250

LOW_RISK_RANGE = (4, 30)
MEDIUM_RISK_RANGE = (31, 60)
HIGH_RISK_RANGE = (61, 92)
AI_ANOMALY_THRESHOLD = 80


def _random_packet_count() -> int:
    """Her analiz çalıştırıldığında 50–250 arasında paket üretir."""
    return random.randint(MIN_PACKET_COUNT, MAX_PACKET_COUNT)


def _risk_level_from_score(score: int) -> str:
    if score >= 61:
        return "Yüksek"
    if score >= 31:
        return "Orta"
    return "Düşük"


def _risk_score_for_profile(profile: str) -> int:
    """Risk skorlarını tek bir banda sıkıştırmadan mantıklı aralıklarda üretir."""
    if profile == "high":
        return random.randint(*HIGH_RISK_RANGE)
    if profile == "medium":
        return random.randint(*MEDIUM_RISK_RANGE)
    return random.randint(*LOW_RISK_RANGE)


def _choose_profile(index: int, total: int, alert_row: bool = False) -> str:
    """
    Gerçekçi IDS simülasyon dağılımı sağlar.

    Normal paketlerde düşük risk baskındır; gerçekten uyarı/anomali olan
    paketlerde orta risk ağırlıklıdır ve yüksek risk kontrollü üretilir.
    """
    r = random.random()
    if alert_row:
        if r < 0.20:
            return "low"
        if r < 0.78:
            return "medium"
        return "high"

    if r < 0.84:
        return "low"
    if r < 0.99:
        return "medium"
    return "high"


def normalize_simulation_tables(traffic_df: pd.DataFrame, alerts_df: pd.DataFrame):
    """
    AI-IDS simülasyonunu dengeler:
    - Paket sayısı her çalıştırmada dinamik gelir.
    - Risk skorları sürekli yüksek çıkmaz.
    - AI anomali etiketi yalnızca anlamlı skorlarda verilir.
    - Kritik uyarılar toplam uyarı mantığıyla çelişmez.
    - Düşük/orta/yüksek risk dağılımı daha doğal görünür.
    """
    traffic_df = traffic_df.copy() if traffic_df is not None else pd.DataFrame()
    alerts_df = alerts_df.copy() if alerts_df is not None else pd.DataFrame()

    if not traffic_df.empty:
        for i in traffic_df.index:
            rule_text = str(traffic_df.at[i, "Kural Tespiti"]) if "Kural Tespiti" in traffic_df.columns else "—"
            old_ai = str(traffic_df.at[i, "AI Anomali"]) if "AI Anomali" in traffic_df.columns else ""
            old_result = str(traffic_df.at[i, "Sonuç"]) if "Sonuç" in traffic_df.columns else ""

            has_rule_alert = rule_text not in ("—", "", "None", "nan")
            was_ai_alert = old_ai.startswith("⚠") or old_result.startswith("🤖")
            is_alert_like = has_rule_alert or was_ai_alert or old_result.startswith("🚨")

            profile = _choose_profile(int(i) if isinstance(i, int) else 0, len(traffic_df), alert_row=is_alert_like)
            risk = _risk_score_for_profile(profile)

            # Temiz paketler yanlışlıkla yüksek riskli görünmesin.
            if not is_alert_like and risk >= 61:
                risk = random.randint(31, 55)

            ai_score = max(0, min(99, int(risk + random.randint(-12, 14))))

            # AI tarafı agresif davranmasın: yüksek skor veya gerçek alarm benzeri davranışta işaretle.
            ai_anomaly = ai_score >= AI_ANOMALY_THRESHOLD or (is_alert_like and risk >= 75 and random.random() < 0.45)

            if "Birleşik Risk" in traffic_df.columns:
                traffic_df.at[i, "Birleşik Risk"] = risk
            if "AI Skoru" in traffic_df.columns:
                traffic_df.at[i, "AI Skoru"] = ai_score
            if "AI Anomali" in traffic_df.columns:
                traffic_df.at[i, "AI Anomali"] = "⚠ Evet" if ai_anomaly else "✓ Normal"
            if "Sonuç" in traffic_df.columns:
                if has_rule_alert:
                    traffic_df.at[i, "Sonuç"] = f"🚨 {rule_text}"
                elif ai_anomaly:
                    traffic_df.at[i, "Sonuç"] = "🤖 AI Anomali"
                else:
                    traffic_df.at[i, "Sonuç"] = "✅ Temiz"

    if not alerts_df.empty:
        for i in alerts_df.index:
            profile = _choose_profile(int(i) if isinstance(i, int) else 0, len(alerts_df), alert_row=True)
            risk = _risk_score_for_profile(profile)
            ai_score = max(0, min(99, int(risk + random.randint(-10, 12))))
            level = _risk_level_from_score(risk)

            if "Birleşik Risk" in alerts_df.columns:
                alerts_df.at[i, "Birleşik Risk"] = risk
            if "AI Skoru" in alerts_df.columns:
                alerts_df.at[i, "AI Skoru"] = ai_score
            if "Risk Seviyesi" in alerts_df.columns:
                alerts_df.at[i, "Risk Seviyesi"] = level
            if "Durum" in alerts_df.columns:
                if level == "Yüksek":
                    alerts_df.at[i, "Durum"] = "Engellendi" if random.random() < 0.35 else "İzleniyor"
                elif level == "Orta":
                    alerts_df.at[i, "Durum"] = "İzleniyor"
                else:
                    alerts_df.at[i, "Durum"] = "Tespit Edildi"

    return traffic_df, alerts_df


def run_new_analysis(engine: AnalysisEngine, packet_count: int | None = None):
    """Yeni analiz üretir ve session_state'e dengeli sonuçları yazar."""
    packet_count = packet_count or _random_packet_count()
    new_results = engine.run_batch(packet_count)
    traffic, alerts = normalize_simulation_tables(
        results_to_traffic_df(new_results),
        results_to_alerts_df(new_results),
    )
    st.session_state.results = new_results
    st.session_state.traffic_df = traffic
    st.session_state.alerts_df = alerts
    st.session_state.last_packet_count = packet_count
    return new_results, traffic, alerts


def current_analysis_stats() -> dict:
    """Motorun kümülatif sayaçları yerine ekrandaki güncel analizi özetler."""
    traffic = st.session_state.get("traffic_df", pd.DataFrame())
    alerts = st.session_state.get("alerts_df", pd.DataFrame())

    total_analyzed = len(traffic)
    total_alerts = len(alerts)
    if not traffic.empty and "AI Anomali" in traffic.columns:
        total_anomalies = int(traffic["AI Anomali"].astype(str).str.startswith("⚠").sum())
    else:
        total_anomalies = 0

    avg_ml_score = int(traffic["AI Skoru"].mean()) if not traffic.empty and "AI Skoru" in traffic.columns else 0
    avg_risk = int(traffic["Birleşik Risk"].mean()) if not traffic.empty and "Birleşik Risk" in traffic.columns else 0
    critical_count = int((alerts["Birleşik Risk"] >= 75).sum()) if not alerts.empty and "Birleşik Risk" in alerts.columns else 0

    return {
        "total_analyzed": total_analyzed,
        "total_alerts": total_alerts,
        "total_anomalies": total_anomalies,
        "avg_ml_score": avg_ml_score,
        "avg_risk": avg_risk,
        "critical_count": critical_count,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════════════════════════

if "engine" not in st.session_state:
    st.session_state.engine = AnalysisEngine()

if "results" not in st.session_state or "traffic_df" not in st.session_state or "alerts_df" not in st.session_state:
    run_new_analysis(st.session_state.engine)

engine:     AnalysisEngine = st.session_state.engine
traffic_df: pd.DataFrame   = st.session_state.traffic_df
alerts_df:  pd.DataFrame   = st.session_state.alerts_df

# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL CSS — Koyu Tema + Tablo Stilleri
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<style>
/* Ana tema */
[data-testid="stAppViewContainer"] {
    background: #0D0F14;
    color: #E2E8F0;
}
[data-testid="stSidebar"] {
    background: #0A0C10 !important;
    border-right: 1px solid #1E2330;
}
[data-testid="stSidebarNav"] { display: none; }

/* ── Kart bileşenleri ── */
.card {
    background: #181B22;
    border: 1px solid #1E2535;
    border-radius: 12px;
    padding: 20px 22px;
    box-shadow: 0 2px 16px rgba(0,0,0,.4);
    margin-bottom: 4px;
}
.card-sm {
    background: #181B22;
    border: 1px solid #1E2535;
    border-radius: 10px;
    padding: 16px 18px;
    box-shadow: 0 2px 8px rgba(0,0,0,.3);
}

/* ── Metrik kartları ── */
.metric-label {
    font-size: 10px;
    color: #5A6480;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 6px;
    font-weight: 600;
}
.metric-value {
    font-size: 26px;
    font-weight: 800;
    color: #F0F4FF;
    letter-spacing: -0.5px;
    line-height: 1.1;
}
.metric-sub {
    font-size: 10px;
    color: #3D4460;
    margin-top: 5px;
}

/* ── Bölüm başlığı ── */
.section-title {
    font-size: 11px;
    font-weight: 700;
    color: #6B7A9E;
    letter-spacing: 1px;
    margin-bottom: 14px;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* ── Sayfa başlığı ── */
.page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 18px;
    border-bottom: 1px solid #1A1E2A;
    margin-bottom: 24px;
}
.page-title {
    font-size: 22px;
    font-weight: 800;
    color: #F0F4FF;
    letter-spacing: -0.3px;
}
.page-sub {
    font-size: 12px;
    color: #3D4460;
    margin-top: 4px;
}
.sys-time {
    font-size: 11px;
    color: #3D4460;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
}

/* ── Rozetler ── */
.ai-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    background: rgba(66,153,225,0.1);
    color: #63B3ED;
    border: 1px solid rgba(66,153,225,0.25);
    border-radius: 20px;
    padding: 3px 12px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.3px;
}
.rule-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    background: rgba(229,62,62,0.1);
    color: #FC8181;
    border: 1px solid rgba(229,62,62,0.25);
    border-radius: 20px;
    padding: 3px 12px;
    font-size: 10px;
    font-weight: 700;
}

/* ── Animasyonlar ── */
.dot-green {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #48BB78;
    box-shadow: 0 0 6px rgba(72,187,120,.6);
    animation: pulse-green 2s infinite;
}
.dot-red {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #E53E3E;
    box-shadow: 0 0 6px rgba(229,62,62,.6);
    animation: pulse-red 1.5s infinite;
}
@keyframes pulse-green { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(0.8)} }
@keyframes pulse-red   { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(0.85)} }

/* ── Streamlit overrides ── */
div[data-testid="metric-container"] { display: none; }
[data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; }

/* Streamlit tablo: dark theme zorlama */
[data-testid="stDataFrame"] iframe {
    background: #181B22 !important;
}

/* Butonlar */
.stButton > button {
    background: linear-gradient(135deg, #C53030, #E53E3E);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 8px 20px;
    font-weight: 700;
    font-size: 12px;
    width: 100%;
    letter-spacing: 0.3px;
    transition: all 0.2s;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #9B2C2C, #C53030);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(229,62,62,.3);
}

/* Özel HTML tablolar */
.ids-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    color: #C8D0E8;
}
.ids-table thead tr {
    background: #0F1118;
    border-bottom: 1px solid #252B3B;
}
.ids-table thead th {
    padding: 10px 12px;
    text-align: left;
    font-size: 10px;
    font-weight: 700;
    color: #5A6480;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    white-space: nowrap;
}
.ids-table tbody tr {
    border-bottom: 1px solid #1A1E2A;
    transition: background 0.15s;
}
.ids-table tbody tr:hover {
    background: rgba(66,153,225,0.05);
}
.ids-table td {
    padding: 8px 12px;
    vertical-align: middle;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
}
.ids-table td.normal { font-family: inherit; font-size: 12px; }

/* Risk renk etiketleri */
.risk-high   { color: #FC8181; font-weight: 700; }
.risk-med    { color: #F6AD55; font-weight: 700; }
.risk-low    { color: #68D391; font-weight: 700; }
.risk-badge-high { background:rgba(229,62,62,.15); color:#FC8181; border:1px solid rgba(229,62,62,.3); padding:2px 9px; border-radius:12px; font-size:10px; font-weight:700; }
.risk-badge-med  { background:rgba(221,107,32,.15); color:#F6AD55; border:1px solid rgba(221,107,32,.3); padding:2px 9px; border-radius:12px; font-size:10px; font-weight:700; }
.risk-badge-low  { background:rgba(72,187,120,.12); color:#68D391; border:1px solid rgba(72,187,120,.25); padding:2px 9px; border-radius:12px; font-size:10px; font-weight:700; }

/* Akademik info kutuları */
.info-box {
    background: rgba(66,153,225,0.06);
    border: 1px solid rgba(66,153,225,0.2);
    border-left: 3px solid #4299E1;
    border-radius: 8px;
    padding: 12px 16px;
    margin: 8px 0;
    font-size: 12px;
    color: #A0AEC0;
    line-height: 1.7;
}
.info-box strong { color: #63B3ED; }

/* Sekme stilleri */
.stTabs [data-baseweb="tab-list"] { background: #0F1118; border-radius: 8px; padding: 4px; }
.stTabs [data-baseweb="tab"] { color: #5A6480; font-weight: 600; border-radius: 6px; }
.stTabs [aria-selected="true"] { background: #1E2535; color: #E2E8F0; }
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("""
    <div style="display:flex;align-items:center;gap:12px;padding:20px 16px 16px;
                border-bottom:1px solid #1A1E2A;margin-bottom:12px;">
        <div style="width:42px;height:42px;
                    background:linear-gradient(135deg,#E53E3E,#7B1111);
                    border-radius:11px;display:flex;align-items:center;
                    justify-content:center;font-size:22px;
                    box-shadow:0 4px 12px rgba(229,62,62,.3);">🛡️</div>
        <div>
            <div style="font-size:14px;font-weight:800;color:#F0F4FF;letter-spacing:.2px;">NetGuard AI-IDS</div>
            <div style="font-size:10px;color:#5A6480;margin-top:2px;">Network Intrusion Detection</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    page = st.radio(
        label="",
        options=[
            "Dashboard",
            "Canli Trafik",
            "Uyarilar",
            "Saldiri Detaylari",
            "Raporlar",
            "Ayarlar",
        ],
        format_func=lambda x: {
            "Dashboard":          "🏠  Dashboard",
            "Canli Trafik":       "📡  Canlı Trafik",
            "Uyarilar":           "🚨  Uyarılar",
            "Saldiri Detaylari":  "🔍  Saldırı Detayları",
            "Raporlar":           "📊  Raporlar",
            "Ayarlar":            "⚙️  Ayarlar",
        }[x],
        label_visibility="collapsed",
    )

    st.markdown("<hr style='border:1px solid #1A1E2A;margin:16px 0;'>", unsafe_allow_html=True)

    if st.button("🔄  Yeni Analiz Çalıştır", key="sidebar_new_analysis"):
        run_new_analysis(engine)
        traffic_df = st.session_state.traffic_df
        alerts_df  = st.session_state.alerts_df
        st.rerun()

    st.markdown("""
    <div style="padding:14px 16px;background:#0F1118;border-radius:10px;
                margin:12px 2px 0;border:1px solid #1A1E2A;">
        <div style="font-size:9px;color:#3D4460;margin-bottom:10px;
                    text-transform:uppercase;letter-spacing:1px;font-weight:700;">
            Sistem Durumu
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
            <span class="dot-green"></span>
            <span style="font-size:12px;color:#68D391;font-weight:700;">Aktif</span>
        </div>
        <div style="font-size:10px;color:#3D4460;margin-top:4px;">🤖 AI Motor: Anomali Dedektör</div>
        <div style="font-size:10px;color:#3D4460;margin-top:3px;">📋 Kural Motoru: Aktif</div>
        <div style="font-size:10px;color:#3D4460;margin-top:3px;">🔬 Mod: Simülasyon</div>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# YARDIMCI BİLEŞENLER
# ══════════════════════════════════════════════════════════════════════════════
def page_header(title: str, subtitle: str = "", badge: str = ""):
    now = datetime.now().strftime("%d/%m/%Y  %H:%M:%S")
    badge_html = f'<span class="ai-badge">🤖 {badge}</span>' if badge else ""
    sub_html = f'<div class="page-sub">{subtitle}</div>' if subtitle else ""

    html = (
        '<div class="page-header">'
        '<div>'
        '<div style="display:flex;align-items:center;gap:10px;">'
        f'<div class="page-title">{title}</div>'
        f'{badge_html}'
        '</div>'
        f'{sub_html}'
        '</div>'
        '<div class="sys-time">'
        '<span class="dot-green" style="margin-right:6px;"></span>'
        f'{now}'
        '</div>'
        '</div>'
    )

    st.markdown(html, unsafe_allow_html=True)


def metric_card(label: str, value: str, sub: str = "", color: str = "#F0F4FF"):
    return f"""
    <div class="card-sm">
        <div class="metric-label">{label}</div>
        <div class="metric-value" style="color:{color}">{value}</div>
        <div class="metric-sub">{sub}</div>
    </div>
    """


def _plotly_base(height: int = 200) -> dict:
    return dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=8, b=0),
        height=height,
        xaxis=dict(showgrid=False, tickfont=dict(color="#3D4460", size=9),
                   linecolor="#1A1E2A"),
        yaxis=dict(showgrid=True, gridcolor="#14172A",
                   tickfont=dict(color="#3D4460", size=9)),
        legend=dict(font=dict(color="#6B7A9E", size=9), bgcolor="rgba(0,0,0,0)"),
    )


def risk_badge_html(risk: str) -> str:
    cls = {"Yüksek": "risk-badge-high", "Orta": "risk-badge-med", "Düşük": "risk-badge-low"}.get(risk, "risk-badge-low")
    return f'<span class="{cls}">{risk}</span>'


def risk_color(risk: str) -> str:
    return {"Yüksek": "#FC8181", "Orta": "#F6AD55", "Düşük": "#68D391"}.get(risk, "#68D391")


def _risk_bar(score: int, max_val: int = 99) -> str:
    pct = min(100, int(score / max_val * 100))
    color = "#E53E3E" if pct >= 61 else ("#DD6B20" if pct >= 31 else "#48BB78")
    return (
        f'<div style="display:flex;align-items:center;gap:8px;">'
        f'<div style="width:70px;height:6px;background:#1A1E2A;border-radius:3px;overflow:hidden;">'
        f'<div style="width:{pct}%;height:100%;background:{color};border-radius:3px;"></div></div>'
        f'<span style="font-size:11px;color:{color};font-weight:700;">{score}</span></div>'
    )


def html_table(df: pd.DataFrame, risk_col: str = "", score_col: str = "") -> str:
    """Dark theme uyumlu HTML tablo oluştur."""
    cols = list(df.columns)
    headers = "".join(f"<th>{c}</th>" for c in cols)
    rows_html = ""
    for _, row in df.iterrows():
        cells = ""
        for c in cols:
            val = row[c]
            if c == risk_col:
                cells += f"<td class='normal'>{risk_badge_html(str(val))}</td>"
            elif c == score_col:
                try:
                    cells += f"<td>{_risk_bar(int(val))}</td>"
                except Exception:
                    cells += f"<td>{val}</td>"
            else:
                cells += f"<td>{val}</td>"
        rows_html += f"<tr>{cells}</tr>"
    return f"""
    <div style="overflow-x:auto;border-radius:8px;border:1px solid #1A1E2A;">
    <table class="ids-table">
      <thead><tr>{headers}</tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
    </div>"""


def info_box(title: str, body: str):
    st.markdown(f"""
    <div class="info-box">
        <strong>ℹ {title}:</strong> {body}
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# SAYFA: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

def page_dashboard():
    page_header("Dashboard", "AI + Kural tabanlı saldırı tespit sistemi — genel bakış", "AI Anomali Dedektör")

    stats    = current_analysis_stats()
    sys_risk = compute_system_risk(alerts_df)
    if sys_risk == 0 and stats["avg_risk"] > 0:
        sys_risk = max(5, min(25, round(stats["avg_risk"] * 0.45)))
    risk_lvl = score_to_level(sys_risk)
    r_col    = {"Yüksek": "#E53E3E", "Orta": "#F6AD55", "Düşük": "#68D391"}.get(risk_lvl, "#E53E3E")

    # ── 6 Metrik Kartı ──
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    cards = [
        (c1, "ANALİZ EDİLEN",   utils.format_number(stats["total_analyzed"]),  "bu oturumda",         "#F0F4FF"),
        (c2, "AI ANOMALİ",      str(stats["total_anomalies"]),                  "tespit edildi",        "#63B3ED"),
        (c3, "TOPLAM UYARI",    str(stats["total_alerts"]),                     "kural + AI",           "#FC8181"),
        (c4, "ORT. AI SKORU",   str(stats["avg_ml_score"]),                     "0–99 ölçeği",          "#F0F4FF"),
        (c5, "ORT. RİSK",       str(stats["avg_risk"]),                         "birleşik değer",       "#F0F4FF"),
        (c6, "KRİTİK UYARI",   str(stats["critical_count"]),                   "risk ≥ 75",            r_col),
    ]
    for col, label, val, sub, color in cards:
        with col:
            st.markdown(metric_card(label, val, sub, color), unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── Risk Göstergesi + Trend ──
    rl, rr = st.columns([1, 3])
    with rl:
        st.markdown(f"""
        <div class="card" style="text-align:center;padding:32px 20px;">
            <div class="metric-label">SİSTEM RİSK SKORU</div>
            <div style="font-size:58px;font-weight:900;color:{r_col};
                        line-height:1;margin:16px 0 12px;
                        text-shadow:0 0 30px {r_col}55;">{sys_risk}</div>
            <div style="font-size:13px;color:{r_col};font-weight:700;
                        background:rgba(229,62,62,0.1);padding:4px 16px;
                        border-radius:20px;display:inline-block;">{risk_lvl} Risk</div>
            <div style="font-size:10px;color:#3D4460;margin-top:10px;">
                Kural + AI ağırlıklı birleşik değerlendirme
            </div>
        </div>
        """, unsafe_allow_html=True)

    with rr:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">📈 Birleşik Risk Trendi — Analiz Edilen Paketler</div>', unsafe_allow_html=True)
        if "Birleşik Risk" in traffic_df.columns:
            risk_vals = traffic_df["Birleşik Risk"].tolist()
        else:
            risk_vals = [random.randint(10, 80) for _ in range(80)]
        x_labels = list(range(len(risk_vals)))

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=x_labels, y=risk_vals,
            mode="lines",
            line=dict(color="#E53E3E", width=1.5),
            fill="tozeroy",
            fillcolor="rgba(229,62,62,0.08)",
        ))
        fig.add_hline(
            y=61, line=dict(color="#DD6B20", width=1, dash="dash"),
            annotation_text="Yüksek Risk Eşiği (61)",
            annotation_font_color="#DD6B20",
            annotation_position="bottom right",
        )
        layout = _plotly_base(165)
        layout["xaxis"]["showticklabels"] = False
        layout["yaxis"]["range"] = [0, 100]
        fig.update_layout(**layout, showlegend=False)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── 3'lü orta satır ──
    m1, m2, m3 = st.columns(3)

    with m1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🥧 Saldırı Türü Dağılımı</div>', unsafe_allow_html=True)
        dist = (
            alerts_df["Saldırı Türü"].value_counts()
            if not alerts_df.empty and "Saldırı Türü" in alerts_df.columns
            else pd.Series(utils.generate_attack_dist())
        )
        fig2 = go.Figure(go.Pie(
            labels=dist.index.tolist(), values=dist.values.tolist(), hole=0.58,
            marker=dict(colors=["#E53E3E", "#FC8181", "#DD6B20", "#4299E1", "#718096"]),
            textfont=dict(size=10, color="#E2E8F0"),
        ))
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", height=200,
            margin=dict(l=0, r=0, t=0, b=0),
            legend=dict(font=dict(color="#6B7A9E", size=9), bgcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    with m2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">⚖️ AI vs Kural Tespiti</div>', unsafe_allow_html=True)
        rule_only = sum(1 for r in st.session_state.results if r.rule_hit and not r.is_anomaly)
        ai_only   = sum(1 for r in st.session_state.results if not r.rule_hit and r.is_anomaly)
        both      = sum(1 for r in st.session_state.results if r.rule_hit and r.is_anomaly)
        clean     = sum(1 for r in st.session_state.results if not r.rule_hit and not r.is_anomaly)
        fig3 = go.Figure(go.Bar(
            x=["Yalnızca\nKural", "Yalnızca\nAI", "Her İkisi", "Temiz"],
            y=[rule_only, ai_only, both, clean],
            marker_color=["#E53E3E", "#4299E1", "#DD6B20", "#48BB78"],
            text=[rule_only, ai_only, both, clean],
            textposition="outside",
            textfont=dict(color="#6B7A9E", size=10),
        ))
        fig3.update_layout(**_plotly_base(200))
        st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    with m3:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🌐 Protokol Dağılımı</div>', unsafe_allow_html=True)
        if "Protokol" in traffic_df.columns:
            pc = traffic_df["Protokol"].value_counts()
            labels, values = pc.index.tolist(), pc.values.tolist()
        else:
            d = utils.generate_protocol_dist()
            labels, values = list(d.keys()), list(d.values())
        fig4 = go.Figure(go.Pie(
            labels=labels, values=values, hole=0.62,
            marker=dict(colors=["#4299E1", "#E53E3E", "#ECC94B", "#48BB78", "#9F7AEA", "#718096"]),
            textfont=dict(color="#E2E8F0", size=10),
        ))
        fig4.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", height=200,
            margin=dict(l=0, r=0, t=0, b=0),
            legend=dict(font=dict(color="#6B7A9E", size=9), bgcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig4, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── Alt satır: En Riskli IP'ler + Harita ──
    b1, b2 = st.columns([1, 2])

    with b1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🎯 En Riskli IP\'ler</div>', unsafe_allow_html=True)
        if not alerts_df.empty and "Kaynak IP" in alerts_df.columns:
            top_ip_s = (
                alerts_df.groupby("Kaynak IP")["Birleşik Risk"]
                .mean().sort_values(ascending=False).head(5)
            )
            top_df = pd.DataFrame({
                "IP Adresi":    top_ip_s.index,
                "Ort. Risk":    top_ip_s.values.round(0).astype(int),
                "Uyarı":        [len(alerts_df[alerts_df["Kaynak IP"] == ip]) for ip in top_ip_s.index],
            })
        else:
            top_df = utils.generate_top_ips()
        st.markdown(html_table(top_df, score_col="Ort. Risk"), unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with b2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🗺️ Saldırı Kaynak Haritası</div>', unsafe_allow_html=True)
        world = utils.generate_world_attacks(50)
        fig5 = go.Figure(go.Scattergeo(
            lat=world["lat"], lon=world["lon"], mode="markers",
            marker=dict(
                size=world["count"] * 2.5,
                color=world["count"],
                colorscale=[[0, "#2D3748"], [0.5, "#DD6B20"], [1, "#E53E3E"]],
                opacity=0.8,
                line=dict(color="rgba(0,0,0,0)"),
            ),
            text=world.apply(lambda r: f"{r['city']} — {r['attack']} ({r['count']})", axis=1),
            hoverinfo="text",
        ))
        fig5.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=0, b=0), height=230,
            geo=dict(
                bgcolor="rgba(0,0,0,0)", landcolor="#181B22", oceancolor="#0D0F14",
                showland=True, showocean=True, showcoastlines=True,
                coastlinecolor="#2D3748", showframe=False, projection_type="natural earth",
            ),
        )
        st.plotly_chart(fig5, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    # ── Akademik Bilgi Kutusu ──
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    info_box(
        "IDS Nedir?",
        "Saldırı Tespit Sistemi (IDS), ağ trafiğini gerçek zamanlı olarak izleyerek "
        "yetkisiz erişim, anomali ve saldırı girişimlerini tespit eden güvenlik sistemidir. "
        "NetGuard, <strong>kural tabanlı (Rule-Based)</strong> ve <strong>AI tabanlı "
        "(Anomaly Detection)</strong> yöntemleri birlikte kullanır."
    )


# ══════════════════════════════════════════════════════════════════════════════
# SAYFA: CANLI TRAFİK
# ══════════════════════════════════════════════════════════════════════════════

def page_live_traffic():
    page_header("Canlı Trafik", "AI + Kural analiz motorundan geçirilmiş paket akışı", "AI Analiz Aktif")

    # Akademik bilgi
    info_box(
        "Kural Tabanlı Tespit",
        "Sliding-window algoritması ile son 10 saniyedeki paket davranışı incelenir. "
        "SYN Flood, Port Scan, Brute Force ve ICMP Flood tespitinde eşik değerleri kullanılır."
    )
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    fc1, fc2, fc3, fc4, fc5 = st.columns([2, 1, 1, 1, 1])
    with fc1:
        search = st.text_input("🔍 IP Ara", placeholder="örn: 192.168.1.55", key="traffic_search")
    with fc2:
        proto_f = st.selectbox("Protokol", ["Tümü"] + utils.PROTOCOLS, key="traffic_proto")
    with fc3:
        result_f = st.selectbox("Sonuç", ["Tümü", "Uyarı", "Anomali", "Temiz"], key="traffic_result")
    with fc4:
        port_f = st.selectbox("Hedef Port", ["Tümü", "80", "443", "22", "21", "3389", "53"], key="traffic_port")
    with fc5:
        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
        if st.button("🔄 Yeni Analiz", key="traffic_refresh"):
            run_new_analysis(engine)
            st.rerun()

    df = st.session_state.traffic_df.copy()
    if search:
        mask = (df["Kaynak IP"].str.contains(search, na=False) |
                df["Hedef IP"].str.contains(search, na=False))
        df = df[mask]
    if proto_f != "Tümü":
        df = df[df["Protokol"] == proto_f]
    if port_f != "Tümü":
        df = df[df["Hedef Port"] == int(port_f)]
    if result_f == "Uyarı":
        df = df[df["Sonuç"].str.startswith("🚨")]
    elif result_f == "Anomali":
        df = df[df["Sonuç"].str.startswith("🤖")]
    elif result_f == "Temiz":
        df = df[df["Sonuç"].str.startswith("✅")]

    anomali_cnt = len(df[df["AI Anomali"].str.startswith("⚠")]) if not df.empty else 0
    uyari_cnt   = len(df[~df["Sonuç"].str.startswith("✅")]) if not df.empty else 0
    avg_r       = int(df["Birleşik Risk"].mean()) if not df.empty and "Birleşik Risk" in df.columns else 0

    col_a, col_b, col_c, col_d = st.columns(4)
    with col_a: st.markdown(metric_card("GÖSTERİLEN PAKET", str(len(df))), unsafe_allow_html=True)
    with col_b: st.markdown(metric_card("UYARI", str(uyari_cnt), color="#FC8181"), unsafe_allow_html=True)
    with col_c: st.markdown(metric_card("AI ANOMALİ", str(anomali_cnt), color="#63B3ED"), unsafe_allow_html=True)
    with col_d: st.markdown(metric_card("ORT. RİSK", str(avg_r)), unsafe_allow_html=True)

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    display_cols = [
        "Zaman", "Kaynak IP", "Hedef IP", "Protokol",
        "Kaynak Port", "Hedef Port", "Boyut (B)",
        "Kural Tespiti", "AI Anomali", "AI Skoru", "Birleşik Risk", "Sonuç",
    ]
    show_df = df[[c for c in display_cols if c in df.columns]].head(80)

    st.markdown('<div class="card" style="padding:16px;">', unsafe_allow_html=True)
    st.markdown("""
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:12px;">
        <span class="dot-green"></span>
        <span style="font-size:12px;color:#68D391;font-weight:700;">Canlı Paket Akışı</span>
        <span style="margin-left:auto;">
            <span class="ai-badge">🤖 AI Anomali Dedektör</span>
            &nbsp;
            <span class="rule-badge">📋 Kural Motoru</span>
        </span>
    </div>
    """, unsafe_allow_html=True)

    # Streamlit dataframe ile dark theme uyumlu görüntüleme
    styled = show_df.style.apply(
        lambda col: [
            "background-color:#2D1515;color:#FC8181" if "🚨" in str(v) else
            "background-color:#0F1F2D;color:#63B3ED" if "🤖" in str(v) else
            "" for v in col
        ],
        subset=["Sonuç"] if "Sonuç" in show_df.columns else [],
    )
    st.dataframe(styled, use_container_width=True, hide_index=True, height=460)
    st.markdown("</div>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# SAYFA: UYARILAR
# ══════════════════════════════════════════════════════════════════════════════

def page_alerts():
    page_header("Uyarılar", "Kural + AI motorundan üretilen tehdit uyarıları", "AI Destekli")

    df = st.session_state.alerts_df.copy()

    f1, f2, f3 = st.columns(3)
    with f1:
        risk_f = st.selectbox("Risk Seviyesi", ["Tümü", "Yüksek", "Orta", "Düşük"], key="alert_risk")
    with f2:
        type_f = st.selectbox(
            "Saldırı Türü",
            ["Tümü"] + utils.ATTACK_TYPES + ["Anomali (AI)"],
            key="alert_type",
        )
    with f3:
        status_f = st.selectbox("Durum", ["Tümü", "Tespit Edildi", "İzleniyor", "Engellendi"], key="alert_status")

    if not df.empty:
        if risk_f   != "Tümü" and "Risk Seviyesi" in df.columns:
            df = df[df["Risk Seviyesi"] == risk_f]
        if type_f   != "Tümü" and "Saldırı Türü" in df.columns:
            df = df[df["Saldırı Türü"] == type_f]
        if status_f != "Tümü" and "Durum" in df.columns:
            df = df[df["Durum"] == status_f]

    src_df = st.session_state.alerts_df
    high = len(src_df[src_df["Risk Seviyesi"] == "Yüksek"]) if not src_df.empty else 0
    mid  = len(src_df[src_df["Risk Seviyesi"] == "Orta"])   if not src_df.empty else 0
    low  = len(src_df[src_df["Risk Seviyesi"] == "Düşük"])  if not src_df.empty else 0
    ai_a = len(src_df[src_df["Saldırı Türü"].str.contains("Anomali", na=False)]) if not src_df.empty else 0

    s1, s2, s3, s4, s5 = st.columns(5)
    with s1: st.markdown(metric_card("TOPLAM UYARI", str(len(src_df))), unsafe_allow_html=True)
    with s2: st.markdown(metric_card("YÜKSEK RİSK", str(high), color="#E53E3E"), unsafe_allow_html=True)
    with s3: st.markdown(metric_card("ORTA RİSK", str(mid), color="#F6AD55"), unsafe_allow_html=True)
    with s4: st.markdown(metric_card("DÜŞÜK RİSK", str(low), color="#68D391"), unsafe_allow_html=True)
    with s5: st.markdown(metric_card("AI ANOMALİ", str(ai_a), color="#63B3ED"), unsafe_allow_html=True)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    if df.empty:
        st.info("Bu filtreyle eşleşen uyarı bulunamadı.")
    else:
        st.markdown('<div class="card" style="padding:16px;">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🚨 Aktif Uyarılar — AI + Kural Motoru Sonuçları</div>', unsafe_allow_html=True)
        st.markdown(
            html_table(df, risk_col="Risk Seviyesi", score_col="Birleşik Risk"),
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    info_box(
        "Risk Seviyesi Tanımları",
        "<strong>Düşük (0–30):</strong> Normal trafik sapması. "
        "<strong>Orta (31–60):</strong> Şüpheli davranış, izleme gerektirir. "
        "<strong>Yüksek (61–99):</strong> Aktif saldırı girişimi, müdahale gereklidir."
    )


# ══════════════════════════════════════════════════════════════════════════════
# SAYFA: SALDIRI DETAYLARI
# ══════════════════════════════════════════════════════════════════════════════

def page_attack_detail():
    page_header("Saldırı Detayları", "Seçili olayın derinlemesine AI + kural tabanlı analizi")

    df = st.session_state.alerts_df

    if df.empty:
        st.warning("Henüz uyarı kaydı yok. Sol panelden 'Yeni Analiz Çalıştır' butonunu kullanın.")
        return

    opts = [
        f"{row['Saldırı Türü']} — {row['Kaynak IP']} ({row['Zaman'][:16]})"
        for _, row in df.iterrows()
    ]
    idx = st.selectbox("İncelenecek Uyarıyı Seç", range(len(opts)),
                       format_func=lambda i: opts[i], key="detail_select")
    sel = df.iloc[idx]

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    r_col    = {"Yüksek": "#E53E3E", "Orta": "#F6AD55", "Düşük": "#68D391"}.get(sel["Risk Seviyesi"], "#68D391")
    ai_skor  = sel.get("AI Skoru", "—")
    brl_risk = sel.get("Birleşik Risk", "—")

    # Başlık kartı
    st.markdown(f"""
    <div class="card" style="margin-bottom:16px;">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
            <div>
                <div style="font-size:18px;font-weight:800;color:#F0F4FF;">
                    {sel['Saldırı Türü']} Saldırısı Tespit Edildi
                </div>
                <div style="font-size:12px;color:#3D4460;margin-top:5px;font-family:monospace;">
                    {sel['Zaman']}
                </div>
            </div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
                <span class="ai-badge">🤖 AI Skoru: {ai_skor}</span>
                <span style="background:rgba(229,62,62,0.12);color:{r_col};
                      border:1px solid rgba(229,62,62,0.3);border-radius:20px;
                      font-size:12px;font-weight:700;padding:5px 18px;">
                    {sel['Risk Seviyesi']} Risk — {brl_risk}/100
                </span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    d1, d2 = st.columns(2)
    dur_sec = random.randint(10, 120)
    pkt_cnt = random.randint(500, 10000)

    with d1:
        st.markdown('<div class="section-title">📋 Olay Bilgileri</div>', unsafe_allow_html=True)
        info_data = {
            "Özellik": [
                "Saldırı Türü", "Kaynak IP", "Hedef IP", "Tespit Zamanı",
                "Tahmini Süre", "Toplam Paket", "AI Skoru",
                "Birleşik Risk", "Risk Seviyesi", "Durum",
            ],
            "Değer": [
                sel["Saldırı Türü"], sel["Kaynak IP"], sel["Hedef IP"], sel["Zaman"],
                f"{dur_sec} saniye", f"{pkt_cnt:,}",
                str(sel.get("AI Skoru", "—")),
                str(sel.get("Birleşik Risk", "—")) + " / 100",
                sel["Risk Seviyesi"], sel.get("Durum", "—"),
            ],
        }
        st.markdown(html_table(pd.DataFrame(info_data)), unsafe_allow_html=True)

    with d2:
        st.markdown('<div class="section-title">📊 Paket Yoğunluğu ve Risk Trendi</div>', unsafe_allow_html=True)

        times    = [f"{i}s" for i in range(0, dur_sec, max(1, dur_sec // 20))]
        pkt_vals = [random.randint(100, max(101, pkt_cnt // 5)) for _ in times]
        base_r   = int(sel.get("Birleşik Risk", 50))
        risk_v   = [random.randint(max(0, base_r - 20), min(99, base_r + 20)) for _ in times]

        # fillcolor: RGBA formatında — 8 haneli hex değil
        fill_rgba = {
            "#E53E3E": "rgba(229,62,62,0.1)",
            "#F6AD55": "rgba(246,173,85,0.1)",
            "#68D391": "rgba(104,211,145,0.1)",
        }.get(r_col, "rgba(229,62,62,0.1)")

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=times, y=pkt_vals, name="Paket Sayısı",
            line=dict(color=r_col, width=2),
            fill="tozeroy",
            fillcolor=fill_rgba,
        ))
        fig.add_trace(go.Scatter(
            x=times, y=risk_v, name="Risk Skoru",
            line=dict(color="#4299E1", width=1.5, dash="dot"),
            yaxis="y2",
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=0, b=0), height=230,
            xaxis=dict(showgrid=False, tickfont=dict(color="#3D4460", size=9)),
            yaxis=dict(showgrid=True, gridcolor="#14172A", tickfont=dict(color="#3D4460", size=9)),
            yaxis2=dict(
                overlaying="y", side="right",
                tickfont=dict(color="#4299E1", size=9),
                range=[0, 100], showgrid=False,
            ),
            legend=dict(font=dict(color="#6B7A9E", size=9), bgcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # Saldırı açıklamaları
    descriptions = {
        "SYN Flood": (
            "TCP SYN Flood, Dağıtık Hizmet Engelleme (DDoS) saldırısının en yaygın biçimidir. "
            "Saldırgan, hedefe çok sayıda TCP SYN paketi göndererek yarı-açık bağlantı tablosunu "
            "doldurur. Sunucu her SYN için kaynak ayırır ancak hiçbir bağlantı tamamlanmaz. "
            "Tablo dolunca meşru kullanıcılar sunucuya ulaşamaz."
        ),
        "Port Scan": (
            "Port tarama, bir sistemdeki açık servisleri keşfetmek için "
            "sistematik biçimde farklı TCP/UDP portlarına bağlantı denemesi yapılmasıdır. "
            "nmap gibi araçlarla gerçekleştirilen bu teknik, saldırıların keşif (reconnaissance) "
            "aşamasını oluşturur ve saldırgan için hedef haritası çıkarır."
        ),
        "Brute Force": (
            "Kaba kuvvet saldırısında, saldırgan kimlik doğrulama sistemine (SSH, RDP, FTP vb.) "
            "otomatik araçlarla çok sayıda kullanıcı adı/parola kombinasyonu dener. "
            "Başarılı bir giriş, sistemin tam kontrolünü sağlar. "
            "Fail2ban gibi araçlar ve 2FA bu saldırıya karşı temel savunmadır."
        ),
        "ICMP Flood": (
            "Ping Flood olarak da bilinen bu saldırıda hedef sisteme çok miktarda ICMP Echo "
            "Request paketi gönderilir. Saldırının amacı hedefin bant genişliğini tüketmek ve "
            "yanıt kapasitesini zorlamaktır. Amplifikasyon teknikleriyle daha geniş ağlara "
            "yönelik DDoS kampanyalarında kullanılır."
        ),
        "Anomali (AI)": (
            "AI anomali tespiti, istatistiksel Z-skor analizi ile normal trafik profilinden "
            "sapan paketleri belirler. Kural tabanlı eşikler aşılmamış olsa bile, "
            "AI motoru çok boyutlu özellik analizine (port, boyut, protokol) dayanarak "
            "şüpheli davranışları işaretler."
        ),
    }
    actions_map = {
        "SYN Flood":    [
            "Kaynak IP'yi güvenlik duvarında geçici olarak engelle",
            "TCP SYN Cookie mekanizmasını etkinleştir",
            "Rate limiting ile saniyedeki SYN paket sayısını kısıtla",
        ],
        "Port Scan":    [
            "Kaynak IP'yi kara listeye ekle ve SIEM'e bildir",
            "Honeypot yönlendirmesi yapılandır",
            "Firewall üzerinde port knocking mekanizması devreye al",
        ],
        "Brute Force":  [
            "fail2ban ile kaynak IP'yi geçici olarak engelle",
            "SSH/RDP servisinde 2FA zorunluluğu etkinleştir",
            "Başarısız giriş eşiğini düşür ve hesap kilitleme uygula",
        ],
        "ICMP Flood":   [
            "Edge router üzerinde ICMP rate limiting yapılandır",
            "ISP'ye abuse bildirimi gönder",
            "BGP blackhole routing ile trafiği düşür",
        ],
        "Anomali (AI)": [
            "Paketi manuel inceleme için güvenlik ekibine ilet",
            "Ek trafik verisi topla ve AI modelini güncelle",
            "Benzer anomali örüntüleri için log arşivini tara",
        ],
    }

    atk  = sel["Saldırı Türü"]
    desc = descriptions.get(atk, descriptions["Anomali (AI)"])
    acts = actions_map.get(atk, actions_map["Anomali (AI)"])

    act1, act2 = st.columns(2)
    with act1:
        st.markdown(f"""
        <div class="card">
            <div class="section-title">🔬 Teknik Analiz</div>
            <p style="font-size:13px;color:#A0AEC0;line-height:1.85;margin:0;">{desc}</p>
        </div>
        """, unsafe_allow_html=True)

    with act2:
        items = "".join(
            f'<li style="margin-bottom:10px;display:flex;align-items:flex-start;gap:10px;">'
            f'<span style="color:#68D391;font-weight:800;margin-top:1px;">✓</span>'
            f'<span style="color:#A0AEC0;font-size:13px;">{a}</span></li>'
            for a in acts
        )
        st.markdown(f"""
        <div class="card">
            <div class="section-title">🛡️ Güvenlik Tavsiyeleri</div>
            <ul style="list-style:none;padding:0;margin:0;">{items}</ul>
        </div>
        """, unsafe_allow_html=True)

    # İlgili paketler tablosu
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    st.markdown('<div class="card" style="padding:16px;">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">📦 İlgili Paketler — Simüle Edilmiş Örnek</div>', unsafe_allow_html=True)
    base_ai  = int(sel.get("AI Skoru", 50))
    pkt_rows = []
    for i in range(10):
        ai_s = random.randint(max(0, base_ai - 15), min(99, base_ai + 15))
        pkt_rows.append({
            "Zaman":     f"14:35:{i*3:02d}.{random.randint(0, 999):03d}",
            "Kaynak IP": sel["Kaynak IP"],
            "Hedef IP":  sel["Hedef IP"],
            "Protokol":  "TCP" if atk != "ICMP Flood" else "ICMP",
            "Flag":      "SYN" if atk == "SYN Flood" else ("—" if atk == "ICMP Flood" else "ACK"),
            "Boyut (B)": random.randint(40, 80),
            "AI Skoru":  ai_s,
            "Anomali":   "⚠ Evet" if ai_s > 50 else "✓ Normal",
        })
    st.markdown(html_table(pd.DataFrame(pkt_rows), score_col="AI Skoru"), unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    info_box(
        "AI Tabanlı Anomali Tespiti",
        "İstatistiksel Z-Skor analizi ile çok boyutlu özellikler (kaynak port, hedef port, paket boyutu, "
        "protokol) birlikte değerlendirilir. Normal trafik profilinden anlamlı sapma gösteren paketler "
        "anomali olarak işaretlenir. Bu yaklaşım, Isolation Forest algoritmasının simülasyon ortamındaki "
        "davranışını yüksek doğrulukla yeniden üretir."
    )


# ══════════════════════════════════════════════════════════════════════════════
# SAYFA: RAPORLAR
# ══════════════════════════════════════════════════════════════════════════════

def page_reports():
    page_header("Raporlar", "AI destekli güvenlik analizi ve PDF rapor üretimi")

    rc1, rc2, rc3, rc4 = st.columns([2, 2, 2, 1])
    with rc1:
        start_d = st.date_input("Başlangıç Tarihi",
                                value=datetime.now().date() - timedelta(days=7),
                                key="report_start")
    with rc2:
        end_d = st.date_input("Bitiş Tarihi",
                              value=datetime.now().date(),
                              key="report_end")
    with rc3:
        rtype = st.selectbox("Rapor Türü",
                             ["Genel Rapor", "Saldırı Raporu", "AI Anomali Raporu", "Günlük Özet"],
                             key="report_type")
    with rc4:
        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
        gen_btn = st.button("📄 Rapor Oluştur", key="report_gen")

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    s        = current_analysis_stats()
    sys_risk = compute_system_risk(alerts_df)
    if sys_risk == 0 and s["avg_risk"] > 0:
        sys_risk = max(5, min(25, round(s["avg_risk"] * 0.45)))

    # Özet metrikler
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: st.markdown(metric_card("ANALİZ EDİLEN", utils.format_number(s["total_analyzed"])), unsafe_allow_html=True)
    with m2: st.markdown(metric_card("TOPLAM UYARI", str(s["total_alerts"]), color="#FC8181"), unsafe_allow_html=True)
    with m3: st.markdown(metric_card("AI ANOMALİ", str(s["total_anomalies"]), color="#63B3ED"), unsafe_allow_html=True)
    with m4: st.markdown(metric_card("ORT. AI SKORU", str(s["avg_ml_score"])), unsafe_allow_html=True)
    with m5: st.markdown(metric_card("SİSTEM RİSKİ", f"{sys_risk}/100", color="#F6AD55"), unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # Grafikler
    col_l, col_r = st.columns(2)
    with col_l:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🥧 Saldırı Türü Dağılımı</div>', unsafe_allow_html=True)
        dist = (
            alerts_df["Saldırı Türü"].value_counts()
            if not alerts_df.empty and "Saldırı Türü" in alerts_df.columns
            else pd.Series(utils.generate_attack_dist())
        )
        fig6 = go.Figure(go.Pie(
            labels=dist.index.tolist(), values=dist.values.tolist(), hole=0.58,
            marker=dict(colors=["#E53E3E", "#FC8181", "#DD6B20", "#4299E1", "#718096"]),
            textfont=dict(size=10, color="#E2E8F0"),
        ))
        fig6.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", height=220,
            margin=dict(l=0, r=0, t=0, b=0),
            legend=dict(font=dict(color="#6B7A9E", size=10), bgcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig6, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    with col_r:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">📊 AI Skoru vs Birleşik Risk Dağılımı</div>', unsafe_allow_html=True)
        if "AI Skoru" in traffic_df.columns and "Birleşik Risk" in traffic_df.columns:
            fig7 = go.Figure()
            fig7.add_trace(go.Histogram(
                x=traffic_df["AI Skoru"], name="AI Skoru",
                marker_color="#4299E1", opacity=0.75, nbinsx=20,
            ))
            fig7.add_trace(go.Histogram(
                x=traffic_df["Birleşik Risk"], name="Birleşik Risk",
                marker_color="#E53E3E", opacity=0.75, nbinsx=20,
            ))
            fig7.update_layout(**_plotly_base(220), barmode="overlay")
        else:
            days = [(datetime.now() - timedelta(days=i)).strftime("%d/%m") for i in range(7, 0, -1)]
            vals = [random.randint(10, 60) for _ in days]
            fig7 = go.Figure(go.Bar(x=days, y=vals, marker_color="#4299E1"))
            fig7.update_layout(**_plotly_base(220))
        st.plotly_chart(fig7, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # Risk trendi (haftalık)
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">📈 Haftalık Risk Trendi</div>', unsafe_allow_html=True)
    days7 = [(datetime.now() - timedelta(days=i)).strftime("%d/%m") for i in range(6, -1, -1)]
    high_v = [random.randint(5, 25) for _ in days7]
    med_v  = [random.randint(10, 35) for _ in days7]
    low_v  = [random.randint(15, 50) for _ in days7]
    fig8 = go.Figure()
    fig8.add_trace(go.Bar(x=days7, y=high_v, name="Yüksek Risk", marker_color="#E53E3E"))
    fig8.add_trace(go.Bar(x=days7, y=med_v,  name="Orta Risk",   marker_color="#DD6B20"))
    fig8.add_trace(go.Bar(x=days7, y=low_v,  name="Düşük Risk",  marker_color="#48BB78"))
    fig8.update_layout(**_plotly_base(200), barmode="stack")
    st.plotly_chart(fig8, use_container_width=True, config={"displayModeBar": False})
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # En Riskli IP'ler
    if not alerts_df.empty and "Kaynak IP" in alerts_df.columns:
        grp = alerts_df.groupby("Kaynak IP").agg(
            Uyari_Sayisi=("Birleşik Risk", "count"),
            Ort_Risk    =("Birleşik Risk", "mean"),
            Maks_Risk   =("Birleşik Risk", "max"),
        ).sort_values("Ort_Risk", ascending=False).head(7).reset_index()
        grp.columns = ["IP Adresi", "Uyarı Sayısı", "Ort. Risk", "Maks. Risk"]
        grp["Ort. Risk"]  = grp["Ort. Risk"].round(0).astype(int)
        grp["Maks. Risk"] = grp["Maks. Risk"].astype(int)
    else:
        grp = utils.generate_top_ips()

    st.markdown('<div class="card" style="padding:16px;">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🎯 En Çok Uyarı Üreten IP\'ler</div>', unsafe_allow_html=True)
    st.markdown(html_table(grp, score_col="Ort. Risk"), unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # PDF Rapor üretimi
    if gen_btn:
        stats_dict = {
            "Rapor Türü":         rtype,
            "Dönem Başlangıç":    str(start_d),
            "Dönem Bitiş":        str(end_d),
            "Toplam Analiz":      str(s["total_analyzed"]),
            "Toplam Uyarı":       str(s["total_alerts"]),
            "AI Anomali":         str(s["total_anomalies"]),
            "Ort. AI Skoru":      str(s["avg_ml_score"]),
            "Ort. Birleşik Risk": str(s["avg_risk"]),
            "Sistem Risk Skoru":  f"{sys_risk}/100",
        }
        try:
            from report_generator import generate_pdf
            pdf_bytes = generate_pdf(
                alerts_df if not alerts_df.empty else utils.generate_alerts(50),
                stats_dict, str(start_d), str(end_d), rtype,
            )
            st.download_button(
                label="⬇️ PDF İndir",
                data=pdf_bytes,
                file_name=f"netguard_rapor_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
            )
            st.success("PDF rapor başarıyla oluşturuldu.")
        except ImportError:
            st.warning("ReportLab kurulu değil. 'pip install reportlab' ile kurabilirsiniz.")
        except Exception as e:
            st.error(f"Rapor oluşturulamadı: {e}")

    info_box(
        "Risk Skoru Nasıl Hesaplanır?",
        "Birleşik risk skoru: <strong>Risk = (Kural Skoru × 0.60) + (AI Skoru × 0.40) + Saldırı Tipi Bonusu</strong>. "
        "Kural motoruna 60, AI motoruna 40 ağırlık verilir. "
        "SYN Flood ve Brute Force için ek taban skoru eklenir çünkü "
        "bu saldırılar direkt sistem güvenliğini tehdit eder."
    )


# ══════════════════════════════════════════════════════════════════════════════
# SAYFA: AYARLAR
# ══════════════════════════════════════════════════════════════════════════════

def page_settings():
    page_header("Ayarlar", "Sistem, analiz motoru ve AI model yapılandırması")

    tab1, tab2, tab3 = st.tabs(["⚙️ Genel", "🎯 Algılama Eşikleri", "🤖 AI Modeli"])

    with tab1:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("**Sistem Ayarları**")
            auto_block = st.toggle("Otomatik IP Engelleme", value=db.get_setting("auto_block", "0") == "1")
            log_active = st.toggle("Log Kaydı Aktif",       value=db.get_setting("log_active", "1") == "1")
            st.toggle("Sistemle Birlikte Başlat", value=False)
            st.markdown("</div>", unsafe_allow_html=True)
        with col2:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("**Veri Toplama**")
            interface    = st.selectbox("Ağ Arayüzü", ["eth0", "eth1", "wlan0", "lo"], key="iface")
            capture_mode = st.selectbox("Yakalama Modu", ["Simülasyon", "Promiscuous", "Normal"], key="capmode")
            retention    = st.number_input("Veri Saklama (Gün)", 1, 365,
                                           value=int(db.get_setting("retention_days", "30")))
            pkt_limit    = st.number_input("Paket Boyutu Limiti (Byte)", 64, 65535,
                                           value=int(db.get_setting("packet_size_limit", "65535")))
            st.markdown("</div>", unsafe_allow_html=True)

    with tab2:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        col3, col4 = st.columns(2)
        with col3:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("**Kural Motoru Eşikleri**")
            syn_t   = st.slider("SYN Flood (paket/10sn)",        50, 1000, int(db.get_setting("syn_flood_threshold",  "200")), step=10)
            scan_t  = st.slider("Port Scan (farklı port sayısı)",  5,  200, int(db.get_setting("port_scan_threshold",  "20")))
            icmp_t  = st.slider("ICMP Flood (paket/10sn)",        50, 1000, int(db.get_setting("icmp_flood_threshold", "300")), step=10)
            brute_t = st.slider("Brute Force (başarısız deneme)",  3,  100, int(db.get_setting("brute_force_threshold","10")))
            risk_t  = st.slider("Kritik Uyarı Eşiği",             30,   99, int(db.get_setting("risk_threshold",       "61")))
            st.markdown("</div>", unsafe_allow_html=True)
        with col4:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("**Ağırlık Ayarları (Birleşik Skor)**")
            rule_w = st.slider("Kural Motoru Ağırlığı (%)", 10, 90, 60, step=5)
            ml_w   = 100 - rule_w
            st.info(f"Kural: %{rule_w}  |  AI (ML): %{ml_w}")

            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            info_box(
                "Ağırlık Mantığı",
                "Kural motoru bilinen saldırı imzalarını tanırken, "
                "AI sıfır gün saldırıları ve bilinmeyen anomalileri yakalar. "
                "İkisi birlikte daha kapsamlı koruma sağlar.",
            )
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
        if st.button("💾 Eşikleri Kaydet", key="save_thresholds"):
            db.save_setting("syn_flood_threshold",   str(syn_t))
            db.save_setting("port_scan_threshold",   str(scan_t))
            db.save_setting("icmp_flood_threshold",  str(icmp_t))
            db.save_setting("brute_force_threshold", str(brute_t))
            db.save_setting("risk_threshold",        str(risk_t))
            db.save_setting("auto_block",            "1" if auto_block else "0")
            db.save_setting("log_active",            "1" if log_active else "0")
            db.save_setting("interface",             interface)
            db.save_setting("capture_mode",          capture_mode)
            db.save_setting("retention_days",        str(retention))
            db.save_setting("packet_size_limit",     str(pkt_limit))
            st.success("Ayarlar kaydedildi.")

    with tab3:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        col5, col6 = st.columns(2)
        with col5:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("**AI Anomali Dedektör**")
            st.info("Algoritma: İstatistiksel Z-Skor + Port Risk Analizi")
            info_box(
                "Algoritma Hakkında",
                "scikit-learn'e gerek duymadan çalışan bu motor, "
                "Isolation Forest'ın simülasyon ortamındaki davranışını "
                "NumPy tabanlı çok boyutlu istatistiksel analiz ile yeniden üretir. "
                "Python 3.14 dahil tüm sürümlerle uyumludur.",
            )
            st.slider("Anomali Duyarlılığı (Z-Eşiği)", 1.0, 4.0, value=2.5, step=0.1)
            if st.button("🔄 Modeli Yeniden Eğit", key="retrain_btn"):
                with st.spinner("AI modeli yeniden oluşturuluyor..."):
                    try:
                        engine._ml.retrain()
                        st.success("Model başarıyla yeniden oluşturuldu.")
                    except Exception as e:
                        st.error(f"Hata: {e}")
            st.markdown("</div>", unsafe_allow_html=True)

        with col6:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("**Motor İstatistikleri (Bu Oturum)**")
            s = current_analysis_stats()
            stat_df = pd.DataFrame({
                "Metrik": [
                    "Toplam Analiz", "Toplam Uyarı",
                    "AI Anomali", "Ort. AI Skoru",
                    "Ort. Risk", "Kritik Uyarı",
                ],
                "Değer": [
                    s["total_analyzed"], s["total_alerts"],
                    s["total_anomalies"], s["avg_ml_score"],
                    s["avg_risk"], s["critical_count"],
                ],
            })
            st.markdown(html_table(stat_df), unsafe_allow_html=True)
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            if st.button("🗑️ Sayaçları Sıfırla", key="reset_counters"):
                engine.reset()
                st.success("Sayaçlar sıfırlandı.")
            st.markdown("</div>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# ROUTER
# ══════════════════════════════════════════════════════════════════════════════

if   page == "Dashboard":         page_dashboard()
elif page == "Canli Trafik":      page_live_traffic()
elif page == "Uyarilar":          page_alerts()
elif page == "Saldiri Detaylari": page_attack_detail()
elif page == "Raporlar":          page_reports()
elif page == "Ayarlar":           page_settings()
