"""
report_generator.py — PDF rapor üretici (ReportLab)
"""

import os
import io
from datetime import datetime
import pandas as pd

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle, HRFlowable,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False


# ── Renk paleti ──────────────────────────────────────────────────────────────
BG_DARK   = colors.HexColor("#1A1D23")
RED_ACC   = colors.HexColor("#E53E3E")
GREY_MID  = colors.HexColor("#2D3748")
GREY_LIGHT= colors.HexColor("#4A5568")
WHITE     = colors.white
TEXT_MAIN = colors.HexColor("#E2E8F0")
TEXT_MUTED= colors.HexColor("#718096")


def _styles():
    base = getSampleStyleSheet()
    title_s = ParagraphStyle(
        "ReportTitle", parent=base["Title"],
        fontSize=22, textColor=RED_ACC,
        spaceAfter=4, alignment=TA_LEFT,
    )
    sub_s = ParagraphStyle(
        "SubTitle", parent=base["Normal"],
        fontSize=10, textColor=TEXT_MUTED,
        spaceAfter=12,
    )
    section_s = ParagraphStyle(
        "Section", parent=base["Heading2"],
        fontSize=13, textColor=WHITE,
        spaceBefore=16, spaceAfter=6,
        borderPad=4,
    )
    body_s = ParagraphStyle(
        "Body", parent=base["Normal"],
        fontSize=9, textColor=TEXT_MAIN,
        leading=14,
    )
    return title_s, sub_s, section_s, body_s


def _summary_table(data: dict, body_s):
    rows = [["Metrik", "Değer"]]
    for k, v in data.items():
        rows.append([k, str(v)])
    t = Table(rows, colWidths=[9*cm, 8*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), GREY_MID),
        ("TEXTCOLOR",   (0, 0), (-1, 0), WHITE),
        ("FONTSIZE",    (0, 0), (-1, 0), 10),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND",  (0, 1), (-1, -1), BG_DARK),
        ("TEXTCOLOR",   (0, 1), (-1, -1), TEXT_MAIN),
        ("FONTSIZE",    (0, 1), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_DARK, GREY_MID]),
        ("GRID",        (0, 0), (-1, -1), 0.5, GREY_LIGHT),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0,0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _alert_table(alerts_df: pd.DataFrame):
    cols = ["Zaman", "Saldırı Türü", "Kaynak IP", "Risk Seviyesi", "Risk Skoru"]
    # tolerant column mapping
    col_map = {
        "timestamp":    "Zaman",
        "attack_type":  "Saldırı Türü",
        "src_ip":       "Kaynak IP",
        "risk_level":   "Risk Seviyesi",
        "risk_score":   "Risk Skoru",
    }
    df2 = alerts_df.rename(columns=col_map)
    # keep only available cols
    avail = [c for c in cols if c in df2.columns]
    df2 = df2[avail].head(20)

    rows = [avail] + df2.values.tolist()
    t = Table(rows, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), RED_ACC),
        ("TEXTCOLOR",   (0, 0), (-1, 0), WHITE),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0), 9),
        ("BACKGROUND",  (0, 1), (-1, -1), BG_DARK),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_DARK, GREY_MID]),
        ("TEXTCOLOR",   (0, 1), (-1, -1), TEXT_MAIN),
        ("FONTSIZE",    (0, 1), (-1, -1), 8),
        ("GRID",        (0, 0), (-1, -1), 0.4, GREY_LIGHT),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def generate_pdf(
    alerts_df: pd.DataFrame,
    stats: dict,
    start_date: str = "",
    end_date: str = "",
    report_type: str = "Genel Rapor",
) -> bytes:
    """
    PDF oluştur ve bytes olarak döndür.
    Streamlit'te st.download_button ile kullanılabilir.
    """
    if not REPORTLAB_OK:
        raise ImportError("reportlab kurulu değil. `pip install reportlab` çalıştırın.")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    title_s, sub_s, section_s, body_s = _styles()
    story = []

    # ── Başlık ──────────────────────────────────────────────────────────────
    story.append(Paragraph("AI-IDS — Ağ Güvenliği Raporu", title_s))
    story.append(Paragraph(
        f"Rapor Türü: {report_type}  |  "
        f"Dönem: {start_date} – {end_date}  |  "
        f"Oluşturulma: {datetime.now().strftime('%d/%m/%Y %H:%M')}",
        sub_s,
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=RED_ACC))
    story.append(Spacer(1, 0.4*cm))

    # ── Özet ────────────────────────────────────────────────────────────────
    story.append(Paragraph("1. Özet İstatistikler", section_s))
    story.append(_summary_table(stats, body_s))
    story.append(Spacer(1, 0.5*cm))

    # ── Saldırı dağılımı (metin) ────────────────────────────────────────────
    story.append(Paragraph("2. Saldırı Türü Dağılımı", section_s))
    if not alerts_df.empty:
        col = "attack_type" if "attack_type" in alerts_df.columns else "Saldırı Türü"
        dist = alerts_df[col].value_counts()
        lines = "  |  ".join(f"{k}: {v}" for k, v in dist.items())
        story.append(Paragraph(lines, body_s))
    story.append(Spacer(1, 0.4*cm))

    # ── En riskli IP'ler ────────────────────────────────────────────────────
    story.append(Paragraph("3. En Riskli Kaynak IP Adresleri", section_s))
    if not alerts_df.empty:
        col_ip = "src_ip" if "src_ip" in alerts_df.columns else "Kaynak IP"
        top_ips = alerts_df[col_ip].value_counts().head(5)
        lines2  = "  |  ".join(f"{ip}: {cnt} saldırı" for ip, cnt in top_ips.items())
        story.append(Paragraph(lines2, body_s))
    story.append(Spacer(1, 0.4*cm))

    # ── Detay tablosu ───────────────────────────────────────────────────────
    story.append(Paragraph("4. Saldırı Kayıtları (İlk 20)", section_s))
    if not alerts_df.empty:
        story.append(_alert_table(alerts_df))
    story.append(Spacer(1, 0.5*cm))

    # ── Çözüm önerileri ─────────────────────────────────────────────────────
    story.append(Paragraph("5. Önerilen Aksiyonlar", section_s))
    recs = [
        "• Yüksek riskli IP adreslerini firewall kural listesine ekleyin.",
        "• SYN cookie özelliğini ağ cihazlarında etkinleştirin.",
        "• SSH ve RDP hizmetlerine rate limiting uygulayın.",
        "• ICMP trafiğini ağ sınırında filtreleyin veya sınırlandırın.",
        "• Anomali eşik değerlerini periyodik olarak gözden geçirin.",
        "• IDS kurallarını güncel tehdit istihbaratıyla düzenli güncelleyin.",
    ]
    for r in recs:
        story.append(Paragraph(r, body_s))

    story.append(Spacer(1, 0.8*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY_LIGHT))
    story.append(Paragraph(
        "Bu rapor AI-IDS sistemi tarafından otomatik oluşturulmuştur.",
        sub_s,
    ))

    doc.build(story)
    return buf.getvalue()
