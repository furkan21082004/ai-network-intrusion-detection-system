"""
packet_capture.py — Ağ paketi yakalama modülü
Gerçek modda Scapy/PyShark kullanır; simülasyon modunda fake paket üretir.
"""

import random
import time
import threading
from datetime import datetime
from typing import Callable, Optional
import database as db

SOURCE_IPS = [
    "192.168.1.55", "10.0.0.23", "172.16.5.8",
    "8.8.8.8",      "192.168.1.100", "45.33.32.156",
]
DEST_IPS   = ["192.168.1.1", "192.168.1.10", "192.168.1.30", "10.0.0.1"]
PROTOCOLS  = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
FLAGS      = ["SYN", "SYN-ACK", "ACK", "FIN", "RST", "PSH"]


def _random_packet() -> dict:
    proto = random.choices(PROTOCOLS, weights=[40,20,10,15,12,3])[0]
    flag  = random.choice(FLAGS) if proto == "TCP" else ""
    return {
        "timestamp": datetime.now().isoformat(),
        "src_ip":    random.choice(SOURCE_IPS),
        "dst_ip":    random.choice(DEST_IPS),
        "protocol":  proto,
        "flags":     flag,
        "src_port":  random.randint(1024, 65535),
        "dst_port":  random.choice([80, 443, 22, 21, 3389, 8080, 53]),
        "size":      random.randint(40, 1500),
    }


class PacketCapture:
    """
    Arka planda sürekli paket üreten / yakalayan sınıf.
    on_packet callback her yeni pakette çağrılır.
    """

    def __init__(self, on_packet: Optional[Callable] = None):
        self._on_packet = on_packet
        self._running   = False
        self._thread: Optional[threading.Thread] = None
        self._mode      = db.get_setting("capture_mode", "Simülasyon")

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            pkt = _random_packet()
            db.insert_packet(
                pkt["src_ip"], pkt["dst_ip"], pkt["protocol"],
                pkt["src_port"], pkt["dst_port"], pkt["size"]
            )
            if self._on_packet:
                self._on_packet(pkt)
            # Gerçekçi gecikme: 50-300 ms arası
            time.sleep(random.uniform(0.05, 0.3))

    # ── Gerçek yakalama (Scapy) ───────────────────────────────────────────

    def start_real(self, iface: str = "eth0"):
        """
        Gerçek ağ arayüzünden paket yakala (root gerektirir).
        Scapy yüklü ve yetki varsa çalışır.
        """
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP

            def _handler(pkt):
                if not pkt.haslayer(IP):
                    return
                ip  = pkt[IP]
                proto = "TCP" if pkt.haslayer(TCP) else \
                        "UDP" if pkt.haslayer(UDP) else \
                        "ICMP" if pkt.haslayer(ICMP) else "Diğer"
                flags = ""
                sport, dport = 0, 0
                if pkt.haslayer(TCP):
                    flags = str(pkt[TCP].flags)
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport

                p = {
                    "timestamp": datetime.now().isoformat(),
                    "src_ip":    ip.src,
                    "dst_ip":    ip.dst,
                    "protocol":  proto,
                    "flags":     flags,
                    "src_port":  sport,
                    "dst_port":  dport,
                    "size":      len(pkt),
                }
                db.insert_packet(
                    p["src_ip"], p["dst_ip"], p["protocol"],
                    p["src_port"], p["dst_port"], p["size"]
                )
                if self._on_packet:
                    self._on_packet(p)

            sniff(iface=iface, prn=_handler, store=False)
        except Exception as e:
            print(f"[PacketCapture] Gerçek mod başlatılamadı: {e}")
