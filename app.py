"""
CodeAlpha - Advanced Network Packet Sniffer
=============================================
Real-time packet capture dashboard built with Scapy + Flask-SocketIO.
"""

import time
import random
import threading
import string
from collections import deque, Counter
from datetime import datetime

from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

app = Flask(__name__)
app.config["SECRET_KEY"] = "codealpha-network-sniffer"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

MAX_LOG = 500
packet_log = deque(maxlen=MAX_LOG)
protocol_counter = Counter()
talker_counter = Counter()
port_counter = Counter()
stats = {
    "total_packets": 0,
    "total_bytes": 0,
    "started_at": None,
    "capturing": False,
    "mode": "demo" if not SCAPY_AVAILABLE else "live",
    "alerts": 0,
}
capture_thread = None
stop_event = threading.Event()

SUSPICIOUS_PORTS = {23: "Telnet (unencrypted)", 21: "FTP (unencrypted)",
                     3389: "RDP", 445: "SMB", 4444: "Metasploit default",
                     6667: "IRC (possible botnet C2)"}

COMMON_PORTS = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
                 25: "SMTP", 110: "POP3", 143: "IMAP", 3306: "MySQL"}


def classify_port(port):
    if port in SUSPICIOUS_PORTS:
        return "suspicious", SUSPICIOUS_PORTS[port]
    if port in COMMON_PORTS:
        return "known", COMMON_PORTS[port]
    return "other", None


def push_packet(entry):
    packet_log.append(entry)
    stats["total_packets"] += 1
    stats["total_bytes"] += entry["length"]
    protocol_counter[entry["protocol"]] += 1
    talker_counter[entry["src"]] += entry["length"]
    if entry.get("risk") == "suspicious":
        stats["alerts"] += 1

    socketio.emit("new_packet", entry)
    socketio.emit("stats_update", build_stats_payload())


def build_stats_payload():
    top_talkers = talker_counter.most_common(6)
    top_protocols = protocol_counter.most_common(8)
    return {
        "total_packets": stats["total_packets"],
        "total_bytes": stats["total_bytes"],
        "alerts": stats["alerts"],
        "capturing": stats["capturing"],
        "mode": stats["mode"],
        "top_talkers": [{"ip": ip, "bytes": b} for ip, b in top_talkers],
        "top_protocols": [{"protocol": p, "count": c} for p, c in top_protocols],
    }


def handle_packet(pkt):
    if stop_event.is_set():
        return
    try:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        length = len(pkt)

        if ARP in pkt:
            entry = {
                "time": ts, "src": pkt[ARP].psrc, "dst": pkt[ARP].pdst,
                "protocol": "ARP", "sport": "-", "dport": "-",
                "length": length, "info": f"who-has {pkt[ARP].pdst}",
                "risk": "normal", "payload": "",
            }
            push_packet(entry)
            return

        if IP not in pkt:
            return

        ip_layer = pkt[IP]
        src, dst = ip_layer.src, ip_layer.dst
        proto, sport, dport, info, risk = "OTHER", "-", "-", "", "normal"

        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = pkt[TCP].flags
            info = f"flags={flags}"
            risk_kind, label = classify_port(dport)
            if risk_kind == "suspicious":
                risk = "suspicious"
                info += f" | {label}"
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            risk_kind, label = classify_port(dport)
            if risk_kind == "suspicious":
                risk = "suspicious"
                info = label
        elif ICMP in pkt:
            proto = "ICMP"
            info = f"type={pkt[ICMP].type}"

        payload = ""
        if Raw in pkt:
            raw = bytes(pkt[Raw].load)[:48]
            payload = "".join(chr(b) if chr(b) in string.printable and b >= 32 else "." for b in raw)

        entry = {
            "time": ts, "src": src, "dst": dst, "protocol": proto,
            "sport": sport, "dport": dport, "length": length,
            "info": info, "risk": risk, "payload": payload,
        }
        push_packet(entry)
    except Exception:
        pass


def run_live_capture():
    try:
        sniff(prn=handle_packet, store=False,
              stop_filter=lambda p: stop_event.is_set())
    except Exception:
        stats["mode"] = "demo"
        run_demo_capture()


DEMO_PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "DNS"]
DEMO_IPS = [f"192.168.1.{i}" for i in (2, 5, 10, 14, 23, 40)]
DEMO_EXTERNAL = ["142.250.72.14", "104.16.132.229", "13.107.42.14",
                  "185.199.108.153", "34.117.59.81", "8.8.8.8"]


def random_demo_packet():
    proto = random.choices(DEMO_PROTOCOLS, weights=[45, 25, 10, 5, 15])[0]
    src = random.choice(DEMO_IPS)
    dst = random.choice(DEMO_EXTERNAL)
    length = random.randint(54, 1500)
    sport = random.randint(1025, 65000)
    risk = "normal"
    info = ""

    if proto in ("TCP", "UDP"):
        dport = random.choices(
            [80, 443, 53, 22, 21, 23, 3389, 4444, 6667, random.randint(1000, 60000)],
            weights=[25, 30, 15, 5, 3, 2, 3, 1, 1, 15]
        )[0]
        kind, label = classify_port(dport)
        if kind == "suspicious":
            risk = "suspicious"
            info = label
        elif kind == "known":
            info = label
    else:
        dport = "-"
        sport = "-"
        if proto == "ARP":
            info = f"who-has {dst}"
        elif proto == "ICMP":
            info = "echo-request"

    payload = "".join(random.choices(string.ascii_letters + string.digits + "   ", k=random.randint(8, 40)))

    return {
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": src, "dst": dst, "protocol": proto,
        "sport": sport, "dport": dport, "length": length,
        "info": info, "risk": risk, "payload": payload,
    }


def run_demo_capture():
    while not stop_event.is_set():
        push_packet(random_demo_packet())
        time.sleep(random.uniform(0.15, 0.55))


@app.route("/")
def index():
    return render_template("index.html", scapy_available=SCAPY_AVAILABLE)


@app.route("/api/export")
def export_csv():
    import csv, io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["time", "src", "dst", "protocol", "sport", "dport", "length", "info", "risk"])
    for p in packet_log:
        writer.writerow([p["time"], p["src"], p["dst"], p["protocol"],
                          p["sport"], p["dport"], p["length"], p["info"], p["risk"]])
    mem = io.BytesIO(buf.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True,
                      download_name=f"packet_capture_{int(time.time())}.csv")


@socketio.on("connect")
def on_connect():
    socketio.emit("stats_update", build_stats_payload())
    socketio.emit("mode_info", {"scapy_available": SCAPY_AVAILABLE, "mode": stats["mode"]})


@socketio.on("start_capture")
def on_start(data=None):
    global capture_thread
    if stats["capturing"]:
        return
    stop_event.clear()
    stats["capturing"] = True
    stats["started_at"] = time.time()

    target = run_live_capture if (SCAPY_AVAILABLE and (data or {}).get("mode") != "demo") else run_demo_capture
    stats["mode"] = "live" if target is run_live_capture else "demo"
    capture_thread = threading.Thread(target=target, daemon=True)
    capture_thread.start()
    socketio.emit("capture_state", {"capturing": True, "mode": stats["mode"]})


@socketio.on("stop_capture")
def on_stop():
    stop_event.set()
    stats["capturing"] = False
    socketio.emit("capture_state", {"capturing": False, "mode": stats["mode"]})


@socketio.on("clear_data")
def on_clear():
    packet_log.clear()
    protocol_counter.clear()
    talker_counter.clear()
    port_counter.clear()
    stats["total_packets"] = 0
    stats["total_bytes"] = 0
    stats["alerts"] = 0
    socketio.emit("stats_update", build_stats_payload())


if __name__ == "__main__":
    print("=" * 60)
    print(" CodeAlpha Network Sniffer Dashboard")
    print(f" Scapy available : {SCAPY_AVAILABLE}")
    print(" Open  http://127.0.0.1:5000  in your browser")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
