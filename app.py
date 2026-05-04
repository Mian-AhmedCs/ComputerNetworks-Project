"""
Traffic Vision — Flask Backend
JS-driven actions + live polling for smooth real-time updates.
"""

import csv, os
from urllib.parse import urlencode
from flask import Flask, render_template, request, redirect, jsonify, render_template_string
from sniffer import PacketSniffer, get_available_interfaces

app = Flask(__name__)
sniffer = PacketSniffer()

CSV_FIELDS = ["time", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "service", "packet_size"]


def format_bytes(b):
    if b == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    i, val = 0, float(b)
    while val >= 1024 and i < len(units) - 1:
        val /= 1024
        i += 1
    return f"{val:.1f} {units[i]}"



def get_filters_from_args():
    return {
        "protocol": request.args.get("protocol", "ALL"),
        "src_ip": request.args.get("src_ip", ""),
        "dst_ip": request.args.get("dst_ip", ""),
    }


def get_template_context(filters):
    packets = sniffer.get_packets(**filters)
    return {
        "stats": sniffer.get_stats(),
        "packets": list(reversed(packets[-500:])),
        "packet_total": len(packets),
        "logs": sniffer.get_logs(),
        "format_bytes": format_bytes,
    }

# ─── Pages ──────────────────────────────────────────────────────

@app.route("/")
def index():
    filters = get_filters_from_args()
    ctx = get_template_context(filters)
    return render_template("index.html",
        interfaces=get_available_interfaces(),
        is_running=sniffer.is_running,
        filters=filters,
        **ctx
    )


# ─── Live API (polled by vanilla JS every 2s) ──────────────────

STATS_HTML = """
<div class="stat-tile stat-highlight-blue"><div class="stat-number">{{ stats.total_packets }}</div><div class="stat-caption">Total Packets</div></div>
<div class="stat-tile stat-highlight-green"><div class="stat-number">{{ stats.tcp_count }}</div><div class="stat-caption">TCP</div></div>
<div class="stat-tile stat-highlight-yellow"><div class="stat-number">{{ stats.udp_count }}</div><div class="stat-caption">UDP</div></div>
<div class="stat-tile stat-highlight-orange"><div class="stat-number">{{ stats.icmp_count }}</div><div class="stat-caption">ICMP</div></div>
<div class="stat-tile"><div class="stat-number">{{ stats.other_count }}</div><div class="stat-caption">Other</div></div>
<div class="stat-tile stat-highlight-purple"><div class="stat-number">{{ format_bytes(stats.avg_packet_size) }}</div><div class="stat-caption">Avg Packet Size</div></div>
<div class="stat-tile stat-highlight-cyan"><div class="stat-number">{{ format_bytes(stats.total_data_size) }}</div><div class="stat-caption">Total Data</div></div>
"""

PACKETS_HTML = """
{% if packets %}
{% for p in packets %}
<tr>
    <td>{{ packet_total - loop.index0 }}</td><td>{{ p.time }}</td><td>{{ p.src_ip }}</td><td>{{ p.dst_ip }}</td>
    <td><span class="proto-badge {% if p.protocol == 'TCP' %}proto-tcp{% elif p.protocol == 'UDP' %}proto-udp{% elif p.protocol == 'ICMP' %}proto-icmp{% else %}proto-other{% endif %}">{{ p.protocol }}</span></td>
    <td>{{ p.src_port }}</td><td>{{ p.dst_port }}</td><td>{{ p.service }}</td><td>{{ p.packet_size }}</td>
</tr>
{% endfor %}
{% else %}
<tr class="empty-row"><td colspan="9">No packets captured yet. Click "Start Monitoring" to begin.</td></tr>
{% endif %}
"""

LOGS_HTML = """
{% if logs %}
{% for log in logs %}<div class="log-entry">{{ log }}</div>{% endfor %}
{% else %}<p class="log-empty">No log entries yet.</p>{% endif %}
"""

@app.route("/api/live")
def api_live():
    """Return rendered HTML fragments as JSON for smooth DOM swapping."""
    ctx = get_template_context(get_filters_from_args())
    return jsonify({
        "stats": render_template_string(STATS_HTML, **ctx),
        "packets": render_template_string(PACKETS_HTML, **ctx),
        "logs": render_template_string(LOGS_HTML, **ctx),
        "packet_count": f"{ctx['packet_total']} packets",
        "is_running": sniffer.is_running,
    })


# ─── Actions (JS fetch → redirect, no page reload) ─────────────

@app.route("/start", methods=["POST"])
def start():
    sniffer.start(interface=request.form.get("interface", "default"))
    return redirect("/")


@app.route("/stop", methods=["POST"])
def stop():
    sniffer.stop()
    return redirect("/")


@app.route("/clear", methods=["POST"])
def clear():
    sniffer.clear()
    return redirect("/")


@app.route("/export", methods=["POST"])
def export():
    packets = sniffer.get_packets()
    if not packets:
        sniffer.add_log("Export failed: No packets to export.")
        return redirect("/?" + urlencode({"toast": "No packets to export", "toast_type": "error"}))

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_traffic_data.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(packets)

    sniffer.add_log(f"Exported {len(packets)} packets to network_traffic_data.csv")
    return redirect("/?" + urlencode({"toast": f"Exported {len(packets)} packets to CSV", "toast_type": "success"}))


@app.route("/filter", methods=["POST"])
def apply_filter():
    proto = request.form.get("protocol", "ALL")
    src = request.form.get("src_ip", "").strip()
    dst = request.form.get("dst_ip", "").strip()
    active = [f"{k}={v}" for k, v in {"protocol": proto, "src_ip": src, "dst_ip": dst}.items() if v and v != "ALL"]
    if active:
        sniffer.add_log(f"Filter applied: {', '.join(active)}")
    return redirect("/")


@app.route("/reset-filter", methods=["POST"])
def reset_filter():
    sniffer.add_log("Filters reset.")
    return redirect("/")


if __name__ == "__main__":
    print("Traffic Vision — http://127.0.0.1:5000 (run as Admin for capture)")
    app.run(debug=True, host="127.0.0.1", port=5000, threaded=True)
