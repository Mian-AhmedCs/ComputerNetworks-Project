"""
Network Traffic Sniffer Module
Uses Scapy for real-time packet capturing from network interfaces.
"""

import threading
import time
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, get_if_list

PORT_SERVICE_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def get_service_name(port):
    if port is None:
        return "N/A"
    return PORT_SERVICE_MAP.get(port, f"Port-{port}")


def get_available_interfaces():
    try:
        ifaces = get_if_list()
        return ifaces if ifaces else ["default"]
    except Exception:
        return ["default"]


class PacketSniffer:
    """Real-time packet sniffer using Scapy."""

    def __init__(self):
        self.packets = []
        self.lock = threading.Lock()
        self.is_running = False
        self.logs = []
        self.interface = None
        self._sniffer = None

    def start(self, interface=None):
        if self.is_running:
            return
        self.interface = interface
        self.is_running = True
        self.add_log(f"Monitoring started on interface: {interface or 'default'}")
        threading.Thread(target=self._sniff_packets, daemon=True).start()

    def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self.add_log("Monitoring stopped.")

    def clear(self):
        with self.lock:
            self.packets.clear()
        self.add_log("Packet data cleared.")

    def _sniff_packets(self):
        try:
            from scapy.all import AsyncSniffer
            kwargs = {"prn": self._process_packet, "store": False}
            if self.interface and self.interface != "default":
                kwargs["iface"] = self.interface

            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()

            while self.is_running:
                time.sleep(0.5)

            try:
                self._sniffer.stop()
            except Exception:
                pass
        except Exception as e:
            self.add_log(f"Sniffer error: {e}")
            self.is_running = False

    def _process_packet(self, packet):
        if not self.is_running or not packet.haslayer(IP):
            return
        try:
            ip = packet[IP]
            protocol, src_port, dst_port = "OTHER", None, None

            if packet.haslayer(TCP):
                protocol, src_port, dst_port = "TCP", packet[TCP].sport, packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol, src_port, dst_port = "UDP", packet[UDP].sport, packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            service = get_service_name(dst_port)
            if service.startswith("Port-") and src_port:
                alt = get_service_name(src_port)
                if not alt.startswith("Port-"):
                    service = alt

            with self.lock:
                self.packets.append({
                    "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    "src_ip": ip.src, "dst_ip": ip.dst,
                    "protocol": protocol,
                    "src_port": src_port or "N/A",
                    "dst_port": dst_port or "N/A",
                    "service": service,
                    "packet_size": len(packet),
                })
        except Exception as e:
            self.add_log(f"Error processing packet: {e}")

    def get_packets(self, protocol=None, src_ip=None, dst_ip=None):
        with self.lock:
            result = list(self.packets)
        if protocol and protocol.upper() != "ALL":
            result = [p for p in result if p["protocol"] == protocol.upper()]
        if src_ip:
            result = [p for p in result if src_ip in p["src_ip"]]
        if dst_ip:
            result = [p for p in result if dst_ip in p["dst_ip"]]
        return result

    def get_stats(self):
        with self.lock:
            pkts = list(self.packets)
        total = len(pkts)
        counts = {proto: sum(1 for p in pkts if p["protocol"] == proto) for proto in ("TCP", "UDP", "ICMP")}
        total_size = sum(p["packet_size"] for p in pkts)
        return {
            "total_packets": total,
            "tcp_count": counts["TCP"], "udp_count": counts["UDP"], "icmp_count": counts["ICMP"],
            "other_count": total - counts["TCP"] - counts["UDP"] - counts["ICMP"],
            "avg_packet_size": round(total_size / total, 2) if total else 0,
            "total_data_size": total_size,
        }

    def get_logs(self):
        return list(self.logs)

    def add_log(self, message):
        self.logs.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")
        if len(self.logs) > 200:
            self.logs = self.logs[-200:]
