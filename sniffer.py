from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS

packet_count = 0
captured_packets = []
port_scan_tracker = {}

def packet_callback(packet):
    global packet_count
    packet_count += 1
    captured_packets.append(packet)

    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst

        protocol = "OTHER"
        info = ""

        # 🔍 TCP
        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            info = f"Ports: {sport} → {dport}"

            # 🚨 Simple Port Scan Detection
            key = (src, dst)
            if key not in port_scan_tracker:
                port_scan_tracker[key] = set()
            port_scan_tracker[key].add(dport)

            if len(port_scan_tracker[key]) > 10:
                print(f"🚨 Possible Port Scan from {src} to {dst}")

        # 🔍 UDP
        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            info = f"Ports: {sport} → {dport}"

        # 🔍 ICMP
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            info = "Ping"

        # 🌐 DNS Decode
        if packet.haslayer(DNS) and packet[DNS].qd:
            domain = packet[DNS].qd.qname.decode()
            print(f"🌍 DNS Query: {domain}")

        print(f"[{packet_count}] {src} → {dst} | {protocol} | {info}")

        # 📦 Payload Preview (safe)
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
            if payload:
                print("Payload:", payload[:50])

        print("-" * 60)


def stop_sniffer():
    print("\n💾 Saving packets to capture.pcap...")
    wrpcap("capture.pcap", captured_packets)
    print("✅ Saved! Open with Wireshark")

print("🚀 Advanced Sniffer Running... Press Ctrl+C to stop\n")

try:
    sniff(prn=packet_callback)
except KeyboardInterrupt:
    stop_sniffer()
