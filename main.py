from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")
        
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"TCP Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")
        
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"UDP Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")

print("Starting network sniffing...")
sniff(prn=packet_callback, count=100, store=0, iface=None)
