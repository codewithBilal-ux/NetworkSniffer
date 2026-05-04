import os
import sys
import platform
import signal
import argparse
from dataclasses import dataclass
from scapy.all import sniff, get_if_list, wrpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# --- CONFIGURATION & GLOBAL STATE ---
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "Total": 0}
captured_packets = []
args = None

# --- UTILS ---
def check_privileges():
    """Checks for root/admin privileges."""
    os_name = platform.system()
    if os_name in ["Linux", "Darwin"]:
        if os.geteuid() != 0:
            print("[-] Error: Root privileges required for packet capture.")
            sys.exit(1)
    elif os_name == "Windows":
        print("[!] Warning: Ensure Npcap is installed with 'WinPcap API-compatible mode'.")

# --- DATA STRUCTURES ---
@dataclass
class PacketInfo:
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    payload: str

# --- PARSING ---
def parse_packet(packet) -> PacketInfo:
    src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "0.0.0.0"
    
    protocol = "OTHER"
    if packet.haslayer(TCP): protocol = "TCP"
    elif packet.haslayer(UDP): protocol = "UDP"
    elif packet.haslayer(ICMP): protocol = "ICMP"
    elif packet.haslayer(ARP): protocol = "ARP"
    elif packet.haslayer(DNS): protocol = "DNS"
    
    payload_str = ""
    if packet.haslayer(Raw):
        try:
            payload_raw = packet[Raw].load.decode(errors='ignore')
            if "HTTP" in payload_raw[:10]:
                protocol = "HTTP"
            payload_str = payload_raw[:100].replace('\r', '').replace('\n', ' ')
        except:
            payload_str = "<binary_data>"
            
    return PacketInfo(src_ip, dst_ip, protocol, len(packet), payload_str)

# --- DISPLAY ---
COLORS = {
    "TCP": Fore.GREEN, "UDP": Fore.CYAN, "ICMP": Fore.YELLOW,
    "ARP": Fore.MAGENTA, "DNS": Fore.BLUE, "HTTP": Fore.RED,
    "OTHER": Fore.WHITE
}

def display_packet(p_info):
    color = COLORS.get(p_info.protocol, Fore.WHITE)
    print(f"{color}[{p_info.protocol:<4}] {p_info.src_ip} -> {p_info.dst_ip} | {p_info.length} bytes | {p_info.payload}")

# --- FILTERS ---
def packet_matches(p_info, ip=None, port=None, keyword=None):
    if ip and (ip != p_info.src_ip and ip != p_info.dst_ip):
        return False
    if port and str(port) not in str(p_info.payload):
        return False
    if keyword and keyword.lower() not in p_info.payload.lower():
        return False
    return True

# --- CAPTURE ---
class PacketCapture:
    def __init__(self, interface=None):
        self.interface = interface
        if self.interface and self.interface not in get_if_list():
            print(f"[-] Error: Invalid interface {self.interface}")
            print(f"Available: {get_if_list()}")
            sys.exit(1)

    def start_capture(self, callback):
        print(f"[*] Starting capture on {self.interface or 'all interfaces'}...")
        sniff(iface=self.interface, prn=callback, store=False)

# --- MAIN LOGIC ---
def packet_callback(packet):
    global stats, captured_packets
    p_info = parse_packet(packet)
    
    if not packet_matches(p_info, args.ip, args.port, args.keyword):
        return

    stats["Total"] += 1
    if p_info.protocol in stats:
        stats[p_info.protocol] += 1
        
    if args.save:
        captured_packets.append(packet)

    display_packet(p_info)

def signal_handler(sig, frame):
    print("\n[*] Stopping capture...")
    if args and args.save:
        print(f"[*] Saving {len(captured_packets)} packets to {args.save}...")
        wrpcap(args.save, captured_packets)
    print(f"[*] Final Stats: {stats}")
    sys.exit(0)

if __name__ == "__main__":
    check_privileges()
    
    parser = argparse.ArgumentParser(description="Single-file Python Network Sniffer")
    parser.add_argument("--iface", help="Interface to sniff")
    parser.add_argument("--ip", help="Filter by IP")
    parser.add_argument("--port", help="Filter by Port")
    parser.add_argument("--keyword", help="Filter payload by keyword")
    parser.add_argument("--save", help="Save packets to PCAP file")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    
    sniffer = PacketCapture(interface=args.iface)
    sniffer.start_capture(callback=packet_callback)