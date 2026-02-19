from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
# import sys


def process_packet(packet):
    try:
        domain = None
        source = None
        client_ip = ""
        server_ip = ""

        if packet.haslayer(IP):
            client_ip = packet[IP].src
            server_ip = packet[IP].dst

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname
            source = "DNS Lookup"

        elif packet.haslayer(TLSClientHello) and packet.haslayer(TLS_Ext_ServerName):
            server_names = packet[TLS_Ext_ServerName].servernames
            
            if server_names and len(server_names) > 0:
                domain = server_names[0].servername
                source = "TLS Handshake"

        if domain:
            if isinstance(domain, bytes):
                clean_domain = domain.decode("utf-8", errors='ignore').rstrip('.')
            else:
                clean_domain = str(domain).rstrip('.')

            GREEN = '\033[92m'
            CYAN = '\033[96m'
            RESET = '\033[0m'

            print(f"{client_ip} --> {server_ip} {CYAN}[{source}]{RESET} Detected: {GREEN}{clean_domain:<30}{RESET}")

    except Exception as e:
        print(f"Skipped {e}")

def start_sniffer():
    print("="*60)
    #print(title)
    print("Scanning for DNS & TLS Traffic...")
    print("="*60)

    try:
        sniff(prn=process_packet, store=0)
    except PermissionError:
        print("\n[!] Error: You need to run this as Root/Administrator!")
    except KeyboardInterrupt:
        print("\n\nStopping sniffer")


if __name__ == "__main__":
    start_sniffer()







