from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls.all import TLSClientHello
from scapy.layers.dhcp import DHCP

from datetime import datetime
import socket
import threading
from queue import Queue

import torList

reverse_dns_cache = {}
TOR_NODES = torList.entryGuards()

# Service port mapping for quick identification
SERVICE_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    5900: "VNC",
    3389: "RDP",
    25: "SMTP",
    143: "IMAP",
    110: "POP3",
    21: "FTP",
    1194: "OpenVPN",
    51820: "Wireguard",
    500: "IPsec",
    4500: "IPsec-NAT",
    1433: "MSSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Non-blocking RevDNS lookup queue
dns_queue = Queue()

def async_reverse_dns_lookup():
    """Worker thread for non-blocking reverse DNS lookups"""
    socket.setdefaulttimeout(1)
    while True:
        ip = dns_queue.get()
        if ip is None:
            break
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            reverse_dns_cache[ip] = hostname
        except (socket.herror, socket.timeout, OSError):
            reverse_dns_cache[ip] = f"Raw IP: {ip}"
        dns_queue.task_done()

# Start DNS worker thread as daemon
dns_worker = threading.Thread(target=async_reverse_dns_lookup, daemon=True)
dns_worker.start()

def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")

def hostnameInfo(ttl):
    if ttl <= 64:
        return "Linux/Mac/Android"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Hardware/Other"
    return "Unknown"

def get_service_name(port):
    """Get service name from port number"""
    return SERVICE_PORTS.get(port, f"Service-{port}")

def extract_tls_sni(packet):
    """
    Extract SNI (Server Name Indication) from TLS ClientHello
    Returns: (sni_domain, source_label) or (None, None)
    """
    try:
        if not packet.haslayer(TLSClientHello):
            return None, None
        
        tls = packet[TLSClientHello]
        
        # Safely access TLS extensions
        if not hasattr(tls, 'ext') or tls.ext is None:
            return None, None
        
        for ext in tls.ext:
            # Check for ServerName extension
            if hasattr(ext, 'servernames'):
                if ext.servernames and len(ext.servernames) > 0:
                    sni = ext.servernames[0]
                    if isinstance(sni, bytes):
                        sni = sni.decode('utf-8', errors='ignore')
                    return sni.rstrip('.'), "TLS SNI"
    except Exception:
        pass
    
    return None, None

def process_packet(packet):
    """
    Process captured packet and detect multiple protocols
    Key improvement: Now detects ALL protocols in a packet (not just first match)
    """
    try:
        if not packet.haslayer(IP):
            return
        
        client_ip = packet[IP].src
        server_ip = packet[IP].dst
        packet_ttl = packet[IP].ttl
        osInfo = hostnameInfo(packet_ttl)
        
        # Collect ALL detections for this packet
        detections = []
        
        # ==== DHCP Detection ====
        if packet.haslayer(DHCP):
            for option in packet[DHCP].options:
                if isinstance(option, tuple) and option[0] == 'hostname':
                    raw_hostname = option[1]
                    if isinstance(raw_hostname, bytes):
                        hostname = raw_hostname.decode('utf-8', errors='ignore')
                    else:
                        hostname = str(raw_hostname)
                    
                    YELLOW = '\033[93m'
                    RESET = '\033[0m'
                    print(f"{YELLOW}[+] DHCP Hostname: MAC {packet.src} is '{hostname}'{RESET}")
                    return
        
        # ==== TOR Detection ====
        if server_ip in TOR_NODES:
            detections.append({
                'domain': f"Encrypted Node: {server_ip}",
                'source': "TOR NETWORK",
                'port': None
            })
        
        # ==== DNS Detection ====
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname
            if isinstance(domain, bytes):
                domain = domain.decode('utf-8', errors='ignore').rstrip('.')
            detections.append({
                'domain': domain,
                'source': "DNS Lookup",
                'port': 53
            })
        
        # ==== TLS SNI Detection ====
        tls_sni, tls_source = extract_tls_sni(packet)
        if tls_sni:
            detections.append({
                'domain': tls_sni,
                'source': tls_source,
                'port': packet[TCP].dport if packet.haslayer(TCP) else None
            })
        
        # ==== VPN Detection (UDP) ====
        if packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            if dport == 1194 or sport == 1194:
                detections.append({
                    'domain': f"VPN Server: {server_ip}",
                    'source': "OpenVPN Tunnel",
                    'port': 1194
                })
            elif dport == 51820 or sport == 51820:
                detections.append({
                    'domain': f"VPN Server: {server_ip}",
                    'source': "Wireguard / Warp",
                    'port': 51820
                })
            elif dport in [500, 4500] or sport in [500, 4500]:
                detections.append({
                    'domain': f"VPN Server: {server_ip}",
                    'source': "IPsec VPN Tunnel",
                    'port': dport if dport in [500, 4500] else sport
                })
        
        # ==== TCP Fallback (RevDNS + Port Mapping) ====
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            dport = packet[TCP].dport
            
            # Only attempt reverse DNS for known service ports
            if dport in [80, 443, 22, 21, 25, 3306, 5432, 8080, 8443, 1433]:
                if server_ip not in reverse_dns_cache:
                    # Queue async DNS lookup (non-blocking)
                    dns_queue.put(server_ip)
                
                if server_ip in reverse_dns_cache:
                    detections.append({
                        'domain': reverse_dns_cache[server_ip],
                        'source': f"RevDNS ({get_service_name(dport)})",
                        'port': dport
                    })
                else:
                    # Fallback to service name + IP if RevDNS not cached yet
                    detections.append({
                        'domain': f"Raw IP: {server_ip}",
                        'source': f"TCP {get_service_name(dport)}",
                        'port': dport
                    })
        
        # ==== Print All Detections ====
        if detections:
            RED = '\x1b[31m'
            GREEN = '\033[92m'
            CYAN = '\033[96m'
            RESET = '\033[0m'
            
            for detection in detections:
                domain = detection['domain']
                source = detection['source']
                port_info = f":{detection['port']}" if detection['port'] else ""
                
                print(f"[{get_timestamp()}] {client_ip}:{RED}[{osInfo}]{RESET} --> {server_ip}{port_info} {CYAN}[{source}]{RESET} Detected: {GREEN}{domain:<40}{RESET}")
    
    except Exception as e:
        # Silently ignore exceptions to avoid terminal spam
        pass

def start_sniffer(filter_str=None):
    """
    Start packet sniffer with optional BPF filter
    
    Args:
        filter_str: Optional Berkeley Packet Filter (e.g., "tcp port 443")
    """
    print("="*60)
    print("Scanning for DNS & TLS Traffic...")
    if filter_str:
        print(f"Filter: {filter_str}")
    print("="*60)

    try:
        # Default filter: only capture relevant traffic
        if filter_str is None:
            filter_str = "tcp port 80 or tcp port 443 or tcp port 22 or udp port 53 or udp port 1194 or udp port 51820 or tcp port 3306 or tcp port 5432 or tcp port 8080 or tcp port 8443"
        
        sniff(prn=process_packet, store=0, filter=filter_str)
    except PermissionError:
        print("[!] Error: You need to run this as Root/Administrator!")
    except KeyboardInterrupt:
        print("\n[!] Stopping sniffer")
    finally:
        # Stop DNS worker thread gracefully
        dns_queue.put(None)

if __name__ == "__main__":
    start_sniffer()