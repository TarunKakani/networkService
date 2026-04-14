import scapy.all as scapy

def scan_lan(target_ip):
    arp_req = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    answered, unanswered = scapy.srp(arp_req_broadcast, timeout=3, retry=2, inter=0.05, verbose=False)

    devices = []
    for sent, recieved in answered:
        # recieved packet has ip (psrc) and MAC (hwsrc) of the replier host
        devices.append({'ip' : recieved.psrc, 'mac' : recieved.hwsrc})
    return devices