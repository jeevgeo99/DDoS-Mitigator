import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

THRESHOLD = 40
print(f"THRESHOLD : {THRESHOLD}")

def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                if os.name == 'nt':
                    block_ip_windows(ip)
                else:
                    block_ip_unix(ip)
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

def block_ip_windows(ip):
    os.system(f"netsh advfirewall firewall add rule name=\"Block IP {ip}\" dir=in action=block remoteip={ip}")

def block_ip_unix(ip):
    os.system(f"iptables -A INPUT -s {ip} -j DROP")

def is_admin():
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except AttributeError:
        return False

if __name__ == "__main__":
    if not is_admin():
        print("This script requires root/admin privileges.")
        sys.exit(1)
    
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)





