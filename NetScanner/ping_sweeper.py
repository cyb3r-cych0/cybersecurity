import sys
from scapy.all import ICMP, IP, sr1
from netaddr import IPNetwork
import threading

def ping_host(host, live_hosts, lock, scanned_hosts, total_hosts):
    response = sr1(IP(dst=str(host))/ICMP(), timeout=1, verbose=0)
    with lock:
        scanned_hosts[0] += 1
        print(f"Scanning: {scanned_hosts[0]}/{total_hosts}", end="\r")
        if response is not None:
            live_hosts.append(str(host))
            print(f"Host {host} is online.")

def ping_sweep(network, netmask):
    live_hosts = []
    ip_network = IPNetwork(network + '/' + netmask)
    hosts = list(ip_network.iter_hosts())
    total_hosts = len(hosts)
    scanned_hosts = [0]
    lock = threading.Lock()
    threads = []

    for host in hosts:
        t = threading.Thread(target=ping_host, args=(host, live_hosts, lock, scanned_hosts, total_hosts))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return live_hosts

if __name__ == "__main__":
    network = sys.argv[1]
    netmask = sys.argv[2]

    live_hosts = ping_sweep(network, netmask)
    print("\nCompleted")
    print(f"Live hosts: {live_hosts}")