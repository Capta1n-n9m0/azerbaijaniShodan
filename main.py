import ipaddress
import nmap
import threading
import time
import subprocess
import shlex

def get_next_az_host(host: ipaddress.IPv4Address = None):
    with open("IP2LOCATION-LITE-DB-AZ-NETS.txt", "r") as az:
        az_nets = [ipaddress.IPv4Network(net[:-1]) for net in az.readlines()]
    az_hosts = list()
    for net in az_nets:
        az_hosts += net.hosts()
    if host:
        try:
            for i in range(az_hosts.index(host)+1, len(az_hosts)):
                yield az_hosts[i]
        except Exception as e:
            raise e
    else:
        for i in range(len(az_hosts)):
            yield az_hosts[i]
    yield None


def scan_host(host):
    print("started")
    nm = nmap.PortScanner()
    host_str = f"{host}"
    print(host_str)
    nm.scan(f"{host_str}", arguments="-T4 -v -A")
    print(nm.command_line())
    with open(f"{host_str}-scan.xml", "w") as f:
        f.write(str(nm.get_nmap_last_output(), "utf-8"))
    print(f"{host_str}:{nm[host_str].state()}")

def main():
    # for host in get_next_az_host():
    #     nm.scan(f"{host}", arguments="-T4 -v -A")
    #     for host in nm.all_hosts():
    #         print(f"{host}:{nm[host].state()}")
    #         print(nm.get_nmap_last_output())
    process_pool = list()
    host_gen = get_next_az_host()
    for _ in range(8):
        next_host = next(host_gen)
        process_pool.append(subprocess.Popen(shlex.split(f"nmap -T4 -A -v -oX {next_host}-scan.xml {next_host}")))
    while True:
        for i in range(len(process_pool)):
            if process_pool[i].poll() != None:
                next_host = next(host_gen)
                process_pool[i] = subprocess.Popen(shlex.split(f"nmap -T4 -A -v -oX {next_host}-scan.xml {next_host}"))
            time.sleep(0.1)


if __name__ == '__main__':
    main()
