import ipaddress
import time
import subprocess
import shlex
import multiprocessing
from icmplib import ping

CONCURRENT_SCANS = 8

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
    # print("started")
    # nm = nmap.PortScanner()
    # host_str = f"{host}"
    # print(host_str)
    # nm.scan(f"{host_str}", arguments="-T4 -v -A")
    # print(nm.command_line())
    # with open(f"{host_str}-scan.xml", "w") as f:
    #     f.write(str(nm.get_nmap_last_output(), "utf-8"))
    # print(f"{host_str}:{nm[host_str].state()}")
    print(f"Scan of {host} started")
    if ping(address=host, count=4, interval=0.5).is_alive:
        print(f"{host} is up")
        subprocess.run(shlex.split(f"nmap -T4 -A -v -oX {host}-scan.xml {host}"))
    else:
        print(f"{host} is down")
    print(f"Scan of {host} finished")

def main():
    # for host in get_next_az_host():
    #     nm.scan(f"{host}", arguments="-T4 -v -A")
    #     for host in nm.all_hosts():
    #         print(f"{host}:{nm[host].state()}")
    #         print(nm.get_nmap_last_output())
    process_pool = list()
    host_gen = get_next_az_host(ipaddress.IPv4Address("37.26.7.237"))
    for _ in range(CONCURRENT_SCANS):
        next_host = next(host_gen)
        process_pool.append(multiprocessing.Process(target=scan_host, args=(f"{next_host}",)))
        # process_pool.append(subprocess.Popen(shlex.split(f"nmap -T4 -A -v -oX {next_host}-scan.xml {next_host}")))
    for i in range(CONCURRENT_SCANS):
        process_pool[i].start()
    while True:
        try:
            for i in range(len(process_pool)):
                if process_pool[i].is_alive():
                    next_host = next(host_gen)
                    process_pool[i] = multiprocessing.Process(target=scan_host, args=(f"{next_host}",))
                    process_pool[i].start()
                else:
                    ...
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("Caught keyboard interrupt")
            break
        except Exception as e:
            print("Caught exception")
            print(e)
            exit(1)
    print("Exiting")


if __name__ == '__main__':
    main()
