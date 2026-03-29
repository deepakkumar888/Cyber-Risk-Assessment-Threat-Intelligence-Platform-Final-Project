import nmap
import pandas as pd


def run_nmap_scan(targets):
    nm = nmap.PortScanner()
    nm.scan(hosts=" ".join(targets), arguments="-sV -T4 --top-ports 100")

    rows = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]
                rows.append(
                    {
                        "host": host,
                        "protocol": proto,
                        "port": port,
                        "state": service["state"],
                        "name": service.get("name", ""),
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                    }
                )
    return pd.DataFrame(rows or [], columns=[
        "host", "protocol", "port", "state", "name", "product", "version"
    ])
