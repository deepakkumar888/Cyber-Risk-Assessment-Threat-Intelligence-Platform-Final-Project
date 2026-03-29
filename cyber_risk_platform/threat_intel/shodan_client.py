import json
from pathlib import Path

import pandas as pd
import shodan


def load_config(path="config.json"):
    return json.loads(Path(path).read_text())


def build_client(config_path="config.json"):
    cfg = load_config(config_path)
    return shodan.Shodan(cfg["shodan_api_key"])


def enrich_with_shodan(ip_list, config_path="config.json"):
    api = build_client(config_path)
    rows = []
    for ip in ip_list:
        try:
            host = api.host(ip)
            vulns = host.get("vulns", []) or []
            rows.append(
                {
                    "ip": ip,
                    "organization": host.get("org", ""),
                    "isp": host.get("isp", ""),
                    "open_ports": ",".join(str(p) for p in host.get("ports", [])),
                    "tags": ",".join(host.get("tags", [])),
                    "vuln_count": len(vulns),
                }
            )
        except shodan.APIError:
            rows.append(
                {
                    "ip": ip,
                    "organization": "",
                    "isp": "",
                    "open_ports": "",
                    "tags": "",
                    "vuln_count": 0,
                }
            )
    return pd.DataFrame(rows)
