import pandas as pd
from datetime import datetime

# If you install Nmap and python-nmap, you can later replace this with a real scan.
def fake_scan(target_ip: str) -> pd.DataFrame:
    data = [
        {'host': target_ip, 'protocol': 'tcp', 'port': 22, 'state': 'open',
         'service': 'ssh', 'product': 'OpenSSH', 'version': '8.4'},
        {'host': target_ip, 'protocol': 'tcp', 'port': 80, 'state': 'open',
         'service': 'http', 'product': 'Apache', 'version': '2.4.52'},
        {'host': target_ip, 'protocol': 'tcp', 'port': 3389, 'state': 'open',
         'service': 'rdp', 'product': 'Microsoft RDP', 'version': ''},
    ]
    df = pd.DataFrame(data)
    df['scan_time'] = datetime.now()
    return df