import requests
import ipaddress
import os
import json

# 설정
url = "https://threatfox.abuse.ch/export/csv/recent/"
excluded_ip_ranges = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14",
    "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
    "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"
]
excluded_networks = [ipaddress.ip_network(net) for net in excluded_ip_ranges]
excluded_ips = {"127.0.0.1", "204.79.197.203"}
valid_ioc_types = {"domain", "sha256_hash", "md5_hash", "ip:port"}
seen_iocs = set()
filtered_data = []

# 요청
response = requests.get(url)
response.raise_for_status()
lines = [line for line in response.text.splitlines() if not line.startswith("#")]

# IP 검사
def is_excluded_ip(ioc_value: str) -> bool:
    try:
        ip_str = ioc_value.split(":")[0]
        if ip_str in excluded_ips:
            return True
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in excluded_networks)
    except ValueError:
        return False

# 필터링
for line in lines:
    parts = line.split(",")
    if len(parts) < 4:
        continue

    timestamp = parts[0].strip().strip('"')
    id_ = parts[1].strip().strip('"')
    ioc_value_raw = parts[2].strip().strip('"')
    ioc_type = parts[3].strip().strip('"').lower()
    rest = [p.strip().strip('"') for p in parts[4:]]

    ioc_value_key = ioc_value_raw.split(":")[0]

    if ioc_type in valid_ioc_types and ioc_value_key not in seen_iocs:
        if not is_excluded_ip(ioc_value_key):
            seen_iocs.add(ioc_value_key)
            row = [timestamp, id_, ioc_value_key, ioc_type] + rest
            filtered_data.append(row)

# GitHub Actions에서 저장할 고정 경로 설정
output_path = "data/threatfox_abuse_feed.json"
os.makedirs(os.path.dirname(output_path), exist_ok=True)

# JSON 저장
with open(output_path, "w", encoding="utf-8") as f:
    for row in filtered_data:
        # row[2]는 IP:PORT 그대로, row[11:16]은 ,로 묶어 1필드로
        if len(row) >= 17:
            combined_field = ",".join(row[11:16])
            new_row = row[:11] + [combined_field] + row[16:]
            line = ",".join(f'"{field}"' for field in new_row)
            f.write(line + "\n")

print(f"총 저장된 항목: {len(filtered_data)}")
