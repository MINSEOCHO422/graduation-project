import json
import csv
import os

INPUT_FILE = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\eve.json"
OUTPUT_FILE = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\suricata_alerts.csv"

rows = []

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        alert = event.get("alert", {})
        rows.append({
            "timestamp": event.get("timestamp", ""),
            "src_ip":    event.get("src_ip", ""),
            "dest_ip":   event.get("dest_ip", ""),
            "dest_port": event.get("dest_port", ""),
            "signature": alert.get("signature", ""),
            "severity":  alert.get("severity", ""),
        })

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8-sig") as f:
    fieldnames = ["timestamp", "src_ip", "dest_ip", "dest_port", "signature", "severity"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"완료: {len(rows)}개 alert 이벤트 → {OUTPUT_FILE}")
