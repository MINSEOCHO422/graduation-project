# -*- coding: utf-8 -*-
"""
eve.json (Suricata flow log) → CICIDS2017 16-column 모델 학습용 CSV 변환 스크립트

[제외된 컬럼 - Suricata 플로우 로그 구조적 한계로 0.0 고정]
- Fwd Packet Length Std : 패킷별 크기 기록 없음
- Flow IAT Mean         : 패킷 간 도착시간 기록 없음
- Flow IAT Std          : 패킷 간 도착시간 기록 없음

[기타 주의]
- SYN/RST/PSH/ACK Flag : 플로우 전체 발생 여부(0/1), 패킷 단위 카운트 아님
- Label                 : flow.alerted=true → "ALERT", false → "BENIGN"
"""

import json
import csv
import os
from datetime import datetime

# ── 경로 설정 ──────────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
INPUT  = os.path.join(BASE, "eve.json")
OUTPUT = os.path.join(BASE, "eve_cicids_model.csv")

# ── 출력 컬럼 (0.0 고정 3개 제외: Fwd Packet Length Std, Flow IAT Mean, Flow IAT Std) ──
COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Bwd Packet Length Mean", "Flow Bytes/s", "Flow Packets/s",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Average Packet Size", "Label"
]

TS_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"

def parse_ts(ts_str):
    """Suricata timestamp → datetime (timezone-aware)"""
    return datetime.strptime(ts_str, TS_FMT)

def convert(record):
    """flow 이벤트 1개 → CICIDS 행 dict"""
    f   = record.get("flow", {})
    tcp = record.get("tcp", {})

    # ── 기본 패킷/바이트 ─────────────────────────────────────────────────
    pkts_fwd = f.get("pkts_toserver", 0)
    pkts_bwd = f.get("pkts_toclient", 0)
    bytes_fwd = f.get("bytes_toserver", 0)
    bytes_bwd = f.get("bytes_toclient", 0)
    total_pkts  = pkts_fwd + pkts_bwd
    total_bytes = bytes_fwd + bytes_bwd

    # ── Flow Duration (마이크로초) ────────────────────────────────────────
    try:
        t_start = parse_ts(f["start"])
        t_end   = parse_ts(f["end"])
        duration_us  = (t_end - t_start).total_seconds() * 1_000_000
        duration_sec = (t_end - t_start).total_seconds()
    except (KeyError, ValueError):
        duration_us  = 0.0
        duration_sec = 0.0

    # ── 패킷 길이 평균 ───────────────────────────────────────────────────
    fwd_pkt_mean = bytes_fwd / pkts_fwd if pkts_fwd > 0 else 0.0
    bwd_pkt_mean = bytes_bwd / pkts_bwd if pkts_bwd > 0 else 0.0
    avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0.0

    # ── 초당 값 (duration=0 이면 0) ──────────────────────────────────────
    flow_bytes_s  = total_bytes / duration_sec if duration_sec > 0 else 0.0
    flow_pkts_s   = total_pkts  / duration_sec if duration_sec > 0 else 0.0

    # ── TCP 플래그 (TCP가 아니면 0) ──────────────────────────────────────
    syn = int(bool(tcp.get("syn", False)))
    rst = int(bool(tcp.get("rst", False)))
    psh = int(bool(tcp.get("psh", False)))
    ack = int(bool(tcp.get("ack", False)))

    # ── Destination Port ─────────────────────────────────────────────────
    dest_port = record.get("dest_port", 0)

    # ── Label ─────────────────────────────────────────────────────────────
    label = "ALERT" if f.get("alerted", False) else "BENIGN"

    return {
        "Destination Port":           dest_port,
        "Flow Duration":              round(duration_us, 6),
        "Total Fwd Packets":          pkts_fwd,
        "Total Backward Packets":     pkts_bwd,
        "Total Length of Fwd Packets": bytes_fwd,
        "Total Length of Bwd Packets": bytes_bwd,
        "Fwd Packet Length Mean":     round(fwd_pkt_mean, 6),
        "Bwd Packet Length Mean":     round(bwd_pkt_mean, 6),
        "Flow Bytes/s":               round(flow_bytes_s, 6),
        "Flow Packets/s":             round(flow_pkts_s, 6),
        "SYN Flag Count":             syn,
        "RST Flag Count":             rst,
        "PSH Flag Count":             psh,
        "ACK Flag Count":             ack,
        "Average Packet Size":        round(avg_pkt_size, 6),
        "Label":                      label,
    }

# ── 메인 ──────────────────────────────────────────────────────────────────
total = 0
converted = 0
skipped = 0

with open(INPUT, "r", encoding="utf-8") as fin, \
     open(OUTPUT, "w", newline="", encoding="utf-8-sig") as fout:

    writer = csv.DictWriter(fout, fieldnames=COLUMNS)
    writer.writeheader()

    for line in fin:
        total += 1
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue

        if record.get("event_type") != "flow":
            continue

        row = convert(record)
        writer.writerow(row)
        converted += 1

        if converted % 1000 == 0:
            print(f"  변환 중... {converted:,}건")

print()
print("=" * 50)
print(f"전체 라인  : {total:,}")
print(f"변환 완료  : {converted:,} (flow 이벤트)")
print(f"건너뜀     : {skipped:,} (파싱 오류)")
print(f"출력 파일  : {OUTPUT}")
print("=" * 50)

input("\nEnter 키를 눌러 종료...")
