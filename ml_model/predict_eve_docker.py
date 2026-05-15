# -*- coding: utf-8 -*-
"""
predict_eve_docker.py
eve.json 실시간 감시 → Suricata flow 이벤트 파싱 → Random Forest 추론
"""
import json
import time
import pickle
import os
import numpy as np
import pandas as pd
from datetime import datetime

MODEL_PATH = "/app/model_rf.pkl"
LABEL_PATH = "/app/label_encoder.pkl"
EVE_LOG    = "/var/log/suricata/eve.json"

MODEL_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Average Packet Size"
]

print("[*] 모델 로드 중...", flush=True)
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)
with open(LABEL_PATH, "rb") as f:
    le = pickle.load(f)
print("[*] 모델 로드 완료.", flush=True)


def parse_flow(event: dict) -> dict | None:
    """Suricata flow 이벤트 → MODEL_FEATURES 딕셔너리 변환"""
    if event.get("event_type") != "flow":
        return None

    flow = event.get("flow", {})
    tcp  = event.get("tcp", {})

    pkts_fwd  = float(flow.get("pkts_toserver",  0) or 0)
    pkts_bwd  = float(flow.get("pkts_toclient",  0) or 0)
    bytes_fwd = float(flow.get("bytes_toserver", 0) or 0)
    bytes_bwd = float(flow.get("bytes_toclient", 0) or 0)

    # Flow Duration (microseconds) — start/end가 없으면 0
    try:
        fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
        t_start = datetime.strptime(flow["start"], fmt)
        t_end   = datetime.strptime(flow["end"],   fmt)
        duration_us = max((t_end - t_start).total_seconds() * 1_000_000, 1)
    except Exception:
        duration_us = 1.0

    duration_s    = duration_us / 1_000_000
    total_pkts    = pkts_fwd + pkts_bwd
    total_bytes   = bytes_fwd + bytes_bwd

    fwd_pkt_mean  = bytes_fwd / pkts_fwd  if pkts_fwd  > 0 else 0.0
    bwd_pkt_mean  = bytes_bwd / pkts_bwd  if pkts_bwd  > 0 else 0.0
    flow_bps      = total_bytes / duration_s if duration_s > 0 else 0.0
    flow_pps      = total_pkts  / duration_s if duration_s > 0 else 0.0
    avg_pkt_size  = total_bytes / total_pkts  if total_pkts > 0 else 0.0

    # TCP 플래그 (있으면 1, 없으면 0)
    flags = tcp.get("tcp_flags", "")
    syn = int(tcp.get("syn", False))
    rst = int(tcp.get("rst", False))
    psh = int(tcp.get("psh", False))
    ack = int(tcp.get("ack", False))

    return {
        "Destination Port":             float(event.get("dest_port", 0) or 0),
        "Flow Duration":                duration_us,
        "Total Fwd Packets":            pkts_fwd,
        "Total Backward Packets":       pkts_bwd,
        "Total Length of Fwd Packets":  bytes_fwd,
        "Total Length of Bwd Packets":  bytes_bwd,
        "Fwd Packet Length Mean":       fwd_pkt_mean,
        "Fwd Packet Length Std":        0.0,   # eve.json에서 구할 수 없음
        "Bwd Packet Length Mean":       bwd_pkt_mean,
        "Flow Bytes/s":                 flow_bps,
        "Flow Packets/s":               flow_pps,
        "Flow IAT Mean":                0.0,   # eve.json에서 구할 수 없음
        "Flow IAT Std":                 0.0,
        "SYN Flag Count":               float(syn),
        "RST Flag Count":               float(rst),
        "PSH Flag Count":               float(psh),
        "ACK Flag Count":               float(ack),
        "Average Packet Size":          avg_pkt_size,
    }


def predict_batch(rows: list[dict]):
    df = pd.DataFrame(rows, columns=MODEL_FEATURES)
    X  = df[MODEL_FEATURES].values
    pred_enc   = model.predict(X)
    pred_prob  = model.predict_proba(X)
    pred_label = le.inverse_transform(pred_enc)
    confidences = (pred_prob.max(axis=1) * 100).round(2)
    return pred_label, confidences


def tail_eve(path: str):
    """eve.json 파일 끝부터 새 줄을 yield"""
    print(f"[*] {path} 감시 시작 (파일 대기 중)...", flush=True)
    while not os.path.exists(path):
        time.sleep(2)
    print(f"[*] {path} 발견. 실시간 스트리밍 시작.", flush=True)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)          # 파일 끝으로 이동 (기존 로그 스킵)
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.5)


BATCH_SIZE    = 10    # 몇 개 flow마다 추론할지
FLUSH_TIMEOUT = 5.0   # 배치가 안 차도 이 시간(초) 지나면 즉시 추론

buffer     = []
last_flush = time.time()

for raw_line in tail_eve(EVE_LOG):
    try:
        event = json.loads(raw_line)
    except json.JSONDecodeError:
        continue

    row = parse_flow(event)
    if row is None:
        continue

    buffer.append(row)

    now = time.time()
    if len(buffer) >= BATCH_SIZE or (now - last_flush) >= FLUSH_TIMEOUT:
        labels, confs = predict_batch(buffer)
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{ts}] ── 추론 결과 ({len(buffer)}건) ──", flush=True)
        for i, (lbl, conf) in enumerate(zip(labels, confs)):
            alert = " *** ALERT ***" if lbl != "BENIGN" else ""
            print(f"  [{i+1:>2}] {lbl:<30} {conf:5.1f}%{alert}", flush=True)
        buffer.clear()
        last_flush = now
