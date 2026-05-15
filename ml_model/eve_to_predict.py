# -*- coding: utf-8 -*-
"""
eve_to_predict.py
────────────────────────────────────────────────────────────────
eve.json (Suricata 실시간 로그)
  → CICIDS2017 피처 변환
  → RF 모델 추론 (model_rf.pkl)
  → 결과 CSV 저장

사용법:
  python eve_to_predict.py                        # 기본 경로 사용
  python eve_to_predict.py C:/경로/eve.json       # eve.json 경로 직접 지정
────────────────────────────────────────────────────────────────
"""

import sys, json, pickle, os
from datetime import datetime
import pandas as pd
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")

# ── 경로 설정 ──────────────────────────────────────────────────────────────
BASE       = os.path.dirname(os.path.abspath(__file__))
EVE_JSON   = sys.argv[1] if len(sys.argv) > 1 else \
             r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\20260324 eve.json"
MODEL_PATH = os.path.join(BASE, "model_rf.pkl")
LABEL_PATH = os.path.join(BASE, "label_encoder.pkl")
OUTPUT_CSV = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\eve_prediction_result.csv"

# ── RF 모델 피처 18개 ─────────────────────────────────────────────────────
MODEL_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Fwd Packet Length Std",    # eve.json 미제공 -> 0.0
    "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean",            # eve.json 미제공 -> 0.0
    "Flow IAT Std",             # eve.json 미제공 -> 0.0
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Average Packet Size",
]

TS_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"

# ─────────────────────────────────────────────────────────────────────────
# 1. 모델 로드
# ─────────────────────────────────────────────────────────────────────────
print("[1] 모델 로드 중...")
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)
with open(LABEL_PATH, "rb") as f:
    le = pickle.load(f)
print(f"    클래스: {list(le.classes_)}\n")

# ─────────────────────────────────────────────────────────────────────────
# 2. eve.json 파싱 -> CICIDS 피처 변환
# ─────────────────────────────────────────────────────────────────────────
print(f"[2] eve.json 파싱 중: {EVE_JSON}")

def parse_flow(ev: dict) -> dict:
    """flow 이벤트 1개 -> CICIDS 피처 딕셔너리"""
    f   = ev.get("flow", {})
    tcp = ev.get("tcp",  {})

    pkts_fwd  = float(f.get("pkts_toserver",  0) or 0)
    pkts_bwd  = float(f.get("pkts_toclient",  0) or 0)
    bytes_fwd = float(f.get("bytes_toserver", 0) or 0)
    bytes_bwd = float(f.get("bytes_toclient", 0) or 0)
    total_pkts  = pkts_fwd + pkts_bwd
    total_bytes = bytes_fwd + bytes_bwd

    # Flow Duration (마이크로초)
    try:
        t_start = datetime.strptime(f["start"], TS_FMT)
        t_end   = datetime.strptime(f["end"],   TS_FMT)
        duration_us  = (t_end - t_start).total_seconds() * 1_000_000
        duration_sec = (t_end - t_start).total_seconds()
    except Exception:
        duration_us  = 0.0
        duration_sec = 0.0

    fwd_mean     = bytes_fwd / pkts_fwd  if pkts_fwd  > 0 else 0.0
    bwd_mean     = bytes_bwd / pkts_bwd  if pkts_bwd  > 0 else 0.0
    avg_pkt_size = total_bytes / total_pkts  if total_pkts  > 0 else 0.0
    flow_bps     = total_bytes / duration_sec if duration_sec > 0 else 0.0
    flow_pps     = total_pkts  / duration_sec if duration_sec > 0 else 0.0

    return {
        "Destination Port":            float(ev.get("dest_port", 0) or 0),
        "Flow Duration":               round(duration_us,  6),
        "Total Fwd Packets":           pkts_fwd,
        "Total Backward Packets":      pkts_bwd,
        "Total Length of Fwd Packets": bytes_fwd,
        "Total Length of Bwd Packets": bytes_bwd,
        "Fwd Packet Length Mean":      round(fwd_mean,     6),
        "Fwd Packet Length Std":       0.0,
        "Bwd Packet Length Mean":      round(bwd_mean,     6),
        "Flow Bytes/s":                round(flow_bps,     6),
        "Flow Packets/s":              round(flow_pps,     6),
        "Flow IAT Mean":               0.0,
        "Flow IAT Std":                0.0,
        "SYN Flag Count":              float(int(tcp.get("syn", False))),
        "RST Flag Count":              float(int(tcp.get("rst", False))),
        "PSH Flag Count":              float(int(tcp.get("psh", False))),
        "ACK Flag Count":              float(int(tcp.get("ack", False))),
        "Average Packet Size":         round(avg_pkt_size, 6),
    }

# flow 이벤트 파싱 + 메타 정보 수집
meta_rows    = []   # src_ip, dest_ip 등
feature_rows = []   # MODEL_FEATURES 값
alert_map    = {}   # flow_id -> {severity, signature}

with open(EVE_JSON, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        etype = ev.get("event_type", "")
        fid   = ev.get("flow_id")

        if etype == "flow":
            meta_rows.append({
                "flow_id":   fid,
                "timestamp": ev.get("timestamp", ""),
                "src_ip":    ev.get("src_ip",    ""),
                "src_port":  ev.get("src_port",  ""),
                "dest_ip":   ev.get("dest_ip",   ""),
                "dest_port": ev.get("dest_port", ""),
                "proto":     ev.get("proto",     ""),
                "suricata_label": "ALERT" if ev.get("flow", {}).get("alerted", False) else "BENIGN",
            })
            feature_rows.append(parse_flow(ev))

        elif etype == "alert":
            alert = ev.get("alert", {})
            if fid not in alert_map or \
               int(alert.get("severity", 99)) < int(alert_map[fid].get("severity") or 99):
                alert_map[fid] = {
                    "severity":  alert.get("severity", ""),
                    "signature": alert.get("signature", ""),
                }

print(f"    flow 이벤트: {len(feature_rows)}건  /  alert 이벤트: {len(alert_map)}건")

if len(feature_rows) == 0:
    print("\n[!] flow 이벤트가 없습니다.")
    print("    suricata.yaml에 flow 타입이 활성화되어 있는지 확인하세요.")
    input("\nEnter 키를 눌러 종료...")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────
# 3. RF 모델 추론
# ─────────────────────────────────────────────────────────────────────────
print(f"\n[3] RF 추론 중...")
df_feat = pd.DataFrame(feature_rows, columns=MODEL_FEATURES)
X = df_feat[MODEL_FEATURES].values

pred_enc    = model.predict(X)
pred_prob   = model.predict_proba(X)
pred_label  = le.inverse_transform(pred_enc)
confidences = (pred_prob.max(axis=1) * 100).round(2)

print(f"    추론 완료: {len(pred_label)}건")
print(f"    예측 분포: {pd.Series(pred_label).value_counts().to_dict()}")

# ─────────────────────────────────────────────────────────────────────────
# 4. 결과 합치기
# ─────────────────────────────────────────────────────────────────────────
def classify(sur_label, rf_label):
    rf_attack = (rf_label != "BENIGN")
    if   sur_label == "ALERT"  and not rf_attack: return "Suricata만 탐지"
    elif sur_label == "BENIGN" and rf_attack:     return "RF만 탐지"
    elif sur_label == "ALERT"  and rf_attack:     return "둘 다 탐지"
    else:                                         return "둘 다 정상"

rows = []
for i, meta in enumerate(meta_rows):
    fid       = meta["flow_id"]
    sur_label = meta["suricata_label"]
    rf_lbl    = pred_label[i]
    rf_prob   = confidences[i]

    alert_info = alert_map.get(fid, {})

    rows.append({
        "flow_id":            fid,
        "timestamp":          meta["timestamp"],
        "src_ip":             meta["src_ip"],
        "src_port":           meta["src_port"],
        "dest_ip":            meta["dest_ip"],
        "dest_port":          meta["dest_port"],
        "proto":              meta["proto"],
        "suricata_판단":      sur_label,
        "suricata_severity":  alert_info.get("severity",  "-"),
        "suricata_signature": alert_info.get("signature", "-"),
        "RF_예측":            rf_lbl,
        "RF_확률(%)":         rf_prob,
        "결과분류":           classify(sur_label, rf_lbl),
    })

df_out = pd.DataFrame(rows)

# ─────────────────────────────────────────────────────────────────────────
# 5. 탐지율 요약 출력
# ─────────────────────────────────────────────────────────────────────────
total  = len(df_out)
counts = df_out["결과분류"].value_counts()
categories = ["둘 다 탐지", "Suricata만 탐지", "RF만 탐지", "둘 다 정상"]

print()
print("=" * 55)
print("  탐지율 요약표")
print("=" * 55)
print(f"  {'분류':<20} {'건수':>6}  {'비율':>7}")
print("-" * 55)
for cat in categories:
    cnt = counts.get(cat, 0)
    pct = cnt / total * 100 if total > 0 else 0
    print(f"  {cat:<20} {cnt:>6}  {pct:>6.1f}%")
print("-" * 55)
print(f"  {'합계':<20} {total:>6}  {'100.0%':>7}")
print("=" * 55)

sur_detected = counts.get("둘 다 탐지", 0) + counts.get("Suricata만 탐지", 0)
rf_detected  = counts.get("둘 다 탐지", 0) + counts.get("RF만 탐지", 0)
print(f"\n  Suricata 탐지율: {sur_detected}/{total} = {sur_detected/total*100:.1f}%")
print(f"  RF       탐지율: {rf_detected}/{total}  = {rf_detected/total*100:.1f}%")
print()

# ─────────────────────────────────────────────────────────────────────────
# 6. CSV 저장
# ─────────────────────────────────────────────────────────────────────────
df_out.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
print(f"[*] 결과 저장: {OUTPUT_CSV}")

input("\nEnter 키를 눌러 종료...")
