# -*- coding: utf-8 -*-
"""
eve_preprocess_and_compare.py
────────────────────────────────────────────────────────────────
20260324 eve.json
  Step 1. CICIDS2017 피처 전처리
          - 확실한 11개 피처만 추출 (0.0 불확실 7개 제외)
          - 출력: eve_preprocessed.csv

  Step 2. RF 모델 추론
          - 불확실 7개 피처는 0.0 보완 후 기존 pkl 사용
          - 출력: eve_comparison.csv (Suricata label vs RF label)
────────────────────────────────────────────────────────────────
"""

import sys, json, pickle, os
from datetime import datetime
import pandas as pd
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")

# ── 경로 ─────────────────────────────────────────────────────────────────
LOG_DIR    = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그"
ML_DIR     = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Git data\ml_model"

EVE_JSON     = os.path.join(LOG_DIR, "20260324 eve.json")
MODEL_PATH   = os.path.join(ML_DIR,  "model_rf.pkl")
LABEL_PATH   = os.path.join(ML_DIR,  "label_encoder.pkl")
OUT_PREPROC  = os.path.join(LOG_DIR, "eve_preprocessed.csv")    # 전처리 결과
OUT_COMPARE  = os.path.join(LOG_DIR, "eve_comparison.csv")      # 비교 결과

# ── 확실하게 추출 가능한 11개 피처 ────────────────────────────────────────
RELIABLE_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size",
]

# ── 모델 학습 시 사용된 전체 18개 피처 ────────────────────────────────────
MODEL_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Fwd Packet Length Std",    # 불확실 -> 0.0
    "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean",            # 불확실 -> 0.0
    "Flow IAT Std",             # 불확실 -> 0.0
    "SYN Flag Count",           # TCP 필드 없음 -> 0.0
    "RST Flag Count",           # TCP 필드 없음 -> 0.0
    "PSH Flag Count",           # TCP 필드 없음 -> 0.0
    "ACK Flag Count",           # TCP 필드 없음 -> 0.0
    "Average Packet Size",
]

UNCERTAIN = [c for c in MODEL_FEATURES if c not in RELIABLE_FEATURES]

TS_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"

# ═════════════════════════════════════════════════════════════════════════
# Step 1. 모델 로드
# ═════════════════════════════════════════════════════════════════════════
print("=" * 60)
print("  Step 1. 모델 로드")
print("=" * 60)
with open(MODEL_PATH, "rb") as f:  model = pickle.load(f)
with open(LABEL_PATH, "rb") as f:  le    = pickle.load(f)
print(f"  클래스: {list(le.classes_)}\n")

# ═════════════════════════════════════════════════════════════════════════
# Step 2. eve.json 파싱 + 전처리
# ═════════════════════════════════════════════════════════════════════════
print("=" * 60)
print("  Step 2. eve.json 전처리 (확실한 피처 11개 추출)")
print("=" * 60)
print(f"  입력: {EVE_JSON}")
print(f"  제외 피처 (0.0 불확실): {UNCERTAIN}\n")

def parse_flow(ev: dict) -> dict:
    """flow 이벤트 -> 피처 딕셔너리 (확실한 11개)"""
    f = ev.get("flow", {})

    pkts_fwd  = float(f.get("pkts_toserver",  0) or 0)
    pkts_bwd  = float(f.get("pkts_toclient",  0) or 0)
    bytes_fwd = float(f.get("bytes_toserver", 0) or 0)
    bytes_bwd = float(f.get("bytes_toclient", 0) or 0)
    total_pkts  = pkts_fwd + pkts_bwd
    total_bytes = bytes_fwd + bytes_bwd

    try:
        t_start      = datetime.strptime(f["start"], TS_FMT)
        t_end        = datetime.strptime(f["end"],   TS_FMT)
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
        "Bwd Packet Length Mean":      round(bwd_mean,     6),
        "Flow Bytes/s":                round(flow_bps,     6),
        "Flow Packets/s":              round(flow_pps,     6),
        "Average Packet Size":         round(avg_pkt_size, 6),
    }

meta_rows    = []
feature_rows = []
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
            sur_label = "ALERT" if ev.get("flow", {}).get("alerted", False) else "BENIGN"
            meta_rows.append({
                "flow_id":        fid,
                "timestamp":      ev.get("timestamp", ""),
                "src_ip":         ev.get("src_ip",    ""),
                "src_port":       ev.get("src_port",  ""),
                "dest_ip":        ev.get("dest_ip",   ""),
                "dest_port":      ev.get("dest_port", ""),
                "proto":          ev.get("proto",     ""),
                "app_proto":      ev.get("app_proto", ""),
                "suricata_label": sur_label,
            })
            feature_rows.append(parse_flow(ev))

        elif etype == "alert":
            alert = ev.get("alert", {})
            if fid not in alert_map or \
               int(alert.get("severity", 99)) < int(alert_map[fid].get("severity") or 99):
                alert_map[fid] = {
                    "severity":  alert.get("severity",  ""),
                    "signature": alert.get("signature", ""),
                    "category":  alert.get("category",  ""),
                }

print(f"  flow 이벤트: {len(feature_rows)}건")
print(f"  alert 이벤트: {len(alert_map)}건")

# ── 전처리 CSV 저장 (확실한 11개 피처 + 메타) ────────────────────────────
df_preproc = pd.DataFrame(feature_rows, columns=RELIABLE_FEATURES)
df_meta    = pd.DataFrame(meta_rows)

df_preproc_out = pd.concat([
    df_meta[["flow_id","timestamp","src_ip","src_port","dest_ip","dest_port","proto","app_proto","suricata_label"]],
    df_preproc
], axis=1)

df_preproc_out.to_csv(OUT_PREPROC, index=False, encoding="utf-8-sig")
print(f"\n  [저장] 전처리 CSV: {OUT_PREPROC}")
print(f"         {len(df_preproc_out)}행 x {len(df_preproc_out.columns)}열\n")

# ═════════════════════════════════════════════════════════════════════════
# Step 3. RF 추론 (불확실 7개 피처 0.0 보완)
# ═════════════════════════════════════════════════════════════════════════
print("=" * 60)
print("  Step 3. RF 모델 추론")
print("=" * 60)
print(f"  불확실 피처 0.0 보완: {UNCERTAIN}")

# 18개 피처 데이터프레임 구성
df_model = df_preproc.copy()
for col in UNCERTAIN:
    df_model[col] = 0.0

X = df_model[MODEL_FEATURES].values
pred_enc    = model.predict(X)
pred_prob   = model.predict_proba(X)
pred_label  = le.inverse_transform(pred_enc)
confidences = (pred_prob.max(axis=1) * 100).round(2)

print(f"\n  추론 완료: {len(pred_label)}건")
rf_dist = pd.Series(pred_label).value_counts()
print(f"  예측 분포:")
for lbl, cnt in rf_dist.items():
    print(f"    {lbl:<35} {cnt}건")

# ═════════════════════════════════════════════════════════════════════════
# Step 4. 비교 테이블 생성
# ═════════════════════════════════════════════════════════════════════════
print()
print("=" * 60)
print("  Step 4. 비교 테이블 생성")
print("=" * 60)

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
        "app_proto":          meta["app_proto"],
        "suricata_판단":      sur_label,
        "suricata_severity":  alert_info.get("severity",  "-"),
        "suricata_signature": alert_info.get("signature", "-"),
        "suricata_category":  alert_info.get("category",  "-"),
        "RF_예측":            rf_lbl,
        "RF_확률(%)":         rf_prob,
        "결과분류":           classify(sur_label, rf_lbl),
    })

df_out = pd.DataFrame(rows)

# ── 탐지율 요약 ───────────────────────────────────────────────────────────
total  = len(df_out)
counts = df_out["결과분류"].value_counts()
categories = ["둘 다 탐지", "Suricata만 탐지", "RF만 탐지", "둘 다 정상"]

print()
print("┌" + "─" * 53 + "┐")
print("│  탐지율 요약표" + " " * 38 + "│")
print("├" + "─" * 53 + "┤")
print(f"│  {'분류':<20} {'건수':>6}  {'비율':>7}          │")
print("├" + "─" * 53 + "┤")
for cat in categories:
    cnt = counts.get(cat, 0)
    pct = cnt / total * 100 if total > 0 else 0
    print(f"│  {cat:<20} {cnt:>6}  {pct:>6.1f}%          │")
print("├" + "─" * 53 + "┤")
print(f"│  {'합계':<20} {total:>6}  {'100.0%':>7}          │")
print("└" + "─" * 53 + "┘")

sur_detected = counts.get("둘 다 탐지", 0) + counts.get("Suricata만 탐지", 0)
rf_detected  = counts.get("둘 다 탐지", 0) + counts.get("RF만 탐지",       0)
print(f"\n  Suricata 탐지율: {sur_detected}/{total} = {sur_detected/total*100:.1f}%")
print(f"  RF       탐지율: {rf_detected}/{total}  = {rf_detected/total*100:.1f}%")

# ── Suricata alert 목록 출력 ──────────────────────────────────────────────
alert_rows = df_out[df_out["suricata_판단"] == "ALERT"]
if not alert_rows.empty:
    print(f"\n  Suricata 탐지 목록 ({len(alert_rows)}건):")
    for _, row in alert_rows.iterrows():
        print(f"    [{row['src_ip']}] -> [{row['dest_ip']}:{row['dest_port']}]"
              f"  severity={row['suricata_severity']}"
              f"  sig={row['suricata_signature']}")

# ── 저장 ─────────────────────────────────────────────────────────────────
print()
df_out.to_csv(OUT_COMPARE, index=False, encoding="utf-8-sig")
print(f"  [저장] 비교 결과 CSV: {OUT_COMPARE}")
print(f"         {len(df_out)}행 x {len(df_out.columns)}열")

print()
print("  생성 파일 요약:")
print(f"    1. eve_preprocessed.csv  - 확실한 11개 피처 전처리 결과")
print(f"    2. eve_comparison.csv    - Suricata vs RF 비교 테이블")

input("\nEnter 키를 눌러 종료...")
