# -*- coding: utf-8 -*-
"""
compare_suricata_rf.py
────────────────────────────────────────────────────────────────
eve.json + eve_cicids_model.csv → Suricata vs RF 비교 테이블 생성

흐름:
  1. eve.json 파싱
       - flow 이벤트: 순서대로 (flow_id, src_ip, dest_ip, dest_port, proto) 추출
       - alert 이벤트: flow_id → {severity, signature} 매핑
  2. eve_cicids_model.csv → RF 모델 추론 (누락 3개 컬럼은 0.0 보완)
  3. flow 순서(= CSV 행 순서)로 join → 결과분류 산정
  4. comparison_final.csv 저장 + 탐지율 요약 출력
────────────────────────────────────────────────────────────────
"""

import sys, json, pickle, os
import pandas as pd
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")

# ── 경로 설정 ─────────────────────────────────────────────────────────────
BASE       = os.path.dirname(os.path.abspath(__file__))
EVE_JSON   = os.path.join(BASE, "eve.json")
CSV_IN     = os.path.join(BASE, "eve_cicids_model.csv")
CSV_OUT    = os.path.join(BASE, "comparison_final.csv")
MODEL_PATH = os.path.join(BASE, "..", "ml_model", "model_rf.pkl")
LABEL_PATH = os.path.join(BASE, "..", "ml_model", "label_encoder.pkl")

# ── RF 모델이 학습된 18개 피처 ────────────────────────────────────────────
MODEL_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Fwd Packet Length Std",        # eve.json 미제공 → 0.0 보완
    "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean",                # eve.json 미제공 → 0.0 보완
    "Flow IAT Std",                 # eve.json 미제공 → 0.0 보완
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Average Packet Size",
]

# ─────────────────────────────────────────────────────────────────────────
# 1. 모델 로드
# ─────────────────────────────────────────────────────────────────────────
print("[1] 모델 로드 중...")
with open(MODEL_PATH, "rb") as f:  model = pickle.load(f)
with open(LABEL_PATH, "rb") as f:  le    = pickle.load(f)
print(f"    클래스: {list(le.classes_)}\n")

# ─────────────────────────────────────────────────────────────────────────
# 2. eve.json 파싱
#    - flow 이벤트 → 순서 리스트 (CSV 행과 1:1 대응)
#    - alert 이벤트 → flow_id 키 딕셔너리
# ─────────────────────────────────────────────────────────────────────────
print(f"[2] eve.json 파싱 중: {EVE_JSON}")

flow_meta  = []   # [{flow_id, src_ip, dest_ip, dest_port, proto}, ...]
alert_map  = {}   # {flow_id: {severity, signature}}

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
            flow_meta.append({
                "flow_id":   fid,
                "src_ip":    ev.get("src_ip",    ""),
                "dest_ip":   ev.get("dest_ip",   ""),
                "dest_port": ev.get("dest_port", ""),
                "proto":     ev.get("proto",     ""),
            })

        elif etype == "alert":
            alert = ev.get("alert", {})
            # 같은 flow_id에 alert 여러 개면 severity 숫자 작을수록(더 위험) 우선
            if fid not in alert_map or \
               int(alert.get("severity", 99)) < int(alert_map[fid]["severity"] or 99):
                alert_map[fid] = {
                    "severity":  alert.get("severity", ""),
                    "signature": alert.get("signature", ""),
                }

print(f"    flow 이벤트: {len(flow_meta)}건  /  alert 이벤트: {len(alert_map)}건\n")

# ─────────────────────────────────────────────────────────────────────────
# 3. eve_cicids_model.csv 로드 + RF 추론
# ─────────────────────────────────────────────────────────────────────────
print(f"[3] CSV 로드 및 RF 추론: {CSV_IN}")
df = pd.read_csv(CSV_IN, encoding="utf-8-sig")
df.columns = df.columns.str.strip()
print(f"    CSV 행 수: {len(df)}  /  flow 이벤트 수: {len(flow_meta)}")

if len(df) != len(flow_meta):
    print(f"    [경고] 행 수 불일치! CSV({len(df)}) ≠ flow 이벤트({len(flow_meta)})")
    print(f"           eve_to_cicids.py를 먼저 재실행하세요.")

# Label 컬럼은 Suricata 판단이므로 피처에서 제외
# 누락된 3개 컬럼은 0.0으로 보완
for col in MODEL_FEATURES:
    if col not in df.columns:
        df[col] = 0.0
        print(f"    누락 피처 0.0 보완: {col}")

X = df[MODEL_FEATURES].values
pred_enc    = model.predict(X)
pred_prob   = model.predict_proba(X)
pred_label  = le.inverse_transform(pred_enc)
confidences = (pred_prob.max(axis=1) * 100).round(2)

print(f"    RF 추론 완료: {len(pred_label)}건")
print(f"    예측 분포: {pd.Series(pred_label).value_counts().to_dict()}\n")

# ─────────────────────────────────────────────────────────────────────────
# 4. flow_id 기준 join → 결과분류
# ─────────────────────────────────────────────────────────────────────────
def classify(sur: str, rf: str) -> str:
    rf_attack = (rf != "BENIGN")
    if   sur == "ALERT" and not rf_attack: return "Suricata만 탐지"
    elif sur == "BENIGN" and rf_attack:    return "RF만 탐지"
    elif sur == "ALERT"  and rf_attack:    return "둘 다 탐지"
    else:                                  return "둘 다 정상"

rows = []
n = min(len(flow_meta), len(pred_label))

for i in range(n):
    meta = flow_meta[i]
    fid  = meta["flow_id"]

    # Suricata 판단: alert_map에 flow_id가 있으면 ALERT
    if fid in alert_map:
        sur_판단   = "ALERT"
        sur_sev    = alert_map[fid]["severity"]
        sur_sig    = alert_map[fid]["signature"]
    else:
        sur_판단   = "BENIGN"
        sur_sev    = "-"
        sur_sig    = "-"

    rf_lbl  = pred_label[i]
    rf_prob = confidences[i]

    rows.append({
        "flow_id":            fid,
        "src_ip":             meta["src_ip"],
        "dest_ip":            meta["dest_ip"],
        "dest_port":          meta["dest_port"],
        "proto":              meta["proto"],
        "suricata_판단":      sur_판단,
        "suricata_severity":  sur_sev,
        "suricata_signature": sur_sig,
        "RF_예측":            rf_lbl,
        "RF_확률(%)":         rf_prob,
        "결과분류":           classify(sur_판단, rf_lbl),
    })

df_out = pd.DataFrame(rows)

# ─────────────────────────────────────────────────────────────────────────
# 5. 탐지율 요약 출력
# ─────────────────────────────────────────────────────────────────────────
total = len(df_out)
counts = df_out["결과분류"].value_counts()

categories = ["둘 다 탐지", "Suricata만 탐지", "RF만 탐지", "둘 다 정상"]

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

# Suricata 탐지율 / RF 탐지율
sur_detected = counts.get("둘 다 탐지", 0) + counts.get("Suricata만 탐지", 0)
rf_detected  = counts.get("둘 다 탐지", 0) + counts.get("RF만 탐지",       0)
print(f"\n  Suricata 탐지율: {sur_detected}/{total} = {sur_detected/total*100:.1f}%")
print(f"  RF       탐지율: {rf_detected}/{total}  = {rf_detected/total*100:.1f}%")
print()

# ─────────────────────────────────────────────────────────────────────────
# 6. CSV 저장
# ─────────────────────────────────────────────────────────────────────────
df_out.to_csv(CSV_OUT, index=False, encoding="utf-8-sig")
print(f"[*] 저장 완료: {CSV_OUT}")

input("\nEnter 키를 눌러 종료...")
