import pickle
import numpy as np
import pandas as pd
from collections import Counter

MAPPED_CSV   = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\Suricati-KISTI\suricata_kisti_mapped_20260428.csv"
MODEL_PATH   = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\model_kisti_rf.pkl"
OUTPUT_PATH  = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\suricata_20260428_result.csv"

LABEL_MAP = {0:"UNKNOWN", 1:"Worm", 2:"WebAttack", 3:"SystemExploit", 4:"Scanning", 5:"Other"}
FEATURES  = ["sourcePort", "destinationPort", "protocol", "eventCount", "duration", "packetSize"]

print("모델 로딩...")
with open(MODEL_PATH, "rb") as f:
    clf = pickle.load(f)

print("전처리된 CSV 로딩...")
df = pd.read_csv(MAPPED_CSV)
print(f"  총 레코드: {len(df):,}")

# 결측값 처리 (비flow 이벤트는 duration/packetSize 0으로 채움)
df[FEATURES] = df[FEATURES].fillna(0)

# 추론
X = df[FEATURES].values
pred_codes = clf.predict(X)
pred_proba = clf.predict_proba(X)

df["pred_label"]  = [LABEL_MAP.get(c, str(c)) for c in pred_codes]
df["confidence"]  = pred_proba.max(axis=1).round(4)

# 결과 출력
print("\n===== 분석 결과 =====")
total = len(df)
for label, cnt in sorted(Counter(df["pred_label"]).items(), key=lambda x: -x[1]):
    print(f"  {label:<15} {cnt:>6,}건  ({cnt/total*100:.1f}%)")
print(f"\n  총 레코드: {total:,}건")

threats = df[df["pred_label"] != "UNKNOWN"]
print(f"  위협 탐지 (UNKNOWN 제외): {len(threats):,}건")

if len(threats) > 0:
    print("\n  [위협 상세]")
    cols = ["timestamp" if "timestamp" in df.columns else "uid",
            "sourceIP", "destinationIP", "sourcePort", "destinationPort",
            "protocol", "eventCount", "duration", "packetSize",
            "pred_label", "confidence"]
    cols = [c for c in cols if c in df.columns]
    print(threats[cols].to_string(index=False))

# 저장
out_cols = ["uid", "sourceIP", "destinationIP", "sourcePort", "destinationPort",
            "protocol", "attackType", "eventCount", "analyResult", "duration",
            "packetSize", "pred_label", "confidence"]
df[out_cols].to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")
print(f"\n결과 저장: {OUTPUT_PATH}")
