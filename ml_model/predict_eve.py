# -*- coding: utf-8 -*-
import sys, pickle
sys.stdout.reconfigure(encoding="utf-8")
import pandas as pd

MODEL_PATH = r"C:\Users\min07\model_rf.pkl"
LABEL_PATH = r"C:\Users\min07\label_encoder.pkl"
INPUT_CSV  = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\eve_cicids_model.csv"
OUTPUT_CSV = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\eve_prediction_result.csv"

# 모델이 학습된 피처 순서 (CICIDS_Cleaned.csv 기준 18개)
MODEL_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Average Packet Size"
]

# ── 로드 ──────────────────────────────────────────────────────────────────
with open(MODEL_PATH, "rb") as f: model = pickle.load(f)
with open(LABEL_PATH, "rb") as f: le    = pickle.load(f)

df = pd.read_csv(INPUT_CSV, encoding="utf-8-sig")
df.columns = df.columns.str.strip()
print(f"입력 데이터: {len(df)}행")

# ── 누락 피처 0.0으로 보완 (Fwd Packet Length Std, Flow IAT Mean, Flow IAT Std) ──
for col in MODEL_FEATURES:
    if col not in df.columns:
        df[col] = 0.0
        print(f"  누락 피처 추가 (0.0): {col}")

X = df[MODEL_FEATURES].values

# ── 추론 ──────────────────────────────────────────────────────────────────
pred_enc  = model.predict(X)
pred_prob = model.predict_proba(X)
pred_label = le.inverse_transform(pred_enc)

# ── 결과 출력 ─────────────────────────────────────────────────────────────
df_result = df[MODEL_FEATURES].copy()
df_result["Suricata_Label"] = df["Label"] if "Label" in df.columns else "-"
df_result["Predicted_Label"] = pred_label
df_result["Confidence(%)"] = (pred_prob.max(axis=1) * 100).round(2)

print()
print("=" * 60)
print("추론 결과")
print("=" * 60)
for i, row in df_result.iterrows():
    print(f"  [{i+1:>2}] 예측: {row['Predicted_Label']:<30} 확률: {row['Confidence(%)']}%  (Suricata Label: {row['Suricata_Label']})")

print()
print(f"예측 분포: {pd.Series(pred_label).value_counts().to_dict()}")

df_result.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
print(f"\n결과 저장: {OUTPUT_CSV}")

input("\nEnter 키를 눌러 종료...")
