# -*- coding: utf-8 -*-
import sys, pickle, os
sys.stdout.reconfigure(encoding="utf-8")

BASE       = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Git data\ml_model\model_rf.pkl"
LABEL_PATH = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Git data\ml_model\label_encoder.pkl"

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)
with open(LABEL_PATH, "rb") as f:
    le = pickle.load(f)

print("=" * 50)
print("  model_rf.pkl 정보")
print("=" * 50)
print(f"  모델 종류     : {type(model)}")
print(f"  트리 개수     : {model.n_estimators}")
print(f"  클래스 목록   : {list(le.classes_)}")
print(f"  피처 수       : {len(model.feature_importances_)}")

print()
print("  피처 중요도 Top 10:")
import pandas as pd
features = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Average Packet Size",
]
importance = pd.Series(model.feature_importances_, index=features)
for name, val in importance.sort_values(ascending=False).head(10).items():
    print(f"    {name:<35} {val:.4f}")

input("\nEnter 키를 눌러 종료...")
