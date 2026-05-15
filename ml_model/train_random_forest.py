# -*- coding: utf-8 -*-
"""
CICIDS_Final_Cleaned_19.csv → Random Forest 학습 → model_rf.pkl 저장
"""

import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import pickle

# ── 경로 설정 ──────────────────────────────────────────────────────────────
BASE       = os.path.dirname(os.path.abspath(__file__))
CSV_PATH   = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\CIC2017Dataset\19_Columns\CICIDS_Final_Cleaned_19.csv"
MODEL_PATH = os.path.join(BASE, "model_rf.pkl")
LABEL_PATH = os.path.join(BASE, "label_encoder.pkl")

# ── 데이터 로드 ────────────────────────────────────────────────────────────
print("데이터 로딩 중...")
df = pd.read_csv(CSV_PATH, encoding="utf-8-sig")
df.columns = df.columns.str.strip()
print(f"  로드 완료: {len(df):,}행 × {len(df.columns)}열")
print(f"  Label 분포:\n{df['Label'].value_counts().to_string()}\n")

# ── 피처 / 레이블 분리 ─────────────────────────────────────────────────────
FEATURE_COLS = [c for c in df.columns if c != "Label"]
X = df[FEATURE_COLS].values
y = df["Label"].values

# ── 레이블 인코딩 ──────────────────────────────────────────────────────────
le = LabelEncoder()
y_enc = le.fit_transform(y)
print(f"클래스 목록: {list(le.classes_)}\n")

# ── 학습 / 테스트 분할 (80:20) ─────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
)
print(f"학습셋: {len(X_train):,}건  /  테스트셋: {len(X_test):,}건\n")

# ── Random Forest 학습 ─────────────────────────────────────────────────────
print("Random Forest 학습 중...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    n_jobs=-1,
    random_state=42
)
model.fit(X_train, y_train)
print("  학습 완료\n")

# ── 평가 ───────────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"정확도 (Accuracy): {acc:.4f}\n")
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ── 피처 중요도 상위 10 ────────────────────────────────────────────────────
importances = pd.Series(model.feature_importances_, index=FEATURE_COLS)
print("피처 중요도 Top 10:")
print(importances.sort_values(ascending=False).head(10).to_string())
print()

# ── 모델 저장 ──────────────────────────────────────────────────────────────
with open(MODEL_PATH, "wb") as f:
    pickle.dump(model, f)
with open(LABEL_PATH, "wb") as f:
    pickle.dump(le, f)

print(f"모델 저장 완료: {MODEL_PATH}")
print(f"레이블 인코더 저장: {LABEL_PATH}")

input("\nEnter 키를 눌러 종료...")
