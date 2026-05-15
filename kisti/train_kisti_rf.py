import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

DATA_PATH = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\kisti_sampled(10%).csv"
MODEL_PATH = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\model_kisti_rf.pkl"
ENCODER_PATH = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\label_encoder_kisti.pkl"

LABEL_MAP = {0: "UNKNOWN", 1: "Worm", 2: "WebAttack", 3: "SystemExploit", 4: "Scanning", 5: "Other"}
FEATURES = ["sourcePort", "destinationPort", "protocol", "eventCount", "duration"]
LABEL_COL = "attackType"

print("데이터 로딩 중...")
df = pd.read_csv(DATA_PATH)
print(f"  총 행 수: {len(df):,}")

# 레이블 분포 출력
print("\n레이블 분포:")
for val, cnt in df[LABEL_COL].value_counts().sort_index().items():
    name = LABEL_MAP.get(val, "?")
    print(f"  {val} ({name}): {cnt:,}")

X = df[FEATURES].values
y = df[LABEL_COL].values

# LabelEncoder 생성 및 저장
le = LabelEncoder()
le.classes_ = np.array(sorted(LABEL_MAP.keys()))
with open(ENCODER_PATH, "wb") as f:
    pickle.dump(le, f)
print(f"\nlabel_encoder 저장: {ENCODER_PATH}")

# 학습/테스트 분할
# Scanning(4)이 샘플 1개뿐이므로 stratify 미사용
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print(f"\n학습 세트: {len(X_train):,}  /  테스트 세트: {len(X_test):,}")

# Random Forest 학습
print("\nRandom Forest 학습 중...")
clf = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
clf.fit(X_train, y_train)

# 모델 저장
with open(MODEL_PATH, "wb") as f:
    pickle.dump(clf, f)
print(f"모델 저장: {MODEL_PATH}")

# 평가
print("\n--- 테스트 세트 평가 ---")
y_pred = clf.predict(X_test)
present_labels = sorted(np.unique(np.concatenate([y_test, y_pred])))
target_names = [LABEL_MAP.get(c, str(c)) for c in present_labels]
print(classification_report(y_test, y_pred, labels=present_labels, target_names=target_names, zero_division=0))

print("특성 중요도:")
for feat, imp in sorted(zip(FEATURES, clf.feature_importances_), key=lambda x: -x[1]):
    print(f"  {feat}: {imp:.4f}")
