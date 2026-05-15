import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

BASE = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋"
SAMPLED_PATH  = BASE + r"\kisti_sampled(10%).csv"
TRAINING_PATH = BASE + r"\training_set.csv"
MODEL_PATH    = BASE + r"\model_kisti_rf.pkl"
ENCODER_PATH  = BASE + r"\label_encoder_kisti.pkl"

LABEL_MAP = {0:"UNKNOWN", 1:"Worm", 2:"WebAttack", 3:"SystemExploit", 4:"Scanning", 5:"Other"}
FEATURES  = ["sourcePort", "destinationPort", "protocol", "eventCount", "duration",
             "packetSize"]

# ── 1. kisti_sampled 로드 ──────────────────────────────────────
print("1) kisti_sampled(10%).csv 로딩...")
df_s = pd.read_csv(SAMPLED_PATH)
print(f"   행 수: {len(df_s):,}")
target_uids = set(df_s["uid"])

# ── 2. training_set에서 uid/packetSize 청크 추출 ──────────────
print("2) training_set.csv 청크 처리 중 (4.8GB)...")
uid_map = {}   # uid -> packetSize
chunk_size = 100_000
chunk_no = 0

for chunk in pd.read_csv(
    TRAINING_PATH,
    sep="\t",
    usecols=["uid", "packetSize"],
    low_memory=False,
    chunksize=chunk_size,
):
    chunk_no += 1
    match = chunk[chunk["uid"].isin(target_uids)]
    for row in match.itertuples(index=False):
        if row.uid not in uid_map:
            uid_map[row.uid] = row.packetSize

    if chunk_no % 50 == 0:
        print(f"   청크 {chunk_no}... 매핑된 uid: {len(uid_map):,}")

print(f"   완료 - 매핑된 uid: {len(uid_map):,} / sampled: {len(target_uids):,}")

# ── 3. 조인 ────────────────────────────────────────────────────
print("3) 두 파일 조인...")
df_s["packetSize"] = df_s["uid"].map(uid_map)

before = len(df_s)
df_s = df_s.dropna(subset=["packetSize"])
df_s["packetSize"] = df_s["packetSize"].astype(float)
after = len(df_s)
print(f"   조인 후 행 수: {after:,}  (매핑 실패로 제거: {before - after:,})")

print("\n레이블 분포:")
for v, c in df_s["attackType"].value_counts().sort_index().items():
    print(f"  {v} ({LABEL_MAP.get(v,'?')}): {c:,}")

# ── 4. 학습 / 테스트 분할 ──────────────────────────────────────
X = df_s[FEATURES].values
y = df_s["attackType"].values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print(f"\n학습: {len(X_train):,}  /  테스트: {len(X_test):,}")

# ── 5. Random Forest 학습 ──────────────────────────────────────
print("\nRandom Forest 학습 중...")
clf = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
clf.fit(X_train, y_train)

# ── 6. 저장 ────────────────────────────────────────────────────
with open(MODEL_PATH, "wb") as f:
    pickle.dump(clf, f)

le = LabelEncoder()
le.classes_ = np.array(sorted(LABEL_MAP.keys()))
with open(ENCODER_PATH, "wb") as f:
    pickle.dump(le, f)

print(f"모델 저장: {MODEL_PATH}")
print(f"인코더 저장: {ENCODER_PATH}")

# ── 7. 평가 ────────────────────────────────────────────────────
print("\n--- 테스트 세트 평가 ---")
y_pred = clf.predict(X_test)
present = sorted(np.unique(np.concatenate([y_test, y_pred])))
names   = [LABEL_MAP.get(c, str(c)) for c in present]
print(classification_report(y_test, y_pred, labels=present, target_names=names, zero_division=0))

print("특성 중요도:")
for feat, imp in sorted(zip(FEATURES, clf.feature_importances_), key=lambda x: -x[1]):
    print(f"  {feat}: {imp:.4f}")
