import pandas as pd
import numpy as np

INPUT_PATH  = r'C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\kisti_preprocessed_v2.csv'
OUTPUT_PATH = r'C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\kisti_sampled_v2.csv'

CHUNK_SIZE = 500_000
rng = np.random.default_rng(42)

chunks = []
total_rows = 0

print("attackType 비율 유지하며 10% 샘플링 중...")

for chunk in pd.read_csv(INPUT_PATH, encoding='utf-8-sig', chunksize=CHUNK_SIZE,
                          low_memory=False, dtype={'uid': str}):
    total_rows += len(chunk)
    indices = []
    for val in chunk['attackType'].unique():
        group_idx = chunk.index[chunk['attackType'] == val].to_numpy()
        n = max(1, int(len(group_idx) * 0.1))
        chosen = rng.choice(group_idx, n, replace=False)
        indices.extend(chosen)
    chunks.append(chunk.loc[sorted(indices)])
    print(f"   처리 중... {total_rows:,}행", end='\r')

df = pd.concat(chunks, ignore_index=True)

print(f"\n\n원본 행 수  : {total_rows:,}")
print(f"샘플 행 수  : {len(df):,}")
print(f"\nattackType 분포:")
print(df['attackType'].value_counts().sort_index())

df.to_csv(OUTPUT_PATH, index=False, encoding='utf-8-sig')
print(f"\n저장 완료: {OUTPUT_PATH}")
