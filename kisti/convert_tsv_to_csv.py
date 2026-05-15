import pandas as pd
import os

INPUT_PATH  = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\training_set.csv"
OUTPUT_PATH = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\training_set_converted.csv"

print(f"변환 시작: {INPUT_PATH}")

total_rows = 0
first_chunk = True

for chunk in pd.read_csv(INPUT_PATH, sep='\t', chunksize=100_000, dtype=str, on_bad_lines='warn'):
    chunk.to_csv(OUTPUT_PATH, mode='w' if first_chunk else 'a', header=first_chunk, index=False, encoding='utf-8-sig')
    total_rows += len(chunk)
    first_chunk = False
    if total_rows % 1_000_000 == 0:
        print(f"  {total_rows:,} 행 처리 완료")

print(f"\n완료! 총 {total_rows:,} 행")
print(f"출력 파일 크기: {os.path.getsize(OUTPUT_PATH) / 1024 / 1024:.1f} MB")

df = pd.read_csv(OUTPUT_PATH, nrows=3, encoding='utf-8-sig')
print("\n=== 미리보기 ===")
print(df.to_string())
