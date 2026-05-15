# -*- coding: utf-8 -*-
import pandas as pd
import os

# 1. 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
output_file = "CICIDS_Total_Raw_Combined.csv"

# 폴더 내 CSV 파일 목록 (합본 제외)
all_csv_files = [f for f in os.listdir(current_dir) if f.lower().endswith('.csv') and f != output_file]

print(f"--- 📂 8개 파일 무손실 통합 시작 (위치: {current_dir}) ---")

total_check = 0

for i, file_name in enumerate(all_csv_files):
    file_path = os.path.join(current_dir, file_name)
    
    # 2. 파일 읽기 (아무것도 건드리지 않고 그대로 읽음)
    # low_memory=False는 속도를 위해, dtype=object는 숫자/글자 섞여도 에러 안 나게 함
    df = pd.read_csv(file_path, low_memory=False)
    
    # 행 개수 누적 확인
    total_check += len(df)
    print(f"▶ [{i+1}/{len(all_csv_files)}] {file_name} 합치는 중... ({len(df):,} 행)")

    # 3. 저장 (첫 파일은 새로 만들기, 나머지는 이어 붙이기)
    if i == 0:
        df.to_csv(os.path.join(current_dir, output_file), index=False, encoding='utf-8-sig', mode='w')
    else:
        # header=False로 해야 중간에 제목줄이 또 안 들어갑니다.
        df.to_csv(os.path.join(current_dir, output_file), index=False, encoding='utf-8-sig', mode='a', header=False)

print("\n" + "="*50)
print(f"✅ 통합 완료! 파일명: {output_file}")
print(f"📊 예상 총합 행 수: {total_check:,} 줄")
print("="*50)

input("\n작업 완료! 엔터를 눌러 종료하세요...")