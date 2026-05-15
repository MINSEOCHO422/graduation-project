import pandas as pd
from datetime import datetime

INPUT_PATH  = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\원본데이터셋\training_set.csv"
OUTPUT_PATH = r"C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\네트워크침입탐지데이터셋\원본데이터셋\training_set_preprocessed.csv"

USECOLS = ["uid", "sourceIP", "destinationIP", "sourcePort", "destinationPort",
           "protocol", "attackType", "eventCount", "analyResult",
           "detectStart", "detectEnd", "packetSize"]

OUT_COLS = ["uid", "sourceIP", "destinationIP", "sourcePort", "destinationPort",
            "protocol", "attackType", "eventCount", "analyResult",
            "duration", "packetSize"]

CHUNK_SIZE = 100_000

def calc_duration(start_series, end_series):
    """yyyymmddHHMMSS 정수 → duration(초)"""
    fmt = "%Y%m%d%H%M%S"
    durations = []
    for s, e in zip(start_series, end_series):
        try:
            dt_s = datetime.strptime(str(int(s)), fmt)
            dt_e = datetime.strptime(str(int(e)), fmt)
            durations.append(int((dt_e - dt_s).total_seconds()))
        except Exception:
            durations.append(None)
    return durations

print("전처리 시작 (4.8GB 청크 처리)...")
total_rows = 0
chunk_no   = 0
first_chunk = True

for chunk in pd.read_csv(
    INPUT_PATH,
    sep="\t",
    usecols=USECOLS,
    low_memory=False,
    chunksize=CHUNK_SIZE,
):
    chunk_no += 1

    # duration 계산
    chunk["duration"] = calc_duration(chunk["detectStart"], chunk["detectEnd"])

    # inf/NaN 제거
    chunk = chunk.dropna(subset=["sourcePort", "destinationPort", "protocol",
                                  "eventCount", "packetSize"])

    out = chunk[OUT_COLS]
    out.to_csv(OUTPUT_PATH,
               mode="w" if first_chunk else "a",
               index=False,
               header=first_chunk,
               encoding="utf-8-sig")

    first_chunk = False
    total_rows += len(out)

    if chunk_no % 50 == 0:
        print(f"  청크 {chunk_no}... 누적 행: {total_rows:,}")

print(f"\n완료 - 총 {total_rows:,}행 저장")
print(f"저장: {OUTPUT_PATH}")
