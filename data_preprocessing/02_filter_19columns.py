import pandas as pd
import numpy as np
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
input_file = os.path.join(current_dir, "..", "무수정 코드통합", "CICIDS_Total_Raw_Combined.csv")
output_file = os.path.join(current_dir, "CICIDS_Final_Cleaned_19.csv")

target_columns = [
    ' Destination Port', ' Flow Duration', ' Total Fwd Packets', 
    ' Total Backward Packets', 'Total Length of Fwd Packets', 
    ' Total Length of Bwd Packets', ' Fwd Packet Length Std', 
    ' Bwd Packet Length Mean', 'Flow Bytes/s', ' Fwd Packet Length Mean', 
    ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', 
    ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count', 
    ' ACK Flag Count', ' Average Packet Size', ' Label'
]

if os.path.exists(output_file):
    os.remove(output_file)

chunk_size = 100000
total_raw = 0
total_cleaned = 0

try:
    reader = pd.read_csv(input_file, usecols=target_columns, low_memory=False, chunksize=chunk_size)

    for i, chunk in enumerate(reader):
        total_raw += len(chunk)
        chunk.columns = chunk.columns.str.strip()
        cleaned_chunk = chunk.replace([np.inf, -np.inf], np.nan).dropna()
        total_cleaned += len(cleaned_chunk)
        
        if i == 0:
            cleaned_chunk.to_csv(output_file, index=False, encoding='utf-8-sig', mode='w')
        else:
            cleaned_chunk.to_csv(output_file, index=False, encoding='utf-8-sig', mode='a', header=False)
            
        print(f"Progress: [{i+1}] Processing... (Total Valid: {total_cleaned:,})")

    print("\nFinish!")
    print(f"Raw Rows: {total_raw:,}")
    print(f"Cleaned Rows: {total_cleaned:,}")
    print(f"File Path: {output_file}")

except Exception as e:
    print(f"Error: {e}")

input("\nPress Enter to exit...")
