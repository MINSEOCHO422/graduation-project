import pandas as pd
import numpy as np
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
input_file = os.path.join(current_dir, "CICIDS_Total_Raw_Combined.csv")
output_file = os.path.join(current_dir, "CICIDS_Total_Cleaned_All_Columns.csv")

if os.path.exists(output_file):
    os.remove(output_file)

chunk_size = 50000 
total_raw = 0
total_cleaned = 0

try:
    reader = pd.read_csv(input_file, low_memory=False, chunksize=chunk_size)

    for i, chunk in enumerate(reader):
        total_raw += len(chunk)
        
        cleaned_chunk = chunk.replace([np.inf, -np.inf], np.nan).dropna()
        
        total_cleaned += len(cleaned_chunk)
        
        if i == 0:
            cleaned_chunk.to_csv(output_file, index=False, encoding='utf-8-sig', mode='w')
        else:
            cleaned_chunk.to_csv(output_file, index=False, encoding='utf-8-sig', mode='a', header=False)
            
        print(f"Progress: [{i+1}] Processing... (Current Valid: {total_cleaned:,})")

    print("\nFinish!")
    print(f"Raw Total Rows: {total_raw:,}")
    print(f"Cleaned Total Rows: {total_cleaned:,}")
    print(f"File Path: {output_file}")

except Exception as e:
    print(f"Error: {e}")

input("\nPress Enter to exit...")
