# Network Intrusion Detection System — Graduation Project

Hongik University, 2026  
Real-time network intrusion detection using Random Forest trained on CICIDS2017 and KISTI datasets, integrated with Suricata IDS.

---

## Project Overview

This system detects network intrusions by:
1. Training a Random Forest classifier on labeled network flow data (CICIDS2017 / KISTI)
2. Converting live Suricata `eve.json` logs into CICIDS-compatible features
3. Running inference and comparing RF predictions against Suricata alerts

---

## Repository Structure

```
graduation-project/
├── data_preprocessing/     # CICIDS2017 dataset preprocessing pipeline
├── ml_model/               # Random Forest training & prediction
├── suricata/               # Suricata log parsing & RF comparison (CICIDS-based)
├── kisti/                  # KISTI dataset training & Suricata mapping
├── docker/                 # Docker deployment for inference service
└── requirements.txt
```

---

## Pipeline

### 1. CICIDS2017 Preprocessing (`data_preprocessing/`)

| Script | Input | Output |
|--------|-------|--------|
| `01_merge_raw.py` | 8 daily PCAP-derived CSVs | `CICIDS_Total_Raw_Combined.csv` (~2.8M rows) |
| `02_filter_19columns.py` | Combined CSV | `CICIDS_Final_Cleaned_19.csv` (19 features) |
| `03_clean_all_columns.py` | Combined CSV | `CICIDS_Total_Cleaned_All_Columns.csv` |

**19 selected features:** Destination Port, Flow Duration, Total Fwd/Bwd Packets, Total Length of Fwd/Bwd Packets, Fwd/Bwd Packet Length Stats, Flow Bytes/s, Flow Packets/s, Flow IAT Mean/Std, SYN/RST/PSH/ACK Flag Count, Average Packet Size, Label

### 2. ML Model (`ml_model/`)

| Script | Description |
|--------|-------------|
| `train_random_forest.py` | Train RF classifier on CICIDS2017 19-column dataset |
| `predict_eve.py` | Run inference on converted Suricata eve.json (local) |
| `predict_eve_docker.py` | Same, for Docker environment |
| `eve_to_predict.py` | Preprocess eve.json → model-compatible format |
| `ml_pkl_view.py` | Inspect saved model / label encoder |

### 3. Suricata Integration (`suricata/`)

| Script | Description |
|--------|-------------|
| `parse_alerts.py` | Parse Suricata alert logs |
| `eve_to_cicids.py` | Convert Suricata eve.json fields → CICIDS feature format |
| `eve_preprocess_and_compare.py` | Preprocess eve.json and compare with RF predictions |
| `compare_suricata_rf.py` | Compare Suricata alert labels vs RF prediction labels |
| `suricata_rf_compare.py` | Full pipeline: eve → CICIDS → RF → comparison report |

### 4. KISTI Dataset (`kisti/`)

| Script | Description |
|--------|-------------|
| `preprocess_training_set.py` | Clean raw KISTI training set |
| `kisti_sample.py` | Sample 10% of KISTI dataset for faster training |
| `train_kisti_rf.py` | Train RF on KISTI dataset (v1) |
| `train_kisti_rf_v2.py` | Train RF on KISTI dataset (v2, improved) |
| `suricata_extract_rf.py` | Extract RF-compatible features from Suricata logs (KISTI) |
| `eve_to_kisti_mapped.py` | Map Suricata eve.json fields → KISTI feature columns |
| `analyze_suricata_eve.py` | Analyze Suricata eve.json structure |
| `convert_tsv_to_csv.py` | Convert KISTI TSV files to CSV |

### 5. Docker (`docker/`)

Containerized inference service — runs `predict_eve_docker.py` against a mounted `eve.json`.

```bash
docker build -f docker/Dockerfile -t ids-inference .
docker run -v /path/to/eve.json:/data/eve.json ids-inference
```

---

## Dataset Sources

- **CICIDS2017**: [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html) — not included (too large; store locally or on Google Drive)
- **KISTI**: Korea Institute of Science and Technology Information network traffic dataset — not included

---

## Setup

```bash
pip install -r requirements.txt
```

Run scripts in order: `data_preprocessing` → `ml_model/train_random_forest.py` → `suricata/` or `kisti/`
