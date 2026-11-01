# Benchmark: cicids2017 (stratified split)

Generated from actual execution; separate model and feature schema from the laboratory model.

- Seeds: [0, 1, 2, 3, 4]; config: {'split': 'stratified', 'seeds': [0, 1, 2, 3, 4], 'max_rows_per_file': None, 'n_estimators': 100}; versions: {'sklearn': '1.9.1', 'numpy': '2.5.4', 'pandas': '3.1.0'}
- Input files: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (sha256 6ff1580f5f81…), Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv (sha256 ca1824c51bfb…), Friday-WorkingHours-Morning.pcap_ISCX.csv (sha256 53a41c24d570…), Monday-WorkingHours.pcap_ISCX.csv (sha256 852c4beb34ed…), Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv (sha256 6bcda3857c25…), Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv (sha256 d67066211fb1…), Tuesday-WorkingHours.pcap_ISCX.csv (sha256 52b8692ae8c7…), Wednesday-workingHours.pcap_ISCX.csv (sha256 893c27dc968b…)
- Cleaning (before split): {'dropped_invalid': 2867, 'dropped_exact_duplicates': 329896, 'dropped_conflicting_label_rows': 1436, 'rows_after': 2496544}
- Cross-split identical-row overlaps (must be 0): {0: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 1: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 2: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 3: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 4: {'train&val': 0, 'train&test': 0, 'val&test': 0}}

| detector | precision | recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|
| rf | 0.9969 [0.9967, 0.9970] | 0.9986 [0.9984, 0.9988] | 0.9977 [0.9976, 0.9979] | 0.0006 [0.0006, 0.0007] | 0.9999 [0.9999, 0.9999] |
| iforest | 0.7208 [0.6382, 0.7865] | 0.1390 [0.0943, 0.1838] | 0.2306 [0.1642, 0.2970] | 0.0098 [0.0095, 0.0101] | — |

Multi-class macro-F1 (mean, 95% bootstrap CI over seeds): (0.8626109914556143, 0.8381187190638446, 0.8888861919058254)
Inference: 1.32 ms per 1k flows

## Per-class (seed 0)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| BENIGN | 0.9992 | 0.9996 | 0.9994 | 414307 |
| Bot | 0.8746 | 0.7333 | 0.7978 | 390 |
| DDoS | 1.0000 | 0.9995 | 0.9997 | 25602 |
| DoS GoldenEye | 0.9971 | 0.9951 | 0.9961 | 2057 |
| DoS Hulk | 0.9988 | 0.9971 | 0.9979 | 34540 |
| DoS Slowhttptest | 0.9895 | 0.9924 | 0.9909 | 1046 |
| DoS slowloris | 0.9953 | 0.9926 | 0.9939 | 1074 |
| FTP-Patator | 0.9992 | 1.0000 | 0.9996 | 1186 |
| Heartbleed | 1.0000 | 1.0000 | 1.0000 | 2 |
| Infiltration | 1.0000 | 0.5714 | 0.7273 | 7 |
| PortScan | 0.9950 | 0.9944 | 0.9947 | 18026 |
| SSH-Patator | 1.0000 | 0.9984 | 0.9992 | 644 |
| Web Attack - Brute Force | 0.7307 | 0.8027 | 0.7650 | 294 |
| Web Attack - Sql Injection | 1.0000 | 0.5000 | 0.6667 | 4 |
| Web Attack - XSS | 0.4343 | 0.3308 | 0.3755 | 130 |

## Data quality (before cleaning)

```json
{
 "rows": 2830743,
 "rows_with_inf": 2867,
 "rows_with_nan": 1358,
 "inf_columns": {
  "Flow Bytes/s": 1509,
  "Flow Packets/s": 2867
 },
 "nan_columns": {
  "Flow Bytes/s": 1358
 },
 "exact_duplicate_rows": 331200,
 "feature_duplicates_with_conflicting_labels": 719,
 "negative_values_in_nonnegative_columns": {
  "Flow Duration": 115,
  "Flow Bytes/s": 85,
  "Flow Packets/s": 115
 },
 "class_counts": {
  "BENIGN": 2273097,
  "DoS Hulk": 231073,
  "PortScan": 158930,
  "DDoS": 128027,
  "DoS GoldenEye": 10293,
  "FTP-Patator": 7938,
  "SSH-Patator": 5897,
  "DoS slowloris": 5796,
  "DoS Slowhttptest": 5499,
  "Bot": 1966,
  "Web Attack - Brute Force": 1507,
  "Web Attack - XSS": 652,
  "Infiltration": 36,
  "Web Attack - Sql Injection": 21,
  "Heartbleed": 11
 }
}
```