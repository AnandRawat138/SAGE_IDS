# Benchmark: cicids2017 (day split)

Generated from actual execution; separate model and feature schema from the laboratory model.

- Seeds: [0, 1, 2, 3, 4]; config: {'split': 'day', 'seeds': [0, 1, 2, 3, 4], 'max_rows_per_file': None, 'n_estimators': 100}; versions: {'sklearn': '1.9.1', 'numpy': '2.5.4', 'pandas': '3.1.0'}
- Input files: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (sha256 6ff1580f5f81…), Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv (sha256 ca1824c51bfb…), Friday-WorkingHours-Morning.pcap_ISCX.csv (sha256 53a41c24d570…), Monday-WorkingHours.pcap_ISCX.csv (sha256 852c4beb34ed…), Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv (sha256 6bcda3857c25…), Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv (sha256 d67066211fb1…), Tuesday-WorkingHours.pcap_ISCX.csv (sha256 52b8692ae8c7…), Wednesday-workingHours.pcap_ISCX.csv (sha256 893c27dc968b…)
- Cleaning (before split): {'dropped_invalid': 2867, 'dropped_exact_duplicates': 329896, 'dropped_conflicting_label_rows': 1436, 'rows_after': 2496544}
- Cross-split identical-row overlaps (must be 0): {0: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 1: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 2: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 3: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 4: {'train&val': 0, 'train&test': 0, 'val&test': 0}}

| detector | precision | recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|
| rf | 0.9980 [0.9978, 0.9981] | 0.3703 [0.3690, 0.3715] | 0.5401 [0.5388, 0.5414] | 0.0004 [0.0004, 0.0005] | 0.7912 [0.7820, 0.8070] |
| iforest | 0.5272 [0.4359, 0.6185] | 0.0659 [0.0428, 0.0890] | 0.1167 [0.0779, 0.1554] | 0.0301 [0.0296, 0.0307] | — |

Multi-class macro-F1 (mean, 95% bootstrap CI over seeds): (0.20081380219603004, 0.19975305086730466, 0.20291291665281844)
Inference: 0.95 ms per 1k flows

## Per-class (seed 0)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| BENIGN | 0.6656 | 0.9998 | 0.7992 | 394744 |
| Bot | 0.0000 | 0.0000 | 0.0000 | 1948 |
| DDoS | 0.0000 | 0.0000 | 0.0000 | 128011 |
| DoS GoldenEye | 0.0000 | 0.0000 | 0.0000 | 0 |
| DoS Hulk | 0.0000 | 0.0000 | 0.0000 | 0 |
| DoS Slowhttptest | 0.0000 | 0.0000 | 0.0000 | 0 |
| DoS slowloris | 0.0000 | 0.0000 | 0.0000 | 0 |
| FTP-Patator | 0.0000 | 0.0000 | 0.0000 | 0 |
| Heartbleed | 0.0000 | 0.0000 | 0.0000 | 0 |
| Infiltration | 0.0000 | 0.0000 | 0.0000 | 0 |
| PortScan | 0.0000 | 0.0000 | 0.0000 | 90130 |
| SSH-Patator | 0.0000 | 0.0000 | 0.0000 | 0 |
| Web Attack - Brute Force | 0.0000 | 0.0000 | 0.0000 | 0 |
| Web Attack - Sql Injection | 0.0000 | 0.0000 | 0.0000 | 0 |
| Web Attack - XSS | 0.0000 | 0.0000 | 0.0000 | 0 |

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