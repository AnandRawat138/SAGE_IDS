# Benchmark: cicids2017 (day split)

Generated from actual execution; separate model and feature schema from the laboratory model.

- Seeds: [0, 1, 2, 3, 4]; config: {'split': 'day', 'seeds': [0, 1, 2, 3, 4], 'max_rows_per_file': 150000, 'n_estimators': 100}; versions: {'sklearn': '1.9.1', 'numpy': '2.5.4', 'pandas': '3.1.0'}
- Input files: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (sha256 6ff1580f5f81…), Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv (sha256 ca1824c51bfb…), Friday-WorkingHours-Morning.pcap_ISCX.csv (sha256 53a41c24d570…), Monday-WorkingHours.pcap_ISCX.csv (sha256 852c4beb34ed…), Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv (sha256 6bcda3857c25…), Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv (sha256 d67066211fb1…), Tuesday-WorkingHours.pcap_ISCX.csv (sha256 52b8692ae8c7…), Wednesday-workingHours.pcap_ISCX.csv (sha256 893c27dc968b…)
- Cleaning (before split): {'dropped_invalid': 1027, 'dropped_exact_duplicates': 104113, 'dropped_conflicting_label_rows': 500, 'rows_after': 1094360}
- Cross-split identical-row overlaps (must be 0): {0: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 1: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 2: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 3: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 4: {'train&val': 0, 'train&test': 0, 'val&test': 0}}

| detector | precision | recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|
| rf | 0.9982 [0.9975, 0.9986] | 0.3741 [0.3733, 0.3749] | 0.5443 [0.5435, 0.5450] | 0.0004 [0.0003, 0.0005] | 0.7977 [0.7768, 0.8232] |
| iforest | 0.5697 [0.5257, 0.6137] | 0.0782 [0.0645, 0.0919] | 0.1373 [0.1149, 0.1597] | 0.0310 [0.0308, 0.0313] | — |

Multi-class macro-F1 (mean, 95% bootstrap CI over seeds): (0.20972456027101088, 0.20507414561837986, 0.21317856382989028)
Inference: 1.12 ms per 1k flows

## Per-class (seed 0)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| BENIGN | 0.7425 | 0.9998 | 0.8521 | 269016 |
| Bot | 0.0000 | 0.0000 | 0.0000 | 1519 |
| DDoS | 0.0000 | 0.0000 | 0.0000 | 85111 |
| DoS GoldenEye | 0.0000 | 0.0000 | 0.0000 | 0 |
| DoS Hulk | 0.0000 | 0.0000 | 0.0000 | 0 |
| DoS Slowhttptest | 0.0000 | 0.0000 | 0.0000 | 0 |
| DoS slowloris | 0.0000 | 0.0000 | 0.0000 | 0 |
| FTP-Patator | 0.0000 | 0.0000 | 0.0000 | 0 |
| Heartbleed | 0.0000 | 0.0000 | 0.0000 | 0 |
| Infiltration | 0.0000 | 0.0000 | 0.0000 | 0 |
| PortScan | 0.0000 | 0.0000 | 0.0000 | 58018 |
| SSH-Patator | 0.0000 | 0.0000 | 0.0000 | 0 |
| Web Attack - Brute Force | 0.0000 | 0.0000 | 0.0000 | 0 |
| Web Attack - Sql Injection | 0.0000 | 0.0000 | 0.0000 | 0 |
| Web Attack - XSS | 0.0000 | 0.0000 | 0.0000 | 0 |

## Data quality (before cleaning)

```json
{
 "rows": 1200000,
 "rows_with_inf": 1027,
 "rows_with_nan": 367,
 "inf_columns": {
  "Flow Bytes/s": 660,
  "Flow Packets/s": 1027
 },
 "nan_columns": {
  "Flow Bytes/s": 367
 },
 "exact_duplicate_rows": 104433,
 "feature_duplicates_with_conflicting_labels": 251,
 "negative_values_in_nonnegative_columns": {
  "Flow Duration": 53,
  "Flow Bytes/s": 44,
  "Flow Packets/s": 53
 },
 "class_counts": {
  "BENIGN": 968718,
  "DDoS": 85119,
  "PortScan": 83400,
  "DoS Hulk": 49871,
  "FTP-Patator": 2698,
  "DoS GoldenEye": 2209,
  "SSH-Patator": 2075,
  "Bot": 1534,
  "Web Attack - Brute Force": 1315,
  "DoS slowloris": 1242,
  "DoS Slowhttptest": 1203,
  "Web Attack - XSS": 576,
  "Infiltration": 20,
  "Web Attack - Sql Injection": 15,
  "Heartbleed": 5
 }
}
```