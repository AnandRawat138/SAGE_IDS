# Benchmark: cicids2017 (stratified split)

Generated from actual execution; separate model and feature schema from the laboratory model.

- Seeds: [0, 1, 2, 3, 4]; config: {'split': 'stratified', 'seeds': [0, 1, 2, 3, 4], 'max_rows_per_file': 150000, 'n_estimators': 100}; versions: {'sklearn': '1.9.1', 'numpy': '2.5.4', 'pandas': '3.1.0'}
- Input files: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (sha256 6ff1580f5f81…), Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv (sha256 ca1824c51bfb…), Friday-WorkingHours-Morning.pcap_ISCX.csv (sha256 53a41c24d570…), Monday-WorkingHours.pcap_ISCX.csv (sha256 852c4beb34ed…), Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv (sha256 6bcda3857c25…), Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv (sha256 d67066211fb1…), Tuesday-WorkingHours.pcap_ISCX.csv (sha256 52b8692ae8c7…), Wednesday-workingHours.pcap_ISCX.csv (sha256 893c27dc968b…)
- Cleaning (before split): {'dropped_invalid': 1027, 'dropped_exact_duplicates': 104113, 'dropped_conflicting_label_rows': 500, 'rows_after': 1094360}
- Cross-split identical-row overlaps (must be 0): {0: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 1: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 2: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 3: {'train&val': 0, 'train&test': 0, 'val&test': 0}, 4: {'train&val': 0, 'train&test': 0, 'val&test': 0}}

| detector | precision | recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|
| rf | 0.9958 [0.9954, 0.9961] | 0.9977 [0.9974, 0.9979] | 0.9967 [0.9965, 0.9969] | 0.0009 [0.0008, 0.0010] | 0.9998 [0.9998, 0.9998] |
| iforest | 0.5784 [0.4763, 0.6663] | 0.0726 [0.0449, 0.1044] | 0.1280 [0.0819, 0.1792] | 0.0100 [0.0097, 0.0102] | — |

Multi-class macro-F1 (mean, 95% bootstrap CI over seeds): (0.8455911259871545, 0.8129745651229664, 0.8651783632696282)
Inference: 1.31 ms per 1k flows

## Per-class (seed 0)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| BENIGN | 0.9988 | 0.9994 | 0.9991 | 180438 |
| Bot | 0.8759 | 0.7664 | 0.8175 | 304 |
| DDoS | 0.9998 | 0.9995 | 0.9996 | 17022 |
| DoS GoldenEye | 0.9954 | 0.9887 | 0.9921 | 442 |
| DoS Hulk | 0.9977 | 0.9936 | 0.9957 | 7546 |
| DoS Slowhttptest | 0.9957 | 0.9871 | 0.9913 | 232 |
| DoS slowloris | 1.0000 | 0.9917 | 0.9958 | 240 |
| FTP-Patator | 1.0000 | 0.9953 | 0.9976 | 423 |
| Heartbleed | 1.0000 | 1.0000 | 1.0000 | 1 |
| Infiltration | 1.0000 | 1.0000 | 1.0000 | 4 |
| PortScan | 0.9947 | 0.9941 | 0.9944 | 11604 |
| SSH-Patator | 1.0000 | 0.9917 | 0.9958 | 241 |
| Web Attack - Brute Force | 0.7224 | 0.7393 | 0.7308 | 257 |
| Web Attack - Sql Injection | 0.0000 | 0.0000 | 0.0000 | 3 |
| Web Attack - XSS | 0.3878 | 0.3304 | 0.3568 | 115 |

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