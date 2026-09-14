# Sched_Ext EDR Starvation Empirical Evaluation Matrix

*Configuration: $N=30$ trials/level, $8\text{s}$ duration, Kernel 7.2.4-arch1-2*

| Starvation Level | Events Emitted (Mean ± SD) | Events Consumed (Mean ± SD) | Drop Rate % (Mean ± SD) | p99 Latency µs (Mean ± SD) | Max Latency µs (Mean ± SD) | MW-U Test ($p$-value vs L0) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Level 0** | 3874 ± 249 | 3874 ± 249 | **0.00% ± 0.00%** | 10354.45 ± 1135.43 µs | 21021.74 ± 5723.16 µs | Baseline |
| **Level 1** | 7272 ± 799 | 1382 ± 388 | **80.83% ± 5.48%** | 6451073.30 ± 1139049.99 µs | 6460729.76 ± 1135252.19 µs | **$p < 10^{-4}$** |
| **Level 2** | 7237 ± 779 | 1331 ± 502 | **81.06% ± 8.81%** | 6656642.41 ± 1101348.88 µs | 6666773.13 ± 1092304.47 µs | **$p < 10^{-4}$** |
| **Level 3** | 7703 ± 552 | 1271 ± 324 | **83.41% ± 4.55%** | 6838808.27 ± 745672.46 µs | 6844906.32 ± 744954.08 µs | **$p < 10^{-4}$** |
| **Level 4** | 7438 ± 805 | 1556 ± 774 | **78.16% ± 11.96%** | 5981501.79 ± 1140660.47 µs | 5983518.60 ± 1139581.77 µs | **$p < 10^{-4}$** |
