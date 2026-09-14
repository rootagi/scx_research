# Section 8: Limitations & Future Work

## 8.1 Multi-Tenant Fairness vs Flexibility Tradeoffs
Enforcing strict dispatch floors (`sysctl_sched_min_granularity`) on protected tasks introduces potential trade-offs for custom real-time or latency-sensitive schedulers (such as gaming schedulers requiring sub-millisecond task preemption). Future kernel designs could explore token-bucket or budget-based scheduling guarantees where security daemons receive minimum throughput over rolling 100ms windows rather than rigid per-dispatch quantum floors.

## 8.2 Dynamic Workload Adaptation
Our empirical benchmarks evaluated standard heavy contention workloads generated via `stress-ng` and high-rate filesystem probes. Exploring adaptive adversarial schedulers that dynamically adjust starvation parameters in response to real-time ringbuffer watermark metrics remains a fruitful direction for future offensive and defensive exploration.
