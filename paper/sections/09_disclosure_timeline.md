# Section 9: Responsible Disclosure Timeline

In accordance with academic security research best practices and responsible vulnerability disclosure standards:

- **2026-06-15**: Initial identification of `sched_ext` micro-quantum starvation and ringbuffer drop behavior during kernel 6.12/6.13 evaluation.
- **2026-07-20**: Development and validation of empirical benchmark harness and statistical verification across 5 intensity levels.
- **2026-08-10**: Implementation and validation of defensive LSM engine (`scx_guard_lsm`) and userspace allowlist monitor (`scx_monitor`).
- **2026-08-27**: Drafted upstream LKML kernel patch (`patches/0001-...`) proposing minimum quantum floors for protected task classes, alongside the tracepoints RFC patch (`patches/0002-...`).
- **Upcoming (Prior to Publication)**: Submission of RFC patchset to LKML (`linux-kernel@vger.kernel.org`, `bpf@vger.kernel.org`) and integration of maintainer feedback into final artifact repository.
