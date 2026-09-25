# SysTrace: System Call Tracing & Performance Analyzer

**SysTrace** is a lightweight system call tracer and performance profiling tool built in C. It intercepts, records, and summarizes system calls executed by a target program, providing execution metrics in both summary and real-time verbose modes.

---

## Features

- **Summary Mode:** Aggregates system call counts, time spent, and error frequencies for quick post-run inspection.
- **Verbose Mode (`-v`):** Streams system call invocations, arguments, and return values live.
- **Attach to Running PID (`-p <pid>`):** Supports dynamic attaching and detaching from active Linux processes.
- **Child Process Tracking (`-f`):** Follows `fork`, `vfork`, and `clone` calls across child threads and processes.
- **Syscall Filtering (`-e`):** Isolates specific syscall groups (e.g., `-e trace=openat,read,write`).
- **Minimal Dependencies:** Built strictly using the standard C library and standard Linux tracing facilities (`ptrace`/`process_vm_readv`) with `gcc`.

---

## Prerequisites

- **OS:** Linux (x86_64 recommended)
- **Compiler:** `gcc` with standard development headers
- **Build Tool:** GNU `make`

---

## Building the Project

Compile binaries (`systrace`, `test_workload`, and `child_demo`):

```bash
make
