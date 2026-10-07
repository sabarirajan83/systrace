# SysTrace: System Call Tracing & Performance Analyzer

A lightweight, user-space system call tracing and performance analysis tool built in C for Linux (x86_64).

---

## Project Overview

**SysTrace** intercepts and inspects system calls executed by a target program or running process. It captures entry parameters, return values, and execution duration, providing both live event streaming and post-run performance profiling.

### Main Purpose of the Project

In an Operating System, the boundary between user space and kernel space is bridged through **system calls**. Understanding how often and why applications cross this boundary is essential for diagnosing performance issues, debugging unexpected errors, and understanding OS resource utilization. SysTrace serves as an educational and practical tool to:

- Monitor process-kernel interactions in real time.
- Measure kernel-mode execution latency at microsecond resolution.
- Classify system call workloads across major OS subsystems (File I/O, Memory, Process Management, Networking, IPC, Signals, and Timers).
- Detect and pinpoint performance bottlenecks caused by heavy kernel activity.

---

## Features

- **Live Tracing Mode (`-v`):** Streams intercepted system calls in real time along with decoded arguments, return codes, and per-call execution latency.
- **Process & Thread Following (`-f`):** Automatically detects and tracks child processes and threads created via `fork`, `vfork`, and `clone`.
- **Attach to Running Process (`-p <pid>`):** Non-destructively attaches to an active process using `PTRACE_SEIZE` and traces its execution.
- **Syscall Filtering (`-e trace=...`):** Filters output to focus specifically on selected system calls (e.g., `-e trace=openat,read,write`).
- **Summary Report (`-c`):** Generates a comprehensive summary table with invocation counts, total time, average latency, min/max latency, and error counts.
- **Microsecond Timestamps (`-tt`):** Prepends wall-clock timestamps (`HH:MM:SS.uuuuuu`) to each trace event.
- **Argument Inspection:** Safely extracts path strings and buffer contents across process address spaces using `process_vm_readv` and `/proc/<pid>/mem`.
- **Subsystem Bottleneck Analysis:** Groups system calls by functional category and automatically identifies the dominant kernel bottleneck.
- **File Redirection (`-o <file>`):** Saves tracing logs and summary reports directly to an output file.

---

## Technologies & Tools Used

- **Programming Language:** C (C99 with GNU extensions)
- **Tracing Mechanism:** Linux `ptrace` system call (`PTRACE_TRACEME`, `PTRACE_SEIZE`, `PTRACE_SYSCALL`, `PTRACE_SETOPTIONS`)
- **Process Memory Inspection:** `process_vm_readv` system call and Linux procfs (`/proc/<pid>/mem`)
- **Timing & Clocks:** POSIX high-resolution monotonic clocks (`clock_gettime`, `CLOCK_MONOTONIC`)
- **Target Platform:** Linux on x86_64 architecture
- **Build System:** GNU `make` and `gcc`

---

## How to Compile and Run

### 1. Compilation

Build the tracer along with the demonstration workloads using `make`:

```bash
make
```

To clean all compiled binaries:

```bash
make clean
```

### 2. Running SysTrace

```bash
# Basic syntax:
./systrace [options] <command> [arguments...]

# Attach to an existing process:
./systrace [options] -p <pid>
```

### Command-Line Options

| Option         | Description                                                                                   |
| :------------- | :-------------------------------------------------------------------------------------------- |
| `-v`           | Verbose mode: prints system calls, decoded arguments, return values, and latency in real time |
| `-f`           | Follow forks: traces child processes and threads spawned by the target                        |
| `-c`           | Counts only: suppresses live event output and shows only the final summary report             |
| `-tt`          | Prints microsecond-precision timestamps (`HH:MM:SS.uuuuuu`) with each event                   |
| `-p <pid>`     | Attaches to an active process by PID                                                          |
| `-o <file>`    | Writes output and report to a specified file instead of standard output                       |
| `-s <N>`       | Maximum string/buffer length to capture and print (default: 32 bytes)                         |
| `-e trace=a,b` | Comma-separated filter list of system calls to trace                                          |

---

## Example Usage and Output

### Example 1: Tracing the Benchmark Workload (Verbose Mode)

```bash
./systrace -v ./test_workload
```

**Live Trace Output:**

```text
test_workload: starting file I/O phase...
[pid 4120] openat(1, "/tmp/systrace_workload.tmp", len=0) = 3  [8.4 us]
[pid 4120] write(fd=3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...", len=256) = 256  [2.1 us]
[pid 4120] write(fd=3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...", len=256) = 256  [1.9 us]
...
[pid 4120] lseek(3, 0, 0) = 0  [1.5 us]
[pid 4120] read(fd=3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...", len=256) = 256  [2.8 us]
[pid 4120] close(3, 0, 0) = 0  [1.8 us]
[pid 4120] unlink("/tmp/systrace_workload.tmp") = 0  [5.2 us]
test_workload: starting memory allocation phase...
[pid 4120] brk(0, 0, 0) = 0x55d1a8c000  [3.2 us]
[pid 4120] mmap(0, 4198400, 3) = 0x7f8d1c000000  [7.1 us]
[pid 4120] munmap(0x7f8d1c000000, 4198400, 0) = 0  [4.1 us]
test_workload: done.
```

**Post-Run Performance Summary Report:**

```text
===================== SysTrace Report =====================
Syscall             Calls    Total(us)    Avg(us)    Min(us)    Max(us)   Errors
-----------------------------------------------------------------------------
read                    5        18.20       3.64       2.10       5.30        0
write                  50       120.50       2.41       1.20       6.80        0
close                   1         1.80       1.80       1.80       1.80        0
lseek                   1         1.50       1.50       1.50       1.50        0
mmap                    2        14.30       7.15       6.80       7.50        0
munmap                  1         4.10       4.10       4.10       4.10        0
brk                     3         9.60       3.20       2.80       3.60        0
openat                  1         8.40       8.40       8.40       8.40        0
unlink                  1         5.20       5.20       5.20       5.20        0
-----------------------------------------------------------------------------
Total syscalls traced     : 65
Total kernel time         : 183.60 us (0.18 ms)
Total signals delivered   : 0
Wall-clock run time       : 1450.00 us (1.45 ms)
Time spent in kernel      : 12.66% of wall-clock run time
-----------------------------------------------------------------------------
By category:
  File I/O               155.60 us  ( 84.7%)
  Memory                  28.00 us  ( 15.3%)
-----------------------------------------------------------------------------
Dominant Bottleneck: File I/O, accounting for 84.7% of total kernel time
Traced command exited with status 0
=============================================================================
```

### Example 2: Tracing Multi-Process Execution

```bash
./systrace -v -f ./child_demo
```

### Example 3: Filtering Specific System Calls

```bash
./systrace -v -e trace=openat,write cat /etc/hosts
```
