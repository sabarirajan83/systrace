# SysTrace: System Call Tracing and Performance Analyzer

A lightweight Linux syscall tracer, built on the `ptrace(2)` API, that
measures how much time a program spends inside the kernel — broken down
per syscall — and reports which subsystem (file I/O vs memory management)
is the dominant bottleneck.

---

## 1. Architecture & System Call Transition Overview

### User Space ↔ Kernel Space

Every process normally executes in **user mode**, a restricted CPU
privilege level that cannot access hardware, other processes' memory, or
privileged instructions. When a program needs a privileged operation
(reading a file, allocating memory, writing to a socket), it issues the
`syscall` instruction on x86_64. This causes a **trap**: the CPU switches
to **kernel mode**, the kernel's syscall handler runs on the process's
behalf, and control returns to user mode with a result placed in the
`rax` register.

```
 User Space                         Kernel Space
 -----------                        -------------
 program calls read()
        |
        v
   syscall instruction  ----trap---->  kernel syscall handler
                                            |
                                       does the actual work
                                       (disk I/O, memory mgmt, etc.)
                                            |
   <---------------------return-------------
   rax = result (or -errno on failure)
```

### How `ptrace` intercepts this transition

`ptrace(2)` lets one process (the **tracer**, e.g. SysTrace) observe and
control another (the **tracee**, e.g. the command being traced).

1. The child calls `ptrace(PTRACE_TRACEME, ...)` before `execvp()`,
   registering itself as traceable by its parent.
2. The parent repeatedly calls `ptrace(PTRACE_SYSCALL, child, ...)`,
   which resumes the child but tells the kernel: *"stop this process and
   signal me the next time it crosses a syscall boundary."*
3. Each single syscall produces **two** such stops:
   - **Entry stop** — the instant the child has issued the syscall, before
     the kernel processes it. At this point `orig_rax` holds the syscall
     number.
   - **Exit stop** — the instant the kernel is about to return control to
     the child. At this point `rax` holds the return value.
4. SysTrace timestamps both stops with `clock_gettime(CLOCK_MONOTONIC)`.
   The difference between entry and exit is the **actual kernel-mode
   latency** of that syscall — a real measurement, not an estimate.
5. A negative return value at the exit stop (POSIX convention: `-errno`)
   is counted as an error for that syscall.

### Why this design is "solid" and not trivial

- **State-machine toggling** (`in_syscall` flag) correctly pairs every
  entry stop with its matching exit stop, even though both produce the
  identical `SIGTRAP` signal — a common beginner bug is losing this
  pairing and reporting nonsensical (or halved) syscall counts.
- **Per-syscall bucketed statistics** (count, total time, error count) are
  built during trace, not fabricated from post-processing.
- **Bottleneck classification** groups related syscalls into subsystems
  (File I/O: `read/write/open/openat/close/stat/lseek`; Memory:
  `mmap/mprotect/munmap/brk`) and reports whichever subsystem consumes
  the largest share of total kernel time.

---

## 2. Compilation & Testing

### Build

```bash
make            # builds ./systrace and ./test_workload
```

### Run SysTrace on the bundled demo workload

```bash
./systrace ./test_workload          # summary table only
./systrace -v ./test_workload       # live per-syscall trace + summary
```

### Run SysTrace on any real command

```bash
./systrace ls -l
./systrace -v cat Makefile
./systrace /bin/echo "hello world"
```

### One-shot automated test

```bash
make test       # builds everything and runs both summary + verbose demos
```

### Sample output (summary mode, `./systrace ./test_workload`)

```
===================== SysTrace Report =====================
Syscall            Calls    Total(us)      Avg(us)   Errors
-------------------------------------------------------------
read                  52       127.30         2.45        0
write                 51       209.38         4.11        0
close                  3         7.86         2.62        0
fstat                  3         8.11         2.70        0
lseek                  1         2.49         2.49        0
mmap                   9        44.72         4.97        0
mprotect               3        21.75         7.25        0
munmap                 2        12.08         6.04        0
brk                    5        22.39         4.48        0
access                 1         3.47         3.47        1
openat                 3        32.83        10.94        0
...
-------------------------------------------------------------
Total syscalls traced : 142
Total kernel time     : 535.75 us (0.54 ms)
---------------------------------------------------------------
Dominant Bottleneck: File I/O (read/write/open/close) accounting for 72.4% of total kernel time
=================================================================
```

### Sample output (verbose mode excerpt, `./systrace -v ./test_workload`)

```
brk            = 94313480945664 [2.5 us]
mmap           = 140035998986240 [7.1 us]
access         = -2       [4.1 us]  <-- ERROR
openat         = 3        [3.8 us]
read           = 832      [2.9 us]
close          = 0        [2.4 us]
...
```

The `access = -2 <-- ERROR` line is expected — it's the dynamic linker
probing for `/etc/ld.so.preload`, which normally doesn't exist
(`ENOENT = 2`). This is a good live demonstration of the error-counting
feature.

### Clean up build artifacts

```bash
make clean
```

---

## 3. Presentation & Viva Guide

### 30-Second Elevator Pitch

"SysTrace is a Linux syscall tracer built on the `ptrace` API. It attaches
to a target process and pauses it at every syscall entry and exit,
measuring exactly how long the kernel spends servicing each call using
`CLOCK_MONOTONIC`. It aggregates this into a summary table showing call
counts, total and average latency, and error counts per syscall — and
automatically flags whether the program is bottlenecked on File I/O or
Memory management. It's essentially a simplified, educational version of
`strace -c`, built to show how user-space tools can observe kernel
behavior without any kernel modifications."

### 5 Likely Viva Questions & High-Scoring Answers

**Q1: What is `ptrace` and why not just modify the kernel to log syscalls?**
`ptrace` is a Linux system call that lets one process (tracer) control and
inspect another (tracee) — reading its registers, memory, and pausing its
execution at defined events. It's preferred here because it requires no
kernel modification or special privileges beyond normal process
ownership, making it portable and safe for a user-space tool.

**Q2: Why does each syscall produce two `ptrace` stops instead of one?**
Because we need to measure kernel-mode duration, we must observe the
process both when it *enters* the kernel and when it's about to *exit*
back to user mode. A single stop would only tell us that a syscall
happened, not how long the kernel spent processing it.

**Q3: How do you distinguish the entry stop from the exit stop, since both raise the same `SIGTRAP`?**
We maintain a boolean state flag (`in_syscall`) that toggles every time we
receive a stop. Since syscalls under `ptrace(PTRACE_SYSCALL,...)` always
alternate strictly entry-exit-entry-exit for a single-threaded tracee,
this toggle reliably pairs each entry with its corresponding exit.

**Q4: How do you detect errors, and what does a negative return value mean?**
At the exit stop, the syscall's return value is in the `rax` register. By
Linux/POSIX convention, syscalls return a negative value equal to
`-errno` on failure (e.g., `-2` is `-ENOENT`, "no such file or
directory"). We simply check `if (rax < 0)` and increment an error
counter for that syscall.

**Q5: What are the limitations of this tool compared to real `strace`?**
It doesn't decode syscall arguments into human-readable form (e.g.,
file paths, flag names) — it only reports the syscall name, return
value, and timing. It's also single-threaded-only (doesn't follow forked
children with `PTRACE_O_TRACEFORK`) and adds tracing overhead itself
(each stop is a context switch), so its absolute timing numbers are
higher than untraced execution — useful for relative/comparative
analysis, not absolute performance benchmarking.

---

## 4. File Manifest

| File               | Purpose                                                   |
|--------------------|------------------------------------------------------------|
| `systrace.c`       | Main tracer: ptrace loop, timing, summary, bottleneck logic |
| `test_workload.c`  | Dummy benchmark exercising file I/O and memory allocation   |
| `Makefile`         | Build (`make`), test (`make test`), clean (`make clean`)    |
| `README.md`        | This file                                                   |
#   s y s t r a c e  
 