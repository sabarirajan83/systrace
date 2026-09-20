# SysTrace: System Call Tracing & Performance Analyzer

**SysTrace** is a lightweight system call tracer and performance profiling tool built in C. It intercepts, records, and summarizes system calls executed by a target program, providing execution metrics in both summary and real-time verbose modes.

---

## Features

- **Summary Mode:** Aggregates system call counts, time spent, and error frequencies for quick post-run inspection.
- **Verbose Mode (`-v`):** Streams system call invocations, arguments, and return values as they happen.
- **Bundled Test Workload:** Comes with a pre-configured `test_workload` binary generating realistic file I/O, memory allocations, and process activity.
- **Minimal Dependencies:** Built strictly using the standard C library and standard Linux tracing facilities (`ptrace`/APIs) with `gcc`.

---

## Prerequisites

- **OS:** Linux (x86_64 recommended)
- **Compiler:** `gcc` with standard development headers
- **Build Tool:** GNU `make`

---

## Building the Project

Compile both the `systrace` binary and the `test_workload` runner using the default target:

```bash
make
```

To remove all compiled binaries and temporary artifacts:

```bash
make clean
```

---

## Quick Start & Testing

To verify your build and see SysTrace in action, run the automated test suite:

```bash
make test
```

This executes `systrace` against `test_workload` twice:
1. In standard **summary mode**.
2. In **verbose mode (`-v`)**, displaying the first 30 system call traces.

---

## Usage

Trace any arbitrary command or binary:

```bash
./systrace [flags] <command> [args...]
```

### Examples

**Run with default summary output:**
```bash
./systrace ls -la
```

**Trace in verbose mode:**
```bash
./systrace -v ./test_workload
```

**Trace a shell command chain:**
```bash
./systrace /bin/echo "Hello SysTrace"
```

---

## Project Structure

```text
.
├── Makefile          # Build configuration and automated test recipes
├── systrace.c        # Main tracer logic and syscall interception engine
├── test_workload.c   # Synthetic workload for demoing and testing
└── README.md         # Project documentation
```

---

## License

This project is open-source and available under the [MIT License](LICENSE).