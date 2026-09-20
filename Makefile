# ==========================================================================
# Makefile for SysTrace: System Call Tracing and Performance Analyzer
# ==========================================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -O2
TARGETS = systrace test_workload

.PHONY: all clean test

# Default target: build both the tracer and the demo workload
all: $(TARGETS)

systrace: systrace.c
	$(CC) $(CFLAGS) -o systrace systrace.c

test_workload: test_workload.c
	$(CC) $(CFLAGS) -o test_workload test_workload.c

# Runs SysTrace against the bundled demo workload so students get an
# immediate, realistic output without needing to trace a real command.
test: all
	@echo "=============================================================="
	@echo " Running SysTrace against test_workload (summary mode)"
	@echo "=============================================================="
	./systrace ./test_workload
	@echo ""
	@echo "=============================================================="
	@echo " Running SysTrace against test_workload (verbose mode, -v)"
	@echo "=============================================================="
	./systrace -v ./test_workload | head -n 30

clean:
	rm -f $(TARGETS) *.o /tmp/systrace_workload.tmp
