/*
 * ==========================================================================
 *  SysTrace: System Call Tracing and Performance Analyzer
 * ==========================================================================
 *  Usage:
 *      ./systrace [-v] <command> [args...]
 *
 *      -v    verbose / live mode: prints each syscall as it completes,
 *            e.g.  read(3, ...) = 1024  [45 us]
 *
 *  Architecture summary:
 *      1. Child calls PTRACE_TRACEME, then execvp()'s the target command.
 *      2. Parent uses PTRACE_SYSCALL + waitpid() to stop the child at every
 *         syscall-enter and syscall-exit boundary (2 stops per syscall).
 *      3. Time between the enter-stop and exit-stop = time the kernel spent
 *         servicing that syscall (measured with CLOCK_MONOTONIC).
 *      4. Return value (rax at exit-stop) is inspected: negative => error.
 *      5. On child exit, a summary table + bottleneck takeaway is printed.
 *
 *  Build target: x86_64 Linux (uses x86_64 syscall ABI: orig_rax / rax)
 * ==========================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#define MAX_SYSCALLS 512   /* x86_64 syscall numbers currently go up to ~450 */

/* ------------------------------------------------------------------------
 * Per-syscall statistics bucket
 * ------------------------------------------------------------------------ */
typedef struct {
    long   count;        /* number of invocations                     */
    long   error_count;  /* number of invocations that returned < 0   */
    double total_us;      /* cumulative time spent inside kernel (us)  */
} SyscallStat;

static SyscallStat stats[MAX_SYSCALLS];
static bool verbose = false;

/* ------------------------------------------------------------------------
 * Syscall number -> human readable name (x86_64 ABI).
 * Covers ~30 of the most frequently observed syscalls in typical
 * CLI / file-processing / memory-allocating workloads.
 * Reference: /usr/include/asm-generic/unistd.h or
 *            /usr/include/x86_64-linux-gnu/asm/unistd_64.h
 * ------------------------------------------------------------------------ */
static const char *syscall_name(long num) {
    switch (num) {
        case 0:   return "read";
        case 1:   return "write";
        case 2:   return "open";
        case 3:   return "close";
        case 4:   return "stat";
        case 5:   return "fstat";
        case 8:   return "lseek";
        case 9:   return "mmap";
        case 10:  return "mprotect";
        case 11:  return "munmap";
        case 12:  return "brk";
        case 13:  return "rt_sigaction";
        case 14:  return "rt_sigprocmask";
        case 16:  return "ioctl";
        case 21:  return "access";
        case 22:  return "pipe";
        case 32:  return "dup";
        case 33:  return "dup2";
        case 39:  return "getpid";
        case 41:  return "socket";
        case 56:  return "clone";
        case 57:  return "fork";
        case 59:  return "execve";
        case 60:  return "exit";
        case 61:  return "wait4";
        case 63:  return "uname";
        case 78:  return "getdents";
        case 79:  return "getcwd";
        case 89:  return "readlink";
        case 102: return "getuid";
        case 158: return "arch_prctl";
        case 186: return "gettid";
        case 218: return "set_tid_address";
        case 228: return "clock_gettime";
        case 231: return "exit_group";
        case 257: return "openat";
        case 262: return "newfstatat";
        case 273: return "set_robust_list";
        case 302: return "prlimit64";
        case 318: return "getrandom";
        case 334: return "rseq";
        default:  return "other";
    }
}

/* Some syscalls are I/O-heavy; used for the bottleneck heuristic. */
static bool is_file_io(long num) {
    switch (num) {
        case 0: case 1: case 2: case 3: case 4: case 5:
        case 8: case 257: case 262:
            return true;
        default:
            return false;
    }
}
static bool is_memory_op(long num) {
    switch (num) {
        case 9: case 10: case 11: case 12:
            return true;
        default:
            return false;
    }
}

static double us_diff(struct timespec *start, struct timespec *end) {
    double sec  = (double)(end->tv_sec  - start->tv_sec);
    double nsec = (double)(end->tv_nsec - start->tv_nsec);
    return (sec * 1e6) + (nsec / 1e3);
}

int main(int argc, char *argv[]) {
    int cmd_index = 1;

    if (argc >= 2 && strcmp(argv[1], "-v") == 0) {
        verbose = true;
        cmd_index = 2;
    }

    if (argc <= cmd_index) {
        fprintf(stderr, "Usage: %s [-v] <command> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* ---------------- CHILD PROCESS ---------------- */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[cmd_index], &argv[cmd_index]);
        perror("execvp failed");
        _exit(127);
    }

    /* ---------------- PARENT PROCESS (tracer) ---------------- */
    int status;
    bool in_syscall = false;      /* false = expect entry, true = expect exit */
    long current_syscall = -1;
    struct timespec t_start, t_end;
    long total_traced_calls = 0;

    waitpid(child, &status, 0);   /* catch the initial stop from execvp() */

    while (1) {
        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) break;
        waitpid(child, &status, 0);

        if (WIFEXITED(status) || WIFSIGNALED(status)) break;

        struct user_regs_struct regs;

        if (!in_syscall) {
            /* ---- SYSCALL ENTRY ---- */
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            current_syscall = regs.orig_rax;
            clock_gettime(CLOCK_MONOTONIC, &t_start);
            in_syscall = true;
        } else {
            /* ---- SYSCALL EXIT ---- */
            clock_gettime(CLOCK_MONOTONIC, &t_end);
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            long ret_val = (long)regs.rax;

            if (current_syscall >= 0 && current_syscall < MAX_SYSCALLS) {
                double elapsed_us = us_diff(&t_start, &t_end);
                stats[current_syscall].count += 1;
                stats[current_syscall].total_us += elapsed_us;
                if (ret_val < 0) stats[current_syscall].error_count += 1;
                total_traced_calls++;

                if (verbose) {
                    printf("%-14s = %-8ld [%.1f us]%s\n",
                           syscall_name(current_syscall),
                           ret_val, elapsed_us,
                           (ret_val < 0) ? "  <-- ERROR" : "");
                }
            }
            in_syscall = false;
        }
    }

    /* ---------------- SUMMARY REPORT ---------------- */
    printf("\n===================== SysTrace Report =====================\n");
    printf("%-15s %8s %12s %12s %8s\n",
           "Syscall", "Calls", "Total(us)", "Avg(us)", "Errors");
    printf("-------------------------------------------------------------\n");

    double grand_total_us = 0.0;
    double file_io_us = 0.0;
    double mem_us = 0.0;

    long other_count = 0, other_errs = 0;
    double other_us = 0.0;

    for (int i = 0; i < MAX_SYSCALLS; i++) {
        if (stats[i].count == 0) continue;

        grand_total_us += stats[i].total_us;
        if (is_file_io(i))   file_io_us += stats[i].total_us;
        if (is_memory_op(i)) mem_us     += stats[i].total_us;

        const char *name = syscall_name(i);
        if (strcmp(name, "other") == 0) {
            other_count += stats[i].count;
            other_errs  += stats[i].error_count;
            other_us    += stats[i].total_us;
            continue;
        }

        double avg = stats[i].total_us / stats[i].count;
        printf("%-15s %8ld %12.2f %12.2f %8ld\n",
               name, stats[i].count, stats[i].total_us, avg, stats[i].error_count);
    }

    if (other_count > 0) {
        printf("%-15s %8ld %12.2f %12.2f %8ld\n",
               "other", other_count, other_us, other_us / other_count, other_errs);
    }

    printf("-------------------------------------------------------------\n");
    printf("Total syscalls traced : %ld\n", total_traced_calls);
    printf("Total kernel time     : %.2f us (%.2f ms)\n",
           grand_total_us, grand_total_us / 1000.0);

    /* ---------------- BOTTLENECK TAKEAWAY ---------------- */
    if (grand_total_us > 0) {
        double io_pct  = (file_io_us / grand_total_us) * 100.0;
        double mem_pct = (mem_us     / grand_total_us) * 100.0;

        printf("---------------------------------------------------------------\n");
        if (io_pct >= mem_pct && io_pct >= 30.0) {
            printf("Dominant Bottleneck: File I/O (read/write/open/close) "
                   "accounting for %.1f%% of total kernel time\n", io_pct);
        } else if (mem_pct >= 30.0) {
            printf("Dominant Bottleneck: Memory management (mmap/brk/mprotect) "
                   "accounting for %.1f%% of total kernel time\n", mem_pct);
        } else {
            printf("No single dominant bottleneck detected "
                   "(I/O=%.1f%%, Memory=%.1f%% of kernel time)\n", io_pct, mem_pct);
        }
    }
    printf("=================================================================\n");

    return 0;
}
