#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>

#define SYSCALL_TABLE_MAX 462
static const char *SYSCALL_NAMES[SYSCALL_TABLE_MAX] = {
    "read", "write", "open", "close", "stat", "fstat",
    "lstat", "poll", "lseek", "mmap", "mprotect", "munmap",
    "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64",
    "pwrite64", "readv", "writev", "access", "pipe", "select",
    "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget",
    "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep",
    "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket",
    "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair",
    "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve",
    "exit", "wait4", "kill", "uname", "semget", "semop",
    "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl",
    "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate",
    "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir",
    "rmdir", "creat", "link", "unlink", "symlink", "readlink",
    "chmod", "fchmod", "chown", "fchown", "lchown", "umask",
    "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace",
    "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid",
    "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid",
    "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid",
    "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget",
    "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack",
    "utime", "mknod", "uselib", "personality", "ustat", "statfs",
    "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam",
    "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock",
    "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root",
    "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot",
    "sync", "acct", "settimeofday", "mount", "umount2", "swapon",
    "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
    "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl",
    "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security",
    "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr",
    "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr",
    "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity",
    "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit",
    "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old",
    "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64",
    "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
    "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl",
    "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy",
    "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr",
    "kexec_load", "waitid", "add_key", "request_key", "keyctl", "ioprio_set",
    "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat",
    "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat",
    "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat",
    "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice",
    "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait",
    "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime",
    "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2",
    "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg",
    "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime",
    "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
    "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp",
    "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat", "userfaultfd",
    "membarrier", "mlock2", "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect",
    "pkey_alloc", "pkey_free", "statx", "io_pgetevents", "rseq", NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, "pidfd_send_signal", "io_uring_setup",
    "io_uring_enter", "io_uring_register", "open_tree", "move_mount", "fsopen", "fsconfig",
    "fsmount", "fspick", "pidfd_open", "clone3", "close_range", "openat2",
    "pidfd_getfd", "faccessat2", "process_madvise", "epoll_pwait2", "mount_setattr", "quotactl_fd",
    "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self", "memfd_secret", "process_mrelease", "futex_waitv",
    "set_mempolicy_home_node", "cachestat", "fchmodat2", "map_shadow_stack", "futex_wake", "futex_wait",
    "futex_requeue", "statmount", "listmount", "lsm_get_self_attr", "lsm_set_self_attr", "lsm_list_modules",
};

static bool verbose        = false;
static bool follow_forks   = false;
static bool counts_only    = false;
static bool show_timestamp = false;
static int  max_str_len    = 32;
static FILE *out           = NULL;              
static char *filter_names[64];
static int   filter_count  = 0;

typedef enum {
    CAT_FILE_IO, CAT_MEMORY, CAT_PROCESS, CAT_NETWORK,
    CAT_IPC_SYNC, CAT_SIGNAL, CAT_TIME, CAT_OTHER, CAT__COUNT
} Category;

static const char *CATEGORY_LABEL[CAT__COUNT] = {
    "File I/O", "Memory", "Process/Thread", "Networking",
    "IPC/Sync", "Signals", "Time", "Other"
};

static Category classify(long num, const char *name) {
    if (!name) return CAT_OTHER;
    /* File I/O */
    if (!strcmp(name,"read")||!strcmp(name,"write")||!strcmp(name,"open")||
        !strcmp(name,"close")||!strcmp(name,"stat")||!strcmp(name,"fstat")||
        !strcmp(name,"lstat")||!strcmp(name,"lseek")||!strcmp(name,"pread64")||
        !strcmp(name,"pwrite64")||!strcmp(name,"readv")||!strcmp(name,"writev")||
        !strcmp(name,"access")||!strcmp(name,"openat")||!strcmp(name,"newfstatat")||
        !strcmp(name,"getdents")||!strcmp(name,"getdents64")||!strcmp(name,"getcwd")||
        !strcmp(name,"chdir")||!strcmp(name,"fchdir")||!strcmp(name,"rename")||
        !strcmp(name,"mkdir")||!strcmp(name,"rmdir")||!strcmp(name,"creat")||
        !strcmp(name,"link")||!strcmp(name,"unlink")||!strcmp(name,"symlink")||
        !strcmp(name,"readlink")||!strcmp(name,"chmod")||!strcmp(name,"fchmod")||
        !strcmp(name,"chown")||!strcmp(name,"fchown")||!strcmp(name,"truncate")||
        !strcmp(name,"ftruncate")||!strcmp(name,"fsync")||!strcmp(name,"fdatasync")||
        !strcmp(name,"fcntl")||!strcmp(name,"flock")||!strcmp(name,"ioctl")||
        !strcmp(name,"sendfile")||!strcmp(name,"dup")||!strcmp(name,"dup2")||
        !strcmp(name,"dup3")||!strcmp(name,"statx")||!strcmp(name,"faccessat")||
        !strcmp(name,"faccessat2")||!strcmp(name,"openat2")||!strcmp(name,"close_range"))
        return CAT_FILE_IO;
    /* Memory */
    if (!strcmp(name,"mmap")||!strcmp(name,"mprotect")||!strcmp(name,"munmap")||
        !strcmp(name,"brk")||!strcmp(name,"mremap")||!strcmp(name,"msync")||
        !strcmp(name,"mincore")||!strcmp(name,"madvise")||!strcmp(name,"mlock")||
        !strcmp(name,"munlock")||!strcmp(name,"mlockall")||!strcmp(name,"munlockall"))
        return CAT_MEMORY;
    /* Process / thread control */
    if (!strcmp(name,"clone")||!strcmp(name,"clone3")||!strcmp(name,"fork")||
        !strcmp(name,"vfork")||!strcmp(name,"execve")||!strcmp(name,"execveat")||
        !strcmp(name,"exit")||!strcmp(name,"exit_group")||!strcmp(name,"wait4")||
        !strcmp(name,"waitid")||!strcmp(name,"getpid")||!strcmp(name,"gettid")||
        !strcmp(name,"getppid")||!strcmp(name,"set_tid_address")||
        !strcmp(name,"sched_yield")||!strcmp(name,"sched_setaffinity")||
        !strcmp(name,"sched_getaffinity")||!strcmp(name,"prctl")||
        !strcmp(name,"arch_prctl")||!strcmp(name,"set_robust_list")||
        !strcmp(name,"prlimit64")||!strcmp(name,"getpriority")||!strcmp(name,"setpriority"))
        return CAT_PROCESS;
    /* Networking */
    if (!strcmp(name,"socket")||!strcmp(name,"connect")||!strcmp(name,"accept")||
        !strcmp(name,"accept4")||!strcmp(name,"sendto")||!strcmp(name,"recvfrom")||
        !strcmp(name,"sendmsg")||!strcmp(name,"recvmsg")||!strcmp(name,"shutdown")||
        !strcmp(name,"bind")||!strcmp(name,"listen")||!strcmp(name,"getsockname")||
        !strcmp(name,"getpeername")||!strcmp(name,"socketpair")||
        !strcmp(name,"setsockopt")||!strcmp(name,"getsockopt"))
        return CAT_NETWORK;
    /* IPC / synchronization */
    if (!strcmp(name,"pipe")||!strcmp(name,"pipe2")||!strcmp(name,"futex")||
        !strcmp(name,"futex_wake")||!strcmp(name,"futex_wait")||!strcmp(name,"futex_waitv")||
        !strcmp(name,"shmget")||!strcmp(name,"shmat")||!strcmp(name,"shmctl")||
        !strcmp(name,"shmdt")||!strcmp(name,"semget")||!strcmp(name,"semop")||
        !strcmp(name,"semctl")||!strcmp(name,"msgget")||!strcmp(name,"msgsnd")||
        !strcmp(name,"msgrcv")||!strcmp(name,"msgctl")||!strcmp(name,"eventfd")||
        !strcmp(name,"eventfd2")||!strcmp(name,"epoll_create")||!strcmp(name,"epoll_create1")||
        !strcmp(name,"epoll_wait")||!strcmp(name,"epoll_ctl")||!strcmp(name,"epoll_pwait")||
        !strcmp(name,"select")||!strcmp(name,"poll")||!strcmp(name,"ppoll"))
        return CAT_IPC_SYNC;
    /* Signals */
    if (!strcmp(name,"rt_sigaction")||!strcmp(name,"rt_sigprocmask")||
        !strcmp(name,"rt_sigreturn")||!strcmp(name,"rt_sigpending")||
        !strcmp(name,"rt_sigsuspend")||!strcmp(name,"rt_sigtimedwait")||
        !strcmp(name,"kill")||!strcmp(name,"tkill")||!strcmp(name,"tgkill")||
        !strcmp(name,"signalfd")||!strcmp(name,"signalfd4")||!strcmp(name,"pause"))
        return CAT_SIGNAL;
    /* Time */
    if (!strcmp(name,"clock_gettime")||!strcmp(name,"clock_settime")||
        !strcmp(name,"clock_nanosleep")||!strcmp(name,"nanosleep")||
        !strcmp(name,"gettimeofday")||!strcmp(name,"settimeofday")||
        !strcmp(name,"getitimer")||!strcmp(name,"setitimer")||!strcmp(name,"alarm")||
        !strcmp(name,"clock_getres")||!strcmp(name,"time")||!strcmp(name,"timer_create")||
        !strcmp(name,"timerfd_create"))
        return CAT_TIME;
    (void)num;
    return CAT_OTHER;
}

typedef struct {
    const char *name;
    int  path_arg;     
    int  buf_arg;      
    int  len_arg;      
    bool buf_at_exit;
} ArgHint;

static const ArgHint ARG_HINTS[] = {
    { "open",     0, -1, -1, false },
    { "openat",   1, -1, -1, false },
    { "openat2",  1, -1, -1, false },
    { "creat",    0, -1, -1, false },
    { "stat",     0, -1, -1, false },
    { "lstat",    0, -1, -1, false },
    { "access",   0, -1, -1, false },
    { "faccessat",1, -1, -1, false },
    { "faccessat2",1,-1, -1, false },
    { "unlink",   0, -1, -1, false },
    { "mkdir",    0, -1, -1, false },
    { "rmdir",    0, -1, -1, false },
    { "chdir",    0, -1, -1, false },
    { "readlink", 0, -1, -1, false },
    { "chmod",    0, -1, -1, false },
    { "chown",    0, -1, -1, false },
    { "execve",   0, -1, -1, false },
    { "rename",   0, -1, -1, false },
    { "symlink",  1, -1, -1, false },
    { "link",     0, -1, -1, false },
    { "write",   -1,  1,  2, false },   /* buffer is input, valid at entry */
    { "read",    -1,  1,  2, true  },   /* buffer is output, valid at exit  */
    { "pwrite64",-1,  1,  2, false },
    { "pread64", -1,  1,  2, true  },
    { "send",    -1,  1,  2, false },
    { "recv",    -1,  1,  2, true  },
    { "sendto",  -1,  1,  2, false },
    { "recvfrom",-1,  1,  2, true  },
    { NULL, -1, -1, -1, false }
};

static const ArgHint *find_hint(const char *name) {
    if (!name) return NULL;
    for (int i = 0; ARG_HINTS[i].name; i++)
        if (!strcmp(ARG_HINTS[i].name, name)) return &ARG_HINTS[i];
    return NULL;
}

static void read_tracee_bytes(pid_t pid, unsigned long addr, char *outbuf, size_t outsz, size_t cap) {
    if (addr == 0) { snprintf(outbuf, outsz, "NULL"); return; }
    if (cap > (size_t)max_str_len) cap = (size_t)max_str_len;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { snprintf(outbuf, outsz, "0x%lx", addr); return; }

    unsigned char raw[256];
    size_t want = cap < sizeof(raw) - 1 ? cap : sizeof(raw) - 1;
    ssize_t n = want > 0 ? pread(fd, raw, want, (off_t)addr) : 0;
    close(fd);
    if (n <= 0) { snprintf(outbuf, outsz, "0x%lx", addr); return; }

    size_t o = 0;
    outbuf[o++] = '"';
    for (ssize_t i = 0; i < n && o + 5 < outsz; i++) {
        unsigned char c = raw[i];
        if (c == '\0') break;
        if (isprint(c)) {
            outbuf[o++] = (char)c;
        } else {
            o += (size_t)snprintf(outbuf + o, outsz - o, "\\x%02x", c);
        }
    }
    outbuf[o++] = '"';
    if (n == (ssize_t)want) { snprintf(outbuf + o, outsz - o, "..."); }
    else outbuf[o] = '\0';
}

static void read_tracee_string(pid_t pid, unsigned long addr, char *outbuf, size_t outsz) {
    read_tracee_bytes(pid, addr, outbuf, outsz, (size_t)max_str_len);
}

typedef struct {
    long   count;
    long   error_count;
    double total_us;
    double min_us, max_us;
} SyscallStat;

static SyscallStat g_stats[SYSCALL_TABLE_MAX];
static long g_unknown_count = 0, g_unknown_errs = 0;
static double g_unknown_us = 0.0;
static long g_total_traced_calls = 0;
static long g_total_signals_delivered = 0;
static long g_total_processes_seen = 0;

#define MAX_TRACEES 256
typedef struct {
    pid_t pid;
    bool  active;
    bool  in_syscall;
    long  current_syscall;
    struct timespec t_start;
    unsigned long entry_args[6];   
} TraceeState;

static TraceeState tracees[MAX_TRACEES];

static TraceeState *find_or_add_tracee(pid_t pid) {
    for (int i = 0; i < MAX_TRACEES; i++)
        if (tracees[i].active && tracees[i].pid == pid) return &tracees[i];
    for (int i = 0; i < MAX_TRACEES; i++) {
        if (!tracees[i].active) {
            tracees[i].active = true;
            tracees[i].pid = pid;
            tracees[i].in_syscall = false;
            g_total_processes_seen++;
            return &tracees[i];
        }
    }
    return NULL; 
}

static void remove_tracee(pid_t pid) {
    for (int i = 0; i < MAX_TRACEES; i++)
        if (tracees[i].active && tracees[i].pid == pid) tracees[i].active = false;
}

static int active_tracee_count(void) {
    int n = 0;
    for (int i = 0; i < MAX_TRACEES; i++) if (tracees[i].active) n++;
    return n;
}

static double us_diff(struct timespec *start, struct timespec *end) {
    double sec  = (double)(end->tv_sec  - start->tv_sec);
    double nsec = (double)(end->tv_nsec - start->tv_nsec);
    return (sec * 1e6) + (nsec / 1e3);
}

static bool name_is_filtered_in(const char *name) {
    if (filter_count == 0) return true; /* no filter => show everything */
    for (int i = 0; i < filter_count; i++)
        if (name && !strcmp(filter_names[i], name)) return true;
    return false;
}

/* Fetch the 6 syscall argument registers (x86_64 ABI: rdi,rsi,rdx,r10,r8,r9) */
static void get_arg_regs(struct user_regs_struct *regs, unsigned long args[6]) {
    args[0] = regs->rdi; args[1] = regs->rsi; args[2] = regs->rdx;
    args[3] = regs->r10; args[4] = regs->r8;  args[5] = regs->r9;
}

static void apply_trace_options(pid_t pid) {
    long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL;
    if (follow_forks) {
        opts |= PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
                PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC;
    }
    ptrace(PTRACE_SETOPTIONS, pid, NULL, opts);
}

static void format_retval(long ret, char *buf, size_t bufsz) {
    if (ret < 0) {
        int e = (int)(-ret);
        snprintf(buf, bufsz, "%ld %s (%s)", ret, strerrorname_np(e), strerror(e));
    } else {
        snprintf(buf, bufsz, "%ld", ret);
    }
}

static void print_timestamp(void) {
    if (!show_timestamp) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tmv;
    localtime_r(&ts.tv_sec, &tmv);
    fprintf(out, "%02d:%02d:%02d.%06ld ", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ts.tv_nsec / 1000);
}

int main(int argc, char *argv[]) {
    int cmd_index = 1;
    pid_t attach_pid = -1;
    out = stdout;

    while (cmd_index < argc && argv[cmd_index][0] == '-') {
        char *a = argv[cmd_index];
        if (!strcmp(a, "-v")) { verbose = true; cmd_index++; }
        else if (!strcmp(a, "-f")) { follow_forks = true; cmd_index++; }
        else if (!strcmp(a, "-c")) { counts_only = true; cmd_index++; }
        else if (!strcmp(a, "-tt")) { show_timestamp = true; cmd_index++; }
        else if (!strcmp(a, "-p")) {
            if (cmd_index + 1 >= argc) { fprintf(stderr, "-p requires a PID\n"); return 1; }
            attach_pid = (pid_t)atoi(argv[cmd_index + 1]);
            cmd_index += 2;
        } else if (!strcmp(a, "-o")) {
            if (cmd_index + 1 >= argc) { fprintf(stderr, "-o requires a filename\n"); return 1; }
            out = fopen(argv[cmd_index + 1], "w");
            if (!out) { perror("fopen"); return 1; }
            cmd_index += 2;
        } else if (!strcmp(a, "-s")) {
            if (cmd_index + 1 >= argc) { fprintf(stderr, "-s requires a byte count\n"); return 1; }
            max_str_len = atoi(argv[cmd_index + 1]);
            cmd_index += 2;
        } else if (!strncmp(a, "-e", 2)) {
            char *spec = a;
            if (strlen(a) == 2) { spec = argv[++cmd_index]; }
            const char *eq = strchr(spec, '=');
            if (eq) spec = (char *)eq + 1;
            char *tmp = strdup(spec);
            char *tok = strtok(tmp, ",");
            while (tok && filter_count < 64) { filter_names[filter_count++] = strdup(tok); tok = strtok(NULL, ","); }
            free(tmp);
            cmd_index++;
        } else {
            fprintf(stderr, "Unknown option: %s\n", a);
            return 1;
        }
    }

    if (attach_pid < 0 && cmd_index >= argc) {
        fprintf(stderr,
            "Usage: %s [-v] [-f] [-c] [-tt] [-s N] [-e trace=a,b] [-o file] <command> [args...]\n"
            "       %s -p <pid>\n", argv[0], argv[0]);
        return 1;
    }
    if (counts_only) verbose = false;

    pid_t root_pid;

    if (attach_pid > 0) {
        /* ---- ATTACH MODE ---- */
        root_pid = attach_pid;
        if (ptrace(PTRACE_SEIZE, root_pid, NULL, follow_forks ?
                (void *)(long)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                                PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
                                PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC)
                : (void *)(long)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)) < 0) {
            perror("PTRACE_SEIZE (attach)");
            return 1;
        }
        if (ptrace(PTRACE_INTERRUPT, root_pid, NULL, NULL) < 0) { perror("PTRACE_INTERRUPT"); return 1; }
        int status;
        waitpid(root_pid, &status, 0);
        TraceeState *ts = find_or_add_tracee(root_pid);
        ts->in_syscall = false;
        fprintf(out, "Attached to pid %d\n", root_pid);
        ptrace(PTRACE_SYSCALL, root_pid, NULL, NULL);
    } else {
        pid_t child = fork();
        if (child < 0) { perror("fork"); return 1; }

        if (child == 0) {
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            execvp(argv[cmd_index], &argv[cmd_index]);
            perror("execvp failed");
            _exit(127);
        }

        root_pid = child;
        int status;
        waitpid(root_pid, &status, 0);      
        apply_trace_options(root_pid);
        TraceeState *ts = find_or_add_tracee(root_pid);
        ts->in_syscall = false;
        ptrace(PTRACE_SYSCALL, root_pid, NULL, NULL);
    }

    struct timespec wall_start, wall_end;
    clock_gettime(CLOCK_MONOTONIC, &wall_start);

    int root_exit_status = -1;

    while (active_tracee_count() > 0) {
        int status;
        pid_t p = waitpid(-1, &status, __WALL);
        if (p < 0) {
            if (errno == ECHILD) break;
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (p == root_pid) root_exit_status = status;
            remove_tracee(p);
            continue;
        }

        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        int event = status >> 16; 
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
            unsigned long newpid_ul = 0;
            ptrace(PTRACE_GETEVENTMSG, p, NULL, &newpid_ul);
            pid_t newpid = (pid_t)newpid_ul;
            TraceeState *nts = find_or_add_tracee(newpid);
            if (nts) {
                nts->in_syscall = false;
                apply_trace_options(newpid);
                ptrace(PTRACE_SYSCALL, newpid, NULL, NULL);
            }
            ptrace(PTRACE_SYSCALL, p, NULL, NULL);
            continue;
        }
        if (event == PTRACE_EVENT_EXEC) {
            ptrace(PTRACE_SYSCALL, p, NULL, NULL);
            continue;
        }

        if (sig == (SIGTRAP | 0x80)) {
            TraceeState *tst = find_or_add_tracee(p);
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, p, NULL, &regs);

            if (!tst->in_syscall) {
                /* ---- ENTRY ---- */
                tst->current_syscall = regs.orig_rax;
                get_arg_regs(&regs, tst->entry_args);
                clock_gettime(CLOCK_MONOTONIC, &tst->t_start);
                tst->in_syscall = true;

                if (verbose && !counts_only) {
                    long n = tst->current_syscall;
                    const char *name = (n >= 0 && n < SYSCALL_TABLE_MAX) ? SYSCALL_NAMES[n] : NULL;
                    if (name_is_filtered_in(name)) {
                        const ArgHint *h = find_hint(name);
                        if (h && h->path_arg >= 0) {
                            char strbuf[300];
                            read_tracee_string(p, tst->entry_args[h->path_arg], strbuf, sizeof(strbuf));
                            print_timestamp();
                            fprintf(out, "[pid %d] %s(%s) ", p, name ? name : "?", strbuf);
                            fflush(out);
                            tst->in_syscall = true; /* remember we already printed the prefix */
                        } else if (h && h->buf_arg >= 0 && !h->buf_at_exit) {
                            char strbuf[300];
                            read_tracee_string(p, tst->entry_args[h->buf_arg], strbuf, sizeof(strbuf));
                            print_timestamp();
                            fprintf(out, "[pid %d] %s(fd=%lu, %s, len=%lu) ",
                                    p, name ? name : "?", tst->entry_args[0], strbuf,
                                    h->len_arg >= 0 ? tst->entry_args[h->len_arg] : 0);
                            fflush(out);
                        }
                    }
                }
            } else {
                /* ---- EXIT ---- */
                struct timespec t_end;
                clock_gettime(CLOCK_MONOTONIC, &t_end);
                long ret_val = (long)regs.rax;
                long n = tst->current_syscall;
                double elapsed_us = us_diff(&tst->t_start, &t_end);

                if (n >= 0 && n < SYSCALL_TABLE_MAX) {
                    SyscallStat *st = &g_stats[n];
                    if (st->count == 0) { st->min_us = st->max_us = elapsed_us; }
                    st->count++;
                    st->total_us += elapsed_us;
                    if (elapsed_us < st->min_us) st->min_us = elapsed_us;
                    if (elapsed_us > st->max_us) st->max_us = elapsed_us;
                    if (ret_val < 0) st->error_count++;
                } else {
                    g_unknown_count++; g_unknown_us += elapsed_us;
                    if (ret_val < 0) g_unknown_errs++;
                }
                g_total_traced_calls++;

                if (verbose && !counts_only) {
                    const char *name = (n >= 0 && n < SYSCALL_TABLE_MAX) ? SYSCALL_NAMES[n] : NULL;
                    if (name_is_filtered_in(name)) {
                        const ArgHint *h = find_hint(name);
                        char retbuf[128];
                        format_retval(ret_val, retbuf, sizeof(retbuf));

                        if (h && h->buf_arg >= 0 && h->buf_at_exit && ret_val > 0) {
                            /* Output buffer only valid now; print it here instead,
                             * capped to the bytes the kernel actually wrote. */
                            char strbuf[300];
                            read_tracee_bytes(p, tst->entry_args[h->buf_arg], strbuf, sizeof(strbuf), (size_t)ret_val);
                            print_timestamp();
                            fprintf(out, "[pid %d] %s(fd=%lu, %s, len=%lu) = %s  [%.1f us]%s\n",
                                    p, name ? name : "?", tst->entry_args[0], strbuf,
                                    h->len_arg >= 0 ? tst->entry_args[h->len_arg] : 0,
                                    retbuf, elapsed_us, ret_val < 0 ? "  <-- ERROR" : "");
                        } else if (h && (h->path_arg >= 0 || h->buf_arg >= 0)) {
                            /* We already printed "name(args) " at entry; finish the line */
                            fprintf(out, "= %s  [%.1f us]%s\n", retbuf, elapsed_us,
                                    ret_val < 0 ? "  <-- ERROR" : "");
                        } else {
                            print_timestamp();
                            fprintf(out, "[pid %d] %-14s(%lu, %lu, %lu) = %-20s [%.1f us]%s\n",
                                    p, name ? name : "other",
                                    tst->entry_args[0], tst->entry_args[1], tst->entry_args[2],
                                    retbuf, elapsed_us, ret_val < 0 ? "  <-- ERROR" : "");
                        }
                    }
                }
                tst->in_syscall = false;
            }
            ptrace(PTRACE_SYSCALL, p, NULL, NULL);
            continue;
        }

        g_total_signals_delivered++;
        if (verbose && !counts_only) {
            print_timestamp();
            fprintf(out, "[pid %d] --- signal %d (%s) ---\n", p, sig, strsignal(sig));
        }
        ptrace(PTRACE_SYSCALL, p, NULL, sig == SIGSTOP ? 0 : (void*)(long)sig);
    }

    clock_gettime(CLOCK_MONOTONIC, &wall_end);
    double wall_us = us_diff(&wall_start, &wall_end);

    fprintf(out, "\n===================== SysTrace Report =====================\n");
    if (follow_forks)
        fprintf(out, "Processes/threads traced : %ld\n", g_total_processes_seen);
    fprintf(out, "%-16s %8s %12s %10s %10s %10s %8s\n",
            "Syscall", "Calls", "Total(us)", "Avg(us)", "Min(us)", "Max(us)", "Errors");
    fprintf(out, "-----------------------------------------------------------------------------\n");

    double grand_total_us = 0.0;
    double cat_us[CAT__COUNT] = {0};

    for (int i = 0; i < SYSCALL_TABLE_MAX; i++) {
        if (g_stats[i].count == 0) continue;
        const char *name = SYSCALL_NAMES[i] ? SYSCALL_NAMES[i] : "other";
        grand_total_us += g_stats[i].total_us;
        cat_us[classify(i, SYSCALL_NAMES[i])] += g_stats[i].total_us;

        double avg = g_stats[i].total_us / g_stats[i].count;
        fprintf(out, "%-16s %8ld %12.2f %10.2f %10.2f %10.2f %8ld\n",
                name, g_stats[i].count, g_stats[i].total_us, avg,
                g_stats[i].min_us, g_stats[i].max_us, g_stats[i].error_count);
    }
    if (g_unknown_count > 0) {
        grand_total_us += g_unknown_us;
        fprintf(out, "%-16s %8ld %12.2f %10.2f %10s %10s %8ld\n",
                "<unmapped>", g_unknown_count, g_unknown_us,
                g_unknown_us / g_unknown_count, "-", "-", g_unknown_errs);
    }

    fprintf(out, "-----------------------------------------------------------------------------\n");
    fprintf(out, "Total syscalls traced     : %ld\n", g_total_traced_calls);
    fprintf(out, "Total kernel time         : %.2f us (%.2f ms)\n", grand_total_us, grand_total_us / 1000.0);
    fprintf(out, "Total signals delivered   : %ld\n", g_total_signals_delivered);
    fprintf(out, "Wall-clock run time       : %.2f us (%.2f ms)\n", wall_us, wall_us / 1000.0);
    if (wall_us > 0)
        fprintf(out, "Time spent in kernel      : %.2f%% of wall-clock run time\n",
                (grand_total_us / wall_us) * 100.0);

    if (grand_total_us > 0) {
        fprintf(out, "-----------------------------------------------------------------------------\n");
        fprintf(out, "By category:\n");
        Category order[CAT__COUNT]; int oc = 0;
        for (int c = 0; c < CAT__COUNT; c++) order[oc++] = (Category)c;
        for (int a = 0; a < oc; a++)
            for (int b = a + 1; b < oc; b++)
                if (cat_us[order[b]] > cat_us[order[a]]) { Category t = order[a]; order[a] = order[b]; order[b] = t; }
        for (int a = 0; a < oc; a++) {
            if (cat_us[order[a]] <= 0.0) continue;
            fprintf(out, "  %-16s %10.2f us  (%5.1f%%)\n",
                    CATEGORY_LABEL[order[a]], cat_us[order[a]],
                    cat_us[order[a]] / grand_total_us * 100.0);
        }

        fprintf(out, "-----------------------------------------------------------------------------\n");
        Category top = order[0];
        double top_pct = cat_us[top] / grand_total_us * 100.0;
        if (top_pct >= 30.0)
            fprintf(out, "Dominant Bottleneck: %s, accounting for %.1f%% of total kernel time\n",
                    CATEGORY_LABEL[top], top_pct);
        else
            fprintf(out, "No single dominant bottleneck detected (top category: %s at %.1f%%)\n",
                    CATEGORY_LABEL[top], top_pct);
    }

    if (root_exit_status >= 0) {
        if (WIFEXITED(root_exit_status))
            fprintf(out, "Traced command exited with status %d\n", WEXITSTATUS(root_exit_status));
        else if (WIFSIGNALED(root_exit_status))
            fprintf(out, "Traced command killed by signal %d (%s)\n",
                    WTERMSIG(root_exit_status), strsignal(WTERMSIG(root_exit_status)));
    }
    fprintf(out, "=============================================================================\n");

    if (out != stdout) fclose(out);
    return 0;
}
