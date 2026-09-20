/*
 * test_workload.c
 * -----------------------------------------------------------------------
 * A small, deliberately "busy" benchmark program used to demonstrate
 * SysTrace with realistic, measurable syscall activity. It performs:
 *   1. File I/O   -> triggers open/openat, write, read, close, lseek
 *   2. Memory ops -> triggers brk / mmap / munmap via malloc/free
 *   3. A tight loop of small writes -> shows syscall-count-heavy behavior
 *
 * Build: gcc -o test_workload test_workload.c
 * Run directly:        ./test_workload
 * Run under SysTrace:  ./systrace ./test_workload
 * -----------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define TMP_FILE   "/tmp/systrace_workload.tmp"
#define NUM_WRITES 50
#define BUF_SIZE   256
#define NUM_ALLOCS 20

static void do_file_io(void) {
    int fd = open(TMP_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return; }

    char buffer[BUF_SIZE];
    memset(buffer, 'A', BUF_SIZE);

    /* Many small writes -> lots of write() syscalls */
    for (int i = 0; i < NUM_WRITES; i++) {
        ssize_t written = write(fd, buffer, BUF_SIZE);
        if (written < 0) { perror("write"); break; }
    }

    /* Rewind and read it all back -> lseek + read syscalls */
    lseek(fd, 0, SEEK_SET);
    char read_buf[BUF_SIZE];
    while (read(fd, read_buf, BUF_SIZE) > 0) {
        /* just consume the data */
    }

    close(fd);
    unlink(TMP_FILE);
}

static void do_memory_ops(void) {
    void *ptrs[NUM_ALLOCS];

    /* Progressively larger allocations -> some will trigger brk/mmap */
    for (int i = 0; i < NUM_ALLOCS; i++) {
        size_t sz = (size_t)(1024 * (i + 1));   /* 1KB, 2KB, ... 20KB */
        ptrs[i] = malloc(sz);
        if (ptrs[i]) memset(ptrs[i], 0, sz);
    }

    for (int i = 0; i < NUM_ALLOCS; i++) {
        free(ptrs[i]);
    }

    /* One large allocation likely to go through mmap directly */
    void *big = malloc(4 * 1024 * 1024); /* 4 MB */
    if (big) {
        memset(big, 1, 4 * 1024 * 1024);
        free(big);
    }
}

int main(void) {
    printf("test_workload: starting file I/O phase...\n");
    do_file_io();

    printf("test_workload: starting memory allocation phase...\n");
    do_memory_ops();

    printf("test_workload: done.\n");
    return 0;
}
