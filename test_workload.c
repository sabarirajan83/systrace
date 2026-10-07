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

// Perform file operations to generate file I/O system calls including open, write, lseek, read, and unlink.
static void do_file_io(void) {
    // Open and truncate a temporary file for write and read benchmarking.
    int fd = open(TMP_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return; }

    char buffer[BUF_SIZE];
    memset(buffer, 'A', BUF_SIZE);

    /* Many small writes -> lots of write() syscalls */
    // Issue multiple small write operations to generate high-frequency write system calls.
    for (int i = 0; i < NUM_WRITES; i++) {
        ssize_t written = write(fd, buffer, BUF_SIZE);
        if (written < 0) { perror("write"); break; }
    }

    /* Rewind and read it all back -> lseek + read syscalls */
    // Rewind file position and read back stored data to trigger lseek and read system calls.
    lseek(fd, 0, SEEK_SET);
    char read_buf[BUF_SIZE];
    while (read(fd, read_buf, BUF_SIZE) > 0) {
        /* just consume the data */
    }

    // Close file descriptor and remove the temporary file to release filesystem resources.
    close(fd);
    unlink(TMP_FILE);
}

// Perform heap and dynamic memory operations to generate memory-related system calls.
static void do_memory_ops(void) {
    void *ptrs[NUM_ALLOCS];

    /* Progressively larger allocations -> some will trigger brk/mmap */
    // Allocate increasingly larger memory blocks to trigger heap allocation via brk or mmap.
    for (int i = 0; i < NUM_ALLOCS; i++) {
        size_t sz = (size_t)(1024 * (i + 1));   /* 1KB, 2KB, ... 20KB */
        ptrs[i] = malloc(sz);
        if (ptrs[i]) memset(ptrs[i], 0, sz);
    }

    // Release allocated memory blocks back to the runtime allocator.
    for (int i = 0; i < NUM_ALLOCS; i++) {
        free(ptrs[i]);
    }

    /* One large allocation likely to go through mmap directly */
    // Allocate and free a large memory chunk to force direct anonymous memory mapping via mmap.
    void *big = malloc(4 * 1024 * 1024); /* 4 MB */
    if (big) {
        memset(big, 1, 4 * 1024 * 1024);
        free(big);
    }
}

// Execute benchmark phases to simulate diverse operating system workloads for tracing.
int main(void) {
    // Execute the file I/O workload phase.
    printf("test_workload: starting file I/O phase...\n");
    do_file_io();

    // Execute the dynamic memory management workload phase.
    printf("test_workload: starting memory allocation phase...\n");
    do_memory_ops();

    printf("test_workload: done.\n");
    return 0;
}
