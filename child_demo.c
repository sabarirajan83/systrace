#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    // Create multiple processes using fork to simulate concurrent execution and test fork tracking.
    pid_t pid = fork();
    fork();

    // Handle process creation failure.
    if (pid < 0) {
        perror("fork failed");
        exit(1);
    } else if (pid == 0) {
        // Child process execution: report PID and exit immediately to simulate short-lived tasks.
        printf("Child process (PID: %d) starting, exiting immediately.\n", getpid());
        _exit(0);
    } else {
        // Parent process execution: pause execution and wait for child processes to exit.
        printf("Parent process (PID: %d) created child (PID: %d)\n", getpid(), pid);
        printf("Parent sleeping for 2 seconds...\n");
        
        sleep(2);
        
        // Wait for child process termination to reclaim process resources and prevent zombies.
        wait(NULL);
        printf("Parent terminating.\n");
    }

    return 0;
}
