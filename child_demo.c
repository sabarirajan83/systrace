#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();
    fork();

    if (pid < 0) {
        perror("fork failed");
        exit(1);
    } else if (pid == 0) {
        printf("Child process (PID: %d) starting, exiting immediately.\n", getpid());
        _exit(0);
    } else {
        printf("Parent process (PID: %d) created child (PID: %d)\n", getpid(), pid);
        printf("Parent sleeping for 2 seconds...\n");
        
        sleep(2);
        
        wait(NULL);
        printf("Parent terminating.\n");
    }

    return 0;
}
