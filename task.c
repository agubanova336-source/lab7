#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <errno.h>

int main() {
    printf("1. Initializing seccomp...\n");

    // Create filter context: ALLOW all system calls by default
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        perror("seccomp_init error");
        return 1;
    }

    // Add rules: DENY fork and clone calls.
    // SCMP_ACT_ERRNO(EPERM) will return "Operation not permitted" error to the process instead of terminating it.
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 0);

    // Apply filter to the current process
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load error");
        seccomp_release(ctx);
        return 1;
    }
    seccomp_release(ctx);

    printf("2. seccomp filters applied successfully.\n");
    printf("3. Attempting to call fork()...\n");

    // Attempting to call blocked fork
    pid_t pid = fork();

    if (pid == -1) {
        // If seccomp worked correctly, fork will return -1
        perror("-> fork call result");
    } else if (pid == 0) {
        printf("Child process!\n");
        return 0;
    } else {
        printf("Parent process!\n");
    }

    printf("4. Attempting to call clone()...\n");
    long clone_res = syscall(SYS_clone, 0, 0, 0, 0, 0);
    
    if (clone_res == -1) {
        perror("-> clone call result");
    }

    // Demonstration that other system calls (e.g., write inside printf) are working
    printf("5. Demonstration: program continues execution after blocked system call.\n");

    return 0;
}
