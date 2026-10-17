#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>

// Helper function to map common x86_64 syscall numbers to names
const char* get_syscall_name(long long syscall_num) {
    switch (syscall_num) {
        case 0:   return "read";
        case 1:   return "write";
        case 2:   return "open";
        case 3:   return "close";
        case 4:   return "stat";
        case 5:   return "fstat";
        case 6:   return "lstat";
        case 8:   return "lseek";
        case 9:   return "mmap";
        case 10:  return "mprotect";
        case 11:  return "munmap";
        case 12:  return "brk";
        case 13:  return "rt_sigaction";
        case 14:  return "rt_sigprocmask";
        case 21:  return "access";
        case 59:  return "execve";
        case 60:  return "exit";
        case 231: return "exit_group";
        case 257: return "openat";
        default:  return "unknown";
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program_to_trace> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();

    if (child == 0) {
        // Child Process: enable tracing and pause until parent attaches
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        
        // Execute the target command
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(1);
    } else if (child > 0) {
        // Parent Process
        int status;
        int in_syscall = 0; // Tracks entry vs exit stop

        // Wait for child to reach SIGSTOP
        waitpid(child, &status, 0);

        // Distinguish syscall-stops from regular signal-stops
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

        printf("=== Starting System Call Trace for: %s ===\n\n", argv[1]);

        while (1) {
            if (ptrace(PTRACE_SYSCALL, child, 0, 0) < 0) {
                perror("ptrace syscall");
                break;
            }

            waitpid(child, &status, 0);

            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                printf("\n==========================================\n");
                printf("Process exited with status %d\n", WEXITSTATUS(status));
                break;
            }

            if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, 0, &regs);

#if defined(__x86_64__)
                if (in_syscall == 0) {
                    // Syscall Entry
                    long long sys_num = regs.orig_rax;
                    const char *sys_name = get_syscall_name(sys_num);
                    printf("[SYSCALL] %-15s (ID: %-3lld)", sys_name, sys_num);
                    fflush(stdout);
                    in_syscall = 1;
                } else {
                    // Syscall Exit
                    printf(" -> Return: %lld\n", (long long)regs.rax);
                    in_syscall = 0;
                }
#else
                #error "Requires x86_64 architecture."
#endif
            }
        }
    } else {
        perror("fork");
        return 1;
    }

    return 0;
}