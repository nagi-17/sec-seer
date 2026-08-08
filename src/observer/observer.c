#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <complex.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>

#include "observer.h"

void observer_loop(pid_t pid, int status, struct user_regs_struct regs) {
    while (1) {
        if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
            perror("Error continuing tracee");
            break;
        }

        waitpid(pid, &status, 0);

        // Break if the child naturally exited or was killed by something else
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }

        // Check if the child stopped because it hit our banned seccomp rule
        if ((status >> 16) == PTRACE_EVENT_SECCOMP) {
            
            // Extract the CPU registers at the exact moment of the banned syscall
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
                perror("Error getting registers");
                break;
            }

            // Registers on x86_64:
            // regs.orig_rax : Syscall number
            // regs.rip      : Instruction pointer (use this for address2line mapping)
            // regs.rdi      : First argument (e.g., file descriptor or path pointer)
            
            printf("[Tracer] Seccomp violation intercepted!\n");
            printf("  PID      : %d\n", pid);
            printf("  Syscall  : %llu\n", regs.orig_rax);
            printf("  Address  : 0x%llx\n", regs.rip);
            
            // TODO: Call your logger function here with the extracted data
            // TODO: Call your address2line mapping function here

            // The test matrix expects the process to be killed immediately after a banned syscall.
            // Since we trapped it via SECCOMP_RET_TRACE, we must manually tear it down.

            kill(pid, SIGKILL);
            break;
        }
    }
}
