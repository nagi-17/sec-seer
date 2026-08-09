#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>

#include "observer.h"

static void print_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    char buf[64];
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    printf("%s.%03ld", buf, ts.tv_nsec / 1000000);
}

void observer_loop(pid_t pid, int status, struct user_regs_struct regs) {
    while (1) {
        if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
            perror("Error continuing tracee");
            kill(pid, SIGKILL);
            exit(EXIT_FAILURE);
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
            printf("  Timestamp : ");
            print_timestamp();
            printf("\n");
            printf("  PID       : %d\n", pid);

            // General purpose registers
            printf("  R15       : 0x%llx\n", regs.r15);
            printf("  R14       : 0x%llx\n", regs.r14);
            printf("  R13       : 0x%llx\n", regs.r13);
            printf("  R12       : 0x%llx\n", regs.r12);
            printf("  RBP       : 0x%llx\n", regs.rbp);
            printf("  RBX       : 0x%llx\n", regs.rbx);
            printf("  R11       : 0x%llx\n", regs.r11);
            printf("  R10       : 0x%llx\n", regs.r10);
            printf("  R9        : 0x%llx\n", regs.r9);
            printf("  R8        : 0x%llx\n", regs.r8);
            printf("  RAX       : 0x%llx\n", regs.rax);
            printf("  RCX       : 0x%llx\n", regs.rcx);
            printf("  RDX       : 0x%llx\n", regs.rdx);
            printf("  RSI       : 0x%llx\n", regs.rsi);
            printf("  RDI       : 0x%llx\n", regs.rdi);

            // Syscall number and instruction pointer
            printf("  Syscall   : %llu (orig_rax)\n", regs.orig_rax);
            printf("  RIP       : 0x%llx\n", regs.rip);

            // Segment and control registers
            printf("  CS        : 0x%llx\n", regs.cs);
            printf("  EFLAGS    : 0x%llx\n", regs.eflags);
            printf("  RSP       : 0x%llx\n", regs.rsp);
            printf("  SS        : 0x%llx\n", regs.ss);
            printf("  FS_BASE   : 0x%llx\n", regs.fs_base);
            printf("  GS_BASE   : 0x%llx\n", regs.gs_base);
            printf("  DS        : 0x%llx\n", regs.ds);
            printf("  ES        : 0x%llx\n", regs.es);
            printf("  FS        : 0x%llx\n", regs.fs);
            printf("  GS        : 0x%llx\n", regs.gs);
            
            
            // TODO: Call your logger function here with the extracted data
            // TODO: Call your address2line mapping function here

            // The test matrix expects the process to be killed immediately after a banned syscall.
            // Since we trapped it via SECCOMP_RET_TRACE, we must manually tear it down.

            kill(pid, SIGKILL);
            break;
        }
    }
}
