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
#include <linux/limits.h>
#include <string.h>
#include "observer.h"
#include <logger/logger.h>
#include <seccomp.h>

typedef struct {
    char* func_name;
    char* file_line;
} addr2line_output;

char* syscall_name_resolver(int syscall_num) {
    uint32_t arch = seccomp_arch_native();
    char *syscall_name = seccomp_syscall_resolve_num_arch(arch, syscall_num);
    return syscall_name;
}

addr2line_output* get_source_location(pid_t pid, unsigned long long rip) {
    addr2line_output* result = (addr2line_output*)calloc(1, sizeof(addr2line_output));

    // Parse /proc/<pid>/maps to find the executable mapping containing rip.
    // This handles both the main binary (fixed base with -no-pie) and shared
    // libraries (ASLR'd base, e.g. libc) -- the faulting syscall usually lives
    // in the latter when the target calls a libc wrapper like read().
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) {
        fprintf(stderr, "Error: failed to open %s\n", maps_path);
        return result;
    }

    char line[512];
    unsigned long long base = 0;
    char file[PATH_MAX] = "";
    int found = 0;

    while (fgets(line, sizeof(line), maps) != NULL) {
        unsigned long long start, end;
        char perms[5];
        char path[PATH_MAX] = "";
        if (sscanf(line, "%llx-%llx %4s %*llx %*s %*s %255s",
                   &start, &end, perms, path) == 4) {
            if (rip >= start && rip < end && strstr(perms, "x")) {
                base = start;
                snprintf(file, sizeof(file), "%s", path);
                found = 1;
                break;
            }
        }
    }
    fclose(maps);

    if (!found) {
        fprintf(stderr, "Error: no executable mapping contains 0x%llx\n", rip);
        return result;
    }

    // addr2line wants the file offset, not the runtime address.
    unsigned long long offset = rip - base;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "addr2line -f -e %s 0x%llx", file, offset);

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: failed to execute addr2line\n");
        return result;
    }

    char* func_name = (char *)calloc(256, sizeof(char));
    char* file_line = (char *)calloc(256, sizeof(char));

    if (fgets(func_name, 256, fp) != NULL &&
        fgets(file_line, 256, fp) != NULL) {
        
        func_name[strcspn(func_name, "\n")] = 0;
        file_line[strcspn(file_line, "\n")] = 0;
    }

    pclose(fp);
    result->file_line = file_line;
    result->func_name = func_name;

    return result;
}

static char* get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char* buf = (char *)calloc(64, 1);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char date[32];
    strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &tm);
    snprintf(buf, 64, "%s.%03ld", date, ts.tv_nsec / 1000000);
    return buf;
}

void observer_loop(pid_t pid, int status, struct user_regs_struct regs, char* logfile) {
    int first_in_array = 1;
    while (1) {
        if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
            perror("Error continuing tracee");
            kill(pid, SIGKILL);
            exit(EXIT_FAILURE);
        }

        waitpid(pid, &status, 0);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }

        if ((status >> 16) == PTRACE_EVENT_SECCOMP) {
            
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
                perror("Error getting registers");
                break;
            }

            char* time_string = get_timestamp();
            printf("[Tracer] Seccomp violation intercepted!\n");
            printf("  Timestamp : ");
            printf("%s", time_string);
            printf("\n");
            printf("  PID       : %d\n", pid);
            printf("  Syscall Number  : %llu\n", regs.orig_rax);
            printf("  RDI       : 0x%016llx\n", regs.rdi);
            printf("  RSI       : 0x%016llx\n", regs.rsi);
            printf("  RDX       : 0x%016llx\n", regs.rdx);
            printf("  R10       : 0x%016llx\n", regs.r10);
            printf("  R8        : 0x%016llx\n", regs.r8);
            printf("  R9        : 0x%016llx\n", regs.r9);
            printf("  RBP       : 0x%016llx\n", regs.rbp);   
            printf("  RIP       : 0x%016llx\n", regs.rip);

            addr2line_output* addr2line_info = get_source_location(pid, regs.rip);

            SeccompViolation sv;
            sv.pid = pid;
            sv.rip = regs.rip;
            sv.rbp = regs.rbp;
            sv.syscall = regs.orig_rax;
            sv.rdi = regs.rdi;
            sv.rsi = regs.rsi;
            sv.rdx = regs.rdx;
            sv.r10 = regs.r10;
            sv.r8 = regs.r8;
            sv.r9 = regs.r9;
            sv.syscall_name = syscall_name_resolver(regs.orig_rax);
            sv.resolved_file = addr2line_info->file_line;
            sv.resolved_func = addr2line_info->func_name;
            sv.timestamp = time_string;

            free(addr2line_info);

            if (log_seccomp_violation(logfile, &sv, &first_in_array) < 0) {
                fprintf(stderr, "Error: could not write json logs to file.\n");
            }
            
            free(sv.syscall_name);
            free(sv.timestamp);
            free(sv.resolved_func);
            free(sv.resolved_file);
            //kill(pid, SIGKILL);
            //break;
        }
    }

    /* Tracee exited or was killed; close the JSON array in the log. */
    logger_close(logfile);
}
