#ifndef SEC_SEER_LOGGER_H
#define SEC_SEER_LOGGER_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Data describing a single seccomp violation, captured in observer.c at
 * the PTRACE_EVENT_SECCOMP stop and passed to log_seccomp_violation().
 */
typedef struct {
    pid_t pid;
    const char *timestamp;      /* preformatted "YYYY-MM-DD HH:MM:SS"  */
    unsigned long long syscall; /* regs.orig_rax                          */
    const char *syscall_name;   /* optional human-readable name or NULL   */
    unsigned long long rdi;
    unsigned long long rsi;
    unsigned long long rdx;
    unsigned long long r10;
    unsigned long long r8;
    unsigned long long r9;
    unsigned long long rbp;
    unsigned long long rip;
    const char *resolved_func;  /* optional addr2line function or NULL    */
    const char *resolved_file;  /* optional addr2line file:line or NULL   */
} SeccompViolation;

/*
 * Appends one JSON object describing `v` to `file_path` (created if missing).
 * Uses pretty serialization so each violation is one readable block; a newline
 * separates consecutive entries. Returns 0 on success, -1 on error.
 */
int log_seccomp_violation(const char *file_path, const SeccompViolation *v);

#endif
