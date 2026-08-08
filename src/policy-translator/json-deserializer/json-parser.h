#ifndef SECCOMP_PROFILE_H
#define SECCOMP_PROFILE_H

#include<stddef.h>

typedef struct {
    unsigned int index;
    unsigned long long value;
    unsigned long long value_two;
    char *op;
} SeccompArgConstraint;

typedef struct {
    char **caps;
    size_t caps_count;
    char **arches;
    size_t arch_count;
    
    char *min_kernel;
} SeccompFilter;

typedef struct {
    char **names;
    size_t names_count;

    char *action;

    SeccompFilter *include;
    SeccompFilter *exclude;

    SeccompArgConstraint *args;
    size_t args_count;
    
    char *comment;
} SeccompSyscallRule;

typedef struct {
    char *default_action;
    int default_errno_ret;

    char **architectures;
    size_t arch_count;
    
    SeccompSyscallRule *syscalls;
    size_t syscalls_count;
} SeccompProfile;

int parse_JSON (const char *file_path, SeccompProfile *profile);
void free_profile(SeccompProfile *profile);

#endif