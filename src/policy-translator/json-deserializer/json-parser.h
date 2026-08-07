#ifndef SECCOMP_PROFILE_H
#define SECCOMP_PROFILE_H

#include<stddef.h>

typedef struct {
    unsigned int index;
    unsigned long long value;
    unsigned long long value_two;   // unused
    char *op;                       // e.g. "SCMP_CMP_EQ"
} SeccompArgConstraint;

/*
typedef struct {
    char **caps;           
    size_t caps_count;
    
    char **arches;       
    size_t arch_count;
    
    char *min_kernel;
} SeccompFilter;
 */

typedef struct {
    char **names;
    size_t names_count;
    
    char *action;                   // e.g. "SCMP_ACT_ALLOW"

    // SeccompFilter *include;
    // SeccompFilter *exclude;

    SeccompArgConstraint *args;
    size_t args_count;
    
    char *comment;
} SeccompSyscallRule;

typedef struct {
    char *default_action;
    int default_errno_ret;          // err no. ret on default action
    
    char **architectures;
    size_t arch_count;
    
    SeccompSyscallRule *syscalls;
    size_t syscalls_count;
} SeccompProfile;

#endif