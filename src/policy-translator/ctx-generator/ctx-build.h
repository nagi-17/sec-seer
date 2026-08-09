#ifndef SECCOMP_PARSER_H
#define SECCOMP_PARSER_H

#include <stddef.h>
#include <seccomp.h>
#include "json-parser.h"

typedef struct {
    char *current_arch;

    char **held_caps;
    size_t held_caps_count;

    unsigned int kernel_major;
    unsigned int kernel_minor;
} SeccompRuntimeContext;

int build_runtime_context(SeccompRuntimeContext *ctx);

void free_runtime_context(SeccompRuntimeContext *ctx);

scmp_filter_ctx build_seccomp_context(const SeccompProfile *profile, const SeccompRuntimeContext *runtime_ctx);

void seccomp_context_free(scmp_filter_ctx ctx);

#endif