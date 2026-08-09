#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/utsname.h>

#include "ctx-build.h"

// helper functions to convert string to real constants
static uint32_t map_action_string(const char *action_str, int default_errno_ret) {
    if (action_str == NULL)
        return SCMP_ACT_ALLOW; // TODO: decide real fallback behavior

    /* TODO: strcmp chain or lookup table for:
     *   SCMP_ACT_ALLOW
     *   SCMP_ACT_ERRNO      -> SCMP_ACT_ERRNO(default_errno_ret)
     *   SCMP_ACT_KILL
     *   SCMP_ACT_KILL_PROCESS
     *   SCMP_ACT_TRAP
     *   SCMP_ACT_TRACE      -> SCMP_ACT_TRACE(some_value)
     *   SCMP_ACT_LOG
     *   SCMP_ACT_NOTIFY
     */

    (void)action_str;
    (void)default_errno_ret;
    return SCMP_ACT_ALLOW;
}

static uint32_t map_arch_string(const char *arch_str) {
    // TODO: strcmp chain or lookup table for SCMP_ARCH_* constants
    (void)arch_str;
    return SCMP_ARCH_NATIVE;
}

static int map_cmp_op_string(const char *op_str) {
    // TODO: strcmp chain or lookup table for SCMP_CMP_* values
    (void)op_str;
    return SCMP_CMP_EQ;
}

// override trace
/*
    TODO: Decide if non-ALLOW actions get rewritten to SCMP_ACT_TRACE(...)
    so ptrace gets control instead of the kernel silently blocking or not
    so basically finalize exact policy (which actions get overridden vs passed
    through as-is).
*/

static uint32_t resolve_rule_action(const SeccompSyscallRule *rule, int syscall_id, int default_errno_ret) {
    (void)rule;
    (void)syscall_id;
    (void)default_errno_ret;

    /* TODO: apply map_action_string() then override per policy */
    return SCMP_ACT_TRACE(0);
}

// include/exclude helper functions
static int arch_matches(const char **arches, size_t arch_count, const SeccompRuntimeContext *runtime_ctx) {
    /* TODO: return 1 if runtime_ctx->current_arch appears in arches[] */
    (void)arches;
    (void)arch_count;
    (void)runtime_ctx;
    return 1;
}

static int caps_match(const char **caps, size_t caps_count, const SeccompRuntimeContext *runtime_ctx) {
    (void)caps;
    (void)caps_count;
    (void)runtime_ctx;
    return 1;
}

static int kernel_matches(const char *min_kernel, const SeccompRuntimeContext *runtime_ctx) {
    /* TODO: parse min_kernel and compare against
     * runtime_ctx->kernel_major / kernel_minor */
    (void)min_kernel;
    (void)runtime_ctx;
    return 1;
}

/*
 * Returns 1 if the rule should be applied given the current runtime
 * context (taking include/exclude filters into account), 0 otherwise.
 */
static int rule_applies(const SeccompSyscallRule *rule, const SeccompRuntimeContext *runtime_ctx) {
    if (rule->include != NULL) {
        /* TODO: rule only applies if arch_matches && caps_match &&
         * kernel_matches against rule->include's fields */
    }

    if (rule->exclude != NULL) {
        /* TODO: rule is skipped if arch_matches && caps_match &&
         * kernel_matches against rule->exclude's fields */
    }

    (void)rule;
    (void)runtime_ctx;
    return 1;
}

int build_runtime_context(SeccompRuntimeContext *ctx) {
    if (ctx == NULL)
        return -EINVAL;

    memset(ctx, 0, sizeof(SeccompRuntimeContext));

    struct utsname uts;
    if (uname(&uts) != 0) {
        fprintf(stderr, "Error: uname() failed\n");
        return -EIO;
    }

    /* TODO: parse uts.machine -> ctx->current_arch (e.g. "x86_64" ->
     * "SCMP_ARCH_X86_64") */

    /* TODO: parse uts.release -> ctx->kernel_major / kernel_minor */

    /* TODO: read /proc/self/status "CapEff" line (or use libcap) to
     * populate ctx->held_caps / held_caps_count */

    return 0;
}

void free_runtime_context(SeccompRuntimeContext *ctx) {
    if (ctx == NULL)
        return;

    free(ctx->current_arch);

    if (ctx->held_caps) {
        for (size_t i = 0; i < ctx->held_caps_count; i++)
            free(ctx->held_caps[i]);
        free(ctx->held_caps);
    }

    memset(ctx, 0, sizeof(SeccompRuntimeContext));
}

// main build func

scmp_filter_ctx build_seccomp_context(const SeccompProfile *profile, const SeccompRuntimeContext *runtime_ctx) {
    if (profile == NULL || runtime_ctx == NULL)
        return NULL;

    uint32_t default_action = map_action_string(profile->default_action,
                                                  profile->default_errno_ret);

    scmp_filter_ctx ctx = seccomp_init(default_action);
    if (ctx == NULL) {
        fprintf(stderr, "Error: seccomp_init() failed\n");
        return NULL;
    }

    /* TODO: add architectures from profile->arch_map */
    for (size_t i = 0; i < profile->arch_map_count; i++) {
        SeccompArchMap *map = &profile->arch_map[i];

        uint32_t arch = map_arch_string(map->architecture);
        int rc = seccomp_arch_add(ctx, arch);
        if (rc != 0 && rc != -EEXIST) {
            fprintf(stderr, "Error: seccomp_arch_add() failed for %s\n",
                    map->architecture);
            goto fail;
        }

        for (int j = 0; j < map->sub_arch_count; j++) {
            uint32_t sub_arch = map_arch_string(map->sub_architectures[j]);
            rc = seccomp_arch_add(ctx, sub_arch);
            if (rc != 0 && rc != -EEXIST) {
                fprintf(stderr, "Error: seccomp_arch_add() failed for sub-arch %s\n",
                        map->sub_architectures[j]);
                goto fail;
            }
        }
    }

    /* TODO: add syscall rules */
    for (size_t i = 0; i < profile->syscalls_count; i++) {
        SeccompSyscallRule *rule = &profile->syscalls[i];

        if (!rule_applies(rule, runtime_ctx))
            continue;

        for (size_t j = 0; j < rule->names_count; j++) {
            int syscall_id = seccomp_syscall_resolve_name(rule->names[j]);
            if (syscall_id == __NR_SCMP_ERROR) {
                fprintf(stderr, "Warning: unknown syscall '%s', skipping\n",
                        rule->names[j]);
                continue; /* TODO: decide skip-vs-fail policy */
            }

            uint32_t action = resolve_rule_action(rule, syscall_id,
                                                    profile->default_errno_ret);

            int rc;
            if (rule->args_count > 0) {
                /* TODO: build struct scmp_arg_cmp[] from rule->args using
                 * map_cmp_op_string(), then call seccomp_rule_add_array() */
                rc = 0; /* placeholder */
            } else {
                rc = seccomp_rule_add(ctx, action, syscall_id, 0);
            }

            if (rc != 0) {
                fprintf(stderr, "Error: seccomp_rule_add() failed for '%s'\n",
                        rule->names[j]);
                goto fail; /* TODO: decide fail-fast vs skip-and-continue */
            }
        }
    }

    return ctx;

fail:
    seccomp_release(ctx);
    return NULL;
}

void seccomp_context_free(scmp_filter_ctx ctx) {
    if (ctx != NULL)
        seccomp_release(ctx);
}