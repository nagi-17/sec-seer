#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/utsname.h>
#include "ctx-build.h"

static uint32_t map_action_string(const char *action_str, int default_errno_ret) {
    if (action_str == NULL)
        return SCMP_ACT_ALLOW;

    if (strcmp(action_str, "SCMP_ACT_ALLOW") == 0)
        return SCMP_ACT_ALLOW;
    if (strcmp(action_str, "SCMP_ACT_ERRNO") == 0)
        return SCMP_ACT_ERRNO(default_errno_ret);
    if (strcmp(action_str, "SCMP_ACT_KILL") == 0)
        return SCMP_ACT_KILL;
    if (strcmp(action_str, "SCMP_ACT_KILL_PROCESS") == 0)
        return SCMP_ACT_KILL_PROCESS;
    if (strcmp(action_str, "SCMP_ACT_KILL_THREAD") == 0)
        return SCMP_ACT_KILL_THREAD;
    if (strcmp(action_str, "SCMP_ACT_TRAP") == 0)
        return SCMP_ACT_TRAP;
    if (strcmp(action_str, "SCMP_ACT_TRACE") == 0)
        return SCMP_ACT_TRACE(0); // trace with data=0; TODO: allow custom value
    if (strcmp(action_str, "SCMP_ACT_LOG") == 0)
        return SCMP_ACT_LOG;
    if (strcmp(action_str, "SCMP_ACT_NOTIFY") == 0)
        return SCMP_ACT_NOTIFY;

    fprintf(stderr, "Warning: unknown action '%s', defaulting to SCMP_ACT_ALLOW\n", action_str);
    return SCMP_ACT_ALLOW;
}

static uint32_t map_arch_string(const char *arch_str) {
    if (arch_str == NULL)
        return SCMP_ARCH_NATIVE;

    if (strcmp(arch_str, "SCMP_ARCH_NATIVE") == 0) return SCMP_ARCH_NATIVE;
    if (strcmp(arch_str, "SCMP_ARCH_X86") == 0) return SCMP_ARCH_X86;
    if (strcmp(arch_str, "SCMP_ARCH_X86_64") == 0) return SCMP_ARCH_X86_64;
    if (strcmp(arch_str, "SCMP_ARCH_X32") == 0) return SCMP_ARCH_X32;
    if (strcmp(arch_str, "SCMP_ARCH_ARM") == 0) return SCMP_ARCH_ARM;
    if (strcmp(arch_str, "SCMP_ARCH_AARCH64") == 0) return SCMP_ARCH_AARCH64;
    if (strcmp(arch_str, "SCMP_ARCH_MIPS") == 0) return SCMP_ARCH_MIPS;
    if (strcmp(arch_str, "SCMP_ARCH_MIPS64") == 0) return SCMP_ARCH_MIPS64;
    if (strcmp(arch_str, "SCMP_ARCH_MIPS64N32") == 0) return SCMP_ARCH_MIPS64N32;
    if (strcmp(arch_str, "SCMP_ARCH_MIPSEL") == 0) return SCMP_ARCH_MIPSEL;
    if (strcmp(arch_str, "SCMP_ARCH_MIPSEL64") == 0) return SCMP_ARCH_MIPSEL64;
    if (strcmp(arch_str, "SCMP_ARCH_MIPSEL64N32") == 0) return SCMP_ARCH_MIPSEL64N32;
    if (strcmp(arch_str, "SCMP_ARCH_PPC") == 0) return SCMP_ARCH_PPC;
    if (strcmp(arch_str, "SCMP_ARCH_PPC64") == 0) return SCMP_ARCH_PPC64;
    if (strcmp(arch_str, "SCMP_ARCH_PPC64LE") == 0) return SCMP_ARCH_PPC64LE;
    if (strcmp(arch_str, "SCMP_ARCH_S390") == 0) return SCMP_ARCH_S390;
    if (strcmp(arch_str, "SCMP_ARCH_S390X") == 0) return SCMP_ARCH_S390X;
    if (strcmp(arch_str, "SCMP_ARCH_PARISC") == 0) return SCMP_ARCH_PARISC;
    if (strcmp(arch_str, "SCMP_ARCH_PARISC64") == 0) return SCMP_ARCH_PARISC64;
    if (strcmp(arch_str, "SCMP_ARCH_RISCV64") == 0) return SCMP_ARCH_RISCV64;

    fprintf(stderr, "Warning: unknown arch '%s', defaulting to SCMP_ARCH_NATIVE\n",
            arch_str);
    return SCMP_ARCH_NATIVE;
}

static int map_cmp_op_string(const char *op_str) {
    if (op_str == NULL)
        return SCMP_CMP_EQ;

    if (strcmp(op_str, "SCMP_CMP_NE") == 0)         return SCMP_CMP_NE;
    if (strcmp(op_str, "SCMP_CMP_LT") == 0)         return SCMP_CMP_LT;
    if (strcmp(op_str, "SCMP_CMP_LE") == 0)         return SCMP_CMP_LE;
    if (strcmp(op_str, "SCMP_CMP_EQ") == 0)         return SCMP_CMP_EQ;
    if (strcmp(op_str, "SCMP_CMP_GE") == 0)         return SCMP_CMP_GE;
    if (strcmp(op_str, "SCMP_CMP_GT") == 0)         return SCMP_CMP_GT;
    if (strcmp(op_str, "SCMP_CMP_MASKED_EQ") == 0)  return SCMP_CMP_MASKED_EQ;

    fprintf(stderr, "Warning: unknown cmp op '%s', defaulting to SCMP_CMP_EQ\n",
            op_str);
    return SCMP_CMP_EQ;
}


// Policy: ALLOW stays ALLOW; everything else becomes SCMP_ACT_TRACE(0).
static uint32_t resolve_rule_action(const SeccompSyscallRule *rule, int syscall_id, int default_errno_ret) {
    (void)syscall_id;

    if (rule->action == NULL)
        return SCMP_ACT_ALLOW;

    uint32_t mapped = map_action_string(rule->action, default_errno_ret);

    if (mapped == SCMP_ACT_ALLOW)
        return SCMP_ACT_ALLOW;

    return SCMP_ACT_TRACE(0);
}

static int arch_matches(const char **arches, size_t arch_count, const SeccompRuntimeContext *runtime_ctx) {
    if (arches == NULL || arch_count == 0)
        return 1;

    if (runtime_ctx == NULL || runtime_ctx->current_arch == NULL)
        return 1;

    for (size_t i = 0; i < arch_count; i++) {
        if (arches[i] == NULL)
            continue;
        // SCMP_ARCH_NATIVE matches whatever the current architecture actually is.
        if (strcmp(arches[i], "SCMP_ARCH_NATIVE") == 0)
            return 1;
        if (strcmp(arches[i], runtime_ctx->current_arch) == 0)
            return 1;
    }

    return 0;
}

static int caps_match(const char **caps, size_t caps_count, const SeccompRuntimeContext *runtime_ctx) {
    if (caps == NULL || caps_count == 0)
        return 1;

    if (runtime_ctx == NULL || runtime_ctx->held_caps == NULL)
        return 0;

    for (size_t i = 0; i < caps_count; i++) {
        int found = 0;
        for (size_t j = 0; j < runtime_ctx->held_caps_count; j++) {
            if (runtime_ctx->held_caps[j] != NULL &&
                strcmp(caps[i], runtime_ctx->held_caps[j]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }

    return 1;
}

static int kernel_matches(const char *min_kernel, const SeccompRuntimeContext *runtime_ctx) {
    if (min_kernel == NULL || min_kernel[0] == '\0')
        return 1;

    if (runtime_ctx == NULL)
        return 0;

    unsigned int req_major = 0, req_minor = 0;
    if (sscanf(min_kernel, "%u.%u", &req_major, &req_minor) != 2)
        return 0;

    if (runtime_ctx->kernel_major > req_major)
        return 1;
    if (runtime_ctx->kernel_major < req_major)
        return 0;

    return runtime_ctx->kernel_minor >= req_minor;
}

static int rule_applies(const SeccompSyscallRule *rule, const SeccompRuntimeContext *runtime_ctx) {
    if (rule == NULL)
        return 0;

    if (rule->include != NULL) {
        SeccompFilter *inc = rule->include;
        if (!arch_matches((const char **)inc->arches, inc->arch_count, runtime_ctx))
            return 0;
        if (!caps_match((const char **)inc->caps, inc->caps_count, runtime_ctx))
            return 0;
        if (!kernel_matches(inc->min_kernel, runtime_ctx))
            return 0;
    }

    if (rule->exclude != NULL) {
        SeccompFilter *exc = rule->exclude;
        if (arch_matches((const char **)exc->arches, exc->arch_count, runtime_ctx) &&
            caps_match((const char **)exc->caps, exc->caps_count, runtime_ctx) &&
            kernel_matches(exc->min_kernel, runtime_ctx))
            return 0;
    }

    return 1;
}

static int build_held_caps(SeccompRuntimeContext *ctx) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: could not open /proc/self/status\n");
        return -EIO;
    }

    char line[512];
    unsigned long long cap_eff = 0;
    int found = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            cap_eff = strtoull(line + 7, NULL, 16);
            found = 1;
            break;
        }
    }
    fclose(fp);

    if (!found)
        return -EIO;

    size_t count = 0;
    for (int i = 0; i < 64; i++) {
        if (cap_eff & (1ULL << i))
            count++;
    }

    if (count == 0)
        return 0;

    ctx->held_caps = calloc(count, sizeof(char *));
    if (ctx->held_caps == NULL)
        return -ENOMEM;

    size_t idx = 0;
    for (int i = 0; i < 64; i++) {
        if (cap_eff & (1ULL << i)) {
            char name[64];
            
            snprintf(name, sizeof(name), "CAP_%d", i);
            ctx->held_caps[idx] = strdup(name);
            if (ctx->held_caps[idx] == NULL) {

                for (size_t k = 0; k < idx; k++)
                    free(ctx->held_caps[k]);
                free(ctx->held_caps);
                ctx->held_caps = NULL;
                
                return -ENOMEM;
            }
            idx++;
        }
    }

    ctx->held_caps_count = count;
    return 0;
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

    /* Parse uts.machine -> ctx->current_arch (e.g. "x86_64" ->
     * "SCMP_ARCH_X86_64"). */
    const char *arch_str = NULL;
    if (strcmp(uts.machine, "x86_64") == 0)        arch_str = "SCMP_ARCH_X86_64";
    else if (strcmp(uts.machine, "i386") == 0 ||
             strcmp(uts.machine, "i486") == 0 ||
             strcmp(uts.machine, "i586") == 0 ||
             strcmp(uts.machine, "i686") == 0)     arch_str = "SCMP_ARCH_X86";
    else if (strcmp(uts.machine, "aarch64") == 0)  arch_str = "SCMP_ARCH_AARCH64";
    else if (strcmp(uts.machine, "armv7l") == 0 ||
             strcmp(uts.machine, "armv6l") == 0)   arch_str = "SCMP_ARCH_ARM";
    else if (strcmp(uts.machine, "ppc64le") == 0)  arch_str = "SCMP_ARCH_PPC64LE";
    else if (strcmp(uts.machine, "ppc64") == 0)    arch_str = "SCMP_ARCH_PPC64";
    else if (strcmp(uts.machine, "ppc") == 0)      arch_str = "SCMP_ARCH_PPC";
    else if (strcmp(uts.machine, "s390x") == 0)    arch_str = "SCMP_ARCH_S390X";
    else if (strcmp(uts.machine, "s390") == 0)     arch_str = "SCMP_ARCH_S390";
    else if (strcmp(uts.machine, "riscv64") == 0)  arch_str = "SCMP_ARCH_RISCV64";
    else if (strcmp(uts.machine, "mips") == 0)     arch_str = "SCMP_ARCH_MIPS";
    else if (strcmp(uts.machine, "mips64") == 0)   arch_str = "SCMP_ARCH_MIPS64";
    else                                           arch_str = "SCMP_ARCH_NATIVE";

    ctx->current_arch = strdup(arch_str);
    if (ctx->current_arch == NULL)
        return -ENOMEM;

    unsigned int major = 0, minor = 0;
    if (sscanf(uts.release, "%u.%u", &major, &minor) != 2) {
        fprintf(stderr, "Warning: could not parse kernel version '%s'\n", uts.release);
        major = 0;
        minor = 0;
    }
    ctx->kernel_major = major;
    ctx->kernel_minor = minor;


    int ret = build_held_caps(ctx);
    if (ret != 0) {
        fprintf(stderr, "Error: could not read capability info\n");
        free_runtime_context(ctx);
        return ret;
    }

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

// main build ctx functions
static int add_arg_rule(scmp_filter_ctx ctx, uint32_t action, int syscall_id, const SeccompSyscallRule *rule) {
    if (rule->args_count == 0 || rule->args_count > UINT_MAX)
        return -EINVAL;

    struct scmp_arg_cmp *cmp_array = calloc(rule->args_count, sizeof(struct scmp_arg_cmp));
    if (cmp_array == NULL)
        return -ENOMEM;

    for (size_t i = 0; i < rule->args_count; i++) {
        const SeccompArgConstraint *arg = &rule->args[i];
        cmp_array[i].arg = arg->index;
        cmp_array[i].op = (enum scmp_compare)map_cmp_op_string(arg->op);
        cmp_array[i].datum_a = (scmp_datum_t)arg->value;
        cmp_array[i].datum_b = (scmp_datum_t)arg->value_two;
    }

    int rc = seccomp_rule_add_array(ctx, action, syscall_id, rule->args_count, cmp_array);
    free(cmp_array);
    return rc;
}

scmp_filter_ctx build_seccomp_context(const SeccompProfile *profile, const SeccompRuntimeContext *runtime_ctx) {
    if (profile == NULL || runtime_ctx == NULL)
        return NULL;

    uint32_t default_action = map_action_string(profile->default_action, profile->default_errno_ret);

    scmp_filter_ctx ctx = seccomp_init(default_action);
    if (ctx == NULL) {
        fprintf(stderr, "Error: seccomp_init() failed\n");
        return NULL;
    }

    // architectures or profile->arch_map
    for (size_t i = 0; i < profile->arch_map_count; i++) {
        SeccompArchMap *map = &profile->arch_map[i];

        uint32_t arch = map_arch_string(map->architecture);
        if (arch == SCMP_ARCH_NATIVE) {
            fprintf(stderr, "Warning: architecture '%s' resolves to SCMP_ARCH_NATIVE "
                            "(already the default); skipping\n", map->architecture);
        }
        int rc = seccomp_arch_add(ctx, arch);
        if (rc != 0 && rc != -EEXIST) {
            fprintf(stderr, "Error: seccomp_arch_add() failed for %s\n", map->architecture);
            goto fail;
        }

        for (size_t j = 0; j < map->sub_arch_count; j++) {
            uint32_t sub_arch = map_arch_string(map->sub_architectures[j]);
            rc = seccomp_arch_add(ctx, sub_arch);
            if (rc != 0 && rc != -EEXIST) {
                fprintf(stderr, "Error: seccomp_arch_add() failed for sub-arch %s\n", map->sub_architectures[j]);
                goto fail;
            }
        }
    }

    // syscall rules
    for (size_t i = 0; i < profile->syscalls_count; i++) {
        SeccompSyscallRule *rule = &profile->syscalls[i];

        if (!rule_applies(rule, runtime_ctx))
            continue;

        for (size_t j = 0; j < rule->names_count; j++) {
            int syscall_id = seccomp_syscall_resolve_name(rule->names[j]);
            if (syscall_id == __NR_SCMP_ERROR) {
                fprintf(stderr, "Warning: unknown syscall '%s', skipping\n", rule->names[j]);
                continue;
            }

            uint32_t action = resolve_rule_action(rule, syscall_id, profile->default_errno_ret);

            int rc;
            if (rule->args_count > 0) {
                rc = add_arg_rule(ctx, action, syscall_id, rule);
            } else {
                rc = seccomp_rule_add(ctx, action, syscall_id, 0);
            }

            if (rc != 0) {
                fprintf(stderr, "Error: seccomp_rule_add() failed for '%s'\n", rule->names[j]);
                goto fail;
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
