#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "json-parser.h"
#include "parson.h"

static char* safe_strdup(const char* src) {
    return src ? strdup(src) : NULL;
}

static int fileJSON_to_str (const char *file_path, char **out_str) {
    if (!file_path || !out_str)
        return -EINVAL;

    *out_str = NULL;

    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Can't open file\n");
        return -ENOENT;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: fseek failed\n");
        fclose(file);
        return -EIO;
    }

    long len = ftell(file);
    if (len < 0) {
        fprintf(stderr, "Error: ftell failed\n");
        fclose(file);
        return -EIO;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: fseek failed\n");
        fclose(file);
        return -EIO;
    }

    char *buff = malloc((size_t)len + 1);
    if (buff == NULL) {
        fprintf(stderr, "Error: Buffer allocation failed\n");
        fclose(file);
        return -ENOMEM;
    }

    size_t bytes_read = fread(buff, 1, (size_t)len, file);
    if (bytes_read < (size_t)len) {
        fprintf(stderr, "Error: Couldn't read the file\n");
        free(buff);
        fclose(file);
        return -EIO;
    }

    buff[bytes_read] = '\0';

    fclose(file);

    *out_str = buff;
    return 0;
}

static void free_profile(SeccompProfile *profile) {
    if (profile == NULL)
        return;

    if (profile->architectures) {
        for (size_t i = 0; i < profile->arch_count; i++)
            free(profile->architectures[i]);
        free(profile->architectures);
    }

    if (profile->syscalls) {
        for (size_t i = 0; i < profile->syscalls_count; i++) {
            SeccompSyscallRule *rule = &profile->syscalls[i];

            if (rule->names) {
                for (size_t j = 0; j < rule->names_count; j++)
                    free(rule->names[j]);
                free(rule->names);
            }

            if (rule->args) {
                for (size_t j = 0; j < rule->args_count; j++)
                    free(rule->args[j].op);
                free(rule->args);
            }

            free(rule->action);
            free(rule->comment);
        }
        free(profile->syscalls);
    }

    free(profile->default_action);

    memset(profile, 0, sizeof(SeccompProfile));
}

int parse_JSON (const char *file_path, SeccompProfile *profile) {
    if (file_path == NULL || profile == NULL)
        return -EINVAL;

    int ret = 0;
    char *string_JSON = NULL;
    JSON_Value *root_value = NULL;
    JSON_Object *root_obj = NULL;

    memset(profile, 0, sizeof(SeccompProfile));

    ret = fileJSON_to_str(file_path, &string_JSON);
    if (ret != 0) {
        fprintf(stderr, "Error: Could not read file into string\n");
        goto cleanup;
    }

    root_value = json_parse_string(string_JSON);
    if (root_value == NULL) {
        fprintf(stderr, "Error: Invalid JSON string\n");
        ret = -EINVAL;
        goto cleanup;
    }

    root_obj = json_value_get_object(root_value);
    if (root_obj == NULL) {
        fprintf(stderr, "Error: Couldn't get root object\n");
        ret = -EINVAL;
        goto cleanup;
    }

    profile->default_action = safe_strdup(json_object_get_string(root_obj, "defaultAction"));
    profile->default_errno_ret = (int)json_object_get_number(root_obj, "defaultErrnoRet");

    JSON_Array *arch_arr = json_object_get_array(root_obj, "architectures");
    if (arch_arr) {
        profile->arch_count = json_array_get_count(arch_arr);

        if (profile->arch_count > 0) {
            profile->architectures = calloc(profile->arch_count, sizeof(char *));

            if (profile->architectures == NULL) {
                fprintf(stderr, "Error: Architectures allocation failed\n");
                ret = -ENOMEM;
                goto cleanup;
            }

            for (size_t i = 0; i < profile->arch_count; i++) {
                profile->architectures[i] = safe_strdup(json_array_get_string(arch_arr, i));
            }
        } else {
            // error handling - what if arch is empty in input config file
        }
    } else {
        // error handling - what if arch is absent in input config file
    }

    JSON_Array *syscall_arr = json_object_get_array(root_obj, "syscalls");
    if (syscall_arr) {
        profile->syscalls_count = json_array_get_count(syscall_arr);

        if (profile->syscalls_count > 0){
            profile->syscalls = calloc(profile->syscalls_count, sizeof(SeccompSyscallRule));

            if (profile->syscalls == NULL) {
                fprintf(stderr, "Error: Syscalls allocation failed\n");
                ret = -ENOMEM;
                goto cleanup;
            }

            for (size_t i = 0; i < profile->syscalls_count; i++) {
                JSON_Object *syscall_obj = json_array_get_object(syscall_arr, i);

                if (syscall_obj == NULL) {
                    fprintf(stderr, "Error: Couldn't get syscall object\n");
                    ret = -EINVAL;
                    goto cleanup;
                }

                SeccompSyscallRule *syscall_rule = &(profile->syscalls[i]);

                syscall_rule->action = safe_strdup(json_object_get_string(syscall_obj, "action"));
                syscall_rule->comment = safe_strdup(json_object_get_string(syscall_obj, "comment"));

                JSON_Array *names_arr = json_object_get_array(syscall_obj, "names");
                if (names_arr){
                    syscall_rule->names_count = json_array_get_count(names_arr);

                    if (syscall_rule->names_count > 0){

                        syscall_rule->names = calloc(syscall_rule->names_count, sizeof(char *));

                        if (syscall_rule->names == NULL) {
                            fprintf(stderr, "Error: Names of syscall allocation failed\n");
                            ret = -ENOMEM;
                            goto cleanup;
                        }

                        for (size_t j = 0; j < syscall_rule->names_count; j++) {
                            syscall_rule->names[j] = safe_strdup(json_array_get_string(names_arr, j));
                        }
                    }
                }

                JSON_Array *arg_arr = json_object_get_array(syscall_obj, "args");
                if (arg_arr){
                    syscall_rule->args_count = json_array_get_count(arg_arr);

                    if (syscall_rule->args_count > 0){
                        syscall_rule->args = calloc(syscall_rule->args_count, sizeof(SeccompArgConstraint));

                        if (syscall_rule->args == NULL) {
                            fprintf(stderr, "Error: Syscall args allocation failed\n");
                            ret = -ENOMEM;
                            goto cleanup;
                        }

                        for (size_t j = 0; j < syscall_rule->args_count; j++) {
                            JSON_Object *arg_obj = json_array_get_object(arg_arr, j);

                            if (arg_obj == NULL) {
                                fprintf(stderr, "Error: Couldn't get args object\n");
                                ret = -EINVAL;
                                goto cleanup;
                            }

                            SeccompArgConstraint *arg = &(syscall_rule->args[j]);

                            arg->index = (unsigned int)json_object_get_number(arg_obj, "index");
                            arg->value = (unsigned long long)json_object_get_number(arg_obj, "value");
                            arg->value_two = (unsigned long long)json_object_get_number(arg_obj, "value_two");
                            arg->op = safe_strdup(json_object_get_string(arg_obj, "op"));
                        }
                    }
                }
            }
        }
        else {
            // IMP error handling - if syscalls arr is empty
        }
    }
    else {
        // IMP error handling - if syscalls are absent
    }

    json_value_free(root_value);
    free(string_JSON);

    return 0;

cleanup:
    free(string_JSON);
    json_value_free(root_value);
    free_profile(profile);
    return ret;
}
