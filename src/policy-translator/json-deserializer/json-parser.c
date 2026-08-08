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

static void free_filter_contents(SeccompFilter *filter) {
    if (filter == NULL)
        return;

    if (filter->caps) {
        for (size_t i = 0; i < filter->caps_count; i++)
            free(filter->caps[i]);
        free(filter->caps);
    }

    if (filter->arches) {
        for (size_t i = 0; i < filter->arch_count; i++)
            free(filter->arches[i]);
        free(filter->arches);
    }

    free(filter->min_kernel);
    memset(filter, 0, sizeof(SeccompFilter));
}

void free_profile(SeccompProfile *profile) {
    if (profile == NULL)
        return;

    if (profile->arch_map) {
        for (size_t i = 0; i < profile->arch_map_count; i++) {
            SeccompArchMap *map = &profile->arch_map[i];

            free(map->architecture);

            if(map->sub_architectures) {
                for (int j = 0; j < map->sub_arch_count; j++) {
                    free(map->sub_architectures[j]);
                }

                free(map->sub_architectures);
            }
        }
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

            if (rule->include) {
                free_filter_contents(rule->include);
                free(rule->include);
            }
            if (rule->exclude) {
                free_filter_contents(rule->exclude);
                free(rule->exclude);
            }

            free(rule->action);
            free(rule->comment);
        }
        free(profile->syscalls);
    }

    free(profile->default_action);

    memset(profile, 0, sizeof(SeccompProfile));
}

static SeccompFilter *parse_filter(const JSON_Object *obj) {
    if (obj == NULL)
        return NULL;

    SeccompFilter *filter = calloc(1, sizeof(SeccompFilter));
    if (filter == NULL)
        return NULL;

    JSON_Array *caps_arr = json_object_get_array(obj, "caps");
    if (caps_arr) {
        filter->caps_count = json_array_get_count(caps_arr);
        if (filter->caps_count > 0) {
            filter->caps = calloc(filter->caps_count, sizeof(char *));
            if (filter->caps == NULL) {
                goto fail;
            }
            for (size_t i = 0; i < filter->caps_count; i++)
                filter->caps[i] = safe_strdup(json_array_get_string(caps_arr, i));
        }
    }

    JSON_Array *arches_arr = json_object_get_array(obj, "arches");
    if (arches_arr) {
        filter->arch_count = json_array_get_count(arches_arr);
        if (filter->arch_count > 0) {
            filter->arches = calloc(filter->arch_count, sizeof(char *));
            if (filter->arches == NULL) {
                goto fail;
            }
            for (size_t i = 0; i < filter->arch_count; i++)
                filter->arches[i] = safe_strdup(json_array_get_string(arches_arr, i));
        }
    }

    filter->min_kernel = safe_strdup(json_object_get_string(obj, "minKernel"));

    return filter;

fail:
    free_filter_contents(filter);
    free(filter);
    return NULL;
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
    if (profile->default_action == NULL) {
        fprintf(stderr, "Error: Missing mandatory field 'defaultAction'\n");
        ret = -EINVAL;
        goto cleanup;
    }

    profile->default_errno_ret = (int)json_object_get_number(root_obj, "defaultErrnoRet");

    JSON_Array *arch_map = json_object_get_array(root_obj, "archMap");
    if (arch_map) {
        profile->arch_map_count = json_array_get_count(arch_map);

        if (profile->arch_map_count > 0) {
            profile->arch_map = calloc(profile->arch_map_count, sizeof(SeccompArchMap));

            if (profile->arch_map == NULL) {
                fprintf(stderr, "Error: Architectures Map allocation failed\n");
                ret = -ENOMEM;
                goto cleanup;
            }

            for (size_t i = 0; i < profile->arch_map_count; i++) {
                JSON_Object *arch_map_obj = json_array_get_object(arch_map, i);

                if (arch_map_obj == NULL) {
                    fprintf(stderr, "Error: Couldn't get arch map object\n");
                    ret = -EINVAL;
                    goto cleanup;
                }

                SeccompArchMap *arch_obj = &profile->arch_map[i];
                
                arch_obj->architecture = safe_strdup(json_object_get_string(arch_map_obj, "architecture"));
                
                JSON_Array *sub_arch_arr = json_object_get_array(arch_map_obj, "subArchitectures");
                if (sub_arch_arr) {
                    arch_obj->sub_arch_count = json_array_get_count(sub_arch_arr);

                    if (arch_obj->sub_arch_count > 0) {
                        arch_obj->sub_architectures = calloc(arch_obj->sub_arch_count, sizeof(char *));

                        if (arch_obj->sub_architectures == NULL) {
                            fprintf(stderr, "Error: Sub-architecture array of arch map allocation failed\n");
                            ret = -ENOMEM;
                            goto cleanup;
                        }

                        for (size_t j = 0; j < arch_obj->sub_arch_count; j++) {
                            arch_obj->sub_architectures[j] = safe_strdup(json_array_get_string(sub_arch_arr, j));
                        }
                    }
                }
            }
        } else {
            fprintf(stderr, "Warning: 'archMap' is empty; proceeding without architectures\n");
        }
    } else {
        fprintf(stderr, "Warning: 'archMap' field is missing; proceeding without architectures\n");
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

                syscall_rule->include = parse_filter(json_object_get_object(syscall_obj, "include"));
                syscall_rule->exclude = parse_filter(json_object_get_object(syscall_obj, "exclude"));

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
            fprintf(stderr, "Warning: 'syscalls' array is empty; proceeding without syscalls\n");
        }
    }
    else {
        fprintf(stderr, "Warning: 'syscalls' field is missing; proceeding without syscalls\n");
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
