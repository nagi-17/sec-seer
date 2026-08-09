#include "logger.h"
#include <parson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* JSON has no hex number literal, so registers are serialized as "0x..." strings. */
static int write_hex_register(JSON_Object *obj, const char *name, unsigned long long value) {
    char hex[32];
    snprintf(hex, sizeof(hex), "0x%llx", value);
    return json_object_set_string(obj, name, hex);
}

int log_seccomp_violation(const char *file_path, const SeccompViolation *v, int *first_in_array) {
    if (file_path == NULL || v == NULL || first_in_array == NULL) {
        return -1;
    }

    JSON_Value *root = json_value_init_object();
    if (root == NULL) {
        return -1;
    }
    JSON_Object *obj = json_value_get_object(root);

    json_object_set_number(obj, "pid", v->pid);
    if (v->timestamp != NULL) {
        json_object_set_string(obj, "timestamp", v->timestamp);
    }

    json_object_set_number(obj, "syscall", (double)v->syscall);
    if (v->syscall_name != NULL) {
        json_object_set_string(obj, "syscall_name", v->syscall_name);
    }

    JSON_Value *regs = json_value_init_object();
    if (regs != NULL) {
        JSON_Object *regs_obj = json_value_get_object(regs);
        write_hex_register(regs_obj, "rdi", v->rdi);
        write_hex_register(regs_obj, "rsi", v->rsi);
        write_hex_register(regs_obj, "rdx", v->rdx);
        write_hex_register(regs_obj, "r10", v->r10);
        write_hex_register(regs_obj, "r8", v->r8);
        write_hex_register(regs_obj, "r9", v->r9);
        write_hex_register(regs_obj, "rbp", v->rbp);
        write_hex_register(regs_obj, "rip", v->rip);
        json_object_set_value(obj, "registers", regs);
    }

    if (v->resolved_func != NULL) {
        json_object_set_string(obj, "function", v->resolved_func);
    }
    if (v->resolved_file != NULL) {
        json_object_set_string(obj, "file", v->resolved_file);
    }

    char *serialized = json_serialize_to_string_pretty(root);
    if (serialized == NULL) {
        json_value_free(root);
        return -1;
    }

    /* Open once with "a" (create if missing). First violation writes '['. */
    FILE *fp = fopen(file_path, "a");
    if (fp == NULL) {
        json_free_serialized_string(serialized);
        json_value_free(root);
        return -1;
    }

    if (*first_in_array) {
        fputc('[', fp);
        *first_in_array = 0;
    } else {
        fputc(',', fp); /* separate objects within the array */
    }

    fputs(serialized, fp);
    fputc('\n', fp);
    fclose(fp);

    json_free_serialized_string(serialized);
    json_value_free(root);

    return 0;
}

int logger_close(const char *file_path) {
    if (file_path == NULL) {
        return -1;
    }
    FILE *fp = fopen(file_path, "a");
    if (fp == NULL) {
        return -1;
    }
    fputc(']', fp);
    fputc('\n', fp);
    fclose(fp);
    return 0;
}
