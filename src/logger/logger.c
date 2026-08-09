#include "logger.h"
#include <parson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int log_seccomp_violation(const char *file_path, const SeccompViolation *v) {
    if (file_path == NULL || v == NULL) {
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
        json_object_set_number(regs_obj, "rdi", (double)v->rdi);
        json_object_set_number(regs_obj, "rsi", (double)v->rsi);
        json_object_set_number(regs_obj, "rdx", (double)v->rdx);
        json_object_set_number(regs_obj, "r10", (double)v->r10);
        json_object_set_number(regs_obj, "r8", (double)v->r8);
        json_object_set_number(regs_obj, "r9", (double)v->r9);
        json_object_set_number(regs_obj, "rbp", (double)v->rbp);
        json_object_set_number(regs_obj, "rip", (double)v->rip);
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

    FILE *fp = fopen(file_path, "a");
    if (fp == NULL) {
        json_free_serialized_string(serialized);
        json_value_free(root);
        return -1;
    }

    fputs(serialized, fp);
    fputc('\n', fp);
    fclose(fp);

    json_free_serialized_string(serialized);
    json_value_free(root);

    return 0;
}
