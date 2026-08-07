#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json-parser.h"
#include "parson.h"

char* fileJSONtoString (const char *filePath){
    FILE* file;
    file = fopen(filePath, "rb");
    if (file == NULL) {
        fprintf(stderr, "ERROR: File is not opened\n");
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    long len = ftell(file);
    
    char *buff = malloc(len+1);
    if (buff == NULL) {
        fprintf(stderr, "ERROR: Buffer allocation failed\n");
        fclose(file);
        exit(1);
    }
    
    fseek(file, 0, SEEK_SET);
    size_t bytesRead = fread(buff, 1, len, file);
    if (bytesRead < len){
        fprintf(stderr, "ERROR: Couldn't read the file\n");
        free(buff);
        buff = NULL;
        fclose(file);
        exit(1);
    }
    buff[bytesRead] = '\0';

    fclose(file);
    return buff;
}

void parseJSON (const char *filePath, SeccompProfile* profile){
    char *stringJSON = fileJSONtoString(filePath);
    if (stringJSON == NULL) {
        fprintf(stderr, "ERROR: Could not read file into string\n");
        exit(1); 
    }

    memset(profile, 0, sizeof(SeccompProfile));

    JSON_Value *rootValue = json_parse_string(stringJSON);
    if (rootValue == NULL){
        fprintf(stderr, "ERROR: Invalid JSON string\n");
        exit(1);
    }
    
    free(stringJSON); 
    stringJSON = NULL;
    
    JSON_Object *rootObj = json_value_get_object(rootValue);
    if (rootObj == NULL) {
        fprintf(stderr, "ERROR: Couldn't get root object\n");
        json_value_free(rootValue);
        exit(1);
    }
    
    profile->default_action = safe_strdup(json_object_get_string(rootObj, "defaultAction"));
    profile->default_errno_ret = (int)json_object_get_AtIndex(rootObj, "defaultErrnoRet");
    
    JSON_Array *archArr = json_object_get_array(rootObj, "architectures");
    if (archArr) {
        profile->arch_count = json_array_get_count(archArr);
        if (profile->arch_count > 0) {
            profile->architectures = malloc((profile->arch_count)*sizeof(char *));
            if (profile->architectures == NULL) {
                fprintf(stderr, "ERROR: Architectures malloc allocation failed\n");
                exit(1);
            }
            for (size_t i = 0; i < profile->arch_count; i++) {
                profile->architectures[i] = safe_strdup(json_array_get_string(archArr, i));
            }
        } else {
            // error handling
        }
    } else {
        // error handling
    }
    
    JSON_Array *syscallArr = json_object_get_array(rootObj, "syscalls");
    if (syscallArr) {
        profile->syscalls_count = json_array_get_count(syscallArr);
        if (profile->syscalls_count > 0){
            profile->syscalls = malloc((profile->syscalls_count)*(sizeof(SeccompSyscallRule)));
            if (profile->syscalls == NULL) {
                fprintf(stderr, "ERROR: Syscalls malloc allocation failed\n");
                exit(1);
            }
            
            for (size_t i = 0; i < profile->syscalls_count; i++){
                JSON_Object *syscallObj = json_array_get_object(syscallArr, i);
                if (syscallObj == NULL) {
                    fprintf(stderr, "ERROR: Couldn't get syscall object\n");
                    exit(1);
                }
                
                SeccompSyscallRule* syscallRule = &(profile->syscalls[i]);
                
                syscallRule->action = safe_strdup(json_object_get_string(syscallObj, "action"));
                syscallRule->comment = safe_strdup(json_object_get_string(syscallObj, "comment"));
                
                JSON_Array *namesArr = json_object_get_array(syscallObj, "names");
                if (namesArr){
                    syscallRule->names_count = json_array_get_count(namesArr);
                    if (syscallRule->names_count > 0){
                        
                        syscallRule->names = malloc((syscallRule->names_count)*(sizeof(char *)));
                        if (syscallRule->names == NULL){
                            fprintf(stderr, "ERROR: Names of syscall malloc allocation failed");
                            exit(1);
                        }
                        
                        for (size_t j = 0; j < syscallRule->names_count; j++) {
                            syscallRule->names[j] = safe_strdup(json_array_get_string(namesArr, j));
                        }
                    }
                }
                
                JSON_Array *argArr = json_object_get_array(syscallObj, "args");
                if (argArr){
                    syscallRule->args_count = json_array_get_count(argArr);
                    
                    if (syscallRule->args_count > 0){
                        syscallRule->args = malloc((syscallRule->args_count)*(sizeof(SeccompArgConstraint)));
                        if (syscallRule->args == NULL){
                            fprintf(stderr, "ERROR: Names of syscall args allocation failed");
                            exit(1);
                        }
                        
                        for (size_t j = 0; j < syscallRule->args_count; j++){
                            JSON_Object *argObj = json_array_get_object(argArr, j);
                            if (argObj == NULL) {
                                fprintf(stderr, "ERROR: Couldn't get args object\n");
                                exit(1);
                            }
                            
                            SeccompArgConstraint *arg = &(syscallRule->args[j]);
                            
                            arg->index = (unsigned int)json_object_get_number(argObj, "index");
                            arg->value = (unsigned long long)json_object_get_number(argObj, "value");
                            arg->value_two = (unsigned long long)json_object_get_number(argObj, "value_two");
                            arg->op = safe_strdup(json_object_get_string(argObj, "op"));
                        }
                        
                    }
                }
            }
        }
    }
    json_value_free(rootValue);

    // fix required: exit(1) leaves room for memory leaks

    return;
}