#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>

#include "vendor/vector.h"

#define OPTSTR "t:p:h"
#define MAX_COMMAND_LEN 1024

static const struct option long_options[] = {
    {"target",  required_argument, NULL, 't'},
    {"profile", required_argument, NULL, 'p'},
    {"help",    no_argument,       NULL, 'h'},
    {NULL,      0,                 NULL,  0 }
};

static char **split_command(const char *cmd);

int main(int argc, char *argv[], char *envp[]) {
    char *target_binary = NULL;
    char *json_profile = NULL;
    int opt;

    while ((opt = getopt_long(argc, argv, OPTSTR, long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                if(target_binary) {
                    fprintf(stderr, "Invalid command line arguments, please specify only a single target.\n");
                    exit(EXIT_FAILURE);
                }
                target_binary = optarg;
                break;
                
            case 'p':
                if(json_profile) {
                    fprintf(stderr, "Invalid command line arguments, please specify only a single seccomp profile.\n");
                    exit(EXIT_FAILURE);
                }
                json_profile = optarg;
                break;
                
            case 'h':
                printf("Usage: %s --target <shell command> --profile <path>\n", argv[0]);
                printf("  -t, --target   Shell command to run test binary\n");
                printf("  -p, --profile  Path to JSON seccomp configuration file\n");
                exit(EXIT_SUCCESS);
                
            default:
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    // prevent user from entering random junk stuff in command line alongside options
    if (optind < argc) {
        fprintf(stderr, "Error: unexpected argument '%s'\n", argv[optind]);
        fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!target_binary || !json_profile) {
        fprintf(stderr, "Error: Both --target (-t) and --profile (-p) are required.\n");
        fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char **target_argv = split_command(target_binary);
    execve(target_argv[0], target_argv, envp);
    //code to pass json 
    //pass json_profile name into it
    //it returns array of structs
    
    //code to fetch ctx from parsed json
    //pass array of structs into libseccomp stuff
    //returns ctx

    /*pid_t pid = fork();
    if(pid == 0) {
        //code to load the context
        execve()
    }*/

    return 0;
}

// make the function static so that it is not accessible by other files
static char **split_command(const char *cmd) {
    Vector args;
    
    if (vector_setup(&args, 4, sizeof(char *)) == VECTOR_ERROR) {
        fprintf(stderr, "Error: failed to allocate arg vector.\n");
        exit(EXIT_FAILURE);
    }

    if (!memchr(cmd, '\0', MAX_COMMAND_LEN+1)) {
        fprintf(stderr, "Error: extremely long argument for target option.");
        exit(EXIT_FAILURE);
    }

    const char* start = cmd;
    const char* end = cmd;
    while(*end != '\0') {
        if (!isspace((unsigned char)*end)) {
            if ( (isspace((unsigned char)*(end + 1))) || (*(end+1) == '\0') ) {
                size_t arg_sz = end - start + 1; // end - start + 1 for normal characters
                char *arg = (char *)malloc(arg_sz + 1); // one extra slot to add null terminator
                if(!arg) {
                    fprintf(stderr, "Error: out of memory.\n");
                    exit(EXIT_FAILURE);
                }
                strncpy(arg, start, arg_sz);
                arg[arg_sz] =  '\0'; 
                if (vector_push_back(&args, &arg) == VECTOR_ERROR) {
                    fprintf(stderr, "Error: failed to expand arg vector.\n");
                    exit(EXIT_FAILURE);
                }
                end++;
                continue;            
            }
        }
        else if (!isspace((unsigned char)*(end + 1))) { // start of a new argument or a null byte
            end++;
            start = end;
            continue;
        }
        end++;
    }
    
    if(args.size == 0) {
        fprintf(stderr, "Error: empty target command.\n");
        exit(EXIT_FAILURE);
    }

    char **argv = (char **)malloc((args.size + 1) * sizeof(char *));  // +1 for NULL
    if (!argv) {
        fprintf(stderr, "Error: out of memory.\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < (int)args.size; i++)
        argv[i] = VECTOR_GET_AS(char *, &args, i);

    argv[args.size] = NULL; 
    vector_destroy(&args);
    return argv;           
    
}