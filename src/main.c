#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>

#include <vector.h>
#include "observer/observer.h"
#include "policy-translator/json-deserializer/json-parser.h"
#include "policy-translator/ctx-generator/ctx-build.h"

#define OPTSTR "t:p:l:h"
#define MAX_COMMAND_LEN 1024

static const struct option long_options[] = {
    {"target",  required_argument, NULL, 't'},
    {"profile", required_argument, NULL, 'p'},
    {"log",     required_argument, NULL, 'l'},
    {"help",    no_argument,       NULL, 'h'},
    {NULL,      0,                 NULL,  0 }
};

static char **split_command(const char *cmd);

int main(int argc, char *argv[], char *envp[]) {
    char *target_binary = NULL;
    char *json_profile = NULL;
    char *logfile = NULL;
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

            case 'l':
                if(logfile) {
                    fprintf(stderr, "Invalid command line arguments, please specify only a single file for logs.\n");
                    exit(EXIT_FAILURE);
                }
                logfile = optarg;
                break;    

            case 'h':
                printf("Usage: %s --target <shell command> --profile <path> --log <path>\n", argv[0]);
                printf("  -t, --target   Shell command to run test binary\n");
                printf("  -p, --profile  Path to JSON seccomp configuration file\n");
                printf("  -l, --log      Path to file for JSON logs\n");
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

    if (!target_binary || !json_profile || !logfile) {
        fprintf(stderr, "Error: missing required arguments.\n");
        fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    SeccompProfile profile;
    if (parse_JSON(json_profile, &profile) < 0) {
        exit(EXIT_FAILURE);
    }
    
    // build the runtime context (kernel version, current arch, held caps)
    // used by build_seccomp_context() to apply include/exclude filters
    SeccompRuntimeContext runtime_ctx;
    if (build_runtime_context(&runtime_ctx) < 0) {
        free_profile(&profile);
        exit(EXIT_FAILURE);
    }

    // code to fetch ctx from parsed json
    // pass array of structs into libseccomp stuff
    // returns ctx
    scmp_filter_ctx seccomp_ctx = build_seccomp_context(&profile, &runtime_ctx);
    if (seccomp_ctx == NULL) {
        fprintf(stderr, "Error: failed to build seccomp context from profile.\n");
        free_profile(&profile);
        exit(EXIT_FAILURE);
    }

    char **target_argv = split_command(target_binary);

    pid_t pid;
    if ((pid = fork()) < 0) {
        perror("Error starting target program[fork]");
        exit(EXIT_FAILURE);
    }
    if (pid == 0) {
        
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("Error setting TRACEME");
            _exit(EXIT_FAILURE);
        }

        // this raise is to make sure parent has time to setup PTRACE_SETOPTIONS before child loads seccomp filter
        raise(SIGTRAP);

        // TODO: fetch ctx from parsed json
        // TODO: load the seccomp context

        // code to load the context
        if (seccomp_load(seccomp_ctx) < 0) {
            perror("Error loading seccomp context");
            _exit(EXIT_FAILURE);
        }
        seccomp_context_free(seccomp_ctx);

        if (execve(target_argv[0], target_argv, envp) < 0) {
            perror("Error starting target program[execve]");
            _exit(EXIT_FAILURE);
        };
    } 
    else if (pid > 0) {
        int status;
        struct user_regs_struct regs;

        // Wait for the child's initial SIGTRAP handshake
        waitpid(pid, &status, 0);

        if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD) < 0) {
            perror("Error setting ptrace options");
            kill(pid, SIGKILL);
            exit(EXIT_FAILURE);
        }

        observer_loop(pid, status, regs, logfile);

        free_profile(&profile);
        free_runtime_context(&runtime_ctx);
        char** ptr = target_argv;
        while(*ptr) {
            free(*ptr);
            ptr++;
        }
        free(target_argv);
        ptr = NULL;
        target_argv = NULL;
    }

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