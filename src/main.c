#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#define OPTSTR "t:p:h"
static const struct option long_options[] = {
        {"target",  required_argument, NULL, 't'},
        {"profile", required_argument, NULL, 'p'},
        {"help",    no_argument,       NULL, 'h'},
        {NULL,      0,                 NULL,  0 }
    };

int main(int argc, char *argv[]) {
    char *target_binary = NULL;
    char *json_profile = NULL;
    int opt;

    while ((opt = getopt_long(argc, argv, OPTSTR, long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                target_binary = optarg;
                break;
                
            case 'p':
                json_profile = optarg;
                break;
                
            case 'h':
                printf("Usage: %s --target <path> --profile <name>\n", argv[0]);
                printf("  -t, --target   Path to target file\n");
                printf("  -p, --profile  Configuration profile name\n");
                exit(EXIT_SUCCESS);
                
            default:
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!target_binary || !json_profile) {
        fprintf(stderr, "Error: Both --target (-t) and --profile (-p) are required.\n");
        fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("Successfully parsed arguments:\n");
    printf("  Target Path  : %s\n", target_binary);
    printf("  Profile Name : %s\n", json_profile);

    return 0;
}