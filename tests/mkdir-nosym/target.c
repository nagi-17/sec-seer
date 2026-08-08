#include <stdio.h>
#include <sys/stat.h>

int main(void) {
    printf("before mkdir()\n");
    fflush(stdout);

    int rc = mkdir("/tmp/seccomp_test_dir", 0755);  // TRACER_TEST_MARKER_LINE

    printf("after mkdir(), rc=%d\n", rc);
    fflush(stdout);
    return 0;
}
