#include <stdio.h>
#include <fcntl.h>

int main(void) {
    printf("before open()\n");
    fflush(stdout);

    int fd = open("/etc/hostname", O_RDONLY);  // TRACER_TEST_MARKER_LINE

    printf("after open(), fd=%d\n", fd);
    fflush(stdout);
    return 0;
}
