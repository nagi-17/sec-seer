#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    const char *path = (argc > 1) ? argv[1] : "/etc/hostname";

    int fd = open(path, O_RDONLY);  /* open is allowed in this profile */

    printf("before read()\n");
    fflush(stdout);

    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));  // TRACER_TEST_MARKER_LINE

    printf("after read(), n=%zd\n", n);
    fflush(stdout);
    return 0;
}
