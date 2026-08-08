#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *msg = getenv("MESSAGE");
    if (!msg) msg = "no MESSAGE env var set";

    /*  Evidence line goes to stderr: stderr is unbuffered, so it reaches the
        terminal even though stdout's "before write()" would sit in glibc's
        buffer and be lost when the process is killed on the write() below. */
    fprintf(stderr, "before write()\n");

    size_t len = strlen(msg);
    write(1, msg, len);  // TRACER_TEST_MARKER_LINE
    write(1, "\n", 1);

    return 0;
}
