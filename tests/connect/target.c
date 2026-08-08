#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);  /* socket() is allowed here */

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    printf("before connect()\n");
    fflush(stdout);

    int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));  // TRACER_TEST_MARKER_LINE

    printf("after connect(), rc=%d\n", rc);
    fflush(stdout);
    return 0;
}
