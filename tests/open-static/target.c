#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

int main(int argc, char *argv[]) {

    srand(time(NULL)); 
    int raw_random = rand();

        if(raw_random % 2){

        const char *path = (argc > 1) ? argv[1] : "/etc/hostname";

        int fd = open(path, O_RDONLY);

        printf("before read()\n");
        fflush(stdout);

        char buf[64];
        ssize_t n = read(fd, buf, sizeof(buf));  // TRACER_TEST_MARKER_LINE

        printf("after read(), n=%zd\n", n);
        fflush(stdout);
        return 0;
    }
    else {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

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
}
