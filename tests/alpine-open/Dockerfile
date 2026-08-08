FROM alpine:3.20

# Alpine uses musl libc, not glibc -- this is the point of this container:
# testing whether syscall-name-based profile matching holds up against a
# different libc, since musl and glibc don't always map C functions to the
# same underlying syscalls (e.g. open() vs openat() aliasing on some archs).
RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY target.c .


RUN gcc -no-pie -g -fno-omit-frame-pointer -O0 -Wall \
        -o target target.c 

ENTRYPOINT ["/app/target"]
