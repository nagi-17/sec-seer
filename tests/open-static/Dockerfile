FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY target.c .

# -static:   no ld.so, no dynamic-linker startup noise (mmap/mprotect/read
#            before main() even runs) -- cleanest possible syscall trace.
# -no-pie:   fixed load address, no ASLR -- simplest case for the symbolizer.
# -g:        keep debug info (DWARF line numbers).
RUN gcc -static -no-pie -g -fno-omit-frame-pointer -O0 -Wall \
        -o target target.c 

ENTRYPOINT ["/app/target"]
