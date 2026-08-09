FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libseccomp2 \
    binutils \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY target.c .

RUN gcc -no-pie -g -fno-omit-frame-pointer -O0 -Wall \
        -o target target.c 

CMD ["/etc/hostname"]

ENTRYPOINT ["/app/target"]
