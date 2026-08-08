FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY target.c .

RUN gcc -no-pie -fno-omit-frame-pointer -O0 -Wall \
        -o target target.c

ENTRYPOINT ["/app/target"]
