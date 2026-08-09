FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libseccomp2 \
    binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY target.c .

RUN gcc -no-pie -g -fno-omit-frame-pointer -O0 -Wall \
        -o target target.c 

# Default env var if none supplied at `docker run` time -- override with:
#   docker run ... -e MESSAGE="something else" image
ENV MESSAGE="hello from write-env container"

ENTRYPOINT ["/app/target"]
