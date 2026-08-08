FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY target.c .
COPY entrypoint.sh .

RUN gcc -no-pie -g -fno-omit-frame-pointer -O0 -Wall \
        -o target target.c \
    && chmod +x entrypoint.sh

# Default CLI arg if none supplied at `docker run` time -- override with:
#   docker run ... image /some/other/path
CMD ["/etc/hostname"]

ENTRYPOINT ["/app/entrypoint.sh"]
