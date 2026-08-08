FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY target.c .
COPY entrypoint.sh .

# Deliberately NO -g here: no DWARF line-number info in the binary. This is
# the test case for the symbolizer's graceful-degradation path (should
# report "no debug info available" / function-name-only, not crash).
RUN gcc -no-pie -fno-omit-frame-pointer -O0 -Wall \
        -o target target.c \
    && chmod +x entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
