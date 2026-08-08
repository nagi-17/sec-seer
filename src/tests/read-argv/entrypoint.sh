#!/bin/sh
# Individual entrypoint for the "read-argv" test.
# "$@" passes through whatever CLI arg was given (default: /etc/hostname,
# set via Dockerfile CMD; override with `docker run ... image /some/path`).
#
# --- MODE A (current) ---
exec /app/target "$@"

# --- MODE B (once seccomp-tracer CLI exists) ---
# exec /usr/local/bin/seccomp-tracer /app/profile-trace.json -- /app/target "$@"
