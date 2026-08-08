#!/bin/sh
# Individual entrypoint for the "mkdir-nosym" test (no debug symbols).
#
# --- MODE A (current) ---
exec /app/target

# --- MODE B (once seccomp-tracer CLI exists) ---
# exec /usr/local/bin/seccomp-tracer /app/profile-trace.json -- /app/target
