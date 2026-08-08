# Test Case Error Reference

Each container in this directory demonstrates a scenario where a banned syscall kills the process.
This file documents what error each test produces, so the tracer/symbolizer can be validated against it.

---

## How to run

```sh
docker build -t mvp-<name> src/tests/<name>
docker run --rm --security-opt seccomp=$(pwd)/src/tests/<name>/profile.json mvp-<name>
```

Note: `docker run --rm` with a banned-syscall kill hangS (see `write-env` / `open-static` below).

---

## connect

- **Profile bans:** `connect`
- **Expected output:** `before connect()`, then the process is killed on `connect()`.
  `after connect()` is never printed (SIGSYS tears the process down immediately).
- **Status:** works as expected.
- **Notes for the tracer:** clean single-syscall kill. `socket()` is allowed, only `connect()` is banned.

---

## mkdir-nosym

- **Profile bans:** `mkdir`
- **Expected output:** `before mkdir()`, then killed on `mkdir()`.
- **Status:** works as expected.
- **Notes for the tracer:** the binary is compiled **without `-g`** (no DWARF debug info).
  This is the symbolizer's graceful-degradation test: it must report
  "no debug info available" / function-name-only instead of crashing.

---

## read-argv

- **Profile bans:** `read`
- **Expected output:** `before read()`, then killed on `read()`.
- **Status:** works as expected.
- **Notes for the tracer:** the target first calls `open()` (allowed) on a CLI-supplied path
  (default `/etc/hostname`), then dies on `read()`. Exercises argv passthrough and a
  two-syscall sequence where only the second is banned.

---

## execve-selfban

- **Profile bans:** `execve` — but **NOT** via `docker --security-opt`.
- **Mechanism:** banning `execve` from outside would kill the container's own launch exec
  (the first `execve()` that starts the entrypoint), so the container would die before it starts.
  Instead, `target.c` installs the filter **in-process** with libseccomp
  (`seccomp_init` / `seccomp_rule_add` / `seccomp_load`) after it's already running,
  then calls `execve("/bin/ls", ...)`.
- **Expected output:** `main: starting`, `filter installed, before execve("/bin/ls")`,
  then killed on the `execve()`.
- **Status:** works as expected.
- **Notes for the tracer:** the killed syscall replaces the address space. The faulting
  instruction is in the *old* binary (the `execve` call site); the symbolizer must map it there.
  This is also the pattern for testing boot-critical syscalls without the `--security-opt` hang.

---

## alpine-open

- **Profile bans:** `open` (only)
- **Expected behavior (intended):** killed on `open("/etc/hostname")`.


---

## write-env

- **Profile bans:** `write`
- **Expected output:** `before write()`, then killed on the raw `write(1, msg, len)`.
- **Actual behavior:** the container **hangs** and `docker run` never returns
  (Ctrl+C required to escape).
- **Root cause (two parts):**
  1. The evidence line went to **stdout**, which is block-buffered when piped — it sat in
     glibc's buffer and was lost when the process died. **Fixed:** evidence line now goes to
     **stderr** (`fprintf(stderr, ...)`), which is unbuffered, so it reaches the terminal.
  2. The **hang itself** is Docker-side: the profile bans `write`, which Docker's runtime
     needs during container startup handshake. The container never reaches "Running"
     (stuck in "Created", `runc create` frozen), so `docker run` never completes.
- **Status:** evidence-line fixed; the hang is a Docker/runc seccomp interaction, not test code.
- **Notes for the tracer:** see `open-static` — same hang cause. If the tracer installs the
  filter in-process (libseccomp, like `execve-selfban`) instead of relying on
  `--security-opt`, the hang is avoided entirely.

---

## open-static

- **Profile bans:** `open` **and** `openat`
- **Expected output:** `before open()`, then killed on `open("/etc/hostname")`
  (glibc dispatches to `openat`; the profile bans both).
- **Actual behavior:** same **hang** as `write-env` — `docker run` never returns.
- **Root cause:** `open`/`openat` are needed by Docker's runtime during container boot, so
  the filter kills the startup handshake and `runc create` never completes.
  Static linking is not the cause.
- **Status:** not fixed — same Docker-side issue as `write-env`.
- **Notes for the tracer:** binary is `-static -no-pie -g`, so it has DWARF but no
  ld.so startup noise — intended as the "cleanest trace" case. Verify whether the tracer's
  symbolizer handles the static binary once the hang is worked around.

---
