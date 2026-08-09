# sec-seer

A ptrace-based seccomp policy tracer and violation observer. sec-seer runs a target binary under a JSON seccomp policy, catches every syscall the policy blocks, and logs each violation — with register state, the resolved syscall name, and the exact source location (`file:line`, function) recovered via `addr2line` — as human-readable JSON.

Instead of killing the offending process silently, sec-seer intercepts the denial and tells you *what* was blocked, *where* in the code it happened, and *when*.

## Why do we need it

Seccomp policies are built on the principle of least privilege: a program should be allowed only the syscalls it actually needs, and nothing more. In practice this means **bans** — sensitive syscalls that the program is never supposed to touch are explicitly blocked.

There are two problems this creates, and they are exactly what sec-seer solves:

1. **Silent, unexplained crashes.** When a program violates its policy, the kernel kills it immediately. Because the developer *assumed* that syscall would never be called, there is no warning, no log, and no debug info — the process just blows up, and you are left asking *which* syscall, *where* in the code, and *when*. Without a tracer, tracking that down is painful guesswork.

2. **Unbounded syscall access is a security hole.** If a program places no restrictions on the syscalls it may issue, any malicious actor who finds a way to drive that program (a bug, an injection, a compromised input) can make it do things it was never meant to do — read or write files it should not touch, open sockets, spawn processes, and so on. Banning syscalls the program does not need shrinks that attack surface to the bare minimum.

So banning sensitive syscalls is necessary for security, but it is only half the story: you also need to *see* the violations when they happen. sec-seer is the visibility half — it turns an opaque `SIGSYS` kill into a structured, debuggable record of exactly what was attempted and from where.

## How it works

```
  policy JSON ──► JSON parser ──► SeccompProfile ──► seccomp context builder (libseccomp)
                                                         │
target binary ──► fork + ptrace(TRACEME) ────────────────┤
                                                         ▼
                              PTRACE_EVENT_SECCOMP stop on banned syscall
                                                         │
                                              observer loop (observer.c)
                                                         │
                       ┌─────────────────────────────────┴─────────────────────────┐
                       ▼                                                           ▼
              register dump (rdi/rsi/rdx/r10/r8/r9/rbp/rip)              JSON log (logger.c)
              + syscall name + addr2line source resolution            appended to --log file
```

1. `parse_JSON()` (via [parson](https://github.com/kgabis/parson)) deserializes the seccomp profile into a typed `SeccompProfile`.
2. `build_seccomp_context()` converts it into a real libseccomp filter. Rules are evaluated against the runtime environment — architecture, kernel version, and the process's effective capabilities — through the `include`/`exclude`/`minKernel`/`arches`/`caps` fields on each rule.
3. The target runs in a forked child under `ptrace(PTRACE_TRACEME)`. The tracer sets `PTRACE_O_TRACESECCOMP`, so the kernel stops the child at every syscall the filter flags with `SCMP_ACT_TRACE`.
4. On each stop the observer grabs the full register set, resolves the syscall name with `seccomp_syscall_resolve_num_arch()`, maps `RIP` back to source with `addr2line -f -e <exe> <rip>`, and appends a JSON violation record to the log file.

## Building

```
make
```

Dependencies:

- **libseccomp** (headers + library) — syscall resolution and filter context
- **gcc**, **glibc** development headers
- `addr2line` (binutils) — source-location resolution, invoked at runtime
- parson (vendored in `include/`) and the `vector` helper (MIT) — no extra step

Install commands by base image / distro:

```sh
# 1. Ubuntu / Debian / Ubuntu-based containers
apt-get update && apt-get install -y \
    libseccomp-dev \
    binutils

# 2. Alpine Linux containers
apk add --no-cache \
    libseccomp-dev \
    binutils

# 3. Fedora / RHEL / CentOS / Rocky Linux
dnf install -y \
    libseccomp-devel \
    binutils
```

## Usage

```
./main --target "<shell command>" --profile <path> --log <path>
```

| Option | Description |
| --- | --- |
| `-t, --target` | Shell command that runs the binary under test |
| `-p, --profile` | Path to the JSON seccomp policy file |
| `-l, --log`    | Path of the JSON log file violations are appended to |
| `-h, --help`   | Show usage |

Example:

```sh
./main --target "./target" --profile profile.json --log violations.json
```

### Running inside Docker

The product can be run as a container so the target binary runs in a clean, predictable environment. `--cap-add=SYS_PTRACE` is required for ptrace, and the profile and log paths are bind-mounted in so the container can read your policy and write violations back to your host:

```sh
docker run \
  --cap-add=SYS_PTRACE \
  -v /path/to/your/seccomp/profile.json:/profile.json \
  -v /path/to/your/product/install:/secsee \
  -v /path/to/your/log/file.json:/log.json \
  --entrypoint /secsee \
  connect-test \
  -p /profile.json \
  -l /log.json \
  -t "/path/to/the/target/binary"
```

Replace each placeholder with your own paths:

| Placeholder | Your value |
| --- | --- |
| `/path/to/your/seccomp/profile.json` | Your seccomp policy file defining which syscalls are banned |
| `/path/to/your/product/install` | The directory where you installed the sec-seer binary |
| `/path/to/your/log/file.json` | The file where you want violations logged as JSON |
| `/path/to/the/target/binary` | The binary you want to run under the policy (the `-t` argument) |

### Policy format

The profile is a Docker-style seccomp JSON document. The only mandatory field is `defaultAction`; `archMap`, `syscalls`, and per-rule `include`/`exclude` filters are optional. Actions and comparison operators use the `SCMP_ACT_*` / `SCMP_CMP_*` string constants.

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "defaultErrnoRet": 1,
  "archMap": [
    { "architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"] }
  ],
  "syscalls": [
    {
      "names": ["connect"],
      "action": "SCMP_ACT_KILL",
      "args": []
    },
    {
      "names": ["openat"],
      "action": "SCMP_ACT_ERRNO",
      "args": [
        { "index": 0, "op": "SCMP_CMP_EQ", "value": 0, "value_two": 0 }
      ]
    }
  ]
}
```

Rule fields:

| Field | Meaning |
| --- | --- |
| `names` | Syscall names the rule applies to |
| `action` | `SCMP_ACT_*` action; anything except `SCMP_ACT_ALLOW` is rewritten to `SCMP_ACT_TRACE(0)` so the tracer can observe it |
| `args` | Optional argument constraints (`index`, `op`, `value`, `value_two`) |
| `include` / `exclude` | Environment filters — `arches`, `caps`, `minKernel` |
| `comment` | Free-form annotation (parsed and freed, not currently used by the filter builder) |

### Violation log

Each violation is appended as one pretty-printed JSON object:

```json
{
  "pid": 12345,
  "timestamp": "2026-08-09 12:34:56",
  "syscall": 41,
  "syscall_name": "connect",
  "registers": {
    "rdi": 3, "rsi": 140737354313912, "rdx": 16, "r10": 0,
    "r8": 0, "r9": 0, "rbp": 140737488346176, "rip": 140737345234567
  },
  "function": "main",
  "file": "/app/target.c:18"
}
```

## Project layout

```
src/
├── main.c                         CLI, arg parsing, fork + ptrace setup
├── observer/observer.c            PTRACE_EVENT_SECCOMP loop, register dump, addr2line resolution
├── logger/logger.c                Appends JSON violation records to the log file
└── policy-translator/
    ├── json-deserializer/json-parser.c   JSON → SeccompProfile (parson)
    └── ctx-generator/ctx-build.c         SeccompProfile → libseccomp filter ctx
include/
├── parson.c / parson.h           vendored JSON parser
└── vector.c / vector.h           dynamic array helper (MIT)
tests/
├── connect/                      bans connect(); clean single-syscall kill
├── mkdir-nosym/                  bans mkdir(); built without -g (no DWARF)
├── read-argv/                    bans read(); exercises argv passthrough
├── execve-selfban/               bans execve() in-process via libseccomp
├── alpine-open/                  bans open()
├── write-env/                    bans write(); hangs under docker run (runc handshake)
├── open-static/                  bans open/openat; -static -no-pie -g; also hangs in Docker
└── READMEERROR.md                expected-vs-actual behavior for every test case
```

## Testing

Each `tests/<name>/` directory is a self-contained container: a `Dockerfile`, a `target.c`, and a `profile.json`. Build and run one with:

```sh
docker build -t mvp-<name> tests/<name>
docker run --rm --security-opt seccomp=$(pwd)/tests/<name>/profile.json mvp-<name>
```

Test binaries are compiled `-no-pie -g -fno-omit-frame-pointer` so `addr2line` gets reliable frame and DWARF info. Two of these flags are hard requirements for every test container:

- **Debug symbols (`-g`).** The tracer resolves violation `RIP`s back to source with `addr2line`, which needs DWARF debug info; without it the log loses the `file:line`/`function` fields (see the `mkdir-nosym` graceful-degradation case below).
- **`-no-pie`** (position-independent code disabled). A PIE binary relocates at load time, so absolute addresses like `RIP` don't line up with the DWARF mapping; `-no-pie` keeps the link address stable and lets `addr2line` resolve correctly.

## Roadmap

- [ ] Wire `build_seccomp_context()` output into the child (currently stubbed with a `TODO` in `main.c`) so the target actually runs under the parsed policy
- [ ] Support `SCMP_ACT_TRACE(n)` with a custom trace value
- [ ] Handle `rip` at the `execve` call site after address-space replacement (see `execve-selfban`)
- [ ] Kernel-version / capability-aware rule matching is already in `ctx-build.c` but needs the runtime context wired into the observer flow
