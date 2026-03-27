# sentinel — Phase 2: Process Tree Tracing and Expanded Syscall Coverage

---

## Context

Phase 1 delivered a working v1: attach to a single PID, trace four syscalls
(`openat`, `connect`, `execve`, `write`), persist to SQLite or PostgreSQL,
query and diff sessions. Validated end-to-end on Raspberry Pi (kernel 6.12,
arm64) and macOS (stub build).

Phase 2 addresses the two most significant gaps discovered during real-world
use: the single-PID limitation and missing syscall coverage.

---

## Problem 1 — Process tree is invisible

Most AI agents spawn subprocesses. A Python agent using `subprocess.run`,
`os.system`, or `asyncio.create_subprocess_exec` forks a child with a new PID.
That child is completely invisible to sentinel today — it has a different PID
and the BPF filter drops all its events.

This means an agent can shell out to `curl`, `git`, `bash`, or any other
binary and sentinel sees nothing.

### Proposed fix

Track the process tree by following `clone`/`fork`/`vfork` events. When a
traced PID clones a child, add the child PID to the filter set automatically.

Implementation options:

**Option A — BPF map of watched PIDs (preferred)**
Replace the single-entry `target_pid` array map with a hash map of watched
PIDs. The `trace_clone` tracepoint inserts the new child PID into the map
whenever the parent is already in the map. All other tracepoints check
membership via `bpf_map_lookup_elem` instead of a scalar compare.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // pid
    __type(value, __u8);  // 1 = watched
} watched_pids SEC(".maps");
```

This is purely kernel-side and requires no userspace polling.

**Option B — Userspace /proc polling**
Periodically scan `/proc` for processes whose `ppid` matches a watched PID.
Simpler to implement but introduces latency and can miss short-lived children.

Option A is the right approach.

---

## Problem 2 — Missing syscall coverage

The four syscalls in v1 cover basic read/connect/exec/write. The following
are commonly triggered by AI agents and currently invisible:

### High priority

| Syscall | Why it matters |
|---|---|
| `clone` / `fork` / `vfork` | Required for process tree tracking (see above) |
| `unlinkat` / `unlink` | File deletion — agents that clean up after themselves |
| `renameat` / `rename` | File moves — writing to a temp path then renaming |
| `sendto` / `sendmsg` | Data sent over network sockets (complement to `connect`) |
| `kill` | Signal sending — agents that manage other processes |

### Medium priority

| Syscall | Why it matters |
|---|---|
| `mkdirat` / `mkdir` | Directory creation |
| `symlinkat` / `symlink` | Symlink creation — can be used to redirect file access |
| `truncate` / `ftruncate` | File truncation without a write |
| `bind` / `listen` / `accept` | Agents that open listening sockets |

### Lower priority (security-relevant but rare in typical agents)

| Syscall | Why it matters |
|---|---|
| `setuid` / `setgid` | Privilege changes |
| `capset` | Capability changes |
| `ptrace` | An agent using ptrace would currently be invisible to sentinel |
| `mount` | Filesystem mounts |
| `memfd_create` | In-memory file execution (common evasion technique) |

---

## Problem 3 — execve captures path only, not argv

`trace_execve` currently stores only the executable path. A call to
`execve("/bin/bash", ["-c", "rm -rf /important"], ...)` looks identical to
`execve("/bin/bash", ["-i"], ...)`.

### Proposed fix

Read up to N argv entries from userspace in the BPF program and concatenate
them into the arg field, space-separated, truncated to `ARG_LEN`.

```c
const char **argv = (const char **)ctx->args[1];
// read argv[0]..argv[3] with bpf_probe_read_user_str, join with spaces
```

The BPF verifier limits loop iterations, so a bounded unroll (e.g. 4 entries)
is the practical approach.

---

## Problem 4 — connect captures address only, not hostname

When an agent connects to an HTTPS endpoint, sentinel records the IP. The
hostname that was resolved is not captured because DNS happens before
`connect`. A connect to `104.18.33.45:443` tells you less than
`api.openai.com:443`.

### Proposed fix (two options)

**Option A — trace getaddrinfo via uprobe on libc**
Attach a uprobe to `getaddrinfo` in libc. Capture the hostname argument and
the resolved address, correlate with subsequent `connect` events by PID and
address. This requires knowing the libc path per process.

**Option B — trace sendmsg for TLS SNI**
For TLS connections, the SNI extension in the ClientHello contains the target
hostname in plaintext. Read it from the first `sendmsg` after `connect` on
port 443. Complex but agent-agnostic.

Option A is simpler for the common case. Option B is more robust across
non-libc runtimes (Go, Rust).

---

## Proposed scope for Phase 2

Ordered by impact:

1. **Process tree tracking** via BPF hash map + `clone` tracepoint
2. **Expanded syscall coverage** — high priority set: `clone`, `unlinkat`,
   `renameat`, `sendto`, `kill`
3. **Full argv capture** for `execve`
4. **DNS correlation** — Option A (libc uprobe), best-effort

Items 1–3 are straightforward extensions of the existing BPF program.
Item 4 is a stretch goal.

---

## Schema changes

The current `agent_events` schema handles all of these without changes —
`syscall` and `arg` are free-form text fields. New syscall types will just
appear as new values in those columns.

The one addition worth considering: a `parent_pid` column to record the
process tree relationship captured at trace time.

---

## Compatibility

All proposed changes are backward-compatible with the existing `query` and
`diff` commands. Existing sessions stored in SQLite remain queryable.

The BPF object (`bpf/trace.bpf.o`) must be recompiled after any BPF changes —
this is already the expected workflow.

---

## Out of scope for Phase 2

- Anomaly detection or baseline learning
- Alerting or policy enforcement
- Dashboard or UI
- Windows or macOS kernel tracing
- Automated integration tests (requires a Linux CI runner with BPF enabled)
