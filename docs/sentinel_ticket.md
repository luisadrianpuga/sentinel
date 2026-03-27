# sentinel — eBPF-based AI Agent Behavioral Monitor

> Attach kernel probes to a running AI agent. Learn what normal looks like. Alert on deviation.

---

## The goal

Build an open-source tool that any developer running an AI agent on Linux can drop in
and immediately see what their agent is *actually* doing at the kernel level.

One command to install. One command to run. Real-time output. PostgreSQL backend.
Shareable on GitHub. The kind of project that gets retweeted by Brendan Gregg.

This is not a demo. It is a tool other engineers will use.

---

## The idea

AI agents execute code, open files, make network calls, spawn processes. Most monitoring
happens at the application layer — you log what the agent *says* it did. `sentinel` watches
what it *actually* does at the kernel level, where nothing can hide.

Built for Mantis. Designed for any agent running on Linux.

---

## Why this matters

- Anthropic is building this exact thing internally (eBPF security sensors for agent safety)
- Datadog, Falco, Cilium are all eBPF-native
- Almost no application engineers have kernel observability experience
- You already have the mental model from your kernel/syscall coursework
- Mantis is running right now on the Pi — real test subject, day one

---

## Mental model

You already know this:
```
userspace process → syscall → kernel
```

eBPF adds:
```
userspace process → syscall → kernel → your eBPF program fires → logs event
```

It's an event listener. The events are kernel operations.
`open()` a file → your handler runs.
`connect()` to a network address → your handler runs.
`execve()` a subprocess → your handler runs.

You're not modifying the kernel. You're subscribing to it.

---

## v1 scope — keep it tight

**Goal:** trace every syscall made by the Mantis agent process and log it to PostgreSQL.

That's it. No anomaly detection yet. No alerting. Just ground truth visibility.

### What you'll build

```
sentinel/
├── bpf/
│   └── trace.c          # eBPF program (C, ~50 lines)
│                        # attaches to: openat, connect, execve, write
├── main.go              # Go daemon
│                        # loads the eBPF program
│                        # reads events from ring buffer
│                        # writes to PostgreSQL
├── db/
│   └── schema.sql       # events table
└── README.md
```

### Events table

```sql
CREATE TABLE agent_events (
    id          SERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ DEFAULT NOW(),
    pid         INTEGER,
    comm        TEXT,          -- process name
    syscall     TEXT,          -- openat / connect / execve
    arg         TEXT,          -- filename / ip:port / command
    agent_run   TEXT           -- optional: tag by Mantis session
);
```

### What a run looks like

```
[2026-03-19 22:14:01] pid=1847 comm=python3 syscall=openat  arg=/home/mantis/.config/mantis/memory.db
[2026-03-19 22:14:01] pid=1847 comm=python3 syscall=connect arg=api.openai.com:443
[2026-03-19 22:14:02] pid=1847 comm=python3 syscall=openat  arg=/tmp/mantis_scratch_4f2a.txt
[2026-03-19 22:14:03] pid=1847 comm=python3 syscall=execve  arg=/bin/bash -c "ls /home/mantis"
```

That's ground truth. The agent cannot lie to this.

---

## Distribution — how users get and run this

```bash
git clone https://github.com/luisadrianpuga/sentinel
cd sentinel
make install    # installs clang, llvm, libbpf — no restart required
sudo make run AGENT="python3 mantis.py"
```

`make install` installs system dependencies only. No kernel modules, no reboot.
eBPF programs load and unload at runtime — they attach when sentinel starts,
detach when it stops. Clean, reversible, no permanent changes to the system.

`sudo` is required to load eBPF programs into the kernel. One-time elevation per run.

---

## Three usage modes

**1. Live terminal** — watch your agent in real time
```
[22:14:01] openat   /home/user/.config/mantis/memory.db
[22:14:01] connect  api.anthropic.com:443
[22:14:02] execve   /bin/bash -c "ls /tmp"
[22:14:03] openat   /tmp/scratch_4f2a.txt
```

**2. Query mode** — ask questions about past runs
```bash
sentinel query --syscall connect       # every network call ever made
sentinel query --arg /etc              # anything that touched /etc
sentinel query --session yesterday     # full yesterday run
```

**3. Diff mode** — compare two runs
```bash
sentinel diff session_1 session_2      # what changed between runs?
```

---

## Storage — SQLite by default, PostgreSQL opt-in

Zero-setup path: SQLite is the default. No database configuration required.
Power users can point it at PostgreSQL with `DATABASE_URL` in `.env`.

This removes the biggest friction point for adoption.

---

## Requirements

- Linux kernel 5.8+ (Ubuntu 20.04+, Debian 11+)
- sudo access (eBPF needs kernel privileges to load)
- Go 1.23+
- clang + libbpf (installed via `make install`)
- matching kernel headers if your distro publishes them

**No restart. No kernel modules. No permanent changes.**

---

## Who uses this

1. **AI agent developers** — "what is my agent actually doing?"
2. **Security engineers** — "is this agent making calls it shouldn't?"
3. **Researchers** — behavioral fingerprinting across different LLM agents
4. **You** — ground truth visibility into Mantis, forever

---

## Stack

| Layer | Tech |
|---|---|
| eBPF programs | C (small, kernel-side logic) |
| eBPF loader | Go + [cilium/ebpf](https://github.com/cilium/ebpf) |
| Storage | SQLite (default) / PostgreSQL (opt-in) |
| Target | Any Linux kernel 5.8+, developed on Raspberry Pi 4 |
| Test subject | Mantis agent (`python3 mantis.py`) |

---

## Step 0 — verify the Pi can run eBPF

```bash
ssh mantis@192.168.1.246
uname -r                          # need 5.8+ for ring buffers
ls /sys/kernel/debug/tracing      # debugfs must be mounted
cat /proc/sys/kernel/perf_event_paranoid  # ideally <= 2
```

## Step 1 — install tools on Pi

```bash
sudo apt install -y golang-go clang llvm libbpf-dev
```

If your distro exposes matching kernel headers, install them separately:

```bash
sudo apt install -y linux-headers-$(uname -r)
```

On Raspberry Pi or other vendor kernels, that package name may not exist in the
default repositories. Install the core toolchain first and only chase headers if
the BPF build specifically requires them.

## Step 1b — set up .gitignore before writing any code

Do this before your first commit. Trace logs contain real agent behavior —
file paths, network destinations, subprocess commands. Keep them local.

```gitignore
# trace logs and DB files — never commit these
data/
*.db
*.sqlite

# environment
.env

# Go build artifacts
sentinel
*.o
```

Optional: add a note to your README so users know the same rule applies to them:

```
> Trace logs are written to `data/` by default and are gitignored.
> To share a trace for debugging, export it manually with:
> sentinel export --session <id>
```

Code is public. Data stays local.

## Step 2 — write the eBPF program (trace.c)

Attach to `sys_enter_openat`, `sys_enter_connect`, `sys_enter_execve`.
Filter by PID (Mantis's PID). Send events to a ring buffer.

## Step 3 — write the Go loader (main.go)

Use `cilium/ebpf` to:
1. Compile and load `trace.c` into the kernel
2. Attach probes to the syscalls
3. Read from the ring buffer
4. Write events to PostgreSQL

## Step 4 — run against Mantis

Start `sentinel`, then start Mantis. Watch every kernel interaction appear in real time.

## Step 5 — v2 ideas (after v1 works)

- Baseline mode: record a "normal" Mantis run, save the fingerprint
- Alert mode: flag deviations (unexpected network destinations, new file paths, subprocess spawns)
- Dashboard: add an `agent_events` tab to the jobbot Next.js dashboard
- Extend to jobbot harvest.py: what does a harvest run actually touch?

---

## The resume line (after v1)

> Built `sentinel`, an eBPF-based behavioral monitor for AI agent processes —
> attaches kernel probes via cilium/ebpf to trace syscalls, file access, and
> network activity in real time. Runs on Linux (Raspberry Pi), stores events
> in PostgreSQL. Built to provide ground-truth observability for autonomous agents.

---

## The interview angle

**At Anthropic:**
> "Anthropic is building eBPF sensors for agent containment. I built a version of that
> independently — attaching kernel probes to watch what my local agent actually does
> vs what it reports doing. The ground truth layer."

**At Datadog / Cilium / any observability company:**
> "I've worked at both layers — application-level instrumentation and kernel-level
> eBPF probes. I understand why eBPF wins for security: the process can't lie to
> the kernel observer."

**At any company running agents in production:**
> "The hardest problem in agent safety isn't alignment — it's visibility. You need
> to know what the agent actually did. eBPF is how you get that."

---

## Resources

- [cilium/ebpf](https://github.com/cilium/ebpf) — Go library, industry standard
- [Learning eBPF](https://isovalent.com/books/learning-ebpf/) — Liz Rice, free PDF
- [BCC tools](https://github.com/iovisor/bcc) — reference implementations in Python/C
- [Falco](https://github.com/falcosecurity/falco) — open source runtime security, study the architecture
- Your kernel syscall coursework — the mental model is already there

---

*Start with Step 0. If the Pi can run eBPF, you're building tomorrow.*
