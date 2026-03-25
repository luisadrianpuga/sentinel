# sentinel

<p align="center">
  <img src="https://flappy-bird.nyc3.cdn.digitaloceanspaces.com/sentinel_logo.svg" alt="sentinel logo" width="220">
</p>

`sentinel` is an eBPF-based behavioral monitor for AI agent processes on Linux.
It attaches kernel tracepoints to a target process, captures syscall activity in
real time, prints a live event stream, and stores those events for later query
and session-to-session comparison.

The point is simple: application logs tell you what the agent says it did.
`sentinel` gives you a kernel-observed record of what it actually did.

## Why this exists

AI agents execute code, open files, spawn subprocesses, and make network calls.
Most current observability around agents is application-level and therefore easy
to omit, misreport, or simply never instrument. `sentinel` moves the observation
point down to the kernel boundary.

That gives you a ground-truth stream of:

- file access attempts
- outbound connection attempts
- subprocess execution
- write activity

This is useful for:

- AI agent developers validating runtime behavior
- security engineers monitoring allowed vs unexpected actions
- researchers comparing behavioral fingerprints across runs
- anyone debugging why an agent behaved differently than expected

## Current scope

This repository implements a focused v1:

- trace `openat`, `connect`, `execve`, and `write`
- filter events to a single PID
- start a target command or attach to an existing process
- print events live in the terminal
- persist events to SQLite by default
- support PostgreSQL via `DATABASE_URL`
- query historical events by syscall, arg substring, or session
- diff two recorded sessions

This is intentionally not a full detection platform yet. There is no anomaly
detection, alerting, policy engine, or dashboard in the current version.

## How it works

At a high level:

1. A small eBPF program attaches Linux syscall tracepoints.
2. The eBPF program filters events by a configured target PID.
3. Matching events are written into a ring buffer in kernel space.
4. The Go daemon reads events from the ring buffer.
5. Events are logged live and inserted into a local or remote database.

Conceptually:

```text
agent process -> syscall -> kernel -> eBPF tracepoint -> ring buffer -> Go daemon -> database
```

## Architecture

```text
sentinel/
├── bpf/trace.c                # kernel-side eBPF program
├── db/schema.sql              # reference schema
├── internal/sentinel/
│   ├── config.go              # runtime config
│   ├── runner_linux.go        # Linux eBPF loader and event loop
│   ├── runner_other.go        # non-Linux stub
│   └── store.go               # SQLite/PostgreSQL persistence and querying
├── main.go                    # CLI entrypoint
└── Makefile                   # build/install helpers
```

## Supported platforms

`sentinel run` is Linux-only because eBPF loading depends on Linux kernel APIs.

- Supported runtime target: Linux kernel 5.8+
- Developed to build cleanly on non-Linux systems
- On macOS or other non-Linux systems, the project will compile, but `run` will
  return a platform error at runtime

That split is deliberate so development tooling, docs, and storage/query code
can still be worked on outside Linux.

## Requirements

### Runtime requirements

- Linux kernel 5.8+
- `sudo` or equivalent privileges to load eBPF programs
- debug and tracepoint support available in the kernel

### Build requirements

- Go 1.23+
- `clang`
- `llvm`
- `libbpf-dev`
- Linux kernel headers matching the running kernel, if your distro publishes them

On Debian/Ubuntu systems:

```bash
sudo apt install -y golang-go clang llvm libbpf-dev
```

The repository includes a helper target for that:

```bash
make install
```

`make install` installs the system toolchain only. It includes Go so `make build`
can succeed, but it does not build the project by itself.

If your distribution publishes matching kernel headers, you can install them
separately:

```bash
sudo apt install -y linux-headers-$(uname -r)
```

Or use:

```bash
make install-headers
```

Some Raspberry Pi and vendor kernels use custom version strings whose matching
`linux-headers-$(uname -r)` package is not present in the default `apt` repos.
In that case, install the core toolchain above first and only add headers if
your BPF build actually requires them.

## Installation

Clone the repository:

```bash
git clone https://github.com/luisadrianpuga/sentinel
cd sentinel
```

Build the Go binary:

```bash
make build
```

Compile the eBPF object:

```bash
make build-bpf
```

This produces:

- `./sentinel`
- `bpf/trace.bpf.o`

## Quick start

Trace a fresh agent process:

```bash
sudo ./sentinel run --agent "python3 mantis.py" --session mantis_local
```

Or use the `make` shortcut:

```bash
make run AGENT="python3 mantis.py"
```

Attach to an existing process by PID:

```bash
sudo ./sentinel run --pid 1847 --session mantis_existing
```

## Example output

Live terminal output looks like this:

```text
2026/03/19 22:14:01 tracing pid=1847 session=mantis_local
2026/03/19 22:14:01 [2026-03-19 22:14:01] pid=1847 comm=python3 syscall=openat arg=/home/mantis/.config/mantis/memory.db
2026/03/19 22:14:01 [2026-03-19 22:14:01] pid=1847 comm=python3 syscall=connect arg=104.18.33.45:443
2026/03/19 22:14:02 [2026-03-19 22:14:02] pid=1847 comm=python3 syscall=execve arg=/bin/bash
```

The exact formatting of `connect` arguments depends on what the kernel exposes at
trace time. IPv4 and IPv6 socket addresses are handled directly in the eBPF program.

## Commands

### `run`

Start tracing a new command:

```bash
sudo ./sentinel run --agent "python3 mantis.py"
```

Attach to an existing PID:

```bash
sudo ./sentinel run --pid 1847
```

Tag a session:

```bash
sudo ./sentinel run --agent "python3 mantis.py" --session run_2026_03_19
```

Use PostgreSQL explicitly:

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/sentinel?sslmode=disable"
sudo ./sentinel run --agent "python3 mantis.py" --session prod_replay
```

Available flags:

- `--agent`: shell command to start and trace
- `--pid`: attach to an existing process instead of starting one
- `--session`: optional run tag stored with each event
- `--database-url`: explicit database DSN or SQLite file path
- `--sqlite-path`: SQLite path used when `DATABASE_URL` is not set
- `--bpf-object`: compiled eBPF object path, defaults to `bpf/trace.bpf.o`

### `query`

Query historical events from storage:

```bash
./sentinel query --syscall connect
./sentinel query --arg /etc
./sentinel query --session mantis_existing
./sentinel query --syscall openat --arg .config --limit 50
```

Available flags:

- `--syscall`: exact syscall name match
- `--arg`: substring match against the stored arg field
- `--session`: exact session tag match
- `--limit`: maximum number of rows returned, default `100`
- `--database-url`: explicit database DSN or SQLite file path
- `--sqlite-path`: SQLite path used when `DATABASE_URL` is not set

### `diff`

Compare the observed behavior of two sessions:

```bash
./sentinel diff baseline_run changed_run
```

Current diff output compares unique `comm syscall arg` signatures present in one
session and absent in the other.

Available flags:

- `--database-url`: explicit database DSN or SQLite file path
- `--sqlite-path`: SQLite path used when `DATABASE_URL` is not set

## Storage model

By default, `sentinel` writes to SQLite:

- default path: `data/sentinel.db`
- no extra database setup required
- good default for local development and single-node use

If `DATABASE_URL` starts with `postgres://` or `postgresql://`, `sentinel` uses
PostgreSQL instead.

The persisted table shape is:

```sql
CREATE TABLE agent_events (
    id        PRIMARY KEY,
    ts        TIMESTAMPTZ,
    pid       INTEGER,
    comm      TEXT,
    syscall   TEXT,
    arg       TEXT,
    agent_run TEXT
);
```

In practice, the implementation creates the correct auto-incrementing primary key
variant for the selected database engine.

## Event model

Each stored event contains:

- `ts`: event timestamp
- `pid`: process ID
- `comm`: short process name from the kernel
- `syscall`: traced syscall name
- `arg`: syscall-specific summary
- `agent_run`: optional session tag

Current syscall argument capture behavior:

- `openat`: file path
- `connect`: socket destination when available
- `execve`: executable path
- `write`: summary in the form `fd=<n> bytes=<n>`

## Build and development workflow

Standard build:

```bash
make build
make build-bpf
```

Combined run:

```bash
make run AGENT="python3 mantis.py"
```

Clean generated artifacts:

```bash
make clean
```

Local Go verification:

```bash
go test ./...
go build ./...
```

## Security and data handling

Trace data can include sensitive runtime behavior, such as:

- local file paths
- network destinations
- command execution paths
- session identifiers

The repository ignores the default local data paths and database files:

- `data/`
- `*.db`
- `*.sqlite`
- `.env`

That is intentional. The code is meant to be shared; captured traces usually are not.

## Limitations

The current implementation is intentionally narrow and has several important limits:

- it filters only a single PID, not an entire process tree
- `execve` currently stores only the executable path, not full argv
- `connect` stores raw address information, not reverse DNS names
- the eBPF program must be compiled separately into `bpf/trace.bpf.o`
- there is no packaged installer beyond `make` targets
- there is no alerting, baseline learning, or policy enforcement yet
- there are no automated integration tests against a live Linux kernel in this repo
- sub-millisecond processes (e.g. `echo`) may still exit before the PID filter
  is armed, producing no events; use `--pid` on a pre-running process for those

If you need child-process tracing, session tree tracking, DNS enrichment, or a
better behavioral diff, those are natural next steps.

## Troubleshooting

### `sentinel run` fails on macOS

That is expected. The tracing runtime is Linux-only.

### `load bpf object ... no such file`

Compile the eBPF object first:

```bash
make build-bpf
```

### Permission errors while running

Loading eBPF programs typically requires root privileges:

```bash
sudo ./sentinel run --agent "python3 mantis.py"
```

### Build succeeds but tracing fails on Linux

Check:

- your kernel is 5.8 or newer
- required packages are installed
- tracepoints are available
- the eBPF object was compiled on the target Linux environment

### `linux-headers-$(uname -r)` cannot be located

That usually means your system is running a vendor or custom kernel whose exact
header package is not available from the configured repositories.

Start with the core build toolchain:

```bash
sudo apt install -y golang-go clang llvm libbpf-dev
```

Then retry:

```bash
make build
make build-bpf
```

If the BPF build still needs headers, try the generic fallback first:

```bash
sudo apt install -y linux-headers-generic
```

If that also fails, install the matching header package from your vendor's
repository or kernel source package instead of assuming the default
Debian/Ubuntu package name exists.

Useful inspection commands:

```bash
uname -r
ls /sys/kernel/debug/tracing
cat /proc/sys/kernel/perf_event_paranoid
```

### `golang-go` from apt is too old (Raspberry Pi / Debian)

Debian and Raspberry Pi OS ship `golang-go` at Go 1.19. This project requires
Go 1.23+. Running `apt install golang-go` installs the wrong version and
`go build` will fail with a directive error.

Check what version you have:

```bash
go version
```

If the output is below `go1.23`, remove the system package and install Go
manually:

```bash
sudo apt remove golang-go
```

Download the correct archive for your architecture. For Raspberry Pi (64-bit):

```bash
wget https://go.dev/dl/go1.23.8.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.23.8.linux-arm64.tar.gz
```

For 32-bit Pi OS (uncommon but possible):

```bash
wget https://go.dev/dl/go1.23.8.linux-armv6l.tar.gz
sudo tar -C /usr/local -xzf go1.23.8.linux-armv6l.tar.gz
```

Add Go to your PATH:

```bash
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile
```

Verify:

```bash
go version
# should print: go version go1.23.x linux/arm64
```

Then build normally:

```bash
make build
```

### Module resolution fails: `cannot find module providing ...`

If `go build` or `make build` reports something like:

```
cannot find module providing github.com/luisadrianpuga/sentinel/internal/sentinel
```

Go is not finding `go.mod`. This means you are either not in the repo root or
your checkout is incomplete.

Verify your location and module state:

```bash
pwd
# should be /home/<user>/sentinel

go env GOMOD
# should print: /home/<user>/sentinel/go.mod
# if empty, Go cannot find go.mod — you are in the wrong directory
```

Check that the internal package exists:

```bash
ls internal/sentinel
# should list: config.go  runner_linux.go  runner_other.go  store.go
```

If `go env GOMOD` is empty, navigate to the repo root and retry:

```bash
cd ~/sentinel
go env GOMOD   # should now show the path
make build
```

If `internal/sentinel` is missing, your checkout is incomplete:

```bash
git status
git rev-parse --abbrev-ref HEAD
git pull
```

After pulling, verify the directory exists and retry the build.

## Roadmap

Logical next steps from the current v1:

- trace child processes, not just a single PID
- capture richer exec metadata, including argv
- add baseline and anomaly detection modes
- export sessions in a shareable format
- add richer diffing across runs
- build a UI or dashboard on top of stored traces

## License

MIT. See [LICENSE](LICENSE).
