#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* AF_INET/AF_INET6 may not resolve in BPF compilation context */
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define COMM_LEN 16
#define SYSCALL_LEN 16
#define ARG_LEN 256

struct event {
    __u64 ts;
    __u32 pid;
    char comm[COMM_LEN];
    char syscall[SYSCALL_LEN];
    char arg[ARG_LEN];
};

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    __u64 unused;
    long id;
    long ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

static __always_inline int is_watched(__u32 pid) {
    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &pid);

    return watched && *watched == 1;
}

static __always_inline int should_trace(void) {
    __u32 current = bpf_get_current_pid_tgid() >> 32;

    return is_watched(current);
}

static __always_inline void watch_pid(__u32 pid) {
    __u8 watched = 1;

    bpf_map_update_elem(&watched_pids, &pid, &watched, BPF_ANY);
}

static __always_inline void unwatch_current(void) {
    __u32 current = bpf_get_current_pid_tgid() >> 32;

    bpf_map_delete_elem(&watched_pids, &current);
}

static __always_inline struct event *reserve_event(const char *syscall) {
    struct event *evt;

    if (!should_trace()) {
        return 0;
    }

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->ts = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_kernel_str(&evt->syscall, sizeof(evt->syscall), syscall);
    return evt;
}

static __always_inline int append_char(char *dst, __u32 dst_len, __u32 *pos, char c) {
    if (*pos + 1 >= dst_len) {
        return 0;
    }

    dst[*pos] = c;
    *pos += 1;
    dst[*pos] = '\0';
    return 1;
}

static __always_inline int append_user_str(char *dst, __u32 dst_len, __u32 *pos, const char *src, char sep) {
    long copied;
    __u32 start = *pos;

    if (!src || *pos >= dst_len) {
        return 0;
    }
    if (*pos > 0 && sep != '\0' && !append_char(dst, dst_len, pos, sep)) {
        return 0;
    }

    copied = bpf_probe_read_user_str(dst + *pos, dst_len - *pos, src);
    if (copied <= 1) {
        *pos = start;
        if (*pos < dst_len) {
            dst[*pos] = '\0';
        }
        return 0;
    }

    *pos += copied - 1;
    return 1;
}

static __always_inline void format_sockaddr(char *dst, __u32 dst_len, const struct sockaddr *sa) {
    __u16 family = 0;

    if (!sa) {
        return;
    }

    bpf_probe_read_user(&family, sizeof(family), (__u16 *)sa);
    if (family == AF_INET) {
        struct sockaddr_in addr = {};
        __u16 port;
        __u8 *ip;

        bpf_probe_read_user(&addr, sizeof(addr), sa);
        port = bpf_ntohs(addr.sin_port);
        ip = (__u8 *)&addr.sin_addr.s_addr;
        __u64 ip4_args[5] = {ip[0], ip[1], ip[2], ip[3], port};
        bpf_snprintf(dst, dst_len, "%d.%d.%d.%d:%d", ip4_args, sizeof(ip4_args));
        return;
    }
    if (family == AF_INET6) {
        struct sockaddr_in6 addr6 = {};
        __u16 port6;
        __u64 ip6_args[9];

        bpf_probe_read_user(&addr6, sizeof(addr6), sa);
        port6 = bpf_ntohs(addr6.sin6_port);
        ip6_args[0] = bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[0]);
        ip6_args[1] = bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[1]);
        ip6_args[2] = bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[2]);
        ip6_args[3] = bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[3]);
        ip6_args[4] = bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[4]);
        ip6_args[5] = bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[5]);
        ip6_args[6] = bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[6]);
        ip6_args[7] = bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[7]);
        ip6_args[8] = port6;
        bpf_snprintf(dst, dst_len, "[%x:%x:%x:%x:%x:%x:%x:%x]:%d", ip6_args, sizeof(ip6_args));
        return;
    }

    __u64 fam_args[1] = {family};
    bpf_snprintf(dst, dst_len, "family=%d", fam_args, sizeof(fam_args));
}

static __always_inline void trace_process_start(struct trace_event_raw_sys_exit *ctx, const char *syscall) {
    struct event *evt;
    __u32 child_pid;
    __u64 child_args[1];

    if (!should_trace() || ctx->ret <= 0) {
        return;
    }

    child_pid = (__u32)ctx->ret;
    watch_pid(child_pid);

    evt = reserve_event(syscall);
    if (!evt) {
        return;
    }

    child_args[0] = child_pid;
    bpf_snprintf(evt->arg, sizeof(evt->arg), "child_pid=%llu", child_args, sizeof(child_args));
    bpf_ringbuf_submit(evt, 0);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("openat");
    const char *filename;

    if (!evt) {
        return 0;
    }

    filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->arg, sizeof(evt->arg), filename);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("execve");
    const char *filename;
    const char *const *argv;
    __u32 pos = 0;
    int captured = 0;
    int i;

    if (!evt) {
        return 0;
    }

    filename = (const char *)ctx->args[0];
    argv = (const char *const *)ctx->args[1];

#pragma unroll
    for (i = 0; i < 4; i++) {
        const char *argp = 0;

        if (bpf_probe_read_user(&argp, sizeof(argp), argv + i) < 0 || !argp) {
            break;
        }
        captured |= append_user_str(evt->arg, sizeof(evt->arg), &pos, argp, ' ');
    }

    if (!captured) {
        bpf_probe_read_user_str(&evt->arg, sizeof(evt->arg), filename);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("write");
    __u64 fd;
    __u64 count;

    if (!evt) {
        return 0;
    }

    fd = ctx->args[0];
    count = ctx->args[2];
    __u64 write_args[2] = {fd, count};
    bpf_snprintf(evt->arg, sizeof(evt->arg), "fd=%llu bytes=%llu", write_args, sizeof(write_args));
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("connect");

    if (!evt) {
        return 0;
    }

    format_sockaddr(evt->arg, sizeof(evt->arg), (const struct sockaddr *)ctx->args[1]);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("sendto");
    const struct sockaddr *sa;
    __u64 send_args[2];

    if (!evt) {
        return 0;
    }

    sa = (const struct sockaddr *)ctx->args[4];
    if (sa) {
        format_sockaddr(evt->arg, sizeof(evt->arg), sa);
    } else {
        send_args[0] = ctx->args[0];
        send_args[1] = ctx->args[2];
        bpf_snprintf(evt->arg, sizeof(evt->arg), "fd=%llu bytes=%llu", send_args, sizeof(send_args));
    }
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("unlink");

    if (!evt) {
        return 0;
    }

    bpf_probe_read_user_str(&evt->arg, sizeof(evt->arg), (const char *)ctx->args[0]);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("unlinkat");

    if (!evt) {
        return 0;
    }

    bpf_probe_read_user_str(&evt->arg, sizeof(evt->arg), (const char *)ctx->args[1]);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("rename");
    __u32 pos = 0;

    if (!evt) {
        return 0;
    }

    append_user_str(evt->arg, sizeof(evt->arg), &pos, (const char *)ctx->args[0], '\0');
    append_char(evt->arg, sizeof(evt->arg), &pos, ' ');
    append_char(evt->arg, sizeof(evt->arg), &pos, '-');
    append_char(evt->arg, sizeof(evt->arg), &pos, '>');
    append_char(evt->arg, sizeof(evt->arg), &pos, ' ');
    append_user_str(evt->arg, sizeof(evt->arg), &pos, (const char *)ctx->args[1], '\0');
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("renameat");
    __u32 pos = 0;

    if (!evt) {
        return 0;
    }

    append_user_str(evt->arg, sizeof(evt->arg), &pos, (const char *)ctx->args[1], '\0');
    append_char(evt->arg, sizeof(evt->arg), &pos, ' ');
    append_char(evt->arg, sizeof(evt->arg), &pos, '-');
    append_char(evt->arg, sizeof(evt->arg), &pos, '>');
    append_char(evt->arg, sizeof(evt->arg), &pos, ' ');
    append_user_str(evt->arg, sizeof(evt->arg), &pos, (const char *)ctx->args[3], '\0');
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("kill");
    __u64 kill_args[2];

    if (!evt) {
        return 0;
    }

    kill_args[0] = ctx->args[0];
    kill_args[1] = ctx->args[1];
    bpf_snprintf(evt->arg, sizeof(evt->arg), "pid=%llu sig=%llu", kill_args, sizeof(kill_args));
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int trace_clone_exit(struct trace_event_raw_sys_exit *ctx) {
    trace_process_start(ctx, "clone");
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fork")
int trace_fork_exit(struct trace_event_raw_sys_exit *ctx) {
    trace_process_start(ctx, "fork");
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_vfork")
int trace_vfork_exit(struct trace_event_raw_sys_exit *ctx) {
    trace_process_start(ctx, "vfork");
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(void *ctx) {
    if (!should_trace()) {
        return 0;
    }

    unwatch_current();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
