#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

static __always_inline int should_trace(void) {
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid, &key);
    __u32 current = bpf_get_current_pid_tgid() >> 32;
    return target && *target == current;
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

    if (!evt) {
        return 0;
    }

    filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&evt->arg, sizeof(evt->arg), filename);
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
    bpf_snprintf(evt->arg, sizeof(evt->arg), "fd=%llu bytes=%llu", fd, count);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event *evt = reserve_event("connect");
    const struct sockaddr *sa;
    __u16 family = 0;

    if (!evt) {
        return 0;
    }

    sa = (const struct sockaddr *)ctx->args[1];
    bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in addr = {};
        __u16 port;
        __u8 *ip;

        bpf_probe_read_user(&addr, sizeof(addr), sa);
        port = bpf_ntohs(addr.sin_port);
        ip = (__u8 *)&addr.sin_addr.s_addr;
        bpf_snprintf(evt->arg, sizeof(evt->arg), "%d.%d.%d.%d:%d",
                     ip[0], ip[1], ip[2], ip[3], port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 addr6 = {};
        __u16 port6;

        bpf_probe_read_user(&addr6, sizeof(addr6), sa);
        port6 = bpf_ntohs(addr6.sin6_port);
        bpf_snprintf(evt->arg, sizeof(evt->arg),
                     "[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
                     bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[0]),
                     bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[1]),
                     bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[2]),
                     bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[3]),
                     bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[4]),
                     bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[5]),
                     bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[6]),
                     bpf_ntohs(addr6.sin6_addr.in6_u.u6_addr16[7]),
                     port6);
    } else {
        bpf_snprintf(evt->arg, sizeof(evt->arg), "family=%d", family);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
