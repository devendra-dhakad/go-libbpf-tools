#include "../../headers/vmlinux.h"
#include "../../headers/bpf_helpers.h"
#include "../../headers/bpf_tracing.h"
#include "../../headers/bpf_core_read.h"

struct event{
    int timeStamp;
    uid_t userIdentifier;
    bool failed;
    pid_t processIdentifier;
    tid_t threadIdentifier;
    u8 filename[100];
    int code;
};

const volatile u32 happy = 0;

#define LAST_32_BITS(x) x & 0xFFFFFFFF
#define FIRST_32_BITS(x) x >> 32

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ringbuff SEC(".maps");

struct event *unused_event __attribute__((unused));




SEC("tracepoint/syscalls/sys_enter_open")
int open_syscall(struct trace_event_raw_sys_enter *ctx){
     struct event *event_t;
     u64 pid_tgid;

    event_t = bpf_ringbuf_reserve(&ringbuff, sizeof(struct event), 0);
    if (!event_t){
        return 0;
    }

    event_t->timeStamp = bpf_ktime_get_ns();
    event_t->userIdentifier = bpf_get_current_uid_gid() >> 32;

    pid_tgid = bpf_get_current_pid_tgid();
    event_t->processIdentifier = FIRST_32_BITS(pid_tgid);
    event_t->threadIdentifier = LAST_32_BITS(pid_tgid);

    bpf_core_read_user_str(event_t->filename, sizeof(event_t->filename), ctx->args[0]);
    bpf_printk("open %s", event_t->filename);
    event_t->code = 111;
    bpf_ringbuf_submit(event_t, 0);

    return 0;
    }



SEC("tracepoint/syscalls/sys_enter_openat")

int openat_syscall(struct trace_event_raw_sys_enter *ctx){
     struct event *event_t;
     u64 pid_tgid;

    event_t = bpf_ringbuf_reserve(&ringbuff, sizeof(struct event), 0);
    if (!event_t){
        return 0;
    }

    event_t->timeStamp = bpf_ktime_get_ns();
    event_t->userIdentifier = bpf_get_current_uid_gid() >> 32;

    pid_tgid = bpf_get_current_pid_tgid();
    event_t->processIdentifier = FIRST_32_BITS(pid_tgid);
    event_t->threadIdentifier = LAST_32_BITS(pid_tgid);

    bpf_core_read_user_str(event_t->filename, sizeof(event_t->filename), ctx->args[1]);
    bpf_printk("openat global %d", happy);
    bpf_printk("openat %s", event_t->filename);
    event_t->code = 222;
    bpf_ringbuf_submit(event_t, 0);

    return 0;
    }


SEC("tracepoint/syscalls/sys_enter_openat2")

int openat2_syscall(struct trace_event_raw_sys_enter *ctx){
     struct event *event_t;
     u64 pid_tgid;

    event_t = bpf_ringbuf_reserve(&ringbuff, sizeof(struct event), 0);
    if (!event_t){
        return 0;
    }

    event_t->timeStamp = bpf_ktime_get_ns();
    event_t->userIdentifier = bpf_get_current_uid_gid() >> 32;

    pid_tgid = bpf_get_current_pid_tgid();
    event_t->processIdentifier = FIRST_32_BITS(pid_tgid);
    event_t->threadIdentifier = LAST_32_BITS(pid_tgid);

    bpf_core_read_user_str(event_t->filename, sizeof(event_t->filename), ctx->args[1]);
    bpf_printk("openat2 %s", event_t->filename);
    event_t->code = 333;
    bpf_ringbuf_submit(event_t, 0);

    return 0;
    }


char LICENSE[] SEC("license") = "GPL";