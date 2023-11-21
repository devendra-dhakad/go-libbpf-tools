#include "../../headers/vmlinux.h"
#include "../../headers/bpf_helpers.h"
#include "../../headers/bpf_tracing.h"
#include "../../headers/bpf_core_read.h"

struct event{
    uid_t uid;
    pid_t pid;
    gid_t gid;
    uid_t euid;
    gid_t egid;
    uint32_t fd;
    __u8 cwd[50];
    __kernel_sa_family_t s_family;
    int addrlen;
    __u32 ip_addr;
    __u16 port;
};

#define FIRST_32_BITS(x) x >> 32

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ringbuff SEC(".maps");

struct event *unused_event __attribute__((unused));


SEC("tracepoint/syscalls/sys_enter_accept")
int accept_syscall(struct trace_event_raw_sys_enter *ctx){
     struct event *event_t;

    event_t = bpf_ringbuf_reserve(&ringbuff, sizeof(struct event), 0);
    if (!event_t){
        return 0;
    }

    // 7. Effective User ID
    // 8. Effective Group ID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&event_t->euid, task, cred , euid.val );
    BPF_CORE_READ_INTO(&event_t->euid, task, cred , egid.val );

    // 2. Curent working directory(not the whole path)
    const unsigned char *name =  BPF_CORE_READ(task, fs, pwd.dentry, d_name.name);
    bpf_core_read_str(&event_t->cwd, sizeof(event_t->cwd), name);

    // 5. User ID
    // 6. Group ID
    __u64  uid_gid=  bpf_get_current_uid_gid();
    event_t->uid = FIRST_32_BITS(uid_gid);
    event_t->gid = uid_gid;

    // process ID
    event_t->pid = FIRST_32_BITS(bpf_get_current_pid_tgid());

    event_t->fd = (uint32_t) BPF_CORE_READ(ctx, args[0]);
    struct sockaddr *saddr = (struct sockaddr *)(ctx->args[1]);
    event_t->s_family = BPF_CORE_READ_USER(saddr, sa_family);

    struct sockaddr_in *saddr_in = (struct sockaddr_in *)saddr;
    __be32 ip_addr =  BPF_CORE_READ_USER(saddr_in, sin_addr.s_addr);
    event_t->ip_addr =  __builtin_bswap32(ip_addr);
    __be16 port =  BPF_CORE_READ_USER(saddr_in, sin_port);
    event_t->port =  __builtin_bswap16(port);

    int *addrlen = (int *)(ctx->args[2]);
    bpf_core_read_user(&event_t->addrlen, sizeof(event_t->addrlen), addrlen);

    bpf_ringbuf_submit(event_t, 0);
    return 0;
    }


char LICENSE[] SEC("license") = "GPL";