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
    u8 file_name[100];
    __u8 cwd[100];
    u8 argv[10][100];
    u8 envp[10][100];
};

#define LAST_32_BITS(x) x & 0xFFFFFFFF
#define FIRST_32_BITS(x) x >> 32

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ringbuff SEC(".maps");

struct event *unused_event __attribute__((unused));


#define FIRST_32_BITS(x) x >> 32
#define MAX_ARGS 10

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_syscall(struct trace_event_raw_sys_enter *ctx){
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

    //All the arguments for syscall.
    bpf_core_read_user_str(event_t->file_name, sizeof(event_t->file_name), ctx->args[0]);
    const char **argv_arr = (const char **)(ctx->args[1]);
    const char *argv;
    const char **envp_arr = (const char **)(ctx->args[2]);
    const char *envp;
    for (int i = 0; i < MAX_ARGS; i++) {

        bpf_probe_read_user(&argv, sizeof(argv), &argv_arr[i]);
        bpf_probe_read_user(&event_t->argv[i], sizeof(event_t->argv[i]), argv);
        if (!event_t->argv[i]){
			goto cleanup;
        }
    }
    cleanup:

    for (int i = 0; i < MAX_ARGS; i++) {
        
        bpf_probe_read_user(&envp, sizeof(envp), &envp_arr[i]);
        bpf_probe_read_user(&event_t->envp[i], sizeof(event_t->envp[i]), envp);
        if (!event_t->envp[i]){
			goto cleanenvp;
        }
    }
    cleanenvp:

    bpf_ringbuf_submit(event_t, 0);
    
    return 0;
    }


char LICENSE[] SEC("license") = "GPL";