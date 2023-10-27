#include "../../headers/vmlinux.h"
#include "../../headers/bpf_helpers.h"
#include "../../headers/bpf_tracing.h"
#include "../../headers/bpf_core_read.h"

struct event{
    int timeStamp;
    u8 filename[100];
};

#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ringbuff SEC(".maps");

struct event *unused_event __attribute__((unused));

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file){
    struct event *event_t;
    const unsigned char *file_name;
    char filelocal[] = "happy.txt";
    unsigned char *k;

    event_t = bpf_ringbuf_reserve(&ringbuff, sizeof(struct event), 0);
    if (!event_t){
        return 0;
    }

    file_name  = file->f_path.dentry->d_name.name;
    bpf_core_read_str(&event_t->filename, sizeof(event_t->filename), file_name);
    k = &event_t->filename;
    if (__builtin_memcmp(k, filelocal, 4) == 0){
        bpf_printk("0000000000000000");
        // return 0;
    }
    
    bpf_ringbuf_submit(event_t, 0);

    return 0;
}
char LICENSE[] SEC("license") = "GPL";
