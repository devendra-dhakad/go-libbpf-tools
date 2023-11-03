#include "../../headers/vmlinux.h"
#include "../../headers/bpf_helpers.h"
#include "../../headers/bpf_tracing.h"
#include "../../headers/bpf_core_read.h"

struct event{
    __u8 file_name[100];
};

#define EPERM 1

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u8[80] );  // size of your string
  __uint(max_entries, 1);
} arg_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ringbuff SEC(".maps");

struct event *unused_event __attribute__((unused));

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file){
    struct event *event_t;
    const unsigned char *file_name;
    u32 key = 0;

    
    u8 *file_n = bpf_map_lookup_elem(&arg_map, &key);
    if (file_n == NULL) {
        return 0;
    }

    event_t = bpf_ringbuf_reserve(&ringbuff, sizeof(struct event), 0);
    if (!event_t){
        return 0;
    }

    file_name  = file->f_path.dentry->d_name.name;
    bpf_core_read_str(&event_t->file_name, sizeof(event_t->file_name), file_name);

    
    if (__builtin_memcmp(file_n , &event_t->file_name, sizeof(*file_n)) == 0){
        bpf_printk("File %s blocked based on current policy", file_n);
        bpf_ringbuf_submit(event_t, 0);
        return -EPERM;
    }

    bpf_ringbuf_submit(event_t, 0);




    return 0;
}
char LICENSE[] SEC("license") = "GPL";
