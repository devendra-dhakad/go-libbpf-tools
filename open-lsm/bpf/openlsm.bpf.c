#include "../../headers/vmlinux.h"
#include "../../headers/bpf_helpers.h"
#include "../../headers/bpf_tracing.h"
#include "../../headers/bpf_core_read.h"

#define EPERM 1
#define MAX_STR  128

struct event{
    __u8 file_name[MAX_STR];
    __u8 path[MAX_STR ];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, const __u8[MAX_STR] );  // size of your string
  __uint(max_entries, 2);
  __uint(map_flags, BPF_F_RDONLY_PROG);
} arg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ringbuff SEC(".maps");

struct event *unused_event __attribute__((unused));

static __always_inline size_t strlen(const char *s) {
  int i;

  for (i = 0; i < MAX_STR; i++)
    if (s[i] == '\0'){
        return i;
    }
  return i;
}

static inline int strncmp(__u8 *s1, __u8 *s2, u32 n)
{
    for (int i = 0; i < n; i++)
    {
        if (s1[i] == s2[i]){
            continue;
        }
        else{
            return s1[i] - s2[i];
        }
    }
    return 0;
}




SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file){
    struct event *event_t;
    const unsigned char *file_name;
    u32 key = 0, key1 = 1;
    
    __u8 *file_n = bpf_map_lookup_elem(&arg_map, &key);
    if (file_n == NULL) {
        return 0;
    }
    __u8 *path = bpf_map_lookup_elem(&arg_map, &key1);
    if (path == NULL) {
        return 0;
    }

    event_t = bpf_ringbuf_reserve(&ringbuff, sizeof(struct event), 0);
    if (event_t == NULL){
        return 0;
    }

    file_name  = file->f_path.dentry->d_name.name;
    bpf_d_path(&file->f_path , (char *)&event_t->path[0] , MAX_STR);

    bpf_core_read_str(&event_t->file_name, sizeof(event_t->file_name), file_name);

    if (__builtin_memcmp(file_n , &event_t->file_name, MAX_STR) == 0){
        bpf_printk("File %s blocked based on current policy %s path", event_t->file_name, event_t->path);

        bpf_ringbuf_submit(event_t, 0);
        return -EPERM;
    }
    
    int len = strlen((const char *)path);
    int ret1 = strncmp(path, &event_t->path[0], len);
    if ( ret1 == 0 && len != 0){
        bpf_printk("hellov ");
        bpf_ringbuf_submit(event_t, 0);
        return -EPERM;
    }


    bpf_ringbuf_discard(event_t, 0);

    return 0;
}
char LICENSE[] SEC("license") = "GPL";
