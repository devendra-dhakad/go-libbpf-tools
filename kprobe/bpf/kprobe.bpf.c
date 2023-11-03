//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, char[80]);  // size of your string
  __uint(max_entries, 1);
} arg_map SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve() {
	u32 key     = 0;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp) {
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		return 0;
	}
	char *str = bpf_map_lookup_elem(&arg_map, &key);
	if (str != NULL) {
		bpf_printk("%s\n", str);
    }
	bpf_printk("%s, %d",str,sizeof(str));
	__sync_fetch_and_add(valp, 1);

	return 0;
}