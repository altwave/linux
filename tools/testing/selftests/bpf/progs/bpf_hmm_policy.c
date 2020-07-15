// SPDX-License-Identifier: GPL-2.0
//#include "vmlinux.h"
//#include <stddef.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_hmm_policy_helpers.h"

char _license[] SEC("license") = "GPL";
/*
struct bpf_map_def_legacy SEC("maps") array_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 1000 //MAX_ENTRIES,
};
*/

struct bpf_map_def SEC("maps") hmm_map = {
	.type			= BPF_MAP_TYPE_ARRAY,
	.key_size		= sizeof(int),
	.value_size		= sizeof(int),
	.max_entries	= 1,
};

SEC("struct_ops/policy_fault")
void BPF_PROG(policy_fault, struct hmm_range * range) {
	int idx = 0;
	/*int key, next_key, fd;
	long long value;

	fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 2, 0);
	*/
//	int a = 5;
	int ret = 5;  //bpf_hmm_range_fault(range, &hmm_map, key);

//	return bpf_map_lookup_elem(&hmm_map, &key, BPF_ANY);
	bpf_hmm_range_fault(range);
	//return 0;
};

SEC(".struct_ops")
struct hmm_policy policy = {
	.fault = (void *)policy_fault,
	.name = "bpf_hmm_policy"
};
