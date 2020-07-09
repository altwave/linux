// SPDX-License-Identifier: GPL-2.0

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_hmm_policy_helpers.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/bpf_hmm_range_fault")
long BPF_PROG(bpf_hmm_range_fault, struct hmm_range * range) {
	char fmt[] = "new bpf hmm_range_fault called\n";
//	bpf_trace_printk(fmt, sizeof(fmt));
	return 0; 
};

SEC(".struct_ops")
struct hmm_policy policy = {
	.fault = (void *)bpf_hmm_range_fault,
	.name = "bpf_hmm_policy",
};
