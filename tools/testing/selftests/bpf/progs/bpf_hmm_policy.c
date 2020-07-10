// SPDX-License-Identifier: GPL-2.0

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_hmm_policy_helpers.h"

char _license[] SEC("license") = "GPL";


static int __always_inline _hmm_range_fault(struct hmm_range * range) {
	struct hmm_vma_walk hmm_vma_walk = {
		.range = range,
		.last = range->start,
	};
	
	struct mm_struct *mm = range->notifier->mm;
	int ret;

	//todo
	//mmap_assert_locked(mm);

	do {
		/* If range is no longer valid force retry. */
		//todo
		//if (mmu_interval_check_retry(range->notifier, range->notifier_seq))
		//	return -EBUSY;
		ret = bpf_walk_page_range(mm, hmm_vma_walk.last, range->end, &hmm_walk_ops, &hmm_vma_walk);
		
		/*
		* When -EBUSY is returned the loop restarts with
		* hmm_vma_walk.last set to an address that has not been stored
		* in pfns. All entries < last in the pfn array are set to their
		* output, and all >= are still at their input values.
		*/
	} while (ret == -EBUSY);
	
	return ret;
};

SEC("struct_ops/bpf_hmm_range_fault")
int BPF_PROG(bpf_hmm_range_fault, struct hmm_range * range) {
	char fmt[] = "new bpf hmm_range_fault called\n";
	return _hmm_range_fault(range);
//	bpf_trace_printk(fmt, sizeof(fmt));
//	return 0; 
};

SEC(".struct_ops")
struct hmm_policy policy = {
	.fault = (void *)bpf_hmm_range_fault,
	.name = "bpf_hmm_policy",
};
