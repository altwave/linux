#ifndef __BPF_HMM_POLICY_HELPERS_H
#define __BPF_HMM_POLICY_HELPERS_H

#include <linux/hmm.h>
#include <linux/pagewalk.h>
#include <linux/mm_types.h>
#include <asm-generic/errno-base.h>
#include <linux/mm_types.h>
#include <stdbool.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

static int hmm_vma_walk_hole(unsigned long addr, unsigned long end, int depth, struct mm_walk *walk)
{
	return 0;//return bpf_hmm_vma_walk_hole(addr, end, depth, walk);
}

static int hmm_vma_walk_pmd(pmd_t *pmdp,
			unsigned long start,
			unsigned long end,
			struct mm_walk *walk)
{
	return 0; //bpf_vma_walk_pmd(pmdp, start, end, walk);
}

static int hmm_vma_walk_pud(pud_t *pudp, unsigned long start, unsigned long end,
				struct mm_walk *walk)
{
	return 0; //bpf_hmm_vma_walk_pud(pudp, start, end, walk);
}

static int hmm_vma_walk_hugetlb_entry(pte_t *pte, unsigned long hmask,
						      unsigned long start, unsigned long end,
						      				      struct mm_walk *walk)
{
	return 0; //return bpf_hmm_vma_walk_hugetlb_entry(pte, hmask, start, end, walk);
}

static int hmm_vma_walk_test(unsigned long start, unsigned long end,
					     struct mm_walk *walk)
{
	return 0; //bpf_hmm_vma_walk_test(start, end, walk);
}

static const struct mm_walk_ops hmm_walk_ops = {
	.pud_entry	= hmm_vma_walk_pud,
	.pmd_entry	= hmm_vma_walk_pmd,
	.pte_hole	= hmm_vma_walk_hole,
	.hugetlb_entry	= hmm_vma_walk_hugetlb_entry,
	.test_walk	= hmm_vma_walk_test,
};

#endif
