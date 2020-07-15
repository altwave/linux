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
static int __always_inline hmm_vma_fault(unsigned long addr, unsigned long end,
					 unsigned int required_fault, struct mm_walk *walk)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct vm_area_struct *vma = (struct vm_area_struct *)bpf_get_mm_walk_vma(walk);
	unsigned int fault_flags = FAULT_FLAG_REMOTE;

	//WARN_ON_ONCE(!required_fault); Cathlyn fix
	hmm_vma_walk->last = addr;

	if (required_fault & HMM_NEED_WRITE_FAULT) {
		if (!(vma->vm_flags & VM_WRITE))
			return -EPERM;
		fault_flags |= FAULT_FLAG_WRITE;
	}

	for (; addr < end; addr += PAGE_SIZE)
		if (bpf_handle_mm_fault(vma, addr, fault_flags) & VM_FAULT_ERROR)
			return -EFAULT;
	return -EBUSY;
}
*/

static unsigned int __always_inline hmm_pte_need_fault(const struct hmm_range *range,
						       unsigned long pfn_req_flags, unsigned long cpu_flags)
{
	unsigned long default_flags;
	unsigned long pfn_flags_mask;

	bpf_probe_read_kernel(&default_flags, sizeof(default_flags), &range->default_flags);
	bpf_probe_read_kernel(&pfn_flags_mask, sizeof(pfn_flags_mask), &range->pfn_flags_mask);

	pfn_req_flags &= pfn_flags_mask;
	pfn_req_flags |= default_flags;

	/* We aren't ask to do anything ... */
	if (!(pfn_req_flags & HMM_PFN_REQ_FAULT))
		return 0;

	/* Need to write fault ? */
	if ((pfn_req_flags & HMM_PFN_REQ_WRITE) &&
		!(cpu_flags & HMM_PFN_WRITE))
			return HMM_NEED_FAULT | HMM_NEED_WRITE_FAULT;

	/* If CPU page table is not valid then we need to fault */
	if (!(cpu_flags & HMM_PFN_VALID))
		return HMM_NEED_FAULT;
	return 0;
}

static unsigned int __always_inline
hmm_range_need_fault(const struct hmm_range *range, const unsigned long hmm_pfns[], unsigned long npages,
				     		     unsigned long cpu_flags)
{
	unsigned int required_fault = 0;
	unsigned long i;
	unsigned long default_flags;
	unsigned long pfn_flags_mask;

	bpf_probe_read_kernel(&default_flags, sizeof(default_flags), &range->default_flags);
	bpf_probe_read_kernel(&pfn_flags_mask, sizeof(pfn_flags_mask), &range->pfn_flags_mask);

	if (!((default_flags | pfn_flags_mask) & HMM_PFN_REQ_FAULT))
		return 0;

	for (i = 0; i < npages; ++i) {
		required_fault |= hmm_pte_need_fault(range, hmm_pfns[i], cpu_flags);
		if (required_fault == HMM_NEED_ALL_BITS)
			return required_fault;
	}
	return required_fault;
}

int BPF_STRUCT_OPS(hmm_vma_walk_pud, pud_t *pudp, unsigned long start, unsigned long end, struct mm_walk *walk) {
	return bpf_hmm_vma_walk_pud(pudp, start, end, walk);	
};

int BPF_STRUCT_OPS(hmm_vma_walk_pmd, pmd_t *pmdp, unsigned long start, unsigned long end, struct mm_walk *walk) {
	return bpf_hmm_vma_walk_pmd(pmdp, start, end, walk);
};

int BPF_STRUCT_OPS(hmm_vma_walk_hole, unsigned long addr, unsigned long end, int depth, struct mm_walk *walk) {	
	unsigned int required_fault;
	unsigned long i, npages;
	unsigned long *hmm_pfns;
	unsigned long start;
	struct hmm_range *range = (struct hmm_range *)bpf_hmm_range(walk);
	
	bpf_probe_read_kernel(&start, sizeof(start), &range->start);

	i = (addr - start) >> PAGE_SHIFT;
	npages = (end - addr) >> PAGE_SHIFT;
	/*hmm_pfns = &range->hmm_pfns[i];
	required_fault = hmm_range_need_fault(range, hmm_pfns, npages, 0);
	if (!walk->vma) {
		if (required_fault)
			return -EFAULT;
		return bpf_hmm_pfns_fill(addr, end, range, HMM_PFN_ERROR);
	}
	if (required_fault)
		return bpf_hmm_vma_fault(addr, end, required_fault, walk);
	*/
	return bpf_hmm_pfns_fill(addr, end, range, 0);
};

int BPF_STRUCT_OPS(hmm_vma_walk_hugetlb_entry, pte_t *pte, unsigned long hmask,
					unsigned long start, unsigned long end, struct mm_walk *walk) {	
	unsigned long addr = start, i, pfn;
	unsigned int required_fault;
	unsigned long pfn_req_flags;
	unsigned long cpu_flags;
	//bpf_spinlock_t *ptl;
	//pte_t entry;

	struct hmm_vma_walk *hmm_vma_walk = (struct hmm_vma_walk *)bpf_get_hmm_vma_walk(walk);
	struct hmm_range *range = (struct hmm_range *)bpf_hmm_range(walk);
	struct vm_area_struct *vma = (struct vm_area_struct *)bpf_get_mm_walk_vma(walk);
/*
	ptl = huge_pte_lock(hstate_vma(vma), walk->mm, pte);
	entry = huge_ptep_get(pte);

	i = (start - range->start) >> PAGE_SHIFT;
	pfn_req_flags = range->hmm_pfns[i];
	cpu_flags = bpf_pte_to_hmm_pfn_flags(range, entry);
	required_fault = hmm_pte_need_fault(hmm_vma_walk, pfn_req_flags, cpu_flags);
	if (required_fault) {
		bpf_spin_unlock(ptl);
		return bpf_hmm_vma_fault(addr, end, required_fault, walk);
	}

	pfn = bpf_pte_ops(PTE_PFN, entry) + ((start & ~hmask) >> PAGE_SHIFT);
	for (; addr < end; addr += PAGE_SIZE, i++, pfn++)
		range->hmm_pfns[i] = pfn | cpu_flags;

	bpf_spin_unlock(ptl);
*/
	return 0;
};

int BPF_STRUCT_OPS(hmm_test_walk, unsigned long start, unsigned long end, struct mm_walk *walk) {
	
	struct hmm_vma_walk *hmm_vma_walk = (struct hmm_vma_walk *)bpf_get_hmm_vma_walk(walk);
	struct hmm_range *range = (struct hmm_range *)bpf_hmm_range(walk);
	struct vm_area_struct * vma = (struct vm_area_struct *)bpf_get_mm_walk_vma(walk);
        unsigned long vm_flags;

	bpf_probe_read_kernel(&vm_flags, sizeof(vm_flags), &vma->vm_flags);
        
	if (!(vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP)) &&
	    vm_flags & VM_READ)
		return 0;

//	bpf_probe_read_kernel(&hmm_pfns, sizeof(hmm_pfns), range->hmm_pfns);
	//if (hmm_range_need_fault(range,
	//			 range->hmm_pfns +
	//				 ((start - range->start) >> PAGE_SHIFT),
	//			 (end - start) >> PAGE_SHIFT, 0))
		return -EFAULT;

	bpf_hmm_pfns_fill(start, end, range, HMM_PFN_ERROR);
	return 1; 
};

SEC(".struct_ops")
struct mm_walk_ops ops = {
	.pud_entry	= (void *)hmm_vma_walk_pud,
	.pmd_entry	= (void *)hmm_vma_walk_pmd,
	.pte_hole	= (void *)hmm_vma_walk_hole,
	.hugetlb_entry	= (void *)hmm_vma_walk_hugetlb_entry,
	.test_walk = (void *)hmm_test_walk,
	.name = "mm_walk_ops",
};
