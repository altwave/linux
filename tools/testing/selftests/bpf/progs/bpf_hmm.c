// SPDX-License-Identifier: GPL-2.0
//#include "vmlinux.h"
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/types.h>
//#include <bpf/bpf.h>
//#include <bpf/libbpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <sys/types.h>
#include "bpf_hmm_policy_helpers.h"

char _license[] SEC("license") = "GPL";

#define BPF_STRUCT_OPS(name, args...) \
SEC("struct_ops/"#name) \
BPF_PROG(name, args)


struct hmm_pfn_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(key, unsigned long);
	__type(value, unsigned long);
};

struct inner_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(key, int);
	__type(value, unsigned long);
} inner_map1 SEC(".maps");

struct outer_hash {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 5);
	__uint(key_size, sizeof(int));
	/* Here everything works flawlessly due to reuse of struct inner_map
	 * and compiler will complain at the attempt to use non-inner_map
	 * references below. This is great experience.
	 */
	__array(values, struct inner_map);
} outer_hash SEC(".maps");

//= {
//	.values = { [0] = &inner_map1 },
//};


struct bpf_map_def SEC("maps") hmm_range_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(unsigned long),
	.value_size		= sizeof(unsigned long),
	.max_entries		= 1024,
};



static int __always_inline hmm_pfns_fill(unsigned long addr, unsigned long end, 
		struct hmm_range *range, unsigned long cpu_flags)
{
       	unsigned long i = (addr - range->start) >> PAGE_SHIFT;
	int npages = (end - addr) >> PAGE_SHIFT;
	
	bpf_hmm_pfn_update_user(&range->hmm_pfns[i], cpu_flags, npages * sizeof(unsigned long));
	return 0;
}

static int __always_inline hmm_vma_fault(unsigned long addr, unsigned long end,
			unsigned int required_fault, struct mm_walk *walk)
{
	struct hmm_range *range;
	struct hmm_vma_walk *hmm_vma_walk = (struct hmm_vma_walk *)bpf_get_hmm_vma_walk(walk);
	struct vm_area_struct * vma = (struct vm_area_struct *)bpf_get_mm_walk_vma(walk);
        unsigned long vm_flags;
	unsigned int fault_flags = FAULT_FLAG_REMOTE;

	WARN_ON_ONCE(!required_fault);
	bpf_hmm_update_walk_last(hmm_vma_walk, addr); //hmm_vma_walk->last = addr;

	bpf_probe_read_kernel(&vm_flags, sizeof(vm_flags), &vma->vm_flags);
	
	if (required_fault & HMM_NEED_WRITE_FAULT) {
		if (!(vm_flags & VM_WRITE))
			return -EPERM;
		fault_flags |= FAULT_FLAG_WRITE;
	}

	for (; addr < end; addr += PAGE_SIZE)
		if (bpf_handle_mm_fault(vma, addr, fault_flags) & VM_FAULT_ERROR)
			return -EFAULT;
	return -EBUSY;
}


static unsigned int __always_inline hmm_pte_need_fault(struct hmm_range * range,
						       unsigned long pfn_req_flags, unsigned long cpu_flags)
{
	if (!range || !pfn_req_flags)
		return 0;

	pfn_req_flags &= range->pfn_flags_mask;
	pfn_req_flags |= range->default_flags;

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
hmm_range_need_fault(struct hmm_range * range, 
		unsigned long hmm_pfns[], unsigned long npages,
		unsigned long cpu_flags) 
{
	unsigned int required_fault = 0;
	unsigned long i;
	unsigned long pfn_req_flags;

	if (!((range->default_flags | range->pfn_flags_mask) & HMM_PFN_REQ_FAULT))
		return 0;
	
	for (i = 0; i < npages; ++i) {
		pfn_req_flags = hmm_pfns[i];
	//	required_fault |= hmm_pte_need_fault(range, pfn_req_flags, cpu_flags);
		if (required_fault == HMM_NEED_ALL_BITS) {
			return required_fault;
		}
	}

	return required_fault;
}

int BPF_STRUCT_OPS(hmm_vma_walk_hole, unsigned long addr_kern, unsigned long end_kern, int depth_kern, 
					struct mm_walk *walk) {	
	unsigned long key;
	unsigned int required_fault;
	unsigned long i, npages;
	unsigned long *hmm_pfns;
	unsigned long start;
	struct vm_area_struct *vma; 
	struct hmm_range * range;
	struct hmm_vma_walk * hmm_vma_walk;
	unsigned long addr;
	unsigned long end;
	
	bpf_probe_read_kernel(&addr, sizeof(addr), &addr_kern);
	bpf_probe_read_kernel(&end, sizeof(end), &end_kern);
	
	key = (unsigned long)bpf_get_hmm_vma_walk(walk);
	range = (struct hmm_range *)bpf_map_lookup_elem(&hmm_range_map, &key);
	if (!range)
		return 0;

	i = (addr - range->start) >> PAGE_SHIFT;
	npages = (end_kern - addr_kern) >> PAGE_SHIFT;
	
	hmm_pfns = &range->hmm_pfns[i]; //fix map
	
	required_fault = hmm_range_need_fault(range, hmm_pfns, npages, 0);
	vma = (struct vm_area_struct *)bpf_get_mm_walk_vma(walk);
	if (!vma) {
		if (required_fault)
			return -EFAULT;
		return hmm_pfns_fill(addr, end, range, HMM_PFN_ERROR);
	}
	if (required_fault)
		return hmm_vma_fault(addr, end, required_fault, walk);
	
	return hmm_pfns_fill(addr, end, range, 0);
};

static __always_inline 
unsigned long pte_to_hmm_pfn_flags(struct hmm_range *range, pte_t *pte)
{
	if (bpf_hmm_pte_ops(PTE_NONE, pte) 
			|| !bpf_hmm_pte_ops(PTE_PRESENT, pte) 
			|| bpf_hmm_pte_ops(PTE_PROTNONE, pte))
		return 0;
	
	return bpf_hmm_pte_ops(PTE_WRITE, pte) ? (HMM_PFN_VALID | HMM_PFN_WRITE) : HMM_PFN_VALID;
}

static __always_inline unsigned long pmd_to_hmm_pfn_flags(struct hmm_range *range, pmd_t pmd)
{
		if (bpf_hmm_pmd_ops(PMD_PROTNONE, pmd))
			return 0;
		return bpf_hmm_pmd_ops(PMD_WRITE, pmd) ? (HMM_PFN_VALID | HMM_PFN_WRITE) : HMM_PFN_VALID;
}

static int __always_inline hmm_vma_handle_pmd(struct mm_walk *walk, unsigned long addr,
					      unsigned long end, unsigned long hmm_pfns[],
					      pmd_t pmd)
{
	struct hmm_range *range;
	unsigned int key;
	unsigned long pfn, npages, i;
	unsigned int required_fault;
	unsigned long cpu_flags;
       	
	key = (unsigned long)bpf_get_hmm_vma_walk(walk);
	range = (struct hmm_range *)bpf_map_lookup_elem(&hmm_range_map, &key);
	
	npages = (end - addr) >> PAGE_SHIFT;
	cpu_flags = pmd_to_hmm_pfn_flags(range, pmd);
	required_fault = hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, cpu_flags);
	if (required_fault)
		return hmm_vma_fault(addr, end, required_fault, walk);

	pfn = pmd_pfn(pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	for (i = 0; addr < end; addr += PAGE_SIZE, i++, pfn++)
		hmm_pfns[i] = pfn | cpu_flags;
	return 0;
}

static __always_inline unsigned long pud_to_hmm_pfn_flags(struct hmm_range *range, pud_t *pud)
{
		if (!bpf_hmm_pud_ops(PUD_PRESENT, pud))
			return 0;
		return bpf_hmm_pud_ops(PUD_WRITE, pud) ? (HMM_PFN_VALID | HMM_PFN_WRITE) : HMM_PFN_VALID;
}

int BPF_STRUCT_OPS(hmm_vma_walk_pud, pud_t *pudp, unsigned long start, unsigned long end, struct mm_walk *walk) {
	struct hmm_range *range;
	unsigned int key;
       	
	key = (unsigned long)bpf_get_hmm_vma_walk(walk);
	range = (struct hmm_range *)bpf_map_lookup_elem(&hmm_range_map, &key);

	unsigned long addr = start;
	pud_t pud;
	int ret = 0;
	
	spinlock_t *ptl = pud_trans_huge_lock(pudp, walk->vma);

	if (!ptl)
		return 0;

	/* Normally we don't want to split the huge page */
	walk->action = ACTION_CONTINUE;

	pud = READ_ONCE(*pudp);
	if (bpf_hmm_pud_ops(PUD_NONE, pud)) {
		bpf_hmm_spin_unlock(ptl);
		return hmm_vma_walk_hole(start, end, -1, walk);
	}

	if (bpf_hmm_pud_ops(PUD_HUGE, pud) && bpf_hmm_pud_ops(PUD_DEVMAP, pud)) {
		unsigned long i, npages, pfn;
		unsigned int required_fault;
		unsigned long *hmm_pfns;
		unsigned long cpu_flags;

		if (!bpf_hmm_pud_ops(PUD_PRESENT, pud)) {
			bpf_hmm_spin_unlock(ptl);
			return hmm_vma_walk_hole(start, end, -1, walk);
		}

		i = (addr - range->start) >> PAGE_SHIFT;
		npages = (end - addr) >> PAGE_SHIFT;
		hmm_pfns = &range->hmm_pfns[i];

		cpu_flags = pud_to_hmm_pfn_flags(range, pud);
		required_fault = hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, cpu_flags);
		
		if (required_fault) {
			spin_unlock(ptl);
			return hmm_vma_fault(addr, end, required_fault, walk);
		}

		//Instead, save user_ptr at init, 
		int offset = offsetof(struct bpf_function_ops, pud_pfn);
		pfn = bpf_hmm_call_fn(offset, pud); //then prob copy to user
		//pfn = pud_pfn(pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
		for (i = 0; i < npages; ++i, ++pfn)
			hmm_pfns[i] = pfn | cpu_flags;
		goto out_unlock;
	}

	/* Ask for the PUD to be split */
	walk->action = ACTION_SUBTREE;

out_unlock:
	spin_unlock(ptl);
	return ret;
};

static int __always_inline thp_migration_supported(void) {
	return 1; //hard-coded for now
}

static int __always_inline hmm_vma_handle_pte(struct mm_walk *walk, unsigned long addr,
				unsigned long end, pmd_t *pmdp, pte_t *ptep,
				unsigned long *hmm_pfn)
{
	struct hmm_range *range;
	unsigned int key;
       	
	key = (unsigned long)bpf_get_hmm_vma_walk(walk);
	range = (struct hmm_range *)bpf_map_lookup_elem(&hmm_range_map, &key);

	unsigned int required_fault;
	unsigned long cpu_flags;
	pte_t pte = *ptep;
	uint64_t pfn_req_flags = *hmm_pfn;

	if (bpf_hmm_pte_ops(PTE_NONE, pte)) {
		required_fault = hmm_pte_need_fault(hmm_vma_walk, pfn_req_flags, 0);
		if (required_fault)
			goto fault;
		*hmm_pfn = 0;
		return 0;
	}

	if (!bpf_hmm_pte_ops(PTE_PRESENT, pte)) {
		swp_entry_t entry = pte_to_swp_entry(pte);

		/*
		* Never fault in device private pages pages, but just report
		* the PFN even if not present.
		*/
		if (bpf_hmm_is_device_private_entry(range, entry)) {
			cpu_flags = HMM_PFN_VALID;
			if (is_write_device_private_entry(entry))
				cpu_flags |= HMM_PFN_WRITE;
			*hmm_pfn = device_private_entry_to_pfn(entry) | cpu_flags;
			return 0;
		}

		required_fault = hmm_pte_need_fault(hmm_vma_walk, pfn_req_flags, 0);
		if (!required_fault) {
			*hmm_pfn = 0;
			return 0;
		}

		if (!non_swap_entry(entry))
			goto fault;

		if (is_migration_entry(entry)) {
			pte_unmap(ptep);
			hmm_vma_walk->last = addr;
			migration_entry_wait(walk->mm, pmdp, addr);
			return -EBUSY;
		}

		/* Report error for everything else */
		pte_unmap(ptep);
		return -EFAULT;
	}
}

int BPF_STRUCT_OPS(hmm_vma_walk_pmd, pmd_t *pmdp, unsigned long start, unsigned long end, struct mm_walk *walk) {
	struct hmm_range *range;
	unsigned int key;
       	
	key = (unsigned long)bpf_get_hmm_vma_walk(walk);
	range = (struct hmm_range *)bpf_map_lookup_elem(&hmm_range_map, &key);
	
	unsigned long *hmm_pfns = &range->hmm_pfns[(start - range->start) >> PAGE_SHIFT];
	unsigned long npages = (end - start) >> PAGE_SHIFT;
	unsigned long addr = start;
	//pte_t *ptep;
	pmd_t pmd;

again:
	pmd = READ_ONCE(*pmdp); //todo fix 
	if (bpf_hmm_pmd_ops(PMD_NONE, &pmd))
		return hmm_vma_walk_hole(start, end, -1, walk);

	if (thp_migration_supported() && is_pmd_migration_entry(pmd)) {
		if (hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, 0)) {
			hmm_vma_walk->last = addr; // fix
			pmd_migration_entry_wait(walk->mm, pmdp);
			return -EBUSY;
		}
		return hmm_pfns_fill(start, end, range, 0);
	}

	if (!bpf_hmm_pmd_ops(PMD_PRESENT, pmd)) {
		if (hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, 0))
			return -EFAULT;
		return hmm_pfns_fill(start, end, range, HMM_PFN_ERROR);
	}

	if (bpf_hmm_pmd_ops(PMD_DEVMAP, pmd) || bpf_hmm_pmd_ops(PMD_TRANS_HUGE, pmd)) {
		// comments omitted
		pmd = pmd_read_atomic(pmdp);
		barrier();
		if (!bpf_hmm_pmd_ops(PMD_DEVMAP, pmd) && !bpf_hmm_pmd_ops(PMD_TRANS_HUGE, pmd))
				goto again;
		
		return hmm_vma_handle_pmd(walk, addr, end, hmm_pfns, pmd);
	}
	if (bpf_hmm_pmd_ops(PMD_BAD, pmd)) {
		if (hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, 0))
			return -EFAULT;
		return hmm_pfns_fill(start, end, range, HMM_PFN_ERROR);
	}

	ptep = pte_offset_map(pmdp, addr);
	for (; addr < end; addr += PAGE_SIZE, ptep++, hmm_pfns++) {
		int r;

		r = hmm_vma_handle_pte(walk, addr, end, pmdp, ptep, hmm_pfns);
		if (r) {
			/* hmm_vma_handle_pte() did pte_unmap() */
			return r;
		}
	}
	pte_unmap(ptep - 1);
	return 0;
};

int BPF_STRUCT_OPS(hmm_vma_walk_hugetlb_entry, pte_t *pte, unsigned long hmask,
					unsigned long start, unsigned long end, 
					struct mm_walk *walk) {	
	unsigned long addr = start, i, pfn;
	unsigned int required_fault;
	unsigned long pfn_req_flags;
	unsigned long cpu_flags;
	struct spinlock_t *ptl;
	pte_t entry;
	struct hmm_range * range;
	struct hmm_vma_walk * hmm_vma_walk;
	unsigned long key;

	key = (unsigned long)bpf_get_hmm_vma_walk(walk);
	range = (struct hmm_range *)bpf_map_lookup_elem(&hmm_range_map, &key);

	struct vm_area_struct *vma = (struct vm_area_struct *)bpf_get_mm_walk_vma(walk);

	ptl = huge_pte_lock(hstate_vma(vma), walk->mm, pte);
	entry = huge_ptep_get(pte);

	i = (start - range->start) >> PAGE_SHIFT;
	pfn_req_flags = range->hmm_pfns[i];
	cpu_flags = pte_to_hmm_pfn_flags(range, entry);
	required_fault = hmm_pte_need_fault(hmm_vma_walk, pfn_req_flags, cpu_flags);
	if (required_fault) {
		bpf_hmm_spin_unlock(ptl);
		return hmm_vma_fault(addr, end, required_fault, walk);
	}

	pfn = bpf_pte_ops(PTE_PFN, entry) + ((start & ~hmask) >> PAGE_SHIFT);
	for (; addr < end; addr += PAGE_SIZE, i++, pfn++)
		range->hmm_pfns[i] = pfn | cpu_flags;

	bpf_hmm_spin_unlock(ptl);

	return 0;
};

SEC("struct_ops/hmm_test_walk")
int BPF_PROG(hmm_test_walk, unsigned long start_kern, unsigned long end_kern, struct mm_walk *walk) {
	struct hmm_vma_walk *hmm_vma_walk;
	struct hmm_range * range;
	unsigned long start = 0;
	unsigned long end = 0;
	unsigned long key, value;
	
	bpf_probe_read_kernel(&start, sizeof(start), &start_kern);
	bpf_probe_read_kernel(&end, sizeof(end), &end_kern);
	
	unsigned long npages = (end_kern - start_kern) >> PAGE_SHIFT;
		
	key = (unsigned long)bpf_get_hmm_vma_walk(walk);
	range = (struct hmm_range *)bpf_map_lookup_elem(&hmm_range_map, &key);
	if (!range)
		return -1;


	// TODO: Fix vma
	struct vm_area_struct * vma = (struct vm_area_struct *)bpf_get_mm_walk_vma(walk);
        unsigned long vm_flags;

	bpf_probe_read_kernel(&vm_flags, sizeof(vm_flags), &vma->vm_flags);
        
	if (!(vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP)) &&
	    vm_flags & VM_READ)
		return 0;

	
	if (hmm_range_need_fault(range,	
				range->hmm_pfns + ((start_kern - range->start) >> PAGE_SHIFT), 
				npages, 0)) {
		return -EFAULT;
	}
	

	hmm_pfns_fill(start, end, range, HMM_PFN_ERROR);
// deallocate usermem and store into kernel mem
	return 1;
};

SEC("struct_ops/policy_fault")
void BPF_PROG(policy_fault, struct hmm_vma_walk * walk, struct mm_walk_ops * ops) {

	unsigned long key, value;
	unsigned long npages;
	struct inner_map * inner_map;
	struct hmm_range * range;

	key = (unsigned long)walk;
	range = bpf_get_hmm_range_user(walk); //replace wmap
	value = (unsigned long)range;

	bpf_map_update_elem(&hmm_range_map, &key, &value, BPF_ANY);

	int inner_key;
	unsigned long inner_value;
	inner_key = 0;
	inner_value = 75;

//	inner_map = bpf_map_lookup_elem(&outer_hash, &inner_key);
	//if (!inner_map)
	//	return;

//	bpf_map_update_elem(inner_map, &inner_key, &inner_value, 0);

//	bpf_map_update_elem(&outer_hash, &key, &value, BPF_ANY);
       
//	key = 1;

//	npages = (range->end - range->start) >> PAGE_SHIFT;
//	unsigned long pfns[npages] = range->hmm_pfns;

//	if (range && range->hmm_pfns && range->hmm_pfns[0]) 
//		bpf_map_update_elem(&hmm_pfn_map, &key, &range->hmm_pfns[0], BPF_ANY);
	//if (!range) {
	
		//return -1;
//	}
	
	//map = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), npages, 0);
	//for (int i=0; i<npages; i++) {
	//	bpf_map_update_elem(map, &i, &range->hmm_pfns[i], BPF_ANY);
	//}

	bpf_hmm_policy_fault(walk, ops);

	bpf_map_delete_elem(&hmm_range_map, &key);

	// update kern_range with user_range	
	// free user memory
};

SEC(".struct_ops")
struct hmm_policy policy = {
	.fault = (void *)policy_fault,
	.name = "bpf_hmm_policy"
};

SEC(".struct_ops")
struct mm_walk_ops ops = {
	.pud_entry	= (void *)hmm_vma_walk_pud,
	.pmd_entry	= (void *)hmm_vma_walk_pmd,
	.pte_hole	= (void *)hmm_vma_walk_hole,
	.hugetlb_entry	= (void *)hmm_vma_walk_hugetlb_entry,
	.test_walk = (void *)hmm_test_walk,
	.name = "bpf_mm_walk_ops",
};
