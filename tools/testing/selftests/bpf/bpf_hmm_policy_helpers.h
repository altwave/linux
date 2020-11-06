#ifndef __BPF_HMM_POLICY_HELPERS_H
#define __BPF_HMM_POLICY_HELPERS_H

//#include "vmlinux.h"
//#include <linux/hmm.h>
#include <linux/const.h>
//#include <linux/pagewalk.h>
//#include <linux/mm_types.h>
#include <asm-generic/errno-base.h>
//#include <linux/mm_types.h>
#include <stdbool.h>
//#include <linux/types.h>
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_core_read.h>
//#include <bpf/bpf_tracing.h>
//#include <linux/bpf.h>

typedef __u64 u64;
typedef u64			uint64_t;
typedef u64 phys_addr_t;
#define pgoff_t unsigned long

#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))
#define barrier() __asm__ __volatile__("": : :"memory")

#define MM_WALK_OPS_NAME_MAX 16

#define VM_NONE		0x00000000

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_UFFD_MISSING	0x00000200	/* missing pages tracking */
#define VM_PFNMAP	0x00000400	/* Page-ranges managed without "struct page", just pure PFN */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */
#define VM_UFFD_WP	0x00001000	/* wrprotect pages tracking */

#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

					/* Used by sys_madvise() */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
#define VM_LOCKONFAULT	0x00080000	/* Lock the pages covered when they are faulted in */
#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */
#define VM_NORESERVE	0x00200000	/* should the VM suppress accounting */
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
#define VM_SYNC		0x00800000	/* Synchronous page faults */
#define VM_ARCH_1	0x01000000	/* Architecture-specific flag */
#define VM_WIPEONFORK	0x02000000	/* Wipe VMA contents in child. */
#define VM_DONTDUMP	0x04000000	/* Do not include in the core dump */

#define VM_MIXEDMAP	0x10000000	/* Can contain "struct page" and pure PFN pages */

#define __force
typedef __bitwise unsigned int vm_fault_t;
enum vm_fault_reason {
	VM_FAULT_OOM            = (__force vm_fault_t)0x000001,
	VM_FAULT_SIGBUS         = (__force vm_fault_t)0x000002,
	VM_FAULT_MAJOR          = (__force vm_fault_t)0x000004,
	VM_FAULT_WRITE          = (__force vm_fault_t)0x000008,
	VM_FAULT_HWPOISON       = (__force vm_fault_t)0x000010,
	VM_FAULT_HWPOISON_LARGE = (__force vm_fault_t)0x000020,
	VM_FAULT_SIGSEGV        = (__force vm_fault_t)0x000040,
	VM_FAULT_NOPAGE         = (__force vm_fault_t)0x000100,
	VM_FAULT_LOCKED         = (__force vm_fault_t)0x000200,
	VM_FAULT_RETRY          = (__force vm_fault_t)0x000400,
	VM_FAULT_FALLBACK       = (__force vm_fault_t)0x000800,
	VM_FAULT_DONE_COW       = (__force vm_fault_t)0x001000,
	VM_FAULT_NEEDDSYNC      = (__force vm_fault_t)0x002000,
	VM_FAULT_HINDEX_MASK    = (__force vm_fault_t)0x0f0000,
};

//unsigned long page_offset_base __ro_after_init = __PAGE_OFFSET_BASE_L4;
//#define __PAGE_OFFSET           page_offset_base

#define __PAGE_OFFSET_BASE_L4	_AC(0xffff888000000000, UL)
#define __PAGE_OFFSET           __PAGE_OFFSET_BASE_L4
#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#define pte_offset_map(dir, address)	pte_offset_kernel((dir), (address))
#define pte_unmap(pte) ((void)(pte))	/* NOP */

#define VM_FAULT_ERROR (VM_FAULT_OOM | VM_FAULT_SIGBUS |	\
VM_FAULT_SIGSEGV | VM_FAULT_HWPOISON |	\
VM_FAULT_HWPOISON_LARGE | VM_FAULT_FALLBACK)

//extern phys_addr_t physical_mask;
//#define __PHYSICAL_MASK		physical_mask

#define __PHYSICAL_MASK_SHIFT	52
#define __PHYSICAL_MASK		((phys_addr_t)((1ULL << __PHYSICAL_MASK_SHIFT) - 1))

#define PAGE_SHIFT		12
#define PAGE_SIZE		(_AC(1,UL) << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))
/*
 * PGDIR_SHIFT determines what a top-level page table entry can map
 */
#define PGDIR_SHIFT		39
#define PTRS_PER_PGD		512
#define MAX_PTRS_PER_P4D	1


/*
 * 3rd level page
 */
#define PUD_SHIFT	30
#define PTRS_PER_PUD	512

/*
 * PMD_SHIFT determines the size of the area a middle-level
 * page table can map
 */
#define PMD_SHIFT	21
#define PTRS_PER_PMD	512

/*
 * entries per page directory level
 */
#define PTRS_PER_PTE	512

#define PMD_SIZE	(_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))
#define PUD_SIZE	(_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE - 1))
#define PGDIR_SIZE	(_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))

#define PMD_PAGE_SIZE		(_AC(1, UL) << PMD_SHIFT)
#define PMD_PAGE_MASK		(~(PMD_PAGE_SIZE-1))

#define PUD_PAGE_SIZE		(_AC(1, UL) << PUD_SHIFT)
#define PUD_PAGE_MASK		(~(PUD_PAGE_SIZE-1))

#define PHYSICAL_PAGE_MASK	(((signed long)PAGE_MASK) & __PHYSICAL_MASK)
#define PHYSICAL_PMD_PAGE_MASK	(((signed long)PMD_PAGE_MASK) & __PHYSICAL_MASK)
#define PHYSICAL_PUD_PAGE_MASK	(((signed long)PUD_PAGE_MASK) & __PHYSICAL_MASK)

#define PHYSICAL_PAGE_MASK	(((signed long)PAGE_MASK) & __PHYSICAL_MASK)
#define PTE_PFN_MASK		((pteval_t)PHYSICAL_PAGE_MASK)
#define PTE_FLAGS_MASK		(~PTE_PFN_MASK)

#define FIRST_USER_ADDRESS	0UL

#define _PAGE_BIT_PRESENT	0	/* is present */
#define _PAGE_BIT_RW		1	/* writeable */
#define _PAGE_BIT_USER		2	/* userspace addressable */
#define _PAGE_BIT_PWT		3	/* page write through */
#define _PAGE_BIT_PCD		4	/* page cache disabled */
#define _PAGE_BIT_ACCESSED	5	/* was accessed (raised by CPU) */
#define _PAGE_BIT_DIRTY		6	/* was written to (raised by CPU) */
#define _PAGE_BIT_PSE		7	/* 4 MB (or 2MB) page */
#define _PAGE_BIT_PAT		7	/* on 4KB pages */
#define _PAGE_BIT_GLOBAL	8	/* Global TLB entry PPro+ */
#define _PAGE_BIT_SOFTW1	9	/* available for programmer */
#define _PAGE_BIT_SOFTW2	10	/* " */
#define _PAGE_BIT_SOFTW3	11	/* " */
#define _PAGE_BIT_PAT_LARGE	12	/* On 2MB or 1GB pages */
#define _PAGE_BIT_SOFTW4	58	/* available for programmer */
#define _PAGE_BIT_PKEY_BIT0	59	/* Protection Keys, bit 1/4 */
#define _PAGE_BIT_PKEY_BIT1	60	/* Protection Keys, bit 2/4 */
#define _PAGE_BIT_PKEY_BIT2	61	/* Protection Keys, bit 3/4 */
#define _PAGE_BIT_PKEY_BIT3	62	/* Protection Keys, bit 4/4 */
#define _PAGE_BIT_NX		63	/* No execute: only valid after cpuid check */

#define _PAGE_BIT_SPECIAL	_PAGE_BIT_SOFTW1
#define _PAGE_BIT_CPA_TEST	_PAGE_BIT_SOFTW1
#define _PAGE_BIT_UFFD_WP	_PAGE_BIT_SOFTW2 /* userfaultfd wrprotected */
#define _PAGE_BIT_SOFT_DIRTY	_PAGE_BIT_SOFTW3 /* software dirty tracking */
#define _PAGE_BIT_DEVMAP	_PAGE_BIT_SOFTW4

/* If _PAGE_BIT_PRESENT is clear, we use these: */
/* - if the user mapped it with PROT_NONE; pte_present gives true */
#define _PAGE_BIT_PROTNONE	_PAGE_BIT_GLOBAL

#define _PAGE_PRESENT	(_AT(pteval_t, 1) << _PAGE_BIT_PRESENT)
#define _PAGE_RW	(_AT(pteval_t, 1) << _PAGE_BIT_RW)
#define _PAGE_USER	(_AT(pteval_t, 1) << _PAGE_BIT_USER)
#define _PAGE_PWT	(_AT(pteval_t, 1) << _PAGE_BIT_PWT)
#define _PAGE_PCD	(_AT(pteval_t, 1) << _PAGE_BIT_PCD)
#define _PAGE_ACCESSED	(_AT(pteval_t, 1) << _PAGE_BIT_ACCESSED)
#define _PAGE_DIRTY	(_AT(pteval_t, 1) << _PAGE_BIT_DIRTY)
#define _PAGE_PSE	(_AT(pteval_t, 1) << _PAGE_BIT_PSE)
#define _PAGE_GLOBAL	(_AT(pteval_t, 1) << _PAGE_BIT_GLOBAL)
#define _PAGE_SOFTW1	(_AT(pteval_t, 1) << _PAGE_BIT_SOFTW1)
#define _PAGE_SOFTW2	(_AT(pteval_t, 1) << _PAGE_BIT_SOFTW2)
#define _PAGE_SOFTW3	(_AT(pteval_t, 1) << _PAGE_BIT_SOFTW3)
#define _PAGE_PAT	(_AT(pteval_t, 1) << _PAGE_BIT_PAT)
#define _PAGE_PAT_LARGE (_AT(pteval_t, 1) << _PAGE_BIT_PAT_LARGE)
#define _PAGE_SPECIAL	(_AT(pteval_t, 1) << _PAGE_BIT_SPECIAL)
#define _PAGE_CPA_TEST	(_AT(pteval_t, 1) << _PAGE_BIT_CPA_TEST)

#define _PAGE_DEVMAP	(_AT(u64, 1) << _PAGE_BIT_DEVMAP)
#define _PAGE_PROTNONE	(_AT(pteval_t, 1) << _PAGE_BIT_PROTNONE)
#define _PAGE_KNL_ERRATUM_MASK (_PAGE_DIRTY | _PAGE_ACCESSED)

#define sme_me_mask	0ULL
#define _PAGE_ENC		(_AT(pteval_t, sme_me_mask))
#define __PP _PAGE_PRESENT
#define __RW _PAGE_RW
#define ___A _PAGE_ACCESSED
#define ___D _PAGE_DIRTY
#define _ENC _PAGE_ENC
#define _KERNPG_TABLE		 (__PP|__RW|   0|___A|   0|___D|   0|   0| _ENC)

#define pmd_val(x)	native_pmd_val(x)
#define pud_val(x)	native_pud_val(x)

#define SWP_TYPE_BITS		5

#define SWP_OFFSET_FIRST_BIT	(_PAGE_BIT_PROTNONE + 1)

/* We always extract/encode the offset by shifting it all the way up, and then down again */
#define SWP_OFFSET_SHIFT	(SWP_OFFSET_FIRST_BIT+SWP_TYPE_BITS)

#define MAX_SWAPFILES_CHECK() BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > SWP_TYPE_BITS)

/* Extract the high bits for type */
#define __swp_type(x) ((x).val >> (64 - SWP_TYPE_BITS))

/* Shift up (to get rid of type), then down to get value */
#define __swp_offset(x) (~(x).val << SWP_TYPE_BITS >> SWP_OFFSET_SHIFT)

/*
 * Shift the offset up "too far" by TYPE bits, then down again
 * The offset is inverted by a binary not operation to make the high
 * physical bits set.
 */
#define __swp_entry(type, offset) ((swp_entry_t) { \
	(~(unsigned long)(offset) << SWP_OFFSET_SHIFT >> SWP_TYPE_BITS) \
	| ((unsigned long)(type) << (64-SWP_TYPE_BITS)) })

#define __pte_to_swp_entry(pte)		((swp_entry_t) { pte_val((pte)) })
#define __pmd_to_swp_entry(pmd)		((swp_entry_t) { pmd_val((pmd)) })
#define __swp_entry_to_pte(x)		((pte_t) { .pte = (x).val })
#define __swp_entry_to_pmd(x)		((pmd_t) { .pmd = (x).val })

#define BITS_PER_XA_VALUE	(BITS_PER_LONG - 1)
#define MAX_SWAPFILES_SHIFT	5
#define SWP_HWPOISON_NUM 1
#define SWP_TYPE_SHIFT	(BITS_PER_XA_VALUE - MAX_SWAPFILES_SHIFT)
#define SWP_OFFSET_MASK	((1UL << SWP_TYPE_SHIFT) - 1)
#define SWP_DEVICE_NUM 2
#define SWP_DEVICE_WRITE (MAX_SWAPFILES+SWP_HWPOISON_NUM+SWP_MIGRATION_NUM)
#define SWP_DEVICE_READ (MAX_SWAPFILES+SWP_HWPOISON_NUM+SWP_MIGRATION_NUM+1)
#define SWP_MIGRATION_NUM 2
#define MAX_SWAPFILES \
	((1 << MAX_SWAPFILES_SHIFT) - SWP_DEVICE_NUM - \
	SWP_MIGRATION_NUM - SWP_HWPOISON_NUM)

#define SWP_HWPOISON		MAX_SWAPFILES
#define SWP_MIGRATION_READ	(MAX_SWAPFILES + SWP_HWPOISON_NUM)
#define SWP_MIGRATION_WRITE	(MAX_SWAPFILES + SWP_HWPOISON_NUM + 1)

#define _PAGE_SWP_SOFT_DIRTY	(_AT(pteval_t, 0))

#define pte_val(x)	native_pte_val(x)
#define __pte_to_swp_entry(pte)		((swp_entry_t) { pte_val((pte)) })

#define WARN_ON_ONCE(cond) 
//(cond ? fprintf (stderr, "WARNING\n") : 0)

typedef unsigned long	pteval_t;
typedef unsigned long	pmdval_t;
typedef unsigned long	pudval_t;
typedef unsigned long	p4dval_t;
typedef unsigned long	pgdval_t;
typedef unsigned long	pgprotval_t;

typedef struct { pgdval_t pgd; } pgd_t;
typedef struct { p4dval_t p4d; } p4d_t;
typedef struct { pudval_t pud; } pud_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pteval_t pte; } pte_t;

typedef struct {
	unsigned long val;
} swp_entry_t;

#define BITS_PER_LONG 64

#define FAULT_FLAG_WRITE			0x01
#define FAULT_FLAG_MKWRITE			0x02
#define FAULT_FLAG_ALLOW_RETRY			0x04
#define FAULT_FLAG_RETRY_NOWAIT			0x08
#define FAULT_FLAG_KILLABLE			0x10
#define FAULT_FLAG_TRIED			0x20
#define FAULT_FLAG_USER				0x40
#define FAULT_FLAG_REMOTE			0x80
#define FAULT_FLAG_INSTRUCTION  		0x100
#define FAULT_FLAG_INTERRUPTIBLE		0x200

enum {
	HMM_NEED_FAULT = 1 << 0,
	HMM_NEED_WRITE_FAULT = 1 << 1,
	HMM_NEED_ALL_BITS = HMM_NEED_FAULT | HMM_NEED_WRITE_FAULT,
};

enum hmm_pfn_flags {
	/* Output flags */
	HMM_PFN_VALID = 1UL << (BITS_PER_LONG - 1),
	HMM_PFN_WRITE = 1UL << (BITS_PER_LONG - 2),
	HMM_PFN_ERROR = 1UL << (BITS_PER_LONG - 3),

	/* Input flags */
	HMM_PFN_REQ_FAULT = HMM_PFN_VALID,
	HMM_PFN_REQ_WRITE = HMM_PFN_WRITE,

	HMM_PFN_FLAGS = HMM_PFN_VALID | HMM_PFN_WRITE | HMM_PFN_ERROR,
};

struct hmm_vma_walk {
	struct hmm_range	*range;
	unsigned long		last;
} __attribute__((preserve_access_index));

struct mm_struct {
        unsigned long start_brk, brk, start_stack;
} __attribute__((preserve_access_index));

struct vm_area_struct {
//        unsigned long start_brk, brk, start_stack;
        unsigned long vm_start, vm_end;
        struct mm_struct *vm_mm;
	unsigned long vm_flags;		/* Flags, see mm.h. */
} __attribute__((preserve_access_index));

struct mmu_interval_notifier {
	struct mm_struct *mm;
} __attribute((preserve_access_index));

/*
 * Action for pud_entry / pmd_entry callbacks.
 * ACTION_SUBTREE is the default
 */
enum page_walk_action {
	/* Descend to next level, splitting huge pages if needed and possible */
	ACTION_SUBTREE = 0,
	/* Continue to next entry at this level (ignoring any subtree) */
	ACTION_CONTINUE = 1,
	/* Call again for this entry */
	ACTION_AGAIN = 2
};

struct mm_walk {
//	const struct mm_walk_ops *ops;
	struct mm_struct *mm;
	pgd_t *pgd;
	struct vm_area_struct *vma;
	enum page_walk_action action;
	bool no_vma;
	void *private;
} __attribute((preserve_access_index));

struct mm_walk_ops {
	int (*pgd_entry)(pgd_t *pgd, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*p4d_entry)(p4d_t *p4d, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pud_entry)(pud_t *pud, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pud_entry2)(pud_t *pud, unsigned long addr,
			 unsigned long next, struct mm_walk *walk, int *ret);
	int (*pmd_entry)(pmd_t *pmd, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pmd_entry2)(pmd_t *pmd, unsigned long addr,
			 unsigned long next, struct mm_walk *walk, int *ret);
	int (*pte_entry)(pte_t *pte, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pte_hole)(unsigned long addr, unsigned long next,
			int depth, struct mm_walk *walk);
	int (*pte_hole2)(unsigned long addr, unsigned long next,
			int depth, struct mm_walk *walk, int *ret);
	int (*hugetlb_entry)(pte_t *pte, unsigned long hmask,
			     unsigned long addr, unsigned long next,
			     struct mm_walk *walk);
	int (*hugetlb_entry2)(pte_t *pte, unsigned long hmask,
			     unsigned long addr, unsigned long next,
			     struct mm_walk *walk, int *ret);
	int (*test_walk)(unsigned long addr, unsigned long next,
			struct mm_walk *walk);
	int (*test_walk2)(unsigned long addr, unsigned long next,
			struct mm_walk *walk, int *ret);
	int (*pre_vma)(unsigned long start, unsigned long end,
		       struct mm_walk *walk);
	void (*post_vma)(struct mm_walk *walk);
	void (*start_hook)(void *private);
	void (*end_hook)(void *private);
	char 		name[MM_WALK_OPS_NAME_MAX];
};


struct hmm_range {
	struct mmu_interval_notifier *notifier;
	unsigned long		notifier_seq;
	unsigned long		start;
	unsigned long		end;
	unsigned long		*hmm_pfns;
	unsigned long		default_flags;
	unsigned long		pfn_flags_mask;
	void			*dev_private_owner;
} __attribute__((preserve_access_index));

struct hmm_policy {
	void (*fault)(struct hmm_range * fault);
	char 		name[MM_WALK_OPS_NAME_MAX];
};

#endif
