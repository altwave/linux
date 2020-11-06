/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2013 Red Hat Inc.
 *
 * Authors: Jérôme Glisse <jglisse@redhat.com>
 *
 * See Documentation/vm/hmm.rst for reasons and overview of what HMM is.
 */
#ifndef LINUX_UAPI_HMM_H
#define LINUX_UAPI_HMM_H

//#include <linux/mmu_notifier.h>
//#include <linux/pagewalk.h>

//#include <linux/kconfig.h>
//#include <linux/pgtable.h>
/*
#include <linux/device.h>
#include <linux/migrate.h>
#include <linux/memremap.h>
#include <linux/completion.h>
#include <linux/bpf-cgroup.h>
*/

#define BITS_PER_LONG 64
#define HMM_POLICY_NAME_MAX	16

/*
 * On output:
 * 0             - The page is faultable and a future call with 
 *                 HMM_PFN_REQ_FAULT could succeed.
 * HMM_PFN_VALID - the pfn field points to a valid PFN. This PFN is at
 *                 least readable. If dev_private_owner is !NULL then this could
 *                 point at a DEVICE_PRIVATE page.
 * HMM_PFN_WRITE - if the page memory can be written to (requires HMM_PFN_VALID)
 * HMM_PFN_ERROR - accessing the pfn is impossible and the device should
 *                 fail. ie poisoned memory, special pages, no vma, etc
 *
 * On input:
 * 0                 - Return the current state of the page, do not fault it.
 * HMM_PFN_REQ_FAULT - The output must have HMM_PFN_VALID or hmm_range_fault()
 *                     will fail
 * HMM_PFN_REQ_WRITE - The output must have HMM_PFN_WRITE or hmm_range_fault()
 *                     will fail. Must be combined with HMM_PFN_REQ_FAULT.
 */
//enum hmm_pfn_flags {
	/* Output flags */
//	HMM_PFN_VALID = 1UL << (BITS_PER_LONG - 1),
//	HMM_PFN_WRITE = 1UL << (BITS_PER_LONG - 2),
//	HMM_PFN_ERROR = 1UL << (BITS_PER_LONG - 3),

	/* Input flags */
//	HMM_PFN_REQ_FAULT = HMM_PFN_VALID,
//	HMM_PFN_REQ_WRITE = HMM_PFN_WRITE,

//	HMM_PFN_FLAGS = HMM_PFN_VALID | HMM_PFN_WRITE | HMM_PFN_ERROR,
//};

/*
 * hmm_pfn_to_page() - return struct page pointed to by a device entry
 *
 * This must be called under the caller 'user_lock' after a successful
 * mmu_interval_read_begin(). The caller must have tested for HMM_PFN_VALID
 * already.
 */
/*static inline struct page *hmm_pfn_to_page(unsigned long hmm_pfn)
{
	return pfn_to_page(hmm_pfn & ~HMM_PFN_FLAGS);
}
*/
/*
 * struct hmm_range - track invalidation lock on virtual address range
 *
 * @notifier: a mmu_interval_notifier that includes the start/end
 * @notifier_seq: result of mmu_interval_read_begin()
 * @start: range virtual start address (inclusive)
 * @end: range virtual end address (exclusive)
 * @hmm_pfns: array of pfns (big enough for the range)
 * @default_flags: default flags for the range (write, read, ... see hmm doc)
 * @pfn_flags_mask: allows to mask pfn flags so that only default_flags matter
 * @dev_private_owner: owner of device private pages
 */
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

/*
struct hmm_range {
	struct mmu_interval_notifier *notifier;
	unsigned long		notifier_seq;
	unsigned long		start;
	unsigned long		end;
	unsigned long		*hmm_pfns;
	unsigned long		default_flags;
	unsigned long		pfn_flags_mask;
	void			*dev_private_owner;
};
*/

struct hmm_vma_walk {
	struct hmm_range	*range;
	unsigned long		last;
};

struct hmm_policy {
//	struct list_head	list;
	int (*fault)(struct hmm_vma_walk * walk, struct mm_walk_ops * ops);
	char 		name[HMM_POLICY_NAME_MAX];
	struct mm_walk_ops * ops;
};


/*
static inline unsigned long pmd_to_hmm_pfn_flags(struct hmm_range *range,
								 pmd_t pmd)
{
		if (pmd_protnone(pmd))
			return 0;
		return pmd_write(pmd) ? (HMM_PFN_VALID | HMM_PFN_WRITE) : HMM_PFN_VALID;
}
*/
/*
int hmm_register_policy(struct hmm_policy *policy);
void hmm_unregister_policy(struct hmm_policy *policy);
*/
/*
 * Please see Documentation/vm/hmm.rst for how to use the range API.
 */
//int hmm_range_fault(struct hmm_range *range);


/*
 * HMM_RANGE_DEFAULT_TIMEOUT - default timeout (ms) when waiting for a range
 *
 * When waiting for mmu notifiers we need some kind of time out otherwise we
 * could potentialy wait for ever, 1000ms ie 1s sounds like a long time to
 * wait already.
 */
#define HMM_RANGE_DEFAULT_TIMEOUT 1000

#endif /* LINUX_UAPI_HMM_H */
