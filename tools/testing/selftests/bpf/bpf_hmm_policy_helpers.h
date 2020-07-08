#ifndef __BPF_HMM_POLICY_HELPERS_H
#define __BPF_HMM_POLICY_HELPERS_H

#include <stdint.h>
#include <linux/types.h>

#define HMM_POLICY_NAME_MAX	16

enum hmm_pfn_flag_e {
	HMM_PFN_VALID = 0,
	HMM_PFN_WRITE,
	HMM_PFN_FLAG_MAX
};
enum hmm_pfn_value_e {
	HMM_PFN_ERROR,
	HMM_PFN_NONE,
	HMM_PFN_SPECIAL,
	HMM_PFN_VALUE_MAX
};
struct hmm_range {
	struct mmu_interval_notifier *notifier;
	unsigned long		notifier_seq;
	unsigned long		start;
	unsigned long		end;
	uint64_t		*pfns;
	const uint64_t		*flags;
	const uint64_t		*values;
	uint64_t		default_flags;
	uint64_t		pfn_flags_mask;
	uint8_t			pfn_shift;
	void			*dev_private_owner;
};

struct hmm_policy {
	long (*fault)(struct hmm_range * range);
	char 		name[HMM_POLICY_NAME_MAX];
};

#endif
