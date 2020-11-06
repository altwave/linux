/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Facebook */
#ifndef _BPF_HMM_RANGE_STORAGE_H
#define _BPF_HMM_RANGE_STORAGE_H

struct hmm_range;

void bpf_hmm_range_storage_free(struct hmm_range *range);

extern const struct bpf_func_proto bpf_hmm_range_storage_get_proto;
extern const struct bpf_func_proto bpf_hmm_range_storage_delete_proto;


#ifdef CONFIG_BPF_SYSCALL
int bpf_hmm_range_storage_clone(const struct hmm_range *range, struct hmm_range *newrange);
#else
static inline int bpf_sk_storage_clone(const struct hmm_range *range,
				       struct hmm_range *newrange)
{
	return 0;
}
#endif

#endif /* _BPF_HMM_RANGE_STORAGE_H */
