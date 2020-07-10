#include <linux/pagewalk.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/hmm.h>

extern struct btf *btf_vmlinux;

static const struct bpf_func_proto bpf_walk_page_range_proto __read_mostly;
static const struct bpf_func_proto bpf_handle_mm_fault_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_vma_walk_pud_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_vma_walk_pmd_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_vma_walk_hole_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_vma_walk_hugetlb_entry_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_vma_walk_test_proto __read_mostly;

static bool bpf_hmm_policy_is_valid_access(int off, int size, 
		enum bpf_access_type type, const struct bpf_prog *prog, 
		struct bpf_insn_access_aux *info) 
{
	return true;
}

static const struct bpf_func_proto * bpf_hmm_policy_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {	
	case BPF_FUNC_walk_page_range:
		return &bpf_walk_page_range_proto;
	case BPF_FUNC_handle_mm_fault:
		return &bpf_handle_mm_fault_proto;
	case BPF_FUNC_hmm_vma_walk_pud:
		return &bpf_hmm_vma_walk_pud_proto;
	case BPF_FUNC_hmm_vma_walk_pmd:
		return &bpf_hmm_vma_walk_pmd_proto;
	case BPF_FUNC_hmm_vma_walk_hole:
		return &bpf_hmm_vma_walk_hole_proto;
	case BPF_FUNC_hmm_vma_walk_hugetlb_entry:
		return &bpf_hmm_vma_walk_hugetlb_entry_proto;
	case BPF_FUNC_hmm_vma_walk_test:
		return &bpf_hmm_vma_walk_test_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
	
	return bpf_base_func_proto(func_id);
}

static int bpf_hmm_policy_btf_struct_access(struct bpf_verifier_log *log, const struct btf_type *t, int off,
					int size, enum bpf_access_type atype, u32 *next_btf_id)
{
	return btf_struct_access(log, t, off, size, atype, next_btf_id);
}


BPF_CALL_5(bpf_walk_page_range, struct mm_struct *, mm, unsigned long, start,
		unsigned long, end, const struct mm_walk_ops *, ops,
		void *, private)
{
	return walk_page_range(mm, start, end, ops, private);
}

static const struct bpf_func_proto bpf_walk_page_range_proto = {
	.func		= bpf_walk_page_range,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
//	.btf_id		= &tcp_sock_id,
};

BPF_CALL_3(bpf_handle_mm_fault, struct vm_area_struct *, vma, unsigned long, address,
					unsigned int, flags) {
	return handle_mm_fault(vma, address, flags);	
}


static const struct bpf_func_proto bpf_handle_mm_fault_proto = {
	.func		= bpf_handle_mm_fault,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_PTR_TO_ALLOC_MEM_OR_NULL,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};
/*
BPF_CALL_1(bpf_pud_write, pud_t, pud) {
	return pud_write(pud);
}

static const struct bpf_pud_write_proto = {
	.func		= bpf_pud_write,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_pud_present, pud_t, pud) {
	return pud_present(pud);
}

static const struct bpf_pud_present_proto = {
	.func		= bpf_pud_present,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};
*/

BPF_CALL_4(bpf_hmm_vma_walk_pud, pud_t *, pudp, unsigned long, start, unsigned long, end, struct mm_walk *,walk) {
	return hmm_vma_walk_pud(pudp, start, end, walk);
}

static const struct bpf_func_proto bpf_hmm_vma_walk_pud_proto = {
	.func		= bpf_hmm_vma_walk_pud,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};



BPF_CALL_4(bpf_hmm_vma_walk_pmd, pmd_t *, pmdp, unsigned long, start, unsigned long, end, struct mm_walk *,walk) {
	return hmm_vma_walk_pmd(pmdp, start, end, walk);
}

static const struct bpf_func_proto bpf_hmm_vma_walk_pmd_proto = {
	.func		= bpf_hmm_vma_walk_pmd,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};



BPF_CALL_4(bpf_hmm_vma_walk_hole, unsigned long, addr, unsigned long, end,
					     int, depth, struct mm_walk *,walk) {
	return hmm_vma_walk_hole(addr, end, depth, walk);
}

static const struct bpf_func_proto bpf_hmm_vma_walk_hole_proto = {
	.func		= bpf_hmm_vma_walk_hole,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};


BPF_CALL_5(bpf_hmm_vma_walk_hugetlb_entry, pte_t *, pte, unsigned long, hmask, unsigned long, start, unsigned long, end, struct mm_walk *, walk) {
	return hmm_vma_walk_hugetlb_entry(pte, hmask, start, end, walk);
}

static const struct bpf_func_proto bpf_hmm_vma_walk_hugetlb_entry_proto = {
	.func		= bpf_hmm_vma_walk_hugetlb_entry,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};



BPF_CALL_3(bpf_hmm_vma_walk_test, unsigned long, start, unsigned long, end,
						     struct mm_walk *, walk) {
	return hmm_vma_walk_test(start, end, walk);
}

static const struct bpf_func_proto bpf_hmm_vma_walk_test_proto = {
	.func		= bpf_hmm_vma_walk_test,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

static const struct bpf_verifier_ops bpf_hmm_policy_verifier_ops = {
	.get_func_proto		= bpf_hmm_policy_get_func_proto,
	.is_valid_access	= bpf_hmm_policy_is_valid_access,
	.btf_struct_access	= bpf_hmm_policy_btf_struct_access,
};

static int bpf_hmm_policy_init_member(const struct btf_type *t, 
		const struct btf_member *member, 
		void *kdata, 
		const void *udata)
{
	const struct hmm_policy *uhmm_policy;
	struct hmm_policy *khmm_policy;
	int prog_fd;
	u32 moff;

	uhmm_policy = (const struct hmm_policy *)udata;
	khmm_policy = (struct hmm_policy *)kdata;

	moff = btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	/*case offsetof(struct hmm_policy, flags):
		if (uhmm_policy->flags & ~TCP_CONG_MASK)
			return -EINVAL;
		khmm_policy->flags = uhmm_policy->flags;
		return 1;
	*/
	case offsetof(struct hmm_policy, name):
		if (bpf_obj_name_cpy(khmm_policy->name, uhmm_policy->name, sizeof(khmm_policy->name)) <= 0)
			return -EINVAL;
		//if (hmm_policy_find(khmm_policy->name))
		//	return -EEXIST;
		return 1;
	}
	
	if (!btf_type_resolve_func_ptr(btf_vmlinux, member->type, NULL))
		return 0;

	/* Ensure bpf_prog is provided for compulsory func ptr */
	prog_fd = (int)(*(unsigned long *)(udata + moff));
	if (!prog_fd) // && !is_optional(moff) && !is_unsupported(moff))
		return -EINVAL;
	
	
	return 0;
}

static int bpf_hmm_policy_init(struct btf *btf) {
	return 0;
}

static int bpf_hmm_policy_check_member(const struct btf_type *t, const struct btf_member *member)
{
	return 0;
}

static int bpf_hmm_policy_reg(void *kdata)
{
		return hmm_register_policy(kdata);
}

static void bpf_hmm_policy_unreg(void *kdata)
{
		hmm_unregister_policy(kdata);
}


extern struct bpf_struct_ops bpf_hmm_policy;

struct bpf_struct_ops bpf_hmm_policy = {
	.verifier_ops = &bpf_hmm_policy_verifier_ops,
	.reg = bpf_hmm_policy_reg,
	.unreg = bpf_hmm_policy_unreg,
	.check_member = bpf_hmm_policy_check_member,
	.init_member = bpf_hmm_policy_init_member,
	.init = bpf_hmm_policy_init,
	.name = "hmm_policy",
};
