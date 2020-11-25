#include <linux/pagewalk.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/hmm.h>
#include <uapi/linux/btf.h>

extern struct btf *btf_vmlinux;

static const struct bpf_func_proto bpf_hmm_vma_walk_pud_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_vma_walk_pmd_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_vma_walk_hole_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_vma_walk_hugetlb_entry_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_vma_walk_test_proto __read_mostly;

static const struct bpf_func_proto bpf_get_mm_walk_vma_proto __read_mostly;
static const struct bpf_func_proto bpf_get_hmm_vma_walk_proto __read_mostly;

static const struct bpf_func_proto bpf_hmm_policy_fault_proto __read_mostly;

static const struct bpf_func_proto bpf_hmm_is_device_private_entry_proto __read_mostly;

static const struct bpf_func_proto bpf_hmm_spin_unlock_proto __read_mostly;
static const struct bpf_func_proto bpf_handle_mm_fault_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_update_walk_last_proto __read_mostly;


static const struct bpf_func_proto bpf_hmm_call_fn_proto __read_mostly;


static const struct bpf_func_proto bpf_hmm_huge_pte_lock_proto __read_mostly;
static const struct bpf_func_proto bpf_hmm_huge_ptep_get_proto __read_mostly;

static const struct bpf_func_proto bpf_hmm_to_user_proto __read_mostly;

static const struct btf_type *mm_struct_type;

static u32 mm_struct_id;

static bool bpf_hmm_policy_is_valid_access(int off, int size, 
		enum bpf_access_type type, const struct bpf_prog *prog, 
		struct bpf_insn_access_aux *info) 
{
	return true;
}

static const struct bpf_func_proto * bpf_hmm_policy_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {	
	case BPF_FUNC_get_mm_walk_vma:
		return &bpf_get_mm_walk_vma_proto;
	case BPF_FUNC_get_hmm_vma_walk:
		return &bpf_get_hmm_vma_walk_proto;
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
	
	case BPF_FUNC_hmm_is_device_private_entry:
		return &bpf_hmm_is_device_private_entry_proto;
	case BPF_FUNC_hmm_spin_unlock:
		return &bpf_hmm_spin_unlock_proto;
	case BPF_FUNC_handle_mm_fault:
		return &bpf_handle_mm_fault_proto;
	case BPF_FUNC_hmm_update_walk_last:
		return &bpf_hmm_update_walk_last_proto;
	case BPF_FUNC_hmm_huge_pte_lock:
		return &bpf_hmm_huge_pte_lock_proto;
	case BPF_FUNC_hmm_to_user:
		return &bpf_hmm_to_user_proto;
	default:
		return bpf_base_func_proto(func_id);
	}	
}

static int bpf_hmm_policy_btf_struct_access(struct bpf_verifier_log *log, const struct btf_type *t, int off,
					int size, enum bpf_access_type atype, u32 *next_btf_id)
{
	return btf_struct_access(log, t, off, size, atype, next_btf_id);
}

BPF_CALL_3(bpf_hmm_huge_pte_lock, struct vm_area_struct *, vma, struct mm_walk *, walk, void *, pte)
{
	struct hstate *h = hstate_vma(vma);
	struct mm_struct *mm = walk->mm;
	pte_t *p = (pte_t *)pte;
	return huge_pte_lock(h, mm, p);
}

static const struct bpf_func_proto bpf_hmm_huge_pte_lock_proto = {
	.func		= bpf_hmm_huge_pte_lock,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_PTR_TO_ALLOC_MEM_OR_NULL,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_hmm_to_user, void __user *, up, void *, kp, size_t __user, size)
{
	return copy_to_user(up, kp, size); 
}

static const struct bpf_func_proto bpf_hmm_to_user_proto = {
	.func		= bpf_hmm_to_user,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING
};

BPF_CALL_2(bpf_hmm_is_device_private_entry, struct hmm_range *, range, void *, entryp) //map need to pass by value here
{
	swp_entry_t * ep = (swp_entry_t *)entryp;
	return 0; //hmm_is_device_private_entry(range, *ep);
}

static const struct bpf_func_proto bpf_hmm_is_device_private_entry_proto = {
	.func		= bpf_hmm_is_device_private_entry,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_hmm_spin_unlock, void *, ptl) //map need to pass by value here
{
	spin_unlock((spinlock_t *)ptl);
	return 0;
}

static const struct bpf_func_proto bpf_hmm_spin_unlock_proto = {
	.func		= bpf_hmm_spin_unlock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_handle_mm_fault, struct vm_area_struct *, vma, unsigned long, address,
			 unsigned int, flags) {
	return handle_mm_fault(vma, address, flags);	
}
static const struct bpf_func_proto bpf_handle_mm_fault_proto = {
	.func		= bpf_handle_mm_fault,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};


BPF_CALL_2(bpf_hmm_update_walk_last, struct hmm_vma_walk *, hmm_vma_walk, unsigned long, addr) {
	hmm_vma_walk->last = addr;
	return 0;	
}

static const struct bpf_func_proto bpf_hmm_update_walk_last_proto = {
	.func		= bpf_hmm_update_walk_last,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_get_mm_walk_vma, struct mm_walk *, walk) {
	//printk(KERN_INFO "Called bpf_get_mm_walk_vma, vm_flags are %lu\n", walk->vma->vm_flags);

	return (long) walk->vma;
}
static const struct bpf_func_proto bpf_get_mm_walk_vma_proto = {
	.func		= bpf_get_mm_walk_vma,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	/*.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING, */
	//.btf_id		= &mm_struct_id,
};

BPF_CALL_1(bpf_get_hmm_vma_walk, struct mm_walk *, walk) {
	return (long)walk->private;
}

static const struct bpf_func_proto bpf_get_hmm_vma_walk_proto = {
	.func		= bpf_get_hmm_vma_walk,
	.gpl_only	= false,
	/* In case we want to report error later */
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	/*.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING, */
	//.btf_id		= &mm_struct_id,
};
/*
BPF_CALL_1(bpf_get_hmm_range_user, struct hmm_vma_walk *, walk) {
//	struct bpf_hmm_storage *stab;
	struct hmm_range *range_user;
	
	struct hmm_range *range = walk->range;
	unsigned long npages = (range->end - range->start) >> PAGE_SHIFT;
	size_t pfns_size = (sizeof(unsigned long)) * npages;


	//printk(KERN_INFO "Called bpf_get_hmm_range_user, npages = %lu\n", npages);

	range_user = kzalloc(sizeof(*range_user), GFP_USER);

	memcpy(&range_user->start, &range->start, sizeof(range_user->start));
	memcpy(&range_user->end, &range->end, sizeof(range_user->end));
	memcpy(&range_user->default_flags, &range->default_flags, sizeof(range_user->default_flags));
	memcpy(&range_user->pfn_flags_mask, &range->pfn_flags_mask, sizeof(range_user->pfn_flags_mask));
		
	range_user->hmm_pfns = kzalloc(pfns_size, GFP_USER);
	memcpy(range_user->hmm_pfns, range->hmm_pfns, pfns_size);
	
	return (unsigned long)range_user;
};

static const struct bpf_func_proto bpf_get_hmm_range_user_proto = {
	.func		= bpf_get_hmm_range_user,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_ALLOC_MEM_OR_NULL,
	.arg1_type	= ARG_ANYTHING,
};

*/
BPF_CALL_5(bpf_hmm_vma_walk_pud, void *, pudp, unsigned long, start, unsigned long, end, struct mm_walk *,walk, int __user *, ret) {
	int val = hmm_vma_walk_pud((pud_t *)pudp, start, end, walk);
	return val;
}

static const struct bpf_func_proto bpf_hmm_vma_walk_pud_proto = {
	.func		= bpf_hmm_vma_walk_pud,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};


BPF_CALL_4(bpf_hmm_vma_walk_pmd, void *, pmdp, unsigned long, start, unsigned long, end, struct mm_walk *,walk) {
	//printk(KERN_INFO "Called bpf_hmm_vma_walk_pmd\n");
	return hmm_vma_walk_pmd((pmd_t *)pmdp, start, end, walk);
}

static const struct bpf_func_proto bpf_hmm_vma_walk_pmd_proto = {
	.func		= bpf_hmm_vma_walk_pmd,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_hmm_vma_walk_hole, unsigned long, addr, unsigned long, end,
					     int, depth, struct mm_walk *,walk) {
	//printk(KERN_INFO "Called bpf_hmm_vma_walk_hole\n");
	return hmm_vma_walk_hole(addr, end, depth, walk);
}

static const struct bpf_func_proto bpf_hmm_vma_walk_hole_proto = {
	.func		= bpf_hmm_vma_walk_hole,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};


BPF_CALL_5(bpf_hmm_vma_walk_hugetlb_entry, void *, pte, unsigned long, hmask, unsigned long, start, unsigned long, end, struct mm_walk *, walk) {
	//printk(KERN_INFO "Called bpf_hmm_vma_walk_hugetlb_entry\n");
	return hmm_vma_walk_hugetlb_entry((pte_t *)pte, hmask, start, end, walk);
}

static const struct bpf_func_proto bpf_hmm_vma_walk_hugetlb_entry_proto = {
	.func		= bpf_hmm_vma_walk_hugetlb_entry,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_hmm_vma_walk_test, unsigned long, start, unsigned long, end,
						     struct mm_walk *, walk) {
	printk(KERN_INFO "Called bpf_hmm_vma_walk_test, start=%lu, end=%lu, walk=%lu\n", 
			start, end, (unsigned long)walk);
	//int val = hmm_vma_walk_test(start, end, walk);
	//printk(KERN_INFO "bpf_hmm_vma_walk_test returned %d\n", val);
	return 7;
}

static const struct bpf_func_proto bpf_hmm_vma_walk_test_proto = {
	.func		= bpf_hmm_vma_walk_test,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};


static const struct bpf_verifier_ops bpf_hmm_verifier_ops = {
	.get_func_proto		= bpf_hmm_policy_get_func_proto,
	.is_valid_access	= bpf_hmm_policy_is_valid_access,
	.btf_struct_access	= bpf_hmm_policy_btf_struct_access,
};

static int bpf_mm_walk_ops_init_member(const struct btf_type *t, 
		const struct btf_member *member, 
		void *kdata, 
		const void *udata)
{
	const struct mm_walk_ops *uhmm_policy;
	struct mm_walk_ops *khmm_policy;
	int prog_fd;
	u32 moff;

	uhmm_policy = (const struct mm_walk_ops *)udata;
	khmm_policy = (struct mm_walk_ops *)kdata;

	moff = btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct mm_walk_ops, name):
		if (bpf_obj_name_cpy(khmm_policy->name, uhmm_policy->name, sizeof(khmm_policy->name)) <= 0)
			return -EINVAL;
		return 1;
	}
	
	
	if (!btf_type_resolve_func_ptr(btf_vmlinux, member->type, NULL))
		return 0;

	/* Ensure bpf_prog is provided for compulsory func ptr */
	prog_fd = (int)(*(unsigned long *)(udata + moff));
	//All mm_walk_ops function pointers are optional
//	if (!prog_fd) // && !is_optional(moff) && !is_unsupported(moff))
//		return -EINVAL;	
	return 0;
}
static int bpf_hmm_init(struct btf *btf) {
	return 0;
}

static int bpf_hmm_check_member(const struct btf_type *t, const struct btf_member *member)
{
	return 0;
}

static int bpf_mm_walk_ops_reg(void *kdata)
{
	printk(KERN_INFO "Calling to register mm_walk_ops\n");
	return hmm_register_mm_walk_ops(kdata);
}

static void bpf_mm_walk_ops_unreg(void *kdata)
{
	printk(KERN_INFO "Calling to unregister mm_walk_ops\n");
	hmm_unregister_mm_walk_ops(kdata);
}

extern struct bpf_struct_ops bpf_mm_walk_ops;

struct bpf_struct_ops bpf_mm_walk_ops = {
	.verifier_ops = &bpf_hmm_verifier_ops,
	.reg = bpf_mm_walk_ops_reg,
	.unreg = bpf_mm_walk_ops_unreg,
	.check_member = bpf_hmm_check_member,
	.init_member = bpf_mm_walk_ops_init_member,
	.init = bpf_hmm_init,
	.name = "mm_walk_ops",
};

