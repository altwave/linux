#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/hmm.h>

extern struct btf *btf_vmlinux;

static bool bpf_hmm_policy_is_valid_access(int off, int size, 
		enum bpf_access_type type, const struct bpf_prog *prog, 
		struct bpf_insn_access_aux *info) 
{
	return true;
}

static const struct bpf_func_proto * bpf_hmm_policy_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	/*switch (func_id) {	
	case BPF_FUNC_tcp_send_ack:
		return &bpf_tcp_send_ack_proto;
	case BPF_FUNC_sk_storage_get:
		return &btf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &btf_sk_storage_delete_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
	*/
	return bpf_base_func_proto(func_id);
}

static int bpf_hmm_policy_btf_struct_access(struct bpf_verifier_log *log, const struct btf_type *t, int off,
					int size, enum bpf_access_type atype, u32 *next_btf_id)
{
	return btf_struct_access(log, t, off, size, atype, next_btf_id);
}

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
