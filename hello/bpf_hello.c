#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/hello.h>
#include <uapi/linux/btf.h>

extern struct btf *btf_vmlinux;



static bool bpf_hello_is_valid_access(int off, int size, 
		enum bpf_access_type type, const struct bpf_prog *prog, 
		struct bpf_insn_access_aux *info) 
{
	return true;
}

static const struct bpf_func_proto * bpf_hello_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	printk(KERN_INFO "bpf_base_func_proto, Func id is %d\n", func_id);
	switch (func_id) {	
	default:
		return bpf_base_func_proto(func_id);
	}	
}

static int bpf_hello_btf_struct_access(struct bpf_verifier_log *log, const struct btf_type *t, int off,
					int size, enum bpf_access_type atype, u32 *next_btf_id)
{
	return btf_struct_access(log, t, off, size, atype, next_btf_id);
}

static const struct bpf_verifier_ops bpf_hello_verifier_ops = {
	.get_func_proto		= bpf_hello_get_func_proto,
	.is_valid_access	= bpf_hello_is_valid_access,
	.btf_struct_access	= bpf_hello_btf_struct_access,
};

static int bpf_hello_init_member(const struct btf_type *t, 
		const struct btf_member *member, 
		void *kdata, 
		const void *udata)
{
	const struct hello_struct *uhmm_policy;
	struct hello_struct *khmm_policy;
	int prog_fd;
	u32 moff;

	printk(KERN_INFO "bpf_hello_init member called\n");
	uhmm_policy = (const struct hello_struct *)udata;
	khmm_policy = (struct hello_struct *)kdata;

	moff = btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct hello_struct, name):
		if (bpf_obj_name_cpy(khmm_policy->name, uhmm_policy->name, sizeof(khmm_policy->name)) <= 0) {
			printk(KERN_INFO "Cannot init hello->name, khmm_policy->name=%s, uhmm_policy->name=%s\n", 
					khmm_policy->name, uhmm_policy->name);
			return -EINVAL;
		}
		printk(KERN_INFO "Name INIT success hello->name, khmm_policy->name=%s, uhmm_policy->name=%s\n", 
					khmm_policy->name, uhmm_policy->name);
		return 1;
	}
	
	if (!btf_type_resolve_func_ptr(btf_vmlinux, member->type, NULL)) {
		printk(KERN_INFO "Cannot resolve func pointer\n");
		return 0;
	}

	/* Ensure bpf_prog is provided for compulsory func ptr */
	prog_fd = (int)(*(unsigned long *)(udata + moff));
	//All mm_walk_ops function pointers are optional
//	if (!prog_fd) // && !is_optional(moff) && !is_unsupported(moff))
//		return -EINVAL;
	if (!prog_fd) printk(KERN_INFO "prog_fd not set\n");
	
	
	printk(KERN_INFO "bpf_hello_init member SUCCESS\n");
	return 0;
}
static int bpf_hello_init(struct btf *btf) {
	return 0;
}

static int bpf_hello_check_member(const struct btf_type *t, const struct btf_member *member)
{
	return 0;
}

static int bpf_hello_reg(void *kdata)
{
	printk(KERN_INFO "Calling to register hello\n");
	return hello_register(kdata);
}

static void bpf_hello_unreg(void *kdata)
{
	printk(KERN_INFO "Calling to unregister hello\n");
	hello_unregister(kdata);
}

extern struct bpf_struct_ops bpf_hello_struct;

struct bpf_struct_ops bpf_hello_struct = {
	.verifier_ops = &bpf_hello_verifier_ops,
	.reg = bpf_hello_reg,
	.unreg = bpf_hello_unreg,
	.check_member = bpf_hello_check_member,
	.init_member = bpf_hello_init_member,
	.init = bpf_hello_init,
	.name = "hello_struct",
};

