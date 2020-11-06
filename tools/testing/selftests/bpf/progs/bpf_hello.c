// SPDX-License-Identifier: GPL-2.0
// /* Copyright (c) 2019 Facebook */
//
// /* WARNING: This implemenation is not necessarily the same
//  * as the tcp_dctcp.c.  The purpose is mainly for testing
//   * the kernel BPF logic.
//    */
//
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

struct hello_struct {
	int (*print_msg)(int a);
	char name[16];
};


SEC("struct_ops/my_print_msg")
int BPF_PROG(my_print_msg, int a)
{
	char fmt[] = "bpf my_print_msg called!\n";
	bpf_trace_printk(fmt, sizeof(fmt));
	return 0;
}


SEC(".struct_ops")
struct hello_struct hello = {
	.print_msg	= (void *)my_print_msg,
	.name		= "bpf_hello",
};

