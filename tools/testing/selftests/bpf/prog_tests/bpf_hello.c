// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */

#include <stdlib.h>
#include <linux/err.h>
#include <test_progs.h>
#include "bpf_hello.skel.h"

static int duration;

static void test_hello(void)
{
	struct bpf_hello *hello_skel;
	struct bpf_link *hello_link;

	
	hello_skel = bpf_hello__open_and_load();
	if (CHECK(!hello_skel, "bpf_hello__open_and_load", "failed\n"))
		return;

	
	hello_link = bpf_map__attach_struct_ops(hello_skel->maps.hello);
	if (CHECK(IS_ERR(hello_link), "bpf_map__attach_struct_ops", "err:%ld\n",
		  PTR_ERR(hello_link))) {
		bpf_hello__destroy(hello_skel);
		return;
	}

	// Execute Hello tests
	int status = system("/home/cat/repos/test/test_sys");
	printf("Hello test status returned %d\n", status);

	bpf_link__destroy(hello_link);
	bpf_hello__destroy(hello_skel);
}


void test_bpf_hello(void)
{
	if (test__start_subtest("hello"))
		test_hello();
}
