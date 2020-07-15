// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */

#include <stdlib.h>
#include <linux/err.h>
#include <test_progs.h>
#include "bpf_mm_walk_ops.skel.h"

static int stop, duration;

static void test_mm_walk_ops(void)
{
	struct bpf_mm_walk_ops *hmm_policy_skel;
	struct bpf_link *link;

	
	hmm_policy_skel = bpf_mm_walk_ops__open_and_load();
	if (CHECK(!hmm_policy_skel, "bpf_hmm_policy__open_and_load", "failed\n"))
		return;

	link = bpf_map__attach_struct_ops(hmm_policy_skel->maps.ops);
	if (CHECK(IS_ERR(link), "bpf_map__attach_struct_ops", "err:%ld\n",
		  PTR_ERR(link))) {
		bpf_mm_walk_ops__destroy(hmm_policy_skel);
		return;
	}

	// Execute HMM tests
	int status = system("sudo /home/cat/repos/linux/tools/testing/selftests/vm/test_hmm.sh smoke");
	printf("HMM test status returned %d\n", status);

	/*do_test("bpf_hmm_policy");
	CHECK(dctcp_skel->bss->stg_result != expected_stg,
	      "Unexpected stg_result", "stg_result (%x) != expected_stg (%x)\n",
	      dctcp_skel->bss->stg_result, expected_stg);
	*/
	
	bpf_link__destroy(link);
	bpf_mm_walk_ops__destroy(hmm_policy_skel);
}


void test_bpf_mm_walk_ops(void)
{
	if (test__start_subtest("mm_walk_ops"))
		test_mm_walk_ops();
}
