// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */

#include <stdlib.h>
#include <linux/err.h>
#include <test_progs.h>
#include "bpf_hmm.skel.h"

static int duration;

static void test_hmm(void)
{
	struct bpf_hmm *hmm_skel;
	struct bpf_link *mm_walk_ops_link, *policy_link;

	
	hmm_skel = bpf_hmm__open_and_load();
	if (CHECK(!hmm_skel, "bpf_hmm__open_and_load", "failed\n"))
		return;

	policy_link = bpf_map__attach_struct_ops(hmm_skel->maps.policy);
	if (CHECK(IS_ERR(policy_link), "bpf_map__attach_struct_ops", "err:%ld\n",
		  PTR_ERR(policy_link))) {
		bpf_hmm__destroy(hmm_skel);
		return;
	}

	mm_walk_ops_link = bpf_map__attach_struct_ops(hmm_skel->maps.ops);
	if (CHECK(IS_ERR(mm_walk_ops_link), "bpf_map__attach_struct_ops", "err:%ld\n",
		  PTR_ERR(mm_walk_ops_link))) {
		bpf_link__destroy(policy_link);
		bpf_hmm__destroy(hmm_skel);
		return;
	}

	// Execute HMM tests
//	int status = system("sudo /home/cat/repos/linux/tools/testing/selftests/vm/test_hmm.sh smoke");
//	printf("HMM test status returned %d\n", status);

	/*do_test("bpf_hmm_policy");
	CHECK(dctcp_skel->bss->stg_result != expected_stg,
	      "Unexpected stg_result", "stg_result (%x) != expected_stg (%x)\n",
	      dctcp_skel->bss->stg_result, expected_stg);
	*/
	
	bpf_link__destroy(policy_link);
	bpf_link__destroy(mm_walk_ops_link);
	bpf_hmm__destroy(hmm_skel);
}


void test_bpf_hmm(void)
{
	if (test__start_subtest("hmm"))
		test_hmm();
}
