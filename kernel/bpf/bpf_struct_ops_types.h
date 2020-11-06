/* SPDX-License-Identifier: GPL-2.0 */
/* internal file - do not include directly */

#ifdef CONFIG_BPF_JIT
#ifdef CONFIG_INET
#include <net/tcp.h>
BPF_STRUCT_OPS_TYPE(tcp_congestion_ops)
#endif
#ifdef CONFIG_HMM_MIRROR
//#include <linux/pagewalk.h>
#include <linux/hmm.h>
BPF_STRUCT_OPS_TYPE(hmm_policy)
BPF_STRUCT_OPS_TYPE(mm_walk_ops)
#endif
#include <linux/hello.h>
BPF_STRUCT_OPS_TYPE(hello_struct)
#endif
