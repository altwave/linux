/* SPDX-License-Identifier: GPL-2.0 */
/* internal file - do not include directly */

#ifdef CONFIG_BPF_JIT
#ifdef CONFIG_INET
#include <net/tcp.h>
BPF_STRUCT_OPS_TYPE(tcp_congestion_ops)
#endif
#ifdef CONFIG_HMM_MIRROR
#include <linux/hmm.h>
BPF_STRUCT_OPS_TYPE(hmm_policy)
#endif
#endif
