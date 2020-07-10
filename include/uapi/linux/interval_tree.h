/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_UAPI_INTERVAL_TREE_H
#define _LINUX_UAPI_INTERVAL_TREE_H

#include <linux/rbtree.h>

struct interval_tree_node {
	struct rb_node rb;
	unsigned long start;	/* Start of interval */
	unsigned long last;	/* Last location _in_ interval */
	unsigned long __subtree_last;
};

#endif	/* _LINUX_UAPI_INTERVAL_TREE_H */
