/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _LINUX_UAPI_MM_TYPES_H
#define _LINUX_UAPI_MM_TYPES_H
 /*
  * A swap entry has to fit into a "unsigned long", as the entry is hidden
  * in the "index" field of the swapper address space.
  */
typedef struct {
	unsigned long val;
} swp_entry_t;

#endif /* _LINUX_UAPI_MM_TYPES_H */
