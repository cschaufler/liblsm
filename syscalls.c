// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Linux system call interfaces.
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <unistd.h>
#include <errno.h>
#include <linux/lsm.h>
#include "liblsm.h"

int lsm_get_self_attr(unsigned int attr, struct lsm_ctx *ctx,  
		      __kernel_size_t *size, __u32 flags)
{
	int rc;

	rc = syscall(__NR_lsm_get_self_attr, attr, ctx, size, flags);
	if (rc < 0 && errno == ENOSYS)
		rc = lsm_get_self_attr_proc(attr, ctx, size);

	return rc;
}

int lsm_set_self_attr(unsigned int attr, struct lsm_ctx *ctx,  
		      __kernel_size_t size, __u32 flags)
{
	int rc;

	rc = syscall(__NR_lsm_set_self_attr, attr, ctx, size, flags);
	if (rc < 0 && errno == ENOSYS)
		rc = lsm_set_self_attr_proc(attr, ctx);

	return rc;
}

int lsm_list_modules(__u64 *result, __kernel_size_t *size, __u32 flags)
{
	int rc;

	rc = syscall(__NR_lsm_list_modules, result, size, flags);
	if (rc < 0 && errno == ENOSYS)
		rc = lsm_list_modules_proc(result, size);

	return rc;
}
