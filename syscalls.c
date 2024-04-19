// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Linux system call interfaces.
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <errno.h>
#include <asm/unistd.h>
#include "liblsm.h"

/**
 * lsm_get_self_attr - fetch current process attribute values.
 * @attr: attribute ID to fetch
 * @ctx: pointer to the result buffer
 * @size: size of the result buffer
 * @flags: indicators of special handling
 *
 * Get the values for the specified @attr from all active LSMs
 * on the system and store them in @ctx.
 *
 * Returns the number of attributes fetched, or -1 on error.
 */
int lsm_get_self_attr(unsigned int attr, struct lsm_ctx *ctx,  
		      __u32 *size, __u32 flags)
{
	int rc;

	rc = syscall(__NR_lsm_get_self_attr, attr, ctx, size, flags);
	if (rc < 0 && errno == ENOSYS)
		rc = lsm_get_self_attr_proc(attr, ctx, size);

	return rc;
}

/**
 * lsm_set_self_attr - set a current process attribute value.
 * @attr: attribute ID to fetch
 * @ctx: pointer to the attribute structure
 * @size: size of the attribute structure
 * @flags: indicators of special handling
 *
 * Set the value for the specified @attr.
 *
 * Returns 0 on success or -1 on error.
 */
int lsm_set_self_attr(unsigned int attr, struct lsm_ctx *ctx,  
		      __u32 size, __u32 flags)
{
	int rc;

	rc = syscall(__NR_lsm_set_self_attr, attr, ctx, size, flags);
	if (rc < 0 && errno == ENOSYS)
		rc = lsm_set_self_attr_proc(attr, ctx);

	return rc;
}

/**
 * lsm_list_modules - fetch the list of active LSMs on the system
 * @result: the buffer to receive the LSM IDs
 * @size: the size of the buffer
 * @flags: indicators of special handling
 * 
 * Fetch the list of LSM IDs that are active on the running system.
 *
 * Returns the number of active LSMs, or -1 on error.
 */
int lsm_list_modules(__u64 *result, __u32 *size, __u32 flags)
{
	int rc;

	rc = syscall(__NR_lsm_list_modules, result, size, flags);
	if (rc < 0 && errno == ENOSYS)
		rc = lsm_list_modules_proc(result, size);

	return rc;
}
