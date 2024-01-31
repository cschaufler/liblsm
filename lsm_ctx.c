// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Functions to help with using struct lsm_ctx
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <unistd.h>
#include <linux/lsm.h>

struct lsm_ctx *lsm_ctx_next(struct lsm_ctx *ctx, __u64 *size)
{
	if (ctx == NULL || size == NULL || *size <= ctx->len)
		return NULL;

	*size -= ctx->len;
	return (struct lsm_ctx *)((void *)ctx + ctx->len);
}
