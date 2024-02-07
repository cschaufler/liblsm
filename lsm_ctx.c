// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Functions to help with using struct lsm_ctx
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <unistd.h>
#include <linux/lsm.h>

/**
 * lsm_ctx_next - get a pointer to the lsm_ctx after this one
 * @ctx: The LSM context currently known
 * @size: The size of the buffer containing the contexts.
 *
 * Verify that there are contexts after the current one,
 * and return a pointer to the next one.
 *
 * Returns NULL if there are no more contexts, the next
 * one if there is one.
 */
struct lsm_ctx *lsm_ctx_next(struct lsm_ctx *ctx, __u64 *size)
{
	if (ctx == NULL || size == NULL || *size <= ctx->len)
		return NULL;

	*size -= ctx->len;
	return (struct lsm_ctx *)((void *)ctx + ctx->len);
}
