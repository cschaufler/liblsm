// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Functions to help with using struct lsm_ctx
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <string.h>
#include <unistd.h>
#include <linux/errno.h>
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
struct lsm_ctx *lsm_ctx_next(struct lsm_ctx *ctx, __u32 *size)
{
	if (ctx == NULL || size == NULL || *size <= ctx->len)
		return NULL;

	*size -= ctx->len;
	return (struct lsm_ctx *)((void *)ctx + ctx->len);
}

/**
 * lsm_ctx_fill - Fill a lsm_ctx structure
 * @uctx: a LSM context to be filled
 * @uctx_len: available uctx size (input), used uctx size (output)
 * @val: the new LSM context value
 * @val_len: the size of the new LSM context value
 * @id: LSM id
 * @flags: LSM defined flags
 *
 * Fill all of the fields in a lsm_ctx structure.  If @uctx is NULL
 * simply calculate the required size to output via @utc_len and return
 * success.
 *
 * Returns 0 on success, -E2BIG if *uctx is not large enough,
 * -EINVAL if uctx_len is NULL.
 */
int lsm_ctx_fill(struct lsm_ctx *uctx, __u64 *uctx_len, void *val,
		 __u64 val_len, __u64 id, __u64 flags)
{
	__u64 nctx_len;
	int pad;

	if (!uctx_len)
		return -EINVAL;

	nctx_len = sizeof(*uctx) + val_len;
	pad = (sizeof(*uctx) + *uctx_len) % sizeof(void *);
	if (pad)
		nctx_len += sizeof(void *) - pad;

	if (nctx_len > *uctx_len) {
		*uctx_len = nctx_len;
		return -E2BIG;
	}
	*uctx_len = nctx_len;

	if (!uctx)
		return 0;

	memset(uctx, 0, nctx_len);
	uctx->id = id;
	uctx->flags = flags;
	uctx->len = nctx_len;
	uctx->ctx_len = val_len;
	memcpy(uctx->ctx, val, val_len);

	return 0;
}
