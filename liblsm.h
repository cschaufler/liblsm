// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Support for LSM system calls
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <string.h>
#include <unistd.h>
#include <linux/lsm.h>
#include <linux/types.h>

/*
 * Functions to make using struct lsm_ctx easier.
 */
extern struct lsm_ctx *lsm_ctx_next(struct lsm_ctx *ctx, __u32 *size);

/*
 * LSM specific system calls.
 */
extern int lsm_get_self_attr(unsigned int attr, struct lsm_ctx *ctx,
			     __u32 *size, __u32 flags);
extern int lsm_set_self_attr(unsigned int attr, struct lsm_ctx *ctx,
			     __u32 size, __u32 flags);
extern int lsm_list_modules(__u64 *result, __u32 *size, __u32 flags);

/*
 * Functions to simulate the system calls using the
 * /proc/self/attr interfaces. Used internally by liblsm.
 */
extern int lsm_get_self_attr_proc(unsigned int attr, struct lsm_ctx *ctx,
			     __u32 *size);
extern int lsm_set_self_attr_proc(unsigned int attr, struct lsm_ctx *ctx);

extern int lsm_list_modules_proc(__u64 *result, __u32 *size);

/*
 * Functions to map LSM id values to strings
 */
const char *lsm_id_to_name(__u64 id);
__u64 lsm_id_from_name(const char *name);

const char *lsm_attr_id_to_name(unsigned int attr);
__u64 lsm_attr_id_from_name(const char *name);
