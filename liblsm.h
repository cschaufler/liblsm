// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Support for LSM system calls
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <unistd.h>
#include <string.h>
#include <linux/types.h>
#include <linux/lsm.h>

/*
 * Functions to make using struct lsm_ctx easier.
 */
extern struct lsm_ctx *lsm_ctx_next(struct lsm_ctx *ctx, __u64 *size);

/*
 * LSM specific system calls.
 */
extern int lsm_get_self_attr(unsigned int attr, struct lsm_ctx *ctx,
			     __kernel_size_t *size, __u32 flags);
extern int lsm_set_self_attr(unsigned int attr, struct lsm_ctx *ctx,
			     __kernel_size_t size, __u32 flags);
extern int lsm_list_modules(__u64 *result, __kernel_size_t *size, __u32 flags);

/*
 * Functions to simulate the system calls using the
 * /proc/self/attr interfaces.
 */
extern int lsm_get_self_attr_proc(unsigned int attr, struct lsm_ctx *ctx,
			     __kernel_size_t *size);
extern int lsm_set_self_attr_proc(unsigned int attr, struct lsm_ctx *ctx);

extern int lsm_list_modules_proc(__u64 *result, __kernel_size_t *size);

/*
 * Functions to map LSM id values to strings
 */
const char *lsm_id_to_name(int id);
int lsm_id_from_name(const char *name);

const char *lsm_attr_flag_to_name(int attr);
int lsm_attr_flag_from_name(const char *name);
