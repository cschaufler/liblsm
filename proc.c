// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Linux system call interfaces.
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <linux/lsm.h>
#include "liblsm.h"

#define BIGATTR 256
#define MAXLSM 20 /* For prototype only - real value should be ??? */

/**
 * readattr - read an attribute value from the specified path
 * @path: file containing the attribute
 *
 * Open the file, read an attribute, and close the file.
 *
 * Returns an allocated buffer containing the attribute or NULL
 * on any failure.
 */
static char *readattr(const char *path)
{
	int lsize;
	char *red;
	int fd;

	if ((fd = open(path, O_RDONLY)) < 0)
		return NULL;

	if ((red = calloc(1, BIGATTR)) != NULL) {
		if ((lsize = read(fd, red, BIGATTR)) < 0) {
			free(red);
			red = NULL;
		} else {
			red[lsize] = '\0';
		}
	}
	close(fd);
	return red;
}

/**
 * writeattr - write an attribute value to the specified path
 * @path: file containing the attribute
 * @data: value to write
 * @len: length of the data to write
 *
 * Open the file, write an attribute, and close the file.
 *
 * Returns number of bytes writen on success, -1 on failure.
 */
static int writeattr(const char *path, char *data, int len)
{
	int fd;
	int rc;

	if ((fd = open(path, O_RDWR)) < 0)
		return -1;

	rc = write(fd, data, len);
	close(fd);

	return rc;
}

/**
 * add_lsm_ctx - fill an lsm_ctx structure
 * @nctx: pointer to the destination buffer
 * @id: the LSM ID to set
 * @attr: the attribute data (must be NUL-terminated string)
 * @size: bytes available in @nctx
 *
 * Fill the lsm_ctx structure pointed to by @nctx, verifying that
 * it fits in the @size available.
 *
 * Returns the final size of the lsm_ctx.
 */
static unsigned int add_lsm_ctx(struct lsm_ctx *nctx, __u64 id, char *attr,
				__u32 size)
{
	unsigned int pad;
	struct lsm_ctx lctx = { };

	lctx.id = id;
	lctx.ctx_len = strlen(attr) + 1;
	lctx.len = sizeof(struct lsm_ctx) + lctx.ctx_len;

	pad = lctx.len % sizeof(void *);
	if (pad) {
		pad = sizeof(void *) - pad;
		lctx.len += pad;
	}

	if (lctx.len <= size) {
		*nctx = lctx;
		memcpy(nctx->ctx, attr, nctx->ctx_len);
		memset(nctx->ctx + lctx.len, 0, pad);
	}
	return lctx.len;
}

/**
 * attrpath - match the attribute and LSM ids to a /proc attr path
 * @attr: attribute ID
 * @lsmid: Security Module ID
 *
 * Use the IDs passed to determine what path name in /proc/self/attr
 * represents them.
 * 
 * Returns the path if known, NULL otherwise.
 */
static const char *attrpath(unsigned int attr, __u64 lsmid)
{
	switch (attr) {
	case LSM_ATTR_CURRENT:
		switch (lsmid) {
		case LSM_ID_SELINUX:
			return "/proc/self/attr/current";
			break;
		case LSM_ID_SMACK:
			return "/proc/self/attr/smack/current";
			break;
		case LSM_ID_APPARMOR:
			return "/proc/self/attr/apparmor/current";
			break;
		}
		break;
	case LSM_ATTR_EXEC:
		if (lsmid == LSM_ID_SELINUX)
			return "/proc/self/attr/exec";
		break;
	case LSM_ATTR_FSCREATE:
		if (lsmid == LSM_ID_SELINUX)
			return "/proc/self/attr/fscreate";
		break;
	case LSM_ATTR_KEYCREATE:
		if (lsmid == LSM_ID_SELINUX)
			return "/proc/self/attr/keycreate";
		break;
	case LSM_ATTR_PREV:
		switch (lsmid) {
		case LSM_ID_SELINUX:
			return "/proc/self/attr/prev";
			break;
		case LSM_ID_APPARMOR:
			return "/proc/self/attr/apparmor/prev";
			break;
		}
		break;
	case LSM_ATTR_SOCKCREATE:
		if (lsmid == LSM_ID_SELINUX)
			return "/proc/self/attr/sockcreate";
		break;
	}
	return NULL;
}

/**
 * lsm_get_self_attr_proc - emulate lsm_get_self_attr from /proc
 * @attr: attribute ID to fetch
 * @ctx: destination buffer
 * @size: size of the destination buffer
 *
 * Identify the appropriate entries in /proc/self/attr for the
 * specified @attr and fetch the data from them, adding the result
 * to @ctx in lsm_ctx format. This emulates the behavior of the
 * lsm_get_self_attr() system call for systems before 6.8 that don't
 * support it.
 *
 * Returns the number of lsm_ctx elements or a negative value
 * on error.
 */
int lsm_get_self_attr_proc(unsigned int attr, struct lsm_ctx *ctx, __u32 *size)
{
	__u64 lsmids[MAXLSM];
	__u32 lsize = MAXLSM * sizeof(__u64);
	struct lsm_ctx *octx = ctx;
	unsigned int off, to_write = 0;
	const char *toread;
	char *red;
	int count = 0;
	int lsmcount;
	int i;

	lsmcount = lsm_list_modules_proc(lsmids, &lsize);

	lsize = *size;
	for (i = 0; i < lsmcount; i++) {
		toread = attrpath(attr, lsmids[i]);
		if (toread && (red = readattr(toread))) {
			count++;
			off = add_lsm_ctx(ctx, lsmids[i], red, lsize);
			to_write += off;
			if (lsize >= off) {
				ctx = (void *)ctx + off;
				lsize -= off;
			} else {
				lsize = 0;
			}
			free(red);
			red = NULL;
		}
	}
	if (to_write <= *size) {
		*size = (void *)ctx - (void *)octx;
		errno = 0;
		return count;
	}
	*size = to_write;
	errno = E2BIG;
	return -1;
}

/**
 * lsm_set_self_attr_proc - emulate lsm_set_self_attr from /proc
 * @attr: attribute ID to fetch
 * @ctx: destination buffer
 *
 * Identify the appropriate entry in /proc/self/attr for the
 * specified @attr and set the data to them. This emulates the
 * behavior of the lsm_set_self_attr() system call for systems
 * before 6.8 that don't support it.
 *
 * Returns the size written or -1 on error.
 */
int lsm_set_self_attr_proc(unsigned int attr, struct lsm_ctx *ctx)
{
	const char *towrite;

	errno = 0;
	towrite = attrpath(attr, ctx->id);
	if (towrite)
		return writeattr(towrite, (char *)ctx->ctx, ctx->ctx_len);
	errno = ENOENT;
	return -1;
}

/**
 * lsm_list_modules_proc - emulate lsm_list_modules
 * @result: destination buffer
 * @size: size of the destination buffer
 *
 * Read the list of active LSMs from securityfs and convert them
 * to LSM IDs. This emulates the behavior of the lsm_set_self_attr()
 * system call for systems before 6.8 that don't support it.
 *
 * Returns the number of LSM IDs or -1 on error.
 */
int lsm_list_modules_proc(__u64 *result, __u32 *size)
{
	char *lsm;
	char *red;
	unsigned int maxcount;
	unsigned int i = 0;

	maxcount = *size / sizeof(__u64);

	if ((red = readattr("/sys/kernel/security/lsm")) == NULL)
		return -1;

	lsm = strtok(red, ",");
	do {
		if (i < maxcount)
			result[i] = lsm_id_from_name(lsm);
		lsm = strtok(NULL, ",");
		i++;
	} while (lsm);
	*size = i * sizeof(*result);

	free(red);
	if (i > maxcount) {
		errno = E2BIG;
		return -1;
	}
	errno = 0;
	return i;
}
