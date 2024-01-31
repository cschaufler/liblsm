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

static unsigned int add_lsm_ctx(struct lsm_ctx *nctx, __u64 id, char *attr,
				__kernel_size_t size)
{
	unsigned int pad;
	struct lsm_ctx lctx;

	lctx.id = id;
	lctx.flags = 0;
	lctx.ctx_len = strlen(attr) + 1;
	lctx.len = sizeof(struct lsm_ctx) + lctx.ctx_len;
	pad = (sizeof(struct lsm_ctx) + lctx.ctx_len) % sizeof(void *);
	if (pad)
		lctx.len += sizeof(void *) - pad;
	if (lctx.len <= size) {
		*nctx = lctx;
		memcpy(nctx->ctx, attr, nctx->ctx_len);
	}
	return lctx.len;
}

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

int lsm_get_self_attr_proc(unsigned int attr, struct lsm_ctx *ctx,
			   __kernel_size_t *size)
{
	__u64 lsmids[MAXLSM];
	__kernel_size_t lsize = MAXLSM * sizeof(__u64);
	struct lsm_ctx *octx = ctx;
	unsigned int off;
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
			ctx = (void *)ctx + off;
			if (off < lsize && lsize - off <= *size)
				lsize -= off;
			else
				lsize = 0;
			free(red);
			red = NULL;
		}
	}
	*size = (void *)ctx - (void *)octx;
	if (lsize)
		return count;
	return E2BIG;
}

int lsm_set_self_attr_proc(unsigned int attr, struct lsm_ctx *ctx)
{
	const char *towrite;

	towrite = attrpath(attr, ctx->id);
	if (towrite)
		return writeattr(towrite, (char *)ctx->ctx, ctx->ctx_len);
	return -1;
}

int lsm_list_modules_proc(__u64 *result, __kernel_size_t *size)
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
	if (i > maxcount)
		return -1;
	return i;
}
