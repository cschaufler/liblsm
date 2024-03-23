// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lsm_get_self_attr - Simple program to print Linux Security Module
 * attributes for the current process.
 *
 * lsm_get_self_attr attrname
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/lsm.h>
#include <linux/types.h>
#include "../liblsm.h"

char line[256];

int main(int argc, char *argv[])
{
	__u32 size;
	__u64 attrid;
	int count;
	struct lsm_ctx *lcp;
	void *vp;
	const char *lsm;
	char *cp;

	if (argc != 2) {
		fprintf(stderr, "%s: attribute name is required.\n", argv[0]);
		exit(1);
	}
	if ((attrid = lsm_attr_id_from_name(argv[1])) == LSM_ATTR_UNDEF) {
		fprintf(stderr, "%s: attribute name unrecognized.\n", argv[0]);
		exit(1);
	}

	size = 0;
	if ((count = lsm_get_self_attr(attrid, NULL, &size, 0)) < 0) {
		if (errno != E2BIG) {
			fprintf(stderr,
				"%s: Failed to get LSM attribute size: %s.\n",
				argv[0], strerror(errno));
			exit(1);
		}
	}
	if ((lcp = malloc(size)) == NULL) {
		fprintf(stderr, "%s: Failed to get memory: %s.\n",
			argv[0], strerror(errno));
		exit(1);
	}
	vp = (void *)lcp;

	count = lsm_get_self_attr(attrid, lcp, &size, 0);
	if (size <= 0 || count <= 0)
		exit(1);

	while (count--) {
		if ((lsm = lsm_id_to_name(lcp->id)) == NULL)
			lsm = "Unknown-LSM";
		strncpy(line, (char *)lcp->ctx, lcp->ctx_len);
		line[lcp->ctx_len] = '\0';
		if ((cp = strstr(line, "\n")) != NULL)
			*cp = '*';

		if (lcp->flags)
			printf("%s %s flags=%llu\n", lsm, line, lcp->flags);
		else
			printf("%s %s\n", lsm, line);

		vp = (void *)lcp + lcp->len;
		lcp = (struct lsm_ctx *)vp;
	}
	exit(0);
}
