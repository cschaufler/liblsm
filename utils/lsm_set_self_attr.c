// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lsm_set_self_attr - Simple program to change Linux Security Module
 * attributes for the current process.
 *
 * lsm_set_self_attr lsm attribute value [cmd [cmd-options]]
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

int main(int argc, char *argv[])
{
	__u64 size;
	int lsmid;
	int attrid;
	int attrlen;
	char *cmd = "/bin/sh";
	struct lsm_ctx *lcp;

	if (argc < 4) {
		fprintf(stderr, "Usage: %s LSM attribute value [cmd [args]]\n",
			argv[0]);
		exit(1);
	}
	if ((lsmid = lsm_id_from_name(argv[1])) == LSM_ID_UNDEF) {
		fprintf(stderr, "%s: Unknown LSM %s\n", argv[0], argv[1]);
		exit(1);
	}
	if ((attrid = lsm_attr_id_from_name(argv[2])) == LSM_ATTR_UNDEF) {
		fprintf(stderr, "%s: Unknown LSM attribute %s\n", argv[0],
			argv[2]);
		exit(1);
	}
	attrlen = strlen(argv[3]) + 1;

	size = sizeof(*lcp) + attrlen + sizeof(lcp);
	if (lsm_ctx_fill(NULL, &size, argv[3], attrlen, lsmid, 0) < 0) {
		fprintf(stderr, "%s: attribute validation failure.\n", argv[0]);
		exit(1);
	}
	if ((lcp = malloc(size)) == NULL) {
		fprintf(stderr, "%s: memory allocation failure.\n", argv[0]);
		exit(1);
	}
	if (lsm_ctx_fill(lcp, &size, argv[3], attrlen, lsmid, 0) < 0) {
		fprintf(stderr, "%s: attribute validation failure.\n", argv[0]);
		exit(1);
	}

	if (lsm_set_self_attr(attrid, lcp, lcp->len, 0)) {
		fprintf(stderr, "%s %s reset failed\n", argv[1], argv[2]);
		exit(1);
	}

	if (argc == 5)
		cmd = argv[4];
	if (argc <= 5) {
		execl(cmd, cmd, NULL);
		fprintf(stderr, "%s: %s exec failed\n", argv[0], cmd);
		exit(1);
	}
	execv(argv[4], &argv[4]);
	fprintf(stderr, "%s: %s exec with argc=%d failed\n", argv[0], argv[4],
		argc);
	exit(1);
}
