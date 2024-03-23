// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lsm_list_modules - Simple program to list active Linux Security Modules
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include "../liblsm.h"

int main(int argc, char *argv[])
{
	const char *lsmname;
	__u32 size;
	__u64 *list;
	int count;
	int i;

	size = 0;
	if ((count = lsm_list_modules(NULL, &size, 0)) < 0) {
		if (errno != E2BIG) {
			fprintf(stderr, "%s: Failed to get LSM list: %s.\n",
				argv[0], strerror(errno));
			exit(1);
		}
	}
	if ((list = malloc(size)) == NULL) {
		fprintf(stderr, "%s: Failed to get memory: %s.\n",
			argv[0], strerror(errno));
		exit(1);
	}

	count = lsm_list_modules(list, &size, 0);
	if (size <= 0 || count <= 0)
		exit(1);

	for (i = 0; i < count; i++)
		if ((lsmname = lsm_id_to_name(list[i])) != NULL)
			printf("%s%s", (i == 0) ? "" : ",", lsmname);
		else
			printf("unnamed LSM %llu\n", list[i]);
	if (count > 0)
		printf("\n");

	exit(0);
}
