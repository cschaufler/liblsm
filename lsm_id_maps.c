// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Functions to map LSM id values to strings
 *
 * Copyright (c) 2024 Casey Schaufler <casey@schaufler-ca.com>
 */
#include <unistd.h>
#include <string.h>
#include <linux/lsm.h>

struct id_map {
	const char *name;
	int id;
};

static const struct id_map lsm_ids[] = {
	{ .name = "undefined",	.id = LSM_ID_UNDEF },
	{ .name = "capability",	.id = LSM_ID_CAPABILITY },
	{ .name = "selinux",	.id = LSM_ID_SELINUX },
	{ .name = "smack",	.id = LSM_ID_SMACK },
	{ .name = "tomoyo",	.id = LSM_ID_TOMOYO },
	{ .name = "apparmor",	.id = LSM_ID_APPARMOR },
	{ .name = "yama",	.id = LSM_ID_YAMA },
	{ .name = "loadpin",	.id = LSM_ID_LOADPIN },
	{ .name = "safesetid",	.id = LSM_ID_SAFESETID },
	{ .name = "lockdown",	.id = LSM_ID_LOCKDOWN },
	{ .name = "bpf",	.id = LSM_ID_BPF },
	{ .name = "landlock",	.id = LSM_ID_LANDLOCK },
};

/**
 * lsm_id_to_name - get the LSM name for an LSM ID
 * @id: The LSM ID in question.
 *
 * Map @id to an LSM ID.
 *
 * Returns a string pointer if the LSM is found, NULL otherwise.
 */
const char *lsm_id_to_name(int id)
{
	unsigned int i;

	for (i = 0; i < sizeof (lsm_ids) / sizeof (struct id_map); i++) {
		if (lsm_ids[i].id == id)
			return lsm_ids[i].name;
	}
	return NULL;
}

/**
 * lsm_id_from_name - get the LSM ID for an LSM name
 * @name: The LSM name in question.
 *
 * Map @name to an LSM name.
 *
 * Returns the LSM ID if the @name is found, LSM_ID_UNDEF otherwise.
 */
int lsm_id_from_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < sizeof (lsm_ids) / sizeof (struct id_map); i++) {
		if (!strcmp(lsm_ids[i].name, name))
			return lsm_ids[i].id;
	}
	return LSM_ID_UNDEF;
}

static const struct id_map lsm_attrs[] = {
	{ .name = "current",	.id = LSM_ATTR_CURRENT },
	{ .name = "exec",	.id = LSM_ATTR_EXEC },
	{ .name = "fscreate",	.id = LSM_ATTR_FSCREATE },
	{ .name = "keycreate",	.id = LSM_ATTR_KEYCREATE },
	{ .name = "prev",	.id = LSM_ATTR_PREV },
	{ .name = "sockcreate",	.id = LSM_ATTR_SOCKCREATE },
};

/**
 * lsm_attr_id_to_name - get the LSM attribute name for an attr ID
 * @attr: The LSM attribute ID in question.
 *
 * Map @attr to an LSM attribute name.
 *
 * Returns a string pointer if the attribute is found, NULL otherwise.
 */
const char *lsm_attr_id_to_name(int attr)
{
	unsigned int i;

	for (i = 0; i < sizeof (lsm_attrs) / sizeof (struct id_map); i++) {
		if (lsm_attrs[i].id == attr)
			return lsm_attrs[i].name;
	}
	return NULL;
}

/**
 * lsm_attr_id_from_name - get the LSM attribute ID for an attr name
 * @name: The LSM attribute name in question.
 *
 * Map @name to an LSM attribute ID.
 *
 * Returns the attribute ID if the @name is found, LSM_ATTR_UNDEF otherwise.
 */
int lsm_attr_id_from_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < sizeof (lsm_attrs) / sizeof (struct id_map); i++) {
		if (!strcmp(lsm_attrs[i].name, name))
			return lsm_attrs[i].id;
	}
	return LSM_ATTR_UNDEF;
}
