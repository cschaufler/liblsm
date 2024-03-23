# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Casey Schaufler <casey@schaufler-ca.com> 2024
#
#
CC=/usr/bin/cc
CFLAGS=-Wall
LIBLSM=../liblsm.so
CPPFLAGS=-I../../../Kernel/linux/usr/include

PROGRAMS=lsm_list_modules lsm_get_self_attr lsm_set_self_attr

.PHONY: default
default: $(PROGRAMS)

lsm_list_modules: lsm_list_modules.c $(LIBLSM)
	cc $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LIBLSM)

lsm_get_self_attr: lsm_get_self_attr.c $(LIBLSM)
	cc $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LIBLSM)

lsm_set_self_attr: lsm_set_self_attr.c $(LIBLSM)
	cc $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LIBLSM)

.PHONY: clean
clean:
	rm $(PROGRAMS)
