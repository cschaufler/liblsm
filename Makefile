# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Casey Schaufler <casey@schaufler-ca.com> 2024
#
#
CFLAGS=-fPIC -Wall -Wextra -O2 -g
LDFLAGS=-shared
LIBLSM=liblsm.so
# If the kernel is too old to find they syscalls point at headers from source
#CPPFLAGS=-I../../Kernel/linux/usr/include

SRC=syscalls.c lsm_ctx.c lsm_id_maps.c proc.c
OBJ=$(SRC:.c=.o)

.PHONY: default
default: $(LIBLSM)

$(LIBLSM): $(OBJ)
	$(CC) $(CPPFLAGS) $(LDFLAGS) -o $@ $^

$(SRC:.c=.d):%.d:%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -MM $< >$@

include $(SRC:.c=.d)

.PHONY: clean
clean:
	rm $(LIBLSM) $(OBJ) $(SRC:.c=.d)
