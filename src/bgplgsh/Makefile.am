#
# Copyright (c) 2022 Claudio Jeker
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

AM_CPPFLAGS = -I$(top_srcdir)/include

ACLOCAL_AMFLAGS = -Im4

bin_PROGRAMS = bgplgsh
man_MANS = bgplgsh.8

EXTRA_DIST = bgplgsh.8.in
CLEANFILES = $(man_MANS)

bgplgsh_CFLAGS = $(AM_CFLAGS)
bgplgsh_CFLAGS += -DRUNSTATEDIR=\"$(runstatedir)\"

bgplgsh_LDADD = $(PLATFORM_LDADD) $(PROG_LDADD) -ledit

bgplgsh_SOURCES = bgplgsh.c
bgplgsh_SOURCES += misc.c

bgplgsh_DEPENDENCIES = $(man_MANS)

noinst_HEADERS = bgplg.h

bgplgsh.8: bgplgsh.8.in
	$(SED) \
		-e 's|@BGPD_USER[@]|$(BGPD_USER)|g' \
		-e 's|@BGPLGD_USER[@]|$(BGPLGD_USER)|g' \
		-e 's|@SYSCONFDIR[@]|$(sysconfdir)|g' \
		-e 's|@RUNSTATEDIR[@]|$(runstatedir)|g' \
		'$(srcdir)/bgplgsh.8.in' >$@
