#
# Copyright (c) 2019 Brent Cook
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

sbin_PROGRAMS = bgplgd
man_MANS = bgplgd.8

EXTRA_DIST = bgplgd.8.in
CLEANFILES = $(man_MANS)

bgplgd_CFLAGS = $(AM_CFLAGS)
bgplgd_CFLAGS += -DSYSCONFDIR=\"$(sysconfdir)\"
bgplgd_CFLAGS += -DRUNSTATEDIR=\"$(runstatedir)\"

bgplgd_LDADD = $(PLATFORM_LDADD) $(PROG_LDADD) -lutil -lm
bgplgd_LDADD += $(top_builddir)/compat/libcompat.la
bgplgd_LDADD += $(top_builddir)/compat/libcompatnoopt.la

bgplgd_SOURCES = bgplgd.c
bgplgd_SOURCES += qs.c
bgplgd_SOURCES += slowcgi.c

bgplgd_DEPENDENCIES = $(man_MANS)

noinst_HEADERS = bgplgd.h
noinst_HEADERS += http.h
noinst_HEADERS += slowcgi.h

bgplgd.8: bgplgd.8.in
	$(SED) \
		-e 's|@BGPD_USER[@]|$(BGPD_USER)|g' \
		-e 's|@BGPLGD_USER[@]|$(BGPLGD_USER)|g' \
		-e 's|@SYSCONFDIR[@]|$(sysconfdir)|g' \
		-e 's|@RUNSTATEDIR[@]|$(runstatedir)|g' \
		'$(srcdir)/bgplgd.8.in' >$@
