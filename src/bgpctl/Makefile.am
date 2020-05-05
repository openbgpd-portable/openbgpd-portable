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
AM_CPPFLAGS += -I$(top_srcdir)/src/bgpd
AM_CPPFLAGS += -I$(top_srcdir)/src/bgpctl

ACLOCAL_AMFLAGS = -Im4

sbin_PROGRAMS = bgpctl
man_MANS = bgpctl.8

EXTRA_DIST = bgpctl.8.in
CLEANFILES = $(man_MANS)

bgpctl_CFLAGS = $(AM_CFLAGS)
bgpctl_CFLAGS += -DSYSCONFDIR=\"$(sysconfdir)\"
bgpctl_CFLAGS += -DRUNSTATEDIR=\"$(runstatedir)\"

bgpctl_LDADD = $(PLATFORM_LDADD) $(PROG_LDADD) -lutil -lm
bgpctl_LDADD += $(top_builddir)/compat/libcompat.la
bgpctl_LDADD += $(top_builddir)/compat/libcompatnoopt.la

bgpctl_SOURCES = bgpctl.c
bgpctl_SOURCES += output.c
bgpctl_SOURCES += output_json.c
bgpctl_SOURCES += parser.c
bgpctl_SOURCES += mrtparser.c
bgpctl_SOURCES += util.c
bgpctl_SOURCES += json.c

bgpctl_DEPENDENCIES = $(man_MANS)

noinst_HEADERS =
noinst_HEADERS += bgpctl.h
noinst_HEADERS += json.h
noinst_HEADERS += mrtparser.h
noinst_HEADERS += parser.h

bgpctl.8: bgpctl.8.in
	$(SED) \
		-e 's|@BGPD_USER[@]|$(BGPD_USER)|g' \
		-e 's|@SYSCONFDIR[@]|$(sysconfdir)|g' \
		-e 's|@RUNSTATEDIR[@]|$(runstatedir)|g' \
		'$(srcdir)/bgpctl.8.in' >$@
