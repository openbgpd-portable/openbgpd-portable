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

ACLOCAL_AMFLAGS = -Im4
CLEANFILES = $(man_MANS)
CLEANFILES += parse.c

sbin_PROGRAMS = bgpd
man_MANS = bgpd.8
man_MANS += bgpd.conf.5

EXTRA_DIST = bgpd.8.in bgpd.conf.5.in

bgpd_CFLAGS = $(AM_CFLAGS)
bgpd_CFLAGS += -DSYSCONFDIR=\"$(sysconfdir)\"
bgpd_CFLAGS += -DRUNSTATEDIR=\"$(runstatedir)\"

bgpd_LDADD = $(PLATFORM_LDADD) $(PROG_LDADD) -lutil
bgpd_LDADD += $(top_builddir)/compat/libcompat.la
bgpd_LDADD += $(top_builddir)/compat/libcompatnoopt.la

bgpd_SOURCES = bgpd.c
bgpd_SOURCES += session.c
bgpd_SOURCES += log.c
bgpd_SOURCES += logmsg.c
bgpd_SOURCES += parse.y
bgpd_SOURCES += config.c
bgpd_SOURCES += rde.c
bgpd_SOURCES += rde_rib.c
bgpd_SOURCES += rde_decide.c
bgpd_SOURCES += rde_prefix.c
bgpd_SOURCES += mrt.c
if HOST_OPENBSD
bgpd_SOURCES += kroute.c
else
if HOST_FREEBSD
bgpd_SOURCES += kroute-freebsd.c
else
if HAVE_MNL
bgpd_SOURCES += kroute-linux.c
else
bgpd_SOURCES += kroute-disabled.c
endif
endif
endif
bgpd_SOURCES += control.c
if HOST_OPENBSD
bgpd_SOURCES += pfkey.c
else
if HOST_FREEBSD
bgpd_SOURCES += pfkey-freebsd.c
else
if HAVE_LINUX_TCPMD5
bgpd_SOURCES += pfkey-linux.c
else
bgpd_SOURCES += pfkey-disabled.c
endif
endif
endif
bgpd_SOURCES += rde_update.c
bgpd_SOURCES += rde_attr.c
bgpd_SOURCES += rde_community.c
bgpd_SOURCES += printconf.c
bgpd_SOURCES += rde_filter.c
bgpd_SOURCES += rde_sets.c
bgpd_SOURCES += rde_trie.c
if HOST_OPENBSD
bgpd_SOURCES += pftable.c
else
bgpd_SOURCES += pftable-disabled.c
endif
bgpd_SOURCES += name2id.c
bgpd_SOURCES += util.c
if HOST_OPENBSD
bgpd_SOURCES += carp.c
else
bgpd_SOURCES += carp-disabled.c
endif
bgpd_SOURCES += timer.c
bgpd_SOURCES += rde_peer.c
bgpd_SOURCES += rtr.c
bgpd_SOURCES += rtr_proto.c

bgpd_DEPENDENCIES = $(man_MANS)

noinst_HEADERS = bgpd.h
noinst_HEADERS += log.h
noinst_HEADERS += mrt.h
noinst_HEADERS += rde.h
noinst_HEADERS += session.h
noinst_HEADERS += version.h

bgpd.conf.5: bgpd.conf.5.in
	$(SED) \
		-e 's|@BGPD_USER[@]|$(BGPD_USER)|g' \
		-e 's|@SYSCONFDIR[@]|$(sysconfdir)|g' \
		-e 's|@RUNSTATEDIR[@]|$(runstatedir)|g' \
		'$(srcdir)/bgpd.conf.5.in' >$@

bgpd.8: bgpd.8.in
	$(SED) \
		-e 's|@BGPD_USER[@]|$(BGPD_USER)|g' \
		-e 's|@SYSCONFDIR[@]|$(sysconfdir)|g' \
		-e 's|@RUNSTATEDIR[@]|$(runstatedir)|g' \
		'$(srcdir)/bgpd.8.in' >$@
