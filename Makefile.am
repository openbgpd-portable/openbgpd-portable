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

SUBDIRS = include compat src/bgpd src/bgpctl
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = README.md LICENSE VERSION bgpd.conf

install-data-hook:
	@if [ ! -d "$(DESTDIR)$(runstatedir)" ]; then \
		$(INSTALL) -m 755 -d "$(DESTDIR)$(runstatedir)"; \
	fi
	@if [ ! -d "$(DESTDIR)$(sysconfdir)" ]; then \
		$(INSTALL) -m 755 -d "$(DESTDIR)$(sysconfdir)"; \
	fi
	@if [ ! -f "$(DESTDIR)$(sysconfdir)/bgpd.conf" ]; then \
		$(INSTALL) -m 644 "$(srcdir)/bgpd.conf" "$(DESTDIR)$(sysconfdir)/bgpd.conf"; \
	else \
		echo; \
		echo " $(DESTDIR)$(sysconfdir)/bgpd.conf already exists, install will not overwrite"; \
	fi

uninstall-local:
	@if cmp -s "$(DESTDIR)$(sysconfdir)/bgpd.conf" "$(srcdir)/bgpd.conf"; then \
		rm -f "$(DESTDIR)$(sysconfdir)/bgpd.conf"; \
	fi
