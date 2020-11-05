This is a port of OpenBGPD to other operating systems. It is based on
portability code from the OpenNTPD, OpenSSH, and LibreSSL portable projects.

OpenBGPD has a web site at http://openbgpd.com/

The current portable tree can be found at
https://github.com/openbgpd-portable/openbgpd-portable

[![Build Status](https://travis-ci.org/openbgpd-portable/openbgpd-portable.svg?branch=master)](https://travis-ci.org/openbgpd-portable/openbgpd-portable)

Platform Requirements
---------------------

At the time of writing the portable version is known to build and work on:

 - OpenBSD-current
 - OpenBSD (6.5)
 - Alpine 3.12
 - Debian 9
 - Fedora 31, 32, 33
 - RHEL/CentOS 7, 8
 - FreeBSD (12.x)

OpenBGPD may work on other operating systems, newer and older, but the above
ones are tested regularly by the developer.

Reports (success or otherwise) are welcome. You may report bugs or submit pull
requests at the GitHub project: https://github.com/openbgpd-portable

Thanks,
  Claudio Jeker <claudio at openbsd.org> and
  Brent Cook <bcook at openbsd.org>.
