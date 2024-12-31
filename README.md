This is a port of OpenBGPD to other operating systems. It is based on
portability code from the OpenNTPD, OpenSSH, and LibreSSL portable projects.

OpenBGPD has a web site at https://www.openbgpd.org/

The current portable tree can be found at
https://github.com/openbgpd-portable/openbgpd-portable

[![Build Status](https://github.com/openbgpd-portable/openbgpd-portable/workflows/Build%20CI/badge.svg)](https://github.com/openbgpd-portable/openbgpd-portable/actions)

Platform Requirements
---------------------

At the time of writing the portable version is known to build and work on:

 - OpenBSD
 - Alpine 3.21, edge
 - Debian 11, 12, 13
 - Fedora 40, 41, Rawhide
 - CentOS/RHEL/Rocky 8, 9, 10
 - Ubuntu 20.04 LTS, 22.04 LTS
 - FreeBSD 12, 13
 - openSUSE
 - SLE 15

OpenBGPD may work on other operating systems, newer and older, but the above
ones are tested regularly by the developer.

Reports (success or otherwise) are welcome. You may report bugs or submit pull
requests at the GitHub project: https://github.com/openbgpd-portable

Thanks,
  Claudio Jeker <claudio at openbsd.org> and
  Brent Cook <bcook at openbsd.org>.
