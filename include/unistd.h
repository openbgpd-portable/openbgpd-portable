/*
 * Public domain
 * unistd.h compatibility shim
 */

#include_next <unistd.h>

#ifndef LIBCOMPAT_UNISTD_H
#define LIBCOMPAT_UNISTD_H

#ifndef HAVE_PLEDGE
#define pledge(request, paths) 0
#endif

#ifndef HAVE_UNVEIL
#define unveil(path, permissions) 0
#endif

#ifndef HAVE_GETENTROPY
int getentropy(void *, size_t);
#endif

#include <grp.h>

#ifndef HAVE_SETGROUPS
int setgroups(int, const gid_t *);
#endif

#ifndef HAVE_SETRESGID
int setresgid(gid_t, gid_t, gid_t);
#endif

#ifndef HAVE_SETRESUID
int setresuid(uid_t, uid_t, uid_t);
#endif

#ifndef HAVE_HOST_NAME_MAX
#include <limits.h>
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

#endif
