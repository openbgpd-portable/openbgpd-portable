/*
 * Public domain
 * getrtable.c compatibility shim
 */

#include <sys/socket.h>

#ifdef HAVE_SETFIB
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <stddef.h>
#endif

int getrtable(void)
{
#ifdef HAVE_SETFIB
	int	fib;
	size_t	len = sizeof(fib);

	if (sysctlbyname("net.my_fibnum", &fib, &len, NULL, 0) == -1) {
		if (errno == ENOENT)	/* no fib support */
			return 0;
		return -1;
	}
	return fib;
#endif
	return 0;
}
