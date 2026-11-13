#ifndef FZN_RPC_COMPAT_H
#define FZN_RPC_COMPAT_H

/*
 * What differs between the POSIX systems and Windows, for the clients' own
 * code: fuzznet carries its own. A file includes this rather than <poll.h>
 * and the rest, and names `fzn_rpc_mkdir` rather than `mkdir`, whose Windows
 * spelling takes no mode. Built with mingw through fmake (project.md, "macOS
 * and Windows go through fmake").
 */
#ifdef _WIN32
#include <winsock2.h> /* WSAPoll, struct pollfd: the console's poll is a socket's */
#include <ws2tcpip.h>
#include <direct.h>
#include <sys/stat.h>
#define poll WSAPoll
#define lstat stat /* Windows has no symbolic link a mkdir would follow */
#define fzn_rpc_mkdir(path, mode) _mkdir(path)
#include <bcrypt.h> /* BCryptGenRandom, the system's generator */
#include <fcntl.h>
#include <io.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static inline int fzn_rpc_entropy(void *buf, size_t len) {
	return BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
}
static inline struct tm *fzn_rpc_gmtime(const time_t *t, struct tm *out) {
	return gmtime_s(out, t) == 0 ? out : NULL;
}
/* An absolute path into `out` (PATH_MAX), as realpath with a buffer does. */
static inline char *fzn_rpc_realpath(const char *path, char *out) {
	return _fullpath(out, path, 4096);
}
/* A directory made from a template ending XXXXXX, as mkdtemp does. */
static inline char *fzn_rpc_mkdtemp(char *tmpl) {
	return _mktemp_s(tmpl, strlen(tmpl) + 1) == 0 && _mkdir(tmpl) == 0 ? tmpl : NULL;
}
static inline int fzn_rpc_nonblocking(int fd) {
	u_long on = 1;
	return ioctlsocket((SOCKET)fd, FIONBIO, &on) == 0 ? 0 : -1;
}
#else
#include <arpa/inet.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#define fzn_rpc_mkdir(path, mode) mkdir(path, mode)
#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h> /* getentropy, where macOS declares it */
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#define fzn_rpc_entropy getentropy
#define fzn_rpc_gmtime gmtime_r
#define fzn_rpc_realpath realpath
#define fzn_rpc_mkdtemp mkdtemp
static inline int fzn_rpc_nonblocking(int fd) {
	const int flags = fcntl(fd, F_GETFL, 0);
	return flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ? -1 : 0;
}
#endif

#endif /* FZN_RPC_COMPAT_H */
