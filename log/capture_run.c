/* See capture_run.h. */

#define _POSIX_C_SOURCE 200809L

#include "capture_run.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t mono_ms(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t) != 0)
		return 0;
	return ((uint64_t)t.tv_sec * 1000u) + ((uint64_t)t.tv_nsec / 1000000u);
}

static void close_fd(int *fd)
{
	if (*fd >= 0) {
		(void)close(*fd);
		*fd = -1;
	}
}

static int cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD);

	return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

/* Whether the deadline has passed, and the poll timeout until it if not. */
static int past(uint64_t start, uint64_t deadline_ms, int *timeout)
{
	uint64_t gone = mono_ms() - start;

	*timeout = -1;
	if (!deadline_ms)
		return 0;
	if (gone >= deadline_ms)
		return 1;
	*timeout = (deadline_ms - gone) > 1000u ? 1000 : (int)(deadline_ms - gone);
	return 0;
}

/* The child: its own process group, stdin from /dev/null, its two streams
 * into the pipes, and exec. What exec says on failure goes back through the
 * close-on-exec pipe, which a successful exec closes instead. */
static void child(const char *const *argv, int out_w, int err_w, int exec_w)
{
	int devnull, e;

	(void)setpgid(0, 0);
	/* A daemon that ignores SIGPIPE would hand that to every tool. */
	(void)signal(SIGPIPE, SIG_DFL);
	devnull = open("/dev/null", O_RDONLY);
	if (devnull >= 0)
		(void)dup2(devnull, 0);
	(void)dup2(out_w, 1);
	(void)dup2(err_w, 2);
	execvp(argv[0], (char *const *)argv);
	e = errno;
	if (write(exec_w, &e, sizeof(e)) < 0)
		e = 0;
	_exit(127);
}

fzn_capture_err_t fzn_capture_run(fzn_capture_t *capture, const char *const *argv,
                                  uint64_t deadline_ms, fzn_capture_end_t *end, int *code,
                                  uint64_t *elapsed_ms)
{
	int out_p[2] = { -1, -1 }, err_p[2] = { -1, -1 }, exec_p[2] = { -1, -1 };
	uint64_t start = mono_ms();
	int status = 0, timed_out = 0, timeout, e = 0, i;
	ssize_t n;
	pid_t pid;

	if (!capture || !argv || !argv[0] || !end || !code || !elapsed_ms)
		return FZN_CAPTURE_ERR_MALFORMED;
	*end = FZN_CAPTURE_NOT_RUN;
	*code = 0;
	*elapsed_ms = 0;
	if (pipe(out_p) != 0 || pipe(err_p) != 0 || pipe(exec_p) != 0 || !cloexec(out_p[0])
	    || !cloexec(out_p[1]) || !cloexec(err_p[0]) || !cloexec(err_p[1])
	    || !cloexec(exec_p[0]) || !cloexec(exec_p[1])) {
		*code = errno;
		goto not_run;
	}
	pid = fork();
	if (pid < 0) {
		*code = errno;
		goto not_run;
	}
	if (pid == 0)
		child(argv, out_p[1], err_p[1], exec_p[1]);
	/* BOTH SIDES SET THE GROUP, so a deadline that fires before the child
	 * has run its own setpgid still kills the right group. */
	(void)setpgid(pid, pid);
	close_fd(&out_p[1]);
	close_fd(&err_p[1]);
	close_fd(&exec_p[1]);

	do
		n = read(exec_p[0], &e, sizeof(e));
	while (n < 0 && errno == EINTR);
	close_fd(&exec_p[0]);
	if (n == (ssize_t)sizeof(e)) {
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
			;
		close_fd(&out_p[0]);
		close_fd(&err_p[0]);
		*code = e;
		(void)fzn_capture_finish(capture);
		*elapsed_ms = mono_ms() - start;
		return FZN_CAPTURE_OK;
	}

	/* BOTH STREAMS AS THEY ARRIVE, until both close or the deadline. */
	while (out_p[0] >= 0 || err_p[0] >= 0) {
		struct pollfd fds[2];
		int *which[2] = { &out_p[0], &err_p[0] };
		const fzn_capture_stream_t streams[2] = { FZN_CAPTURE_STDOUT, FZN_CAPTURE_STDERR };
		int r;

		if (past(start, deadline_ms, &timeout)) {
			timed_out = 1;
			break;
		}
		for (i = 0; i < 2; i++) {
			fds[i].fd = *which[i];
			fds[i].events = POLLIN;
			fds[i].revents = 0;
		}
		r = poll(fds, 2, timeout);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			break;
		for (i = 0; i < 2; i++) {
			uint8_t buf[4096];

			if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;
			n = read(fds[i].fd, buf, sizeof(buf));
			if (n > 0)
				(void)fzn_capture_feed(capture, streams[i], buf, (size_t)n);
			else if (n == 0 || (errno != EINTR && errno != EAGAIN))
				close_fd(which[i]);
		}
	}
	close_fd(&out_p[0]);
	close_fd(&err_p[0]);

	/* REAPED ON EVERY PATH. A tool that closed its streams and kept
	 * running is waited for until the deadline, and then its group goes. */
	for (;;) {
		pid_t w;

		if (timed_out) {
			(void)kill(-pid, SIGKILL);
			while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
				;
			break;
		}
		w = waitpid(pid, &status, deadline_ms ? WNOHANG : 0);
		if (w == pid)
			break;
		if (w < 0 && errno != EINTR)
			break;
		if (past(start, deadline_ms, &timeout)) {
			timed_out = 1;
			continue;
		}
		if (w == 0) {
			struct timespec ten_ms = { 0, 10000000L };

			(void)nanosleep(&ten_ms, NULL);
		}
	}
	(void)fzn_capture_finish(capture);
	*elapsed_ms = mono_ms() - start;
	if (timed_out) {
		*end = FZN_CAPTURE_TIMED_OUT;
	} else if (WIFEXITED(status)) {
		*end = FZN_CAPTURE_EXITED;
		*code = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		*end = FZN_CAPTURE_SIGNALLED;
		*code = WTERMSIG(status);
	}
	return FZN_CAPTURE_OK;

not_run:
	close_fd(&out_p[0]);
	close_fd(&out_p[1]);
	close_fd(&err_p[0]);
	close_fd(&err_p[1]);
	close_fd(&exec_p[0]);
	close_fd(&exec_p[1]);
	(void)fzn_capture_finish(capture);
	return FZN_CAPTURE_OK;
}
