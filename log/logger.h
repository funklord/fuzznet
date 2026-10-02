/* A process's logger: it names each entry, keeps every one in the flight
 * recorder, and appends the ones its level keeps to the program's file as
 * classic lines. sec 458, step 3 of sec 456's order. POSIX, and built only
 * with FZN_LOG_FILE.
 *
 * WHO IT IS, READ ONCE (`fzn_logger_identify`): the machine from
 * `/etc/machine-id`, the host name, the Unix account it runs as, the program,
 * the pid, and the time the logger was identified, in milliseconds, as the
 * instance's start. That time is not the kernel's record of the process's
 * start; it is what makes `pid@start` name one instance, which is all the
 * name asks of it, and it is read without anything Linux-specific.
 *
 * WHERE ITS FILES GO, per Unix user (sec 428): `/var/log/fuzznet` for root,
 * else `$XDG_STATE_HOME/fuzznet/log`, else `~/.local/state/fuzznet/log`.
 * The separation the holder asked for comes from where each account writes,
 * and the permissions from the filesystem.
 *
 * ONE FILE A PROGRAM, `PROGRAM.log`, appended to by every instance of it:
 * each line is one `write()` with O_APPEND, so instances interleave whole
 * lines. That holds on local Linux filesystems and is not a POSIX promise
 * for regular files (sec 428); a network filesystem would want a file per
 * process. A new file opens with a header line:
 *
 *     #fuzznet-log 1 machine=MACHINEHEX host=HOST
 *
 * which says the format's version -- the line is positional, so a new
 * field is a new version -- and which machine the host name shows.
 *
 * SEGMENTS ROTATE BY SIZE. When a line would carry the shared file past
 * the segment size, the writer renames it to
 * `PROGRAM.TIME.PID.log` -- the time of the rotation in microseconds and
 * the rotating pid, so two instances rotating at once cannot pick one name
 * -- and starts a new `PROGRAM.log`. Another instance still holding the old
 * file sees that the path no longer names its open file, and reopens before
 * it writes: one `stat` a kept line, the price of sharing a file.
 *
 * WHAT IS NOT HERE YET (sec 458): packing closed segments, the hash-chain
 * trailer, and the prune and keep rules.
 */

#ifndef FZN_LOG_LOGGER_H
#define FZN_LOG_LOGGER_H

#include <stddef.h>
#include <stdint.h>

#include "entry.h"
#include "ring.h"

#define FZN_LOGGER_PATH_MAX 512u
/* A segment's size when the caller names none: 8 MiB. */
#define FZN_LOGGER_SEGMENT_DEFAULT (8u * 1024u * 1024u)

typedef enum fzn_logger_err {
	FZN_LOGGER_OK = 0,
	FZN_LOGGER_ERR_MALFORMED = -1, /* a null, a name or a field that is not one */
	FZN_LOGGER_ERR_IDENTITY = -2,  /* the machine, the host or the account would not read */
	FZN_LOGGER_ERR_FILE = -3       /* the directory or the file refused */
} fzn_logger_err_t;

const char *fzn_logger_err_str(fzn_logger_err_t err);

typedef struct fzn_logger {
	fzn_entry_name_t self; /* `position` is the next entry's */
	char host[FZN_ENTRY_WORD_MAX + 1u];
	fzn_entry_level_t keep; /* levels at least this severe go to the file */
	fzn_ring_t *ring;       /* every entry, when set */
	char dir[FZN_LOGGER_PATH_MAX];
	char path[FZN_LOGGER_PATH_MAX];
	int fd;
	uint64_t segment_max;
	/* The clock in microseconds; the wall clock when NULL. A test sets it. */
	uint64_t (*now_us)(void);
} fzn_logger_t;

/* Who this process is: `machine_id_path` is `/etc/machine-id` when NULL.
 * `self->position` starts at 0. */
fzn_logger_err_t fzn_logger_identify(fzn_entry_name_t *self, char host[FZN_ENTRY_WORD_MAX + 1u],
                                     const char *program, const char *machine_id_path);

/* The default directory for this account, as above. */
fzn_logger_err_t fzn_logger_default_dir(char *out, size_t cap);

/* Ready to log as `self` shown as `host`, into `dir` (created mode 0700
 * if it is not there), keeping levels at least as severe as `keep` in the
 * file and every level in `ring` when it is set. `segment_max` 0 is the
 * default. */
fzn_logger_err_t fzn_logger_open(fzn_logger_t *logger, const fzn_entry_name_t *self,
                                 const char *host, const char *dir, fzn_entry_level_t keep,
                                 fzn_ring_t *ring, uint64_t segment_max);

/* ONE ENTRY: the next position, the time now, into the ring, and into the
 * file when its level is kept. `cause` and `origin` both or neither. The
 * entry's own name, so a caller can hand it on as a cause, in `*named`
 * when set. A level the file does not keep costs no formatting. */
fzn_logger_err_t fzn_logger_log(fzn_logger_t *logger, fzn_entry_level_t level,
                                const char *subsystem, const fzn_entry_name_t *cause,
                                const fzn_entry_name_t *origin, const uint8_t *text,
                                size_t text_len, fzn_entry_name_t *named);

void fzn_logger_close(fzn_logger_t *logger);

#endif /* FZN_LOG_LOGGER_H */
