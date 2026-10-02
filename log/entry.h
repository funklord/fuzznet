/* One log entry, its name, and the classic line. sec 456, the second piece
 * of sec 428's logging after the relay of sec 441.
 *
 * ONE RECORD, THREE FORMATS (sec 428). This is the record and the first of
 * the three, the classic line: positional text, one line an entry, complete
 * on its own, for grep and for people. The performant and packed formats are
 * encodings of the same record and convert to and from it without loss.
 *
 * EVERY ENTRY IS NAMED BY WHAT IT IS, and nothing is generated (sec 428):
 *
 *     machine / user / program / pid@start#position
 *
 *   - THE MACHINE is `/etc/machine-id`'s 128 bits, stable across renames;
 *     a classic line shows the host name instead, for people, and the file
 *     it is in says which machine that is. The holder's choice, sec 456.
 *   - THE USER is the Unix account.
 *   - THE INSTANCE is the process: its pid and its start time in
 *     MILLISECONDS since the epoch, so a pid reused within a second is
 *     still another instance. The holder's choice, sec 456.
 *   - THE POSITION is the entry's place in its instance's sequence.
 *
 * The estate is not in the name: a machine's resources belong to one estate
 * (sec 430), so the machine names it, and a file says it once.
 *
 * THE CLASSIC LINE, every field always present and none holding a space:
 *
 *     TIME HOST USER PROGRAM PID@START#POS LEVEL SUBSYSTEM CAUSE ORIGIN TEXT
 *
 *     2026-10-02T12:34:56.789123Z nabbe root fuzznetd 4121@1727778896123#1834 W notes/sync - - a record refused
 *
 *   - TIME is UTC to the microsecond, so a plain sort across machines is
 *     roughly right -- roughly, because their clocks disagree, which is
 *     what causes are for.
 *   - CAUSE is `<` and the name of the entry whose work this is done for,
 *     and ORIGIN `<<` and the name of the entry where that work began; `-`
 *     each when there is none. A name is
 *     `MACHINEHEX/USER/PROGRAM/PID@START#POS`.
 *   - THE INSTANCE FIELD ENDS EVERY NAME OF IT, so one grep for
 *     `4121@1727778896123#1834` finds the entry and everything it caused,
 *     on any machine.
 *   - TEXT is the rest of the line, escaped as `log/capture.h` escapes a
 *     tool's line: one entry is exactly one line whatever its text holds,
 *     and the text reads back byte for byte.
 *
 * POSITIONAL IS A FORMAT TO VERSION, NOT TO EXTEND (sec 428): a field added
 * later moves the text, so a file says its format version once, at its
 * head, and a new field is a new version.
 */

#ifndef FZN_LOG_ENTRY_H
#define FZN_LOG_ENTRY_H

#include <stddef.h>
#include <stdint.h>

#define FZN_ENTRY_MACHINE_LEN 16u
/* A user, a program or a host: what a Unix account name, a program's file
 * name and a host name are, bounded. */
#define FZN_ENTRY_WORD_MAX 64u
/* A subsystem path, `notes/sync`. */
#define FZN_ENTRY_SUBSYSTEM_MAX 64u
/* An entry's text, unescaped. */
#define FZN_ENTRY_TEXT_MAX 4096u
/* The longest classic line, newline included: every escaped byte four
 * characters, every field at its bound. */
#define FZN_ENTRY_LINE_MAX (512u + (FZN_ENTRY_TEXT_MAX * 4u))

typedef enum fzn_entry_err {
	FZN_ENTRY_OK = 0,
	FZN_ENTRY_ERR_MALFORMED = -1, /* a null, a field that is not one */
	FZN_ENTRY_ERR_ROOM = -2       /* the line does not fit `cap` */
} fzn_entry_err_t;

const char *fzn_entry_err_str(fzn_entry_err_t err);

/* flog's eight levels, most severe first, each a letter on the line. */
typedef enum fzn_entry_level {
	FZN_ENTRY_CRITICAL = 1, /* C */
	FZN_ENTRY_ERROR = 2,    /* E */
	FZN_ENTRY_WARNING = 3,  /* W */
	FZN_ENTRY_NOTE = 4,     /* N */
	FZN_ENTRY_INFO = 5,     /* I */
	FZN_ENTRY_VERBOSE = 6,  /* V */
	FZN_ENTRY_DEBUG = 7,    /* D */
	FZN_ENTRY_TRACE = 8     /* T, flog's deep debug */
} fzn_entry_level_t;

/* The level's letter, or 0 for none. */
char fzn_entry_level_letter(fzn_entry_level_t level);

typedef struct fzn_entry_name {
	uint8_t machine[FZN_ENTRY_MACHINE_LEN];
	char user[FZN_ENTRY_WORD_MAX + 1u];
	char program[FZN_ENTRY_WORD_MAX + 1u];
	uint32_t pid;
	uint64_t start_ms;
	uint64_t position;
} fzn_entry_name_t;

typedef struct fzn_entry {
	fzn_entry_name_t name;
	uint64_t time_us; /* since the epoch, UTC */
	fzn_entry_level_t level;
	char subsystem[FZN_ENTRY_SUBSYSTEM_MAX + 1u];
	/* The work this entry is done for, and where it began; both or
	 * neither. */
	int caused;
	fzn_entry_name_t cause;
	fzn_entry_name_t origin;
	const uint8_t *text; /* unescaped, `text_len` bytes */
	size_t text_len;
} fzn_entry_t;

/* `/etc/machine-id`'s text, 32 hex digits and perhaps a newline, as the
 * machine's 16 bytes. */
fzn_entry_err_t fzn_entry_machine_parse(const char *text, size_t len,
                                          uint8_t out[FZN_ENTRY_MACHINE_LEN]);

/* A name as text, `MACHINEHEX/USER/PROGRAM/PID@START#POS`, NUL-terminated;
 * its length in `*len`. */
fzn_entry_err_t fzn_entry_name_text(const fzn_entry_name_t *name, char *out, size_t cap,
                                      size_t *len);

/* And back. */
fzn_entry_err_t fzn_entry_name_parse(const char *text, size_t len, fzn_entry_name_t *out);

/* THE CLASSIC LINE for `entry`, shown with `host`, newline-terminated and
 * NUL-terminated; its length, newline included, in `*len`. ROOM, and
 * nothing written that could be taken for a line, when it does not fit. A
 * field that is not one -- a space, a control byte, an empty word -- is
 * MALFORMED rather than escaped: a positional line cannot hold it. */
fzn_entry_err_t fzn_entry_classic(const fzn_entry_t *entry, const char *host, char *out,
                                    size_t cap, size_t *len);

/* THE LINE READ BACK. `machine` is the file's, since the line shows the
 * host; the host is written to `host`. The text is unescaped into
 * `text_buf`, which `out->text` then points at. One trailing newline may
 * be present. */
fzn_entry_err_t fzn_entry_classic_parse(const char *line, size_t len,
                                          const uint8_t machine[FZN_ENTRY_MACHINE_LEN],
                                          fzn_entry_t *out, char host[FZN_ENTRY_WORD_MAX + 1u],
                                          uint8_t *text_buf, size_t text_cap);

/* THE PERFORMANT RECORD, sec 457: the same entry as fixed binary fields,
 * laid out by `log/entry.situ` and checked against it. Nothing formatted,
 * nothing escaped -- the format the flight recorder holds. */
#define FZN_ENTRY_RECORD_VERSION 1u
#define FZN_ENTRY_RECORD_MIN 55u
#define FZN_ENTRY_RECORD_MAX 4672u

/* A NAME IN THE RECORD'S FORM, `log/entry.situ`'s `fzn_entry_name_record`,
 * for another message to carry one (`log/cause.h`, sec 462): 40 to 166
 * bytes. Unpacking reads one name from the front of `in`, `*used` bytes. */
#define FZN_ENTRY_NAME_RECORD_MAX 166u
fzn_entry_err_t fzn_entry_name_pack(const fzn_entry_name_t *name, uint8_t *out, size_t cap,
                                    size_t *len);
fzn_entry_err_t fzn_entry_name_unpack(const uint8_t *in, size_t len, fzn_entry_name_t *out,
                                      size_t *used);

/* `entry` as a record into `out`; its length in `*len`. The same fields
 * the classic line refuses are refused here, so a record always has a
 * line. */
fzn_entry_err_t fzn_entry_pack(const fzn_entry_t *entry, uint8_t *out, size_t cap, size_t *len);

/* And back, every byte of `in` used. `out->text` points into `in`. */
fzn_entry_err_t fzn_entry_unpack(const uint8_t *in, size_t len, fzn_entry_t *out);

#endif /* FZN_LOG_ENTRY_H */
