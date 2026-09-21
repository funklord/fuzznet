/* THE WIRE ENCODING OF A TERM AND AN EXPRESSION. facet/facet.h section 8's
 * first item, and project.md sec 342.
 *
 * NOT `facet/wire.h`, because `wire/` is this tree's own module for frames and
 * seals, and a second thing called wire inside another module is the collision
 * catalog paid for in sec 339. The tree's word for this is CODEC -- catalog.h
 * says "the attribute codec" -- so this is facet's.
 *
 * ---------------------------------------------------------------------------
 * THE SPEC HAD ALREADY DECIDED MOST OF IT.
 * ---------------------------------------------------------------------------
 *
 * F16 to F19 are about an encoding that did not exist yet, which is why the
 * encoding could be written without asking anybody anything: the canonical
 * form, the sort, the recursion into alternation members and the one-spelling
 * rules are all stated. What was left was the byte layout and the arithmetic.
 *
 * TWO RULES OF THE SPEC BECOME STRUCTURAL RATHER THAN CHECKED, which is the
 * part worth reading:
 *
 *   - F8, an alternation binds to ONE dimension. The dimension is hoisted out
 *     of the members and encoded once, so an alternation SPANNING dimensions
 *     cannot be spelled at all. A refusal a decoder has to remember to make is
 *     a refusal that can be forgotten; this one cannot.
 *   - F7, `inclusive` applies only to a CLOSED bound. A bound is one byte
 *     saying open, closed-exclusive or closed-inclusive, rather than a flag
 *     pair -- so "open and inclusive" is not a combination that exists, and
 *     there is no forbidden spelling to refuse.
 *
 * ---------------------------------------------------------------------------
 * THE LAYOUT. Big-endian, as every other format in this tree.
 * ---------------------------------------------------------------------------
 *
 *   expression
 *     0   object    FZN_FACET_OBJECT_EXPR
 *     1   pos       u16, terms in P -- F14: at least one
 *     3   neg       u16, terms in N -- may be zero
 *     5   term[]    P's terms then N's, each as below
 *
 *   term, PREFIX
 *     0   kind      FZN_FACET_PREFIX
 *     1   dim_len   u8, then dim
 *         id_len    u8, then id
 *
 *   term, RANGE       (`node` is the PARENT; the bounds are its children)
 *     0   kind      FZN_FACET_RANGE
 *     1   dim_len   u8, then dim
 *         id_len    u8, then id
 *         lo        bound, then hi
 *
 *   term, ALT
 *     0   kind      FZN_FACET_ALT
 *     1   dim_len   u8, then dim          -- once, for every member (F8)
 *         members   u16, at least TWO (F19: one member is a PREFIX term)
 *         id_len    u8, then id           -- per member, ascending (F18)
 *
 *   bound
 *     0   what      0 open, 1 closed-exclusive, 2 closed-inclusive
 *     1   id_len    u8, then id           -- absent entirely when open
 *
 * A LENGTH IS ONE BYTE BECAUSE AN IDENTIFIER IS AN IDENTITY, NOT CONTENT. F22
 * makes a term hold an identifier -- a MusicBrainz id, a TMDB id, a No-Intro
 * entry -- and 255 bytes is generous for one. A length field that can express
 * far more than the thing ever is, is a field that can be wrong in more ways;
 * catalog's attribute name uses one byte for the same reason.
 *
 * THERE IS NO VERSION BYTE, AND THAT IS F10 READ LITERALLY. "A term kind
 * carries a TAG. Kinds may be added" puts the extension point at the term, and
 * F26 says an unknown kind is REFUSED rather than skipped. A second version
 * number at the expression would be a second way to say the same thing, and
 * every expression hash would change the day it was introduced.
 *
 * THE OBJECT BYTE IS THERE FOR DOMAIN SEPARATION, NOT FRAMING. A record's own
 * `kind` field names the format of its body, so nothing here needs a tag to be
 * parsed. What needs one is the HASH: section 4 of facet.h encodes an
 * expression so that "equal expressions are byte-equal and may be hashed for
 * identity, deduplication and cache keys", and a hash over untagged bytes can
 * be equal to a hash over some other structure's untagged bytes. The tag is in
 * the hashed range, which is the only place it does any good.
 *
 * ---------------------------------------------------------------------------
 * WHAT DECODE REFUSES, AND THE ONE THING IT CANNOT.
 * ---------------------------------------------------------------------------
 *
 * F27 requires refusing "an encoding violating F16 to F19", so decode is not a
 * parser that trusts its input. It refuses a wrong object byte, a truncated
 * field, a TRAILING byte, an unknown kind (F26), an empty P (F14), an
 * alternation of fewer than two members (F19), terms out of order or equal
 * within P or within N (F16, and equality is F19's dedup), members out of
 * order or equal within an alternation (F18), and a term present in both P and
 * N (F27).
 *
 * THE ONE IT CANNOT IS F19's SINGLE-CHILD RANGE. "A RANGE whose bounds denote
 * one child MUST be encoded as a PREFIX term" is a statement about the
 * taxonomy, and this module has no index. `fzn_facet_normalize` defers it for
 * the same reason and says so. Pinned here rather than left to be assumed,
 * because a gate whose limits are unwritten gets quoted for guarantees it
 * never made: a decoded expression is canonical in every respect EXCEPT that
 * one.
 *
 * ---------------------------------------------------------------------------
 * THE ORDER IS OVER ENCODED BYTES, WHICH IS WHAT MAKES CHECKING IT CHEAP.
 * ---------------------------------------------------------------------------
 *
 * F16 sorts by "BYTE-WISE COMPARISON of each term's canonical encoding:
 * memcmp order, and where one encoding is a prefix of another the shorter
 * sorts first". The terms lie consecutively in the buffer already encoded, so
 * the check is a memcmp between two byte ranges -- nothing is re-encoded and
 * no term needs to be held in memory to compare it with its neighbour.
 *
 * F17's warning is satisfied by construction: this compares raw encoded bytes
 * and never the F20 collation key, which is lossy and would make two distinct
 * terms sort equal.
 *
 * F18 is the same rule applied to a member's own encoding, `id_len || id`. A
 * CONSEQUENCE worth stating so nobody reads it as a defect: because the length
 * byte leads, members group by length -- every 3-byte identifier sorts before
 * every 4-byte one. That is a total deterministic order, which is all F16 is
 * for, and it is the same rule rather than a second one.
 */

#ifndef FZN_FACET_CODEC_H
#define FZN_FACET_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "facet.h"

/* Domain separation for the identity hash; see the header. */
#define FZN_FACET_OBJECT_EXPR 1u

/* object + pos count + neg count. */
#define FZN_FACET_EXPR_HEAD_LEN 5u

/* The longest dimension or identifier a term can carry, the length field
 * being one byte. */
#define FZN_FACET_NAME_MAX 255u

/* A bound's first byte (F7). Open carries no identifier at all, so "open and
 * inclusive" is not a spelling that exists. */
typedef enum fzn_facet_bound_kind {
	FZN_FACET_BOUND_OPEN      = 0,
	FZN_FACET_BOUND_EXCLUSIVE = 1,
	FZN_FACET_BOUND_INCLUSIVE = 2
} fzn_facet_bound_kind_t;

/*
 * Encode one term.
 *
 * The expression encoder below is what a caller normally wants; this is
 * exposed because F16's order is defined over a term's own encoding, so a
 * caller sorting its arrays before building an expression needs the same
 * bytes this produces.
 *
 * FZN_FACET_ERR_KIND for a kind this build does not know (F26).
 * FZN_FACET_ERR_MALFORMED for a null, an empty dimension or identifier, an
 * alternation of fewer than two members (F19), or members that do not all
 * share the term's dimension (F8). FZN_FACET_ERR_RANGE when a dimension or
 * identifier is longer than FZN_FACET_NAME_MAX, or the term does not fit
 * `cap`. Writes nothing unless the whole term fits.
 *
 * AN OPEN BOUND'S `inclusive` IS DROPPED, not refused. facet.h says the field
 * "applies only to a closed bound", so an open-and-inclusive bound is two
 * in-memory spellings of one thing and this writes the one spelling. A caller
 * comparing a decoded term with what it encoded should compare the ENCODINGS,
 * which is what F16 makes the identity anyway.
 */
fzn_facet_err_t fzn_facet_term_encode(const fzn_facet_term_t *term,
                                      uint8_t *out, size_t cap,
                                      size_t *len_out);

/*
 * Encode an expression: the head, then P's terms, then N's.
 *
 * THE CALLER'S ARRAYS MUST ALREADY BE IN F16 ORDER within P and within N, and
 * this refuses them otherwise with FZN_FACET_ERR_MALFORMED rather than sorting
 * them. Sorting here would mean either allocating or reordering the caller's
 * arrays behind its back, and this module allocates nothing;
 * `fzn_facet_expr_ordered` is how a caller checks, and it may sort its own
 * arrays with any algorithm it likes using `fzn_facet_term_encode`.
 *
 * The expression is validated first (F27), so the errors
 * `fzn_facet_validate` returns are returned here. FZN_FACET_ERR_RANGE when the
 * encoding does not fit `cap`, or either count exceeds its field. Writes
 * nothing unless the whole expression fits.
 */
fzn_facet_err_t fzn_facet_expr_encode(const fzn_facet_expr_t *expr,
                                      uint8_t *out, size_t cap,
                                      size_t *len_out);

/*
 * Are `expr`'s arrays in F16 order within P and within N?
 *
 * Returns 1 when they are, 0 when they are not or when a term will not
 * encode. `scratch` (capacity `scratch_cap`) holds two encoded terms at a
 * time and is the caller's, this module allocating nothing; 2 *
 * (the longest term's encoding) is enough, and a scratch too small answers 0
 * -- which is indistinguishable from out of order, so a caller that cares
 * gives it room rather than reading the answer as a verdict.
 */
int fzn_facet_expr_ordered(const fzn_facet_expr_t *expr, uint8_t *scratch,
                           size_t scratch_cap);

/*
 * Decode an expression, filling the caller's term arrays.
 *
 * Every view in the filled terms BORROWS from `body`, which must outlive
 * them -- facet's zero-copy style throughout. `alt_members` is where
 * alternation members are written, since a term holds a pointer to a run of
 * them rather than carrying them; all the alternations' members share it.
 *
 * `expr`'s four fields are set to point at the caller's arrays and the counts
 * decoded. The refusals are the header's list; `*at_out` is optional and
 * receives the byte offset the refusal happened at, which is the difference
 * between an error a person can act on and a puzzle.
 *
 * FZN_FACET_ERR_RANGE when the expression holds more terms or members than
 * the caller's arrays take.
 */
fzn_facet_err_t fzn_facet_expr_decode(const uint8_t *body, size_t body_len,
                                      fzn_facet_term_t *pos, size_t pos_cap,
                                      fzn_facet_term_t *neg, size_t neg_cap,
                                      fzn_facet_node_t *alt_members,
                                      size_t alt_cap, fzn_facet_expr_t *expr,
                                      size_t *at_out);

#endif /* FZN_FACET_CODEC_H */
