/* Tests for facet/codec.c: the wire encoding of a term and an expression.
 * facet.h section 8's first item, and sec 342.
 *
 * WHAT THIS SUITE IS FOR is the canonical form, because that is what the
 * encoding is FOR: section 4 of facet.h wants equal expressions to be
 * byte-equal so they can be hashed for identity. So the property driven hardest
 * is ENCODE, DECODE, RE-ENCODE IS THE SAME BYTES -- over random expressions
 * rather than over cases chosen by whoever wrote the codec.
 *
 * Re-encoding is also the right comparison rather than a field-by-field one:
 * an open bound's `inclusive` is dropped on the way out (facet.h says the
 * field applies only to a closed bound), so two in-memory spellings become one
 * encoding, which is the codec working and would read as a round-trip failure
 * to a field-wise check.
 */

#include "../codec.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL codec_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static const uint8_t DIM[] = "genre";
#define DIM_LEN (sizeof(DIM) - 1u)
static const uint8_t DIM2[] = "year";
#define DIM2_LEN (sizeof(DIM2) - 1u)

static void prefix(fzn_facet_term_t *t, const uint8_t *dim, size_t dim_len,
                   const char *id)
{
	memset(t, 0, sizeof(*t));
	t->kind = FZN_FACET_PREFIX;
	t->node.dim = dim;
	t->node.dim_len = dim_len;
	t->node.id = (const uint8_t *)id;
	t->node.id_len = strlen(id);
}

static void test_a_term_round_trips(void)
{
	fzn_facet_term_t p[2], n[1], dp[4], dn[4];
	fzn_facet_node_t members[4], dmembers[8];
	fzn_facet_expr_t expr, back;
	uint8_t buf[256], again[256];
	size_t len = 0, len2 = 0;

	/* P: a PREFIX and a RANGE. N: an ALT of three. */
	prefix(&p[0], DIM, DIM_LEN, "house");
	memset(&p[1], 0, sizeof(p[1]));
	p[1].kind = FZN_FACET_RANGE;
	p[1].node.dim = DIM2;
	p[1].node.dim_len = DIM2_LEN;
	p[1].node.id = (const uint8_t *)"decade";
	p[1].node.id_len = 6;
	p[1].lo.id = (const uint8_t *)"1990";
	p[1].lo.id_len = 4;
	p[1].lo.inclusive = 1;
	p[1].hi.id = NULL;      /* open on the right */
	p[1].hi.id_len = 0;
	p[1].hi.inclusive = 1;  /* DROPPED: an open bound has nothing to
	                         * include, and this is the second spelling
	                         * the encoding removes. */

	memset(&n[0], 0, sizeof(n[0]));
	n[0].kind = FZN_FACET_ALT;
	n[0].node.dim = DIM;
	n[0].node.dim_len = DIM_LEN;
	{
		static const char *ids[3] = { "aaa", "bbb", "ccc" };
		size_t i;

		for (i = 0; i < 3; i++) {
			members[i].dim = DIM;
			members[i].dim_len = DIM_LEN;
			members[i].id = (const uint8_t *)ids[i];
			members[i].id_len = 3;
		}
	}
	n[0].members = members;
	n[0].member_count = 3;

	expr.pos = p;
	expr.pos_count = 2;
	expr.neg = n;
	expr.neg_count = 1;

	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_OK, "the expression would not encode");
	CHECK(buf[0] == FZN_FACET_OBJECT_EXPR, "the object byte is wrong");

	CHECK(fzn_facet_expr_decode(buf, len, dp, 4, dn, 4, dmembers, 8, &back,
	                            NULL) == FZN_FACET_OK,
	      "the expression would not decode");
	CHECK(back.pos_count == 2 && back.neg_count == 1,
	      "the counts did not survive");
	CHECK(back.neg[0].member_count == 3, "the members did not survive");
	/* F8 is structural: a decoded member takes the term's one dimension,
	 * so an alternation spanning dimensions is not expressible. */
	CHECK(back.neg[0].members[2].dim == back.neg[0].node.dim
	          && back.neg[0].members[2].dim_len == DIM_LEN,
	      "a decoded member does not share the term's dimension");

	CHECK(fzn_facet_expr_encode(&back, again, sizeof(again), &len2)
	          == FZN_FACET_OK, "the decoded expression would not re-encode");
	CHECK(len2 == len && memcmp(buf, again, len) == 0,
	      "encode-decode-encode is not the same bytes");

	/* The open bound's `inclusive` really was dropped, which is the point
	 * of comparing encodings rather than fields. */
	CHECK(back.pos[1].hi.id == NULL && back.pos[1].hi.inclusive == 0,
	      "an open bound came back carrying an inclusive flag");
	CHECK(back.pos[1].lo.inclusive == 1,
	      "a closed bound lost its inclusive flag");
}

static void test_the_refusals(void)
{
	fzn_facet_term_t p[3], n[2], dp[4], dn[4];
	fzn_facet_node_t members[4], dmembers[8];
	fzn_facet_expr_t expr, back;
	uint8_t buf[256];
	size_t len = 0, at = 0;

	prefix(&p[0], DIM, DIM_LEN, "aaa");
	prefix(&p[1], DIM, DIM_LEN, "bbb");
	expr.pos = p;
	expr.pos_count = 2;
	expr.neg = NULL;
	expr.neg_count = 0;

	/* The control, which must keep passing or nothing below means
	 * anything. */
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_OK, "the control would not encode");

	/* F16: strictly ascending. Out of order... */
	prefix(&p[0], DIM, DIM_LEN, "bbb");
	prefix(&p[1], DIM, DIM_LEN, "aaa");
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_ERR_MALFORMED, "an out-of-order P encoded");
	/* ...and equal, which is F19's duplicate. */
	prefix(&p[0], DIM, DIM_LEN, "aaa");
	prefix(&p[1], DIM, DIM_LEN, "aaa");
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_ERR_MALFORMED, "a duplicate term encoded");

	/* F26: a kind this build does not know is refused, never skipped. */
	prefix(&p[0], DIM, DIM_LEN, "aaa");
	prefix(&p[1], DIM, DIM_LEN, "bbb");
	p[1].kind = (fzn_facet_kind_t)9;
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_ERR_KIND, "an unknown kind encoded");
	prefix(&p[1], DIM, DIM_LEN, "bbb");

	/* F19: a single-member alternation is a PREFIX term. */
	memset(&n[0], 0, sizeof(n[0]));
	n[0].kind = FZN_FACET_ALT;
	n[0].node.dim = DIM;
	n[0].node.dim_len = DIM_LEN;
	members[0].dim = DIM;
	members[0].dim_len = DIM_LEN;
	members[0].id = (const uint8_t *)"zzz";
	members[0].id_len = 3;
	n[0].members = members;
	n[0].member_count = 1;
	expr.neg = n;
	expr.neg_count = 1;
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_ERR_MALFORMED,
	      "a one-member alternation encoded");

	/* F8: a member in another dimension. */
	members[1].dim = DIM2;
	members[1].dim_len = DIM2_LEN;
	members[1].id = (const uint8_t *)"yyy";
	members[1].id_len = 3;
	n[0].member_count = 2;
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_ERR_ALT_DIMENSION,
	      "an alternation spanning dimensions encoded");
	/* AND THROUGH THE TERM ENCODER, which is the only route that reaches
	 * the CODEC's own check: `fzn_facet_expr_encode` validates first, so
	 * facet.c answers this before the codec is asked. A sabotage of the
	 * codec's check stayed green until this line existed -- a control has
	 * to be REACHED, not merely able to fire. */
	CHECK(fzn_facet_term_encode(&n[0], buf, sizeof(buf), &len)
	          == FZN_FACET_ERR_ALT_DIMENSION,
	      "the term encoder wrote an alternation spanning dimensions");
	/* The control: put it back in one dimension and it encodes. */
	members[1].dim = DIM;
	members[1].dim_len = DIM_LEN;
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_OK, "a two-member alternation would not encode");

	/* F27: the same term in P and N. */
	expr.neg = p;   /* P's own array as N */
	expr.neg_count = 1;
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_ERR_BOTH_SIDES,
	      "a term in both P and N encoded");

	/* F14: P must not be empty -- on the wire, where it arrives from
	 * somebody else. */
	expr.neg = NULL;
	expr.neg_count = 0;
	fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len);
	buf[1] = 0;
	buf[2] = 0;
	CHECK(fzn_facet_expr_decode(buf, len, dp, 4, dn, 4, dmembers, 8, &back,
	                            &at) == FZN_FACET_ERR_EMPTY_POS,
	      "an empty P decoded");

	/* And the three that are about the bytes rather than the model. */
	fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len);
	CHECK(fzn_facet_expr_decode(buf, len, dp, 4, dn, 4, dmembers, 8, &back,
	                            &at) == FZN_FACET_OK,
	      "the control would not decode");
	CHECK(fzn_facet_expr_decode(buf, len + 1u, dp, 4, dn, 4, dmembers, 8,
	                            &back, &at) == FZN_FACET_ERR_MALFORMED,
	      "a trailing byte was ignored -- two spellings, two identities");
	CHECK(fzn_facet_expr_decode(buf, len - 1u, dp, 4, dn, 4, dmembers, 8,
	                            &back, &at) == FZN_FACET_ERR_MALFORMED,
	      "a truncated expression decoded");
	buf[0] = 9;
	CHECK(fzn_facet_expr_decode(buf, len, dp, 4, dn, 4, dmembers, 8, &back,
	                            &at) == FZN_FACET_ERR_MALFORMED,
	      "a wrong object byte decoded");
	buf[0] = FZN_FACET_OBJECT_EXPR;

	/* The caller's arrays are too small: refused, not truncated. */
	CHECK(fzn_facet_expr_decode(buf, len, dp, 1, dn, 4, dmembers, 8, &back,
	                            &at) == FZN_FACET_ERR_RANGE,
	      "two terms fitted a one-term array");
}

static void test_out_of_order_on_the_wire(void)
{
	fzn_facet_term_t p[2], dp[4], dn[4];
	fzn_facet_node_t dmembers[8];
	fzn_facet_expr_t expr, back;
	uint8_t buf[256];
	size_t len = 0, at = 0, tlen = 0;

	/* An encoder refuses to WRITE terms out of order; a decoder must
	 * refuse to READ them, because bytes arrive from somewhere that may
	 * not have used this encoder. */
	prefix(&p[0], DIM, DIM_LEN, "aaa");
	prefix(&p[1], DIM, DIM_LEN, "bbb");
	expr.pos = p;
	expr.pos_count = 2;
	expr.neg = NULL;
	expr.neg_count = 0;
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_OK, "the control would not encode");
	CHECK(fzn_facet_term_encode(&p[0], NULL, 0, &tlen)
	          == FZN_FACET_ERR_MALFORMED, "a null output encoded");
	CHECK(fzn_facet_term_encode(&p[0], buf + 200, 2, &tlen)
	          == FZN_FACET_ERR_RANGE, "a term overflowed its buffer");

	/* Swap the two encoded terms where they lie. They are the same length,
	 * so this is a pure reordering of the wire bytes. */
	{
		uint8_t swap[16];
		size_t one = (len - FZN_FACET_EXPR_HEAD_LEN) / 2u;

		CHECK(one <= sizeof(swap), "the fixture terms grew");
		memcpy(swap, &buf[FZN_FACET_EXPR_HEAD_LEN], one);
		memcpy(&buf[FZN_FACET_EXPR_HEAD_LEN],
		       &buf[FZN_FACET_EXPR_HEAD_LEN + one], one);
		memcpy(&buf[FZN_FACET_EXPR_HEAD_LEN + one], swap, one);
		CHECK(fzn_facet_expr_decode(buf, len, dp, 4, dn, 4, dmembers, 8,
		                            &back, &at)
		          == FZN_FACET_ERR_MALFORMED,
		      "terms out of order on the wire decoded");
		CHECK(at == FZN_FACET_EXPR_HEAD_LEN + one,
		      "the offset did not name the term that broke the order");
	}
}

static void test_members_out_of_order_on_the_wire(void)
{
	fzn_facet_term_t n[1], p[1], dp[4], dn[4];
	fzn_facet_node_t members[3], dmembers[8];
	fzn_facet_expr_t expr, back;
	uint8_t buf[256];
	size_t len = 0, at = 0, i;

	prefix(&p[0], DIM2, DIM2_LEN, "any");
	memset(&n[0], 0, sizeof(n[0]));
	n[0].kind = FZN_FACET_ALT;
	n[0].node.dim = DIM;
	n[0].node.dim_len = DIM_LEN;
	for (i = 0; i < 3; i++) {
		static const char *ids[3] = { "aaa", "bbb", "ccc" };

		members[i].dim = DIM;
		members[i].dim_len = DIM_LEN;
		members[i].id = (const uint8_t *)ids[i];
		members[i].id_len = 3;
	}
	n[0].members = members;
	n[0].member_count = 3;
	expr.pos = p;
	expr.pos_count = 1;
	expr.neg = n;
	expr.neg_count = 1;

	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_OK, "the control would not encode");
	CHECK(fzn_facet_expr_decode(buf, len, dp, 4, dn, 4, dmembers, 8, &back,
	                            &at) == FZN_FACET_OK,
	      "the control would not decode");

	/* F18 on the wire: swap two members' identifier bytes. They are the
	 * same length, so only the order changes.
	 *
	 * THE OFFSET IS COMPUTED, NOT SEARCHED FOR. The first draft found it
	 * with memchr for 'a' -- and "year" and "any" both contain one, so the
	 * swap landed in the P term and the case proved nothing. Sabotage is
	 * what said so. */
	{
		size_t plen = 0, alt, m0, m1;

		CHECK(fzn_facet_term_encode(&p[0], buf + 200, 56, &plen)
		          == FZN_FACET_OK, "the P term would not encode alone");
		/* kind, dim_len, dim, member count, then (id_len, id) each. */
		alt = FZN_FACET_EXPR_HEAD_LEN + plen;
		m0 = alt + 1u + 1u + DIM_LEN + 2u + 1u;
		m1 = m0 + 4u;
		CHECK(memcmp(&buf[m0], "aaa", 3) == 0
		          && memcmp(&buf[m1], "bbb", 3) == 0,
		      "the computed member offsets are wrong");
		memcpy(&buf[m0], "bbb", 3);
		memcpy(&buf[m1], "aaa", 3);
		CHECK(fzn_facet_expr_decode(buf, len, dp, 4, dn, 4,
		                            dmembers, 8, &back, &at)
		          == FZN_FACET_ERR_MALFORMED,
		      "members out of order on the wire decoded");
	}

	/* F26 ON THE WAY IN, which is the half the first draft missed: it
	 * refused an unknown kind on the way OUT only, so the decoder's own
	 * refusal was never exercised. Skipping a term evaluates a DIFFERENT
	 * expression while reporting success. */
	{
		fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len);
		buf[FZN_FACET_EXPR_HEAD_LEN] = 9;
		CHECK(fzn_facet_expr_decode(buf, len, dp, 4, dn, 4, dmembers, 8,
		                            &back, &at) == FZN_FACET_ERR_KIND,
		      "an unknown term kind decoded");
		CHECK(at == FZN_FACET_EXPR_HEAD_LEN + 1u,
		      "the offset did not name the kind byte");
	}
}

static void test_ordered_needs_room_and_says_so(void)
{
	fzn_facet_term_t p[2];
	fzn_facet_expr_t expr;
	uint8_t scratch[64], tiny[4];

	prefix(&p[0], DIM, DIM_LEN, "aaa");
	prefix(&p[1], DIM, DIM_LEN, "bbb");
	expr.pos = p;
	expr.pos_count = 2;
	expr.neg = NULL;
	expr.neg_count = 0;

	CHECK(fzn_facet_expr_ordered(&expr, scratch, sizeof(scratch)),
	      "an ordered expression was called unordered");
	prefix(&p[0], DIM, DIM_LEN, "bbb");
	prefix(&p[1], DIM, DIM_LEN, "aaa");
	CHECK(!fzn_facet_expr_ordered(&expr, scratch, sizeof(scratch)),
	      "an unordered expression was called ordered");
	/* Too little scratch answers 0, which is what the header says and is
	 * indistinguishable from out of order -- pinned here so nobody quotes
	 * a 0 as a verdict about the order. */
	prefix(&p[0], DIM, DIM_LEN, "aaa");
	prefix(&p[1], DIM, DIM_LEN, "bbb");
	CHECK(!fzn_facet_expr_ordered(&expr, tiny, sizeof(tiny)),
	      "a scratch too small answered yes");
	CHECK(!fzn_facet_expr_ordered(&expr, NULL, 0), "a null scratch answered yes");
}

static void test_the_sort_produces_what_encode_demands(void)
{
	static const uint8_t D[] = "genre";
	fzn_facet_term_t p[4], n[2];
	fzn_facet_node_t members[4];
	fzn_facet_expr_t expr;
	uint8_t scratch[128], buf[256];
	size_t pc = 4, nc = 1, len = 0, i;

	/* Deliberately out of order, with a duplicate, and an alternation
	 * whose members are out of order and repeat. This is what an editor's
	 * marks look like before anybody canonicalises them (F32). */
	prefix(&p[0], D, DIM_LEN, "ccc");
	prefix(&p[1], D, DIM_LEN, "aaa");
	prefix(&p[2], D, DIM_LEN, "ccc");   /* duplicate of p[0] */
	memset(&p[3], 0, sizeof(p[3]));
	p[3].kind = FZN_FACET_ALT;
	p[3].node.dim = D;
	p[3].node.dim_len = DIM_LEN;
	{
		static const char *ids[4] = { "zzz", "bbb", "zzz", "mmm" };

		for (i = 0; i < 4; i++) {
			members[i].dim = D;
			members[i].dim_len = DIM_LEN;
			members[i].id = (const uint8_t *)ids[i];
			members[i].id_len = 3;
		}
	}
	p[3].members = members;
	p[3].member_count = 4;
	prefix(&n[0], DIM2, DIM2_LEN, "old");

	expr.pos = p;
	expr.pos_count = pc;
	expr.neg = n;
	expr.neg_count = nc;

	/* THE CONTROL FOR THE WHOLE TEST: this is refused BEFORE the sort, so
	 * the pass afterwards is the sort's doing and not an accident of the
	 * fixture. */
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_ERR_MALFORMED,
	      "the unsorted fixture encoded, so this test proves nothing");

	CHECK(fzn_facet_expr_sort(p, &pc, n, &nc, scratch, sizeof(scratch))
	          == FZN_FACET_OK, "the sort refused");

	/* F19: the duplicate term is gone. */
	CHECK(pc == 3, "P has %u terms, expected 3", (unsigned)pc);
	CHECK(nc == 1, "N changed size");
	/* F18: the members are sorted and the repeat removed. */
	CHECK(p[0].kind == FZN_FACET_ALT || p[1].kind == FZN_FACET_ALT
	          || p[2].kind == FZN_FACET_ALT, "the alternation vanished");
	for (i = 0; i < pc; i++) {
		if (p[i].kind != FZN_FACET_ALT)
			continue;
		CHECK(p[i].member_count == 3,
		      "the alternation has %u members, expected 3",
		      (unsigned)p[i].member_count);
		CHECK(memcmp(p[i].members[0].id, "bbb", 3) == 0
		          && memcmp(p[i].members[1].id, "mmm", 3) == 0
		          && memcmp(p[i].members[2].id, "zzz", 3) == 0,
		      "the members are not in F18 order");
	}

	expr.pos = p;
	expr.pos_count = pc;
	expr.neg = n;
	expr.neg_count = nc;
	/* AND THE POINT: what the sort produces is what encode demands. */
	CHECK(fzn_facet_expr_ordered(&expr, scratch, sizeof(scratch)),
	      "the sorted expression is not in F16 order");
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_OK, "the sorted expression would not encode");
	/* Sorting again changes nothing -- it is a canonical form, not a
	 * rearrangement, so a second pass has to be a no-op. */
	{
		size_t pc2 = pc, nc2 = nc, len2 = 0;
		uint8_t again[256];

		CHECK(fzn_facet_expr_sort(p, &pc2, n, &nc2, scratch,
		                          sizeof(scratch)) == FZN_FACET_OK,
		      "the second sort refused");
		CHECK(pc2 == pc && nc2 == nc, "the second sort changed the counts");
		expr.pos_count = pc2;
		expr.neg_count = nc2;
		CHECK(fzn_facet_expr_encode(&expr, again, sizeof(again), &len2)
		          == FZN_FACET_OK && len2 == len
		          && memcmp(buf, again, len) == 0,
		      "sorting twice is not the same as sorting once");
	}
}

static void test_the_sort_orders_without_anything_to_dedup(void)
{
	/* A fixture ONLY THE SORT CAN ANSWER. The test above mixes disorder
	 * with a duplicate, so breaking either the ordering or the dedup
	 * fails the same term-count assertion -- the two sabotages are not
	 * separated by it, and a control that cannot say WHICH check failed is
	 * half a control. Here there is nothing to deduplicate, so only the
	 * ordering can be wrong. */
	static const uint8_t D[] = "genre";
	fzn_facet_term_t p[3];
	fzn_facet_expr_t expr;
	uint8_t scratch[128], buf[256];
	size_t pc = 3, nc = 0, len = 0;

	prefix(&p[0], D, DIM_LEN, "ccc");
	prefix(&p[1], D, DIM_LEN, "aaa");
	prefix(&p[2], D, DIM_LEN, "bbb");

	CHECK(fzn_facet_expr_sort(p, &pc, NULL, &nc, scratch, sizeof(scratch))
	          == FZN_FACET_OK, "the sort refused");
	CHECK(pc == 3, "the sort dropped a term it had no duplicate for");
	CHECK(memcmp(p[0].node.id, "aaa", 3) == 0
	          && memcmp(p[1].node.id, "bbb", 3) == 0
	          && memcmp(p[2].node.id, "ccc", 3) == 0,
	      "three distinct terms did not come back in order");

	expr.pos = p;
	expr.pos_count = pc;
	expr.neg = NULL;
	expr.neg_count = 0;
	CHECK(fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
	          == FZN_FACET_OK, "the ordered expression would not encode");
}

static void test_the_sort_collapses_a_dedup_to_a_prefix(void)
{
	static const uint8_t D[] = "genre";
	fzn_facet_term_t p[1];
	fzn_facet_node_t members[3];
	uint8_t scratch[128];
	size_t pc = 1, nc = 0, i;

	/* Three members, all the same. F18's dedup leaves one, and F19 says
	 * one member is a PREFIX term -- which is why the collapse has to
	 * happen AFTER the dedup and BEFORE the term sort. */
	memset(&p[0], 0, sizeof(p[0]));
	p[0].kind = FZN_FACET_ALT;
	p[0].node.dim = D;
	p[0].node.dim_len = DIM_LEN;
	for (i = 0; i < 3; i++) {
		members[i].dim = D;
		members[i].dim_len = DIM_LEN;
		members[i].id = (const uint8_t *)"solo";
		members[i].id_len = 4;
	}
	p[0].members = members;
	p[0].member_count = 3;

	CHECK(fzn_facet_expr_sort(p, &pc, NULL, &nc, scratch, sizeof(scratch))
	          == FZN_FACET_OK, "the sort refused");
	CHECK(p[0].kind == FZN_FACET_PREFIX,
	      "an alternation deduplicated to one member stayed an alternation");
	CHECK(p[0].member_count == 0 && p[0].members == NULL,
	      "the collapsed term kept its members");
	CHECK(p[0].node.id_len == 4 && memcmp(p[0].node.id, "solo", 4) == 0,
	      "the collapsed term lost its identifier");
}

static void test_the_sort_refuses_what_it_cannot_encode(void)
{
	static const uint8_t D[] = "genre";
	fzn_facet_term_t p[2];
	uint8_t scratch[128], tiny[8];
	size_t pc = 2, nc = 0;

	prefix(&p[0], D, DIM_LEN, "bbb");
	prefix(&p[1], D, DIM_LEN, "aaa");
	/* The control: it sorts with room. */
	CHECK(fzn_facet_expr_sort(p, &pc, NULL, &nc, scratch, sizeof(scratch))
	          == FZN_FACET_OK, "the control would not sort");
	/* A scratch too small is a RANGE, not a silent wrong order. */
	prefix(&p[0], D, DIM_LEN, "bbb");
	prefix(&p[1], D, DIM_LEN, "aaa");
	CHECK(fzn_facet_expr_sort(p, &pc, NULL, &nc, tiny, sizeof(tiny))
	          == FZN_FACET_ERR_RANGE, "a scratch too small sorted anyway");
	CHECK(fzn_facet_expr_sort(p, &pc, NULL, &nc, scratch, 2)
	          == FZN_FACET_ERR_RANGE, "a two-byte scratch was accepted");
	/* A term that will not encode stops the sort with its own error. */
	p[1].kind = (fzn_facet_kind_t)9;
	CHECK(fzn_facet_expr_sort(p, &pc, NULL, &nc, scratch, sizeof(scratch))
	          == FZN_FACET_ERR_KIND, "an unknown kind sorted");
	CHECK(fzn_facet_expr_sort(NULL, &pc, NULL, &nc, scratch, sizeof(scratch))
	          == FZN_FACET_ERR_MALFORMED, "a null P with a count sorted");
}

/* ------------------------------------------------------------------------
 * The property that matters: over random expressions, encode-decode-encode
 * is the same bytes. Random rather than chosen, because cases chosen by
 * whoever wrote the codec agree with the codec by construction.
 * ---------------------------------------------------------------------- */

static uint32_t rng_state = 0x243f6a88u;

static uint32_t rng_next(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

#define POOL 12u

static void test_round_trip_over_random_expressions(void)
{
	static uint8_t ids[POOL][4];
	static const uint8_t *dims[2];
	static size_t dim_lens[2];
	fzn_facet_term_t terms[8], dp[8], dn[8];
	fzn_facet_node_t members[8 * 4], dmembers[8 * 4];
	fzn_facet_expr_t expr, back;
	uint8_t buf[1024], again[1024];
	uint8_t enc[8][64];
	size_t enc_len[8];
	size_t round, mismatches = 0, encoded = 0;

	dims[0] = DIM;
	dim_lens[0] = DIM_LEN;
	dims[1] = DIM2;
	dim_lens[1] = DIM2_LEN;

	for (round = 0; round < 3000; round++) {
		size_t count = 1u + rng_next() % 5u;
		size_t i, j, used = 0, len = 0, len2 = 0, split;
		int ok = 1;

		for (i = 0; i < POOL; i++) {
			ids[i][0] = (uint8_t)('a' + (rng_next() % 6u));
			ids[i][1] = (uint8_t)('a' + (rng_next() % 6u));
			ids[i][2] = (uint8_t)('a' + (rng_next() % 6u));
			ids[i][3] = 0;
		}

		for (i = 0; i < count; i++) {
			size_t d = rng_next() % 2u;
			uint32_t k = rng_next() % 3u;

			memset(&terms[i], 0, sizeof(terms[i]));
			terms[i].node.dim = dims[d];
			terms[i].node.dim_len = dim_lens[d];
			if (k == 0) {
				terms[i].kind = FZN_FACET_PREFIX;
				terms[i].node.id = ids[rng_next() % POOL];
				terms[i].node.id_len = 3;
			} else if (k == 1) {
				terms[i].kind = FZN_FACET_RANGE;
				terms[i].node.id = ids[rng_next() % POOL];
				terms[i].node.id_len = 3;
				if (rng_next() % 2u) {
					terms[i].lo.id = ids[rng_next() % POOL];
					terms[i].lo.id_len = 3;
					terms[i].lo.inclusive =
					        (int)(rng_next() % 2u);
				}
				if (rng_next() % 2u) {
					terms[i].hi.id = ids[rng_next() % POOL];
					terms[i].hi.id_len = 3;
					terms[i].hi.inclusive =
					        (int)(rng_next() % 2u);
				}
			} else {
				size_t m = 2u + rng_next() % 3u;

				terms[i].kind = FZN_FACET_ALT;
				terms[i].members = &members[used];
				terms[i].member_count = m;
				for (j = 0; j < m; j++) {
					members[used + j].dim = dims[d];
					members[used + j].dim_len = dim_lens[d];
					members[used + j].id =
					        ids[(rng_next() % POOL)];
					members[used + j].id_len = 3;
				}
				used += m;
			}
		}

		/* Sort and dedup the members of each alternation (F18/F19),
		 * and the terms themselves (F16), using the codec's own bytes
		 * -- which is what F16 defines the order over. */
		for (i = 0; i < count; i++) {
			if (terms[i].kind != FZN_FACET_ALT)
				continue;
			{
				fzn_facet_node_t *m =
				        (fzn_facet_node_t *)(size_t)terms[i].members;
				size_t n = terms[i].member_count, a, b, w;

				for (a = 0; a + 1u < n; a++)
					for (b = 0; b + 1u < n - a; b++)
						if (memcmp(m[b].id, m[b + 1u].id, 3) > 0) {
							fzn_facet_node_t t = m[b];

							m[b] = m[b + 1u];
							m[b + 1u] = t;
						}
				w = 1;
				for (a = 1; a < n; a++)
					if (memcmp(m[a].id, m[w - 1u].id, 3) != 0)
						m[w++] = m[a];
				terms[i].member_count = w;
				if (w < 2u)
					ok = 0;   /* F19: becomes a PREFIX. */
			}
		}
		if (!ok)
			continue;

		for (i = 0; i < count; i++) {
			if (fzn_facet_term_encode(&terms[i], enc[i],
			                          sizeof(enc[i]), &enc_len[i])
			    != FZN_FACET_OK) {
				ok = 0;
				break;
			}
		}
		if (!ok)
			continue;

		/* Insertion sort the terms by their encodings, and drop
		 * duplicates. */
		for (i = 1; i < count; i++) {
			for (j = i; j > 0; j--) {
				size_t n = enc_len[j - 1u] < enc_len[j]
				                   ? enc_len[j - 1u]
				                   : enc_len[j];
				int c = memcmp(enc[j - 1u], enc[j], n);

				if (c == 0)
					c = enc_len[j - 1u] < enc_len[j] ? -1
					    : enc_len[j - 1u] > enc_len[j] ? 1
					                                   : 0;
				if (c <= 0)
					break;
				{
					fzn_facet_term_t tt = terms[j - 1u];
					uint8_t te[64];
					size_t tl = enc_len[j - 1u];

					memcpy(te, enc[j - 1u], tl);
					terms[j - 1u] = terms[j];
					memcpy(enc[j - 1u], enc[j], enc_len[j]);
					enc_len[j - 1u] = enc_len[j];
					terms[j] = tt;
					memcpy(enc[j], te, tl);
					enc_len[j] = tl;
				}
			}
		}
		{
			size_t w = 1;

			for (i = 1; i < count; i++) {
				if (enc_len[i] == enc_len[w - 1u]
				    && memcmp(enc[i], enc[w - 1u], enc_len[i]) == 0)
					continue;
				terms[w] = terms[i];
				memcpy(enc[w], enc[i], enc_len[i]);
				enc_len[w] = enc_len[i];
				w++;
			}
			count = w;
		}

		/* Split into P and N. P must not be empty (F14), and a term
		 * cannot be on both sides (F27) -- a split of a deduplicated
		 * sorted list gives both for free. */
		split = 1u + rng_next() % count;
		expr.pos = terms;
		expr.pos_count = split;
		expr.neg = &terms[split];
		expr.neg_count = count - split;

		if (fzn_facet_expr_encode(&expr, buf, sizeof(buf), &len)
		    != FZN_FACET_OK)
			continue;
		encoded++;
		if (fzn_facet_expr_decode(buf, len, dp, 8, dn, 8, dmembers,
		                          sizeof(dmembers) / sizeof(dmembers[0]),
		                          &back, NULL) != FZN_FACET_OK) {
			mismatches++;
			continue;
		}
		if (fzn_facet_expr_encode(&back, again, sizeof(again), &len2)
		    != FZN_FACET_OK) {
			mismatches++;
			continue;
		}
		if (len2 != len || memcmp(buf, again, len) != 0)
			mismatches++;
	}

	CHECK(encoded > 1500, "only %u of 3000 random expressions encoded -- "
	      "the generator, not the codec", (unsigned)encoded);
	CHECK(mismatches == 0,
	      "encode-decode-encode differed for %u of %u expressions",
	      (unsigned)mismatches, (unsigned)encoded);
}

int main(void)
{
	test_a_term_round_trips();
	test_the_refusals();
	test_out_of_order_on_the_wire();
	test_members_out_of_order_on_the_wire();
	test_ordered_needs_room_and_says_so();
	test_the_sort_produces_what_encode_demands();
	test_the_sort_orders_without_anything_to_dedup();
	test_the_sort_collapses_a_dedup_to_a_prefix();
	test_the_sort_refuses_what_it_cannot_encode();
	test_round_trip_over_random_expressions();

	printf("facet_codec_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
