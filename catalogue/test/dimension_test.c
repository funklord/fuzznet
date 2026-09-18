/* Tests for catalogue.h section 2 (DIMENSIONS AND LINKS), which is where the
 * MEMBERSHIP question the supersession left open is actually answered -- and
 * the answer is that there is no separate membership record to answer it with.
 *
 * THE CLAIM THIS SUITE VALIDATES, project.md sec 315. A dimension is a TREE an
 * entity is linked into (C6), and facet (F1-F6) is the algebra over it. A
 * CURATED link (C9) is therefore an ATTRIBUTE whose NAME is the dimension and
 * whose VALUE is the node -- a path in the tree -- and facet's PREFIX term,
 * which selects "every file at or beneath a node", is hierarchical membership.
 * So the ATTRIBUTE record already shipped (catalogue/attribute.situ) is the
 * link, and the availability/holder link needs no record at all (C8, derived
 * from a record's issuer and subject). No membership record is built because
 * none is needed.
 *
 * The proof is end to end: build attribute records, ENCODE and DECODE them
 * over the real wire path, drive a facet index off the decoded assertions, and
 * evaluate hierarchical queries -- the composition the claim rests on, run
 * rather than asserted. This links catalogue.o AND facet.o, the first test to
 * exercise the two together.
 *
 * test_partial then validates the same model over PARTIAL data (project.md sec
 * 316): an index that has synced some dimensions and not others reports
 * `incomplete`, facet's F24 asymmetry keeps the partial answer safe (under-
 * include yes, wrongly exclude never), and a delta firms what was partial --
 * the substrate for storing overlays as deltas over partial data rather than
 * over full datasets.
 */

#include "../catalogue.h"
#include "../../facet/facet.h"

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
	fprintf(stderr, "  FAIL dimension_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* A small catalogue: each row is one entity linked into one dimension at one
 * node. `class` distinguishes a CURATED reference (LABEL) from an OBSERVED
 * fact (FACT), which is C9's reference-versus-observation as an axis rather
 * than a second record type. Every row round-trips through the wire encoding
 * before it reaches the index, so the index is fed exactly what a peer would
 * decode off the stream. */
struct row {
	const char *entity;
	const char *dim;   /* attribute name: the dimension */
	const char *node;  /* attribute value: a path in the dimension tree */
	fzn_catalogue_class_t cls;
};

/* The decoded assertions, plus the body buffers their name/value views borrow
 * from -- both must outlive the query, so they are one array. */
#define MAXROWS 16
static uint8_t bodies[MAXROWS][FZN_RECORD_BODY_MAX];
static fzn_catalogue_assertion_t assertions[MAXROWS];
static size_t nassert;

static int load(const struct row *rows, size_t n)
{
	size_t i, len;
	nassert = 0;
	for (i = 0; i < n && i < MAXROWS; i++) {
		fzn_catalogue_assertion_t a;
		memset(&a, 0, sizeof(a));
		a.name = (const uint8_t *)rows[i].dim;
		a.name_len = strlen(rows[i].dim);
		a.value = (const uint8_t *)rows[i].node;
		a.value_len = strlen(rows[i].node);
		a.attr_class = rows[i].cls;
		a.scope = FZN_CATALOGUE_ESTATE;
		a.merge = FZN_CATALOGUE_UNION;
		a.capability = FZN_CATALOGUE_CAP_NONE;
		if (fzn_catalogue_attribute_encode(&a, bodies[i], sizeof(bodies[i]), &len)
		    != FZN_CATALOGUE_OK)
			return 0;
		/* entity is the record's subject; pass it as the caller would from a
		 * decoded record. It is a stable string, so the borrow outlives use. */
		if (fzn_catalogue_attribute_decode((const uint8_t *)"issuer", 6,
		                                    (const uint8_t *)rows[i].entity,
		                                    strlen(rows[i].entity),
		                                    bodies[i], len, &assertions[i])
		    != FZN_CATALOGUE_OK)
			return 0;
		nassert++;
	}
	return nassert == n;
}

/* Which dimensions this partial index has fully synced. A streaming node has
 * caught some dimensions up to every admitted issuer and is still behind on
 * others; a term over a dimension it has NOT caught up is answered `incomplete`
 * (F24). `cover_all` is the default so the hierarchy tests above see a complete
 * index; test_partial narrows it to model a node partway through a sync. */
static const char *covered[8];
static size_t ncovered;
static int cover_all = 1;

static void cover_reset(void)
{
	ncovered = 0;
	cover_all = 0;
}

static void cover(const char *dim)
{
	if (ncovered < 8)
		covered[ncovered++] = dim;
}

static int dim_covered(const uint8_t *dim, size_t dim_len)
{
	size_t i;
	if (cover_all)
		return 1;
	for (i = 0; i < ncovered; i++)
		if (strlen(covered[i]) == dim_len
		    && memcmp(covered[i], dim, dim_len) == 0)
			return 1;
	return 0;
}

/* The index facet evaluates against, built directly off the decoded
 * assertions. For a PREFIX term it returns every entity whose link in that
 * dimension is at or beneath the node -- a value-prefix match, which is what
 * makes the dimension a tree. This is the whole of the mapping the claim
 * rests on: an attribute IS a dimension link, and a prefix over its value IS
 * the subtree. It also reports `incomplete` for a dimension not yet caught up,
 * which is what makes evaluation over PARTIAL data safe (F24, test_partial). */
static fzn_facet_err_t postings(void *ctx, const fzn_facet_term_t *term,
                                fzn_facet_entity_t *out, size_t out_cap,
                                size_t *out_count, int *incomplete)
{
	size_t i, w = 0;

	(void)ctx;
	*incomplete = dim_covered(term->node.dim, term->node.dim_len) ? 0 : 1;
	if (term->kind != FZN_FACET_PREFIX)
		return FZN_FACET_ERR_KIND; /* this index answers prefixes only */

	for (i = 0; i < nassert; i++) {
		const fzn_catalogue_assertion_t *a = &assertions[i];
		if (a->name_len != term->node.dim_len
		    || memcmp(a->name, term->node.dim, a->name_len) != 0)
			continue;
		if (a->value_len < term->node.id_len
		    || memcmp(a->value, term->node.id, term->node.id_len) != 0)
			continue;
		if (w >= out_cap)
			return FZN_FACET_ERR_RANGE;
		out[w].id = a->entity;
		out[w].id_len = a->entity_len;
		w++;
	}
	*out_count = w;
	return FZN_FACET_OK;
}

/* Does the evaluated set hold an entity named `id`? */
static int has(const fzn_facet_entity_t *set, size_t n, const char *id)
{
	size_t i, len = strlen(id);
	for (i = 0; i < n; i++)
		if (set[i].id_len == len && memcmp(set[i].id, id, len) == 0)
			return 1;
	return 0;
}

static fzn_facet_term_t prefix(const char *dim, const char *node)
{
	fzn_facet_term_t t;
	memset(&t, 0, sizeof(t));
	t.kind = FZN_FACET_PREFIX;
	t.node.dim = (const uint8_t *)dim;
	t.node.dim_len = strlen(dim);
	t.node.id = (const uint8_t *)node;
	t.node.id_len = strlen(node);
	return t;
}

/* A record arriving: encode and decode one more assertion into the next slot,
 * the delta a streaming node applies to advance its partial view. */
static int sync_one(const char *entity, const char *dim, const char *node,
                    fzn_catalogue_class_t cls)
{
	fzn_catalogue_assertion_t a;
	size_t len;

	if (nassert >= MAXROWS)
		return 0;
	memset(&a, 0, sizeof(a));
	a.name = (const uint8_t *)dim;
	a.name_len = strlen(dim);
	a.value = (const uint8_t *)node;
	a.value_len = strlen(node);
	a.attr_class = cls;
	a.scope = FZN_CATALOGUE_ESTATE;
	a.merge = FZN_CATALOGUE_UNION;
	a.capability = FZN_CATALOGUE_CAP_NONE;
	if (fzn_catalogue_attribute_encode(&a, bodies[nassert], sizeof(bodies[nassert]),
	                                   &len) != FZN_CATALOGUE_OK)
		return 0;
	if (fzn_catalogue_attribute_decode((const uint8_t *)"issuer", 6,
	                                   (const uint8_t *)entity, strlen(entity),
	                                   bodies[nassert], len, &assertions[nassert])
	    != FZN_CATALOGUE_OK)
		return 0;
	nassert++;
	return 1;
}

/* Partial data and deltas. An index that has fully synced some dimensions and
 * not others reports `incomplete`, and facet's F24 asymmetry makes the partial
 * answer SAFE: you may under-include (a visible absence), you may NOT wrongly
 * exclude (which could drive a deletion). A delta -- a record arriving, a
 * dimension caught up -- firms what was partial. This is the substrate for
 * storing overlays as deltas over partial data: an answer is honest about its
 * own completeness, so a resolution or quorum overlay built on it can mark a
 * value provisional and firm it as records arrive, never rebuilding from a full
 * dataset. project.md sec 316. */
static void test_partial(void)
{
	fzn_facet_index_ops_t index = { NULL, postings };
	fzn_facet_entity_t out[MAXROWS], scratch[MAXROWS];
	fzn_facet_term_t pos[1], neg[1];
	fzn_facet_expr_t expr;
	size_t n = 0;

	/* This host has caught lib up to every admitted issuer but is still behind
	 * on genre -- exactly a streaming node partway through a sync. */
	cover_reset();
	cover("lib");

	/* You CANNOT exclude on a dimension you have not fully synced: subtracting
	 * an incomplete genre removes too little and so over-includes, and facet
	 * refuses rather than answer wrong. This is the poisoning case from the
	 * other side -- you cannot filter out a spam genre using genre data you
	 * have not caught up on, and the model will not pretend you can. */
	pos[0] = prefix("lib", "music");
	neg[0] = prefix("genre", "jazz");
	expr.pos = pos; expr.pos_count = 1; expr.neg = neg; expr.neg_count = 1;
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_ERR_INCOMPLETE,
	      "cannot exclude on an un-synced dimension -- refused, not guessed (F24)");

	/* You MAY include on it: an incomplete positive under-includes, a visible
	 * absence you fix by syncing more. Only song-a's genre is synced so far. */
	expr.neg = NULL; expr.neg_count = 0;
	pos[0] = prefix("genre", "jazz");
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_OK && n == 1 && has(out, n, "song-a"),
	      "an incomplete positive under-includes -- allowed, a visible absence");

	/* The delta: a record arrives (song-b's genre) and the dimension catches
	 * up. State advances by delta, never a full rebuild. */
	CHECK(sync_one("song-b", "genre", "jazz", FZN_CATALOGUE_FACT),
	      "a genre record arrives -- the delta");
	cover("genre");

	pos[0] = prefix("genre", "jazz");
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_OK && n == 2 && has(out, n, "song-a") && has(out, n, "song-b"),
	      "the delta firms the answer -- jazz now finds song-b too");

	/* And with genre caught up, the exclusion that was refused is now safe. */
	pos[0] = prefix("lib", "music");
	neg[0] = prefix("genre", "jazz");
	expr.neg = neg; expr.neg_count = 1;
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_OK && n == 1 && has(out, n, "song-c"),
	      "genre synced, the exclusion is safe -- music minus jazz is song-c");
}

int main(void)
{
	static const struct row rows[] = {
		{ "song-a", "lib", "music/jazz/bebop", FZN_CATALOGUE_LABEL },
		{ "song-b", "lib", "music/jazz/cool",  FZN_CATALOGUE_LABEL },
		{ "song-c", "lib", "music/rock/punk",  FZN_CATALOGUE_LABEL },
		{ "song-a", "lib", "mood/energetic",   FZN_CATALOGUE_LABEL },
		{ "song-a", "genre", "jazz",           FZN_CATALOGUE_FACT  },
	};
	fzn_facet_index_ops_t index = { NULL, postings };
	fzn_facet_entity_t out[MAXROWS], scratch[MAXROWS];
	fzn_facet_term_t pos[2], neg[1];
	fzn_facet_expr_t expr;
	size_t n = 0;

	CHECK(load(rows, sizeof(rows) / sizeof(rows[0])),
	      "every row encodes and decodes over the wire path");

	/* A prefix in the tree selects its subtree -- hierarchical membership from
	 * attribute records alone, no membership record in sight. */
	pos[0] = prefix("lib", "music/jazz");
	expr.pos = pos; expr.pos_count = 1; expr.neg = NULL; expr.neg_count = 0;
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_OK, "evaluate lib=music/jazz");
	CHECK(n == 2 && has(out, n, "song-a") && has(out, n, "song-b")
	      && !has(out, n, "song-c"), "music/jazz selects the jazz subtree, not rock");

	/* A parent prefix selects everything beneath it. */
	pos[0] = prefix("lib", "music");
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_OK, "evaluate lib=music");
	CHECK(n == 3, "music selects the whole music subtree");

	/* (P) minus (N) over the same tree: all of music that is not jazz. This is
	 * the (intersection of P) minus (union of N) with hierarchy on both sides. */
	pos[0] = prefix("lib", "music");
	neg[0] = prefix("lib", "music/jazz");
	expr.neg = neg; expr.neg_count = 1;
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_OK, "evaluate music minus music/jazz");
	CHECK(n == 1 && has(out, n, "song-c"),
	      "music minus jazz leaves only the rock entry");

	/* One entity linked in several places within, and across, dimensions (C9):
	 * song-a is under music/jazz AND under mood. A query in the other subtree
	 * finds it there without disturbing the first. */
	pos[0] = prefix("lib", "mood");
	expr.neg = NULL; expr.neg_count = 0;
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_OK, "evaluate lib=mood");
	CHECK(n == 1 && has(out, n, "song-a"),
	      "song-a is linked under mood too -- an entity links several times (C9)");

	/* An exact leaf is a prefix that reaches one node. */
	pos[0] = prefix("lib", "music/jazz/bebop");
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_OK, "evaluate the leaf");
	CHECK(n == 1 && has(out, n, "song-a"), "the bebop leaf selects one entity");

	/* A CURATED reference and an OBSERVED fact are the same record shape,
	 * separated by the class axis (C9). Both are queryable the same way: the
	 * genre dimension is a FACT, and it answers a prefix like any other. */
	pos[0] = prefix("genre", "jazz");
	CHECK(fzn_facet_evaluate(&expr, &index, out, MAXROWS, &n, scratch, MAXROWS)
	      == FZN_FACET_OK, "evaluate genre=jazz");
	CHECK(n == 1 && has(out, n, "song-a")
	      && assertions[4].attr_class == FZN_CATALOGUE_FACT
	      && assertions[0].attr_class == FZN_CATALOGUE_LABEL,
	      "a FACT dimension and a LABEL link share one record, split by class");

	/* The same model over PARTIAL data: safe under incompleteness, firmed by
	 * delta. Run last, since it narrows the index's coverage. */
	test_partial();

	printf("dimension_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
