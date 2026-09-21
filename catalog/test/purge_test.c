/* Tests for catalog/purge.c: the queued purge of C19a. sec 335.
 *
 * THE CASES THIS SUITE EXISTS FOR are the two C19a names as the things an
 * implementation gets wrong BY BEING HELPFUL, because both are invisible in
 * ordinary use and both are expensive:
 *
 *   THE SET IS PINNED, NOT RECOMPUTED. A set recomputed against the current
 *   estate can never close while a host is away, and closes early when one
 *   leaves. Both directions are driven here, because an implementation that
 *   recomputed would pass a test for only one of them.
 *
 *   THE SET IS THE HOSTS THAT HOLD, not every sibling. A host that only
 *   forwards never stores and must never be waited on, or the queue grows for
 *   ever while every host in it behaves correctly.
 *
 * AND ELIMINATION IS REFUSED WHILE THE SET IS OPEN, which is not bookkeeping:
 * a host that has not agreed still holds a copy and will re-send it, so an
 * early elimination undoes the deletion at that host's next sync.
 */

#include "../purge.h"

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
	fprintf(stderr, "  FAIL purge_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static uint8_t hostA[32], hostB[32], hostC[32];
static uint8_t e1[FZN_CATALOG_ENTITY_LEN];
static uint8_t e2[FZN_CATALOG_ENTITY_LEN];

static void fixtures(void)
{
	memset(hostA, 0xa1, sizeof(hostA));
	memset(hostB, 0xb2, sizeof(hostB));
	memset(hostC, 0xc3, sizeof(hostC));
	memset(e1, 0xe1, sizeof(e1));
	memset(e2, 0xe2, sizeof(e2));
}

/* A HOLDER assertion -- only these make a host a holder (C5e/C8a). */
static void holder(fzn_catalog_assertion_t *a, const uint8_t *issuer,
                   const uint8_t *entity)
{
	memset(a, 0, sizeof(*a));
	a->issuer = issuer;  a->issuer_len = 32;
	a->entity = entity;  a->entity_len = FZN_CATALOG_ENTITY_LEN;
	a->name = (const uint8_t *)"held"; a->name_len = 4;
	a->attr_class = FZN_CATALOG_FACT;
	a->scope = FZN_CATALOG_ESTATE;
	a->merge = FZN_CATALOG_UNION;
	a->capability = FZN_CATALOG_CAP_HOLDER;
	a->live = 1;
}

/* A curated link -- a host that curates but does not hold. */
static void curated(fzn_catalog_assertion_t *a, const uint8_t *issuer,
                    const uint8_t *entity)
{
	holder(a, issuer, entity);
	a->capability = FZN_CATALOG_CAP_NONE;
}

/* THE ORDINARY CYCLE: queue, agree, close, eliminate. */
static void test_the_cycle(void)
{
	fzn_catalog_assertion_t set[2];
	fzn_catalog_purge_t rows[4];
	fzn_catalog_purges_t purges;
	size_t pinned = 0, agreed = 0;

	holder(&set[0], hostA, e1);
	holder(&set[1], hostB, e1);

	CHECK(fzn_catalog_purges_init(&purges, rows, 4) == FZN_CATALOG_OK,
	      "a queue over caller-owned rows was refused");
	CHECK(!fzn_catalog_purge_queued(&purges, e1, sizeof(e1)),
	      "an entity nobody queued reported a purge");

	CHECK(fzn_catalog_purge_queue(&purges, set, 2, e1, sizeof(e1)) == FZN_CATALOG_OK,
	      "queueing a purge over two holders was refused");
	CHECK(fzn_catalog_purge_queued(&purges, e1, sizeof(e1)), "the purge did not queue");
	CHECK(fzn_catalog_purge_count(&purges) == 1, "one purge was not one row");

	CHECK(fzn_catalog_purge_progress(&purges, e1, sizeof(e1), &pinned, &agreed) ==
	          FZN_CATALOG_OK && pinned == 2 && agreed == 0,
	      "the pinned set is %zu hosts with %zu agreed, not 2 and 0", pinned, agreed);

	/* NOT CLOSED, AND NOT ELIMINABLE, until every pinned host agrees. */
	CHECK(!fzn_catalog_purge_closed(&purges, e1, sizeof(e1)),
	      "a purge closed before anybody agreed");
	CHECK(fzn_catalog_purge_eliminate(&purges, e1, sizeof(e1)) == FZN_CATALOG_ERR_BUSY,
	      "the queue entry was eliminated before consensus, which does not lose "
	      "bookkeeping -- it undoes the deletion at the next sync of a host that "
	      "still holds a copy");

	CHECK(fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostA, 32) == FZN_CATALOG_OK,
	      "a pinned host's agreement was refused");
	CHECK(!fzn_catalog_purge_closed(&purges, e1, sizeof(e1)),
	      "one of two agreements closed the purge");
	CHECK(fzn_catalog_purge_eliminate(&purges, e1, sizeof(e1)) == FZN_CATALOG_ERR_BUSY,
	      "a half-agreed purge was eliminable");

	/* AGREEING TWICE IS A RE-DELIVERED MESSAGE, not a fault. */
	CHECK(fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostA, 32) == FZN_CATALOG_OK,
	      "a repeated agreement was treated as an error");

	CHECK(fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostB, 32) == FZN_CATALOG_OK,
	      "the second pinned host's agreement was refused");
	CHECK(fzn_catalog_purge_closed(&purges, e1, sizeof(e1)),
	      "every pinned host agreed and the purge did not close");
	CHECK(fzn_catalog_purge_progress(&purges, e1, sizeof(e1), &pinned, &agreed) ==
	          FZN_CATALOG_OK && pinned == 2 && agreed == 2,
	      "progress is %zu/%zu, not 2/2", agreed, pinned);

	CHECK(fzn_catalog_purge_eliminate(&purges, e1, sizeof(e1)) == FZN_CATALOG_OK,
	      "a closed purge could not be eliminated, and the entry is the thing "
	      "being paid for");
	CHECK(fzn_catalog_purge_count(&purges) == 0, "elimination did not give the row back");
	CHECK(!fzn_catalog_purge_queued(&purges, e1, sizeof(e1)),
	      "the eliminated purge is still queued");
}

/* THE PIN, IN BOTH DIRECTIONS. C19a names a recomputed set as the thing an
 * implementation gets wrong by being helpful, and it fails two opposite ways.
 * An implementation that recomputed would pass a test for only one. */
static void test_the_set_is_pinned(void)
{
	fzn_catalog_assertion_t set[3];
	fzn_catalog_purge_t rows[4];
	fzn_catalog_purges_t purges;
	size_t pinned = 0, agreed = 0;

	/* A HOST THAT ARRIVES LATER IS NOT WAITED ON. It never agreed to
	 * anything, and a recomputed set would never close while it was away. */
	holder(&set[0], hostA, e1);
	holder(&set[1], hostB, e1);
	fzn_catalog_purges_init(&purges, rows, 4);
	fzn_catalog_purge_queue(&purges, set, 2, e1, sizeof(e1));

	holder(&set[2], hostC, e1); /* C starts holding it AFTER the queue */

	CHECK(fzn_catalog_purge_progress(&purges, e1, sizeof(e1), &pinned, &agreed) ==
	          FZN_CATALOG_OK && pinned == 2,
	      "a host that began holding the entity after the purge was queued was "
	      "added to the consensus set (pinned=%zu), so the set is recomputed and "
	      "can never close while a host is away", pinned);
	CHECK(fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostC, 32) ==
	          FZN_CATALOG_ERR_ABSENT,
	      "a host outside the pinned set had its agreement counted, which lets "
	      "the queue close while a PINNED host has not answered");

	fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostA, 32);
	fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostB, 32);
	CHECK(fzn_catalog_purge_closed(&purges, e1, sizeof(e1)),
	      "the two pinned hosts agreed and the purge did not close");

	/* AND A HOST THAT LEAVES IS STILL WAITED ON, which is the other
	 * direction: a recomputed set CLOSES EARLY when one leaves, dropping
	 * bytes a host that still has them was simply not asked about. */
	{
		fzn_catalog_purge_t rows2[4];
		fzn_catalog_purges_t p2;
		fzn_catalog_assertion_t gone[2];

		holder(&gone[0], hostA, e2);
		holder(&gone[1], hostB, e2);
		fzn_catalog_purges_init(&p2, rows2, 4);
		fzn_catalog_purge_queue(&p2, gone, 2, e2, sizeof(e2));

		gone[1].live = 0; /* B stops holding it after the queue */

		fzn_catalog_purge_agree(&p2, e2, sizeof(e2), hostA, 32);
		CHECK(!fzn_catalog_purge_closed(&p2, e2, sizeof(e2)),
		      "a host that stopped holding the entity after the purge was "
		      "queued was dropped from the set, so the purge closed early and "
		      "the bytes go while that host still has them");
		CHECK(fzn_catalog_purge_eliminate(&p2, e2, sizeof(e2)) ==
		          FZN_CATALOG_ERR_BUSY,
		      "the early-closing purge was eliminable");
		fzn_catalog_purge_agree(&p2, e2, sizeof(e2), hostB, 32);
		CHECK(fzn_catalog_purge_closed(&p2, e2, sizeof(e2)),
		      "the departed host agreed and the purge still did not close");
	}
}

/* THE SET IS THE HOSTS THAT HOLD. A host that only forwards never stores and
 * must never be waited on, or the queue grows for ever while every host in it
 * behaves correctly. */
static void test_only_holders_are_pinned(void)
{
	fzn_catalog_assertion_t set[3];
	fzn_catalog_purge_t rows[4];
	fzn_catalog_purges_t purges;
	size_t pinned = 0, agreed = 0;

	holder(&set[0], hostA, e1);
	curated(&set[1], hostB, e1);  /* curates it, does not hold it */
	holder(&set[2], hostC, e1);

	fzn_catalog_purges_init(&purges, rows, 4);
	CHECK(fzn_catalog_purge_queue(&purges, set, 3, e1, sizeof(e1)) == FZN_CATALOG_OK,
	      "queueing was refused");
	CHECK(fzn_catalog_purge_progress(&purges, e1, sizeof(e1), &pinned, &agreed) ==
	          FZN_CATALOG_OK && pinned == 2,
	      "a host that curates the entity without holding it was pinned "
	      "(pinned=%zu), so the queue waits for a host that has nothing to "
	      "delete and can never close", pinned);
	CHECK(fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostB, 32) ==
	          FZN_CATALOG_ERR_ABSENT,
	      "the non-holder was in the pinned set after all");

	fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostA, 32);
	fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostC, 32);
	CHECK(fzn_catalog_purge_closed(&purges, e1, sizeof(e1)),
	      "both holders agreed and the purge did not close");
}

/* WHAT IS REFUSED, each with a control. */
static void test_refusals(void)
{
	fzn_catalog_assertion_t set[2];
	fzn_catalog_purge_t rows[1];
	fzn_catalog_purges_t purges;
	size_t a = 0, b = 0;

	holder(&set[0], hostA, e1);
	holder(&set[1], hostA, e2);

	fzn_catalog_purges_init(&purges, rows, 1);

	/* NOTHING HOLDS IT: there is no consensus to attain, and an empty set
	 * would close instantly while some host nobody asked still had it. */
	{
		fzn_catalog_assertion_t none[1];

		curated(&none[0], hostA, e1);
		CHECK(fzn_catalog_purge_queue(&purges, none, 1, e1, sizeof(e1)) ==
		          FZN_CATALOG_ERR_ABSENT,
		      "a purge was queued for an entity no host holds, and it would "
		      "close instantly");
		CHECK(fzn_catalog_purge_count(&purges) == 0, "a refused queue stored a row");
	}

	CHECK(fzn_catalog_purge_queue(&purges, set, 2, e1, sizeof(e1)) == FZN_CATALOG_OK,
	      "the control -- a real holder -- was refused too");

	/* RE-QUEUEING WOULD DISCARD THE AGREEMENT ALREADY COLLECTED. */
	fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostA, 32);
	CHECK(fzn_catalog_purge_queue(&purges, set, 2, e1, sizeof(e1)) == FZN_CATALOG_ERR_KIND,
	      "queueing the same entity twice re-pinned it, discarding the agreement "
	      "already collected and restarting against a different set");
	CHECK(fzn_catalog_purge_progress(&purges, e1, sizeof(e1), &a, &b) ==
	          FZN_CATALOG_OK && b == 1,
	      "the agreement was lost anyway (agreed=%zu)", b);

	/* A full queue. */
	CHECK(fzn_catalog_purge_queue(&purges, set, 2, e2, sizeof(e2)) ==
	          FZN_CATALOG_ERR_RANGE, "a full queue took another purge");

	/* Unknown entities. */
	CHECK(fzn_catalog_purge_agree(&purges, e2, sizeof(e2), hostA, 32) ==
	          FZN_CATALOG_ERR_ABSENT, "agreeing to a purge nobody queued");
	CHECK(fzn_catalog_purge_eliminate(&purges, e2, sizeof(e2)) ==
	          FZN_CATALOG_ERR_ABSENT, "eliminating a purge nobody queued");
	CHECK(fzn_catalog_purge_progress(&purges, e2, sizeof(e2), &a, &b) ==
	          FZN_CATALOG_ERR_ABSENT, "progress for a purge nobody queued");
	CHECK(!fzn_catalog_purge_closed(&purges, e2, sizeof(e2)),
	      "an entity with no queued purge reported CLOSED, which a caller must "
	      "not be able to read as done");

	/* Arguments. */
	CHECK(fzn_catalog_purges_init(NULL, rows, 1) == FZN_CATALOG_ERR_MALFORMED,
	      "a null queue initialised");
	CHECK(fzn_catalog_purges_init(&purges, NULL, 1) == FZN_CATALOG_ERR_MALFORMED,
	      "a capacity with no rows initialised");
	CHECK(fzn_catalog_purge_queue(NULL, set, 2, e1, sizeof(e1)) ==
	          FZN_CATALOG_ERR_MALFORMED, "a null queue took a purge");
	CHECK(fzn_catalog_purge_queue(&purges, set, 2, e1, FZN_CATALOG_ENTITY_LEN - 1u) ==
	          FZN_CATALOG_ERR_MALFORMED, "a short entity was accepted");
	CHECK(fzn_catalog_purge_progress(&purges, e1, sizeof(e1), NULL, &b) ==
	          FZN_CATALOG_ERR_MALFORMED, "progress with nowhere to put it");
	CHECK(fzn_catalog_purge_count(NULL) == 0, "a null queue holds purges");
}

/* A NEAR MISS IS A DIFFERENT ENTITY, AND A DIFFERENT HOST. The prefix-compare
 * class: folding two hosts into one would let a purge close on an agreement
 * that a different host gave. */
static void test_near_misses(void)
{
	fzn_catalog_assertion_t set[2];
	fzn_catalog_purge_t rows[4];
	fzn_catalog_purges_t purges;
	static uint8_t hostA2[32];

	memcpy(hostA2, hostA, sizeof(hostA2));
	hostA2[31] ^= 0x01u;

	holder(&set[0], hostA, e1);
	holder(&set[1], hostA2, e1);

	fzn_catalog_purges_init(&purges, rows, 4);
	fzn_catalog_purge_queue(&purges, set, 2, e1, sizeof(e1));

	{
		size_t pinned = 0, agreed = 0;

		fzn_catalog_purge_progress(&purges, e1, sizeof(e1), &pinned, &agreed);
		CHECK(pinned == 2,
		      "two hosts differing in their last byte pinned as one (pinned=%zu)",
		      pinned);
	}
	fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostA, 32);
	CHECK(!fzn_catalog_purge_closed(&purges, e1, sizeof(e1)),
	      "one host's agreement closed a purge pinned on two, so a near-miss "
	      "host key was counted for another host");
	fzn_catalog_purge_agree(&purges, e1, sizeof(e1), hostA2, 32);
	CHECK(fzn_catalog_purge_closed(&purges, e1, sizeof(e1)),
	      "both near-miss hosts agreed and the purge did not close");
}

/* THE WIRE FORM. sec 336.
 *
 * THE COMMAND CARRIES THE PINNED SET, which is the whole reason it is a record
 * rather than a flag: hosts that each derived the set from their own view
 * would disagree about which set must close, which is C19a's recomputing
 * failure arriving over the network. So the round trip has to preserve the set
 * exactly, in order.
 *
 * AND THE ENCODING IS CANONICAL, which matters because the signature is over
 * these bytes: two byte strings decoding to one command would let a peer
 * re-sign a different spelling of what a host said. Every refusal below is a
 * second spelling being turned away.
 */
static void test_the_wire_form(void)
{
	fzn_catalog_host_t hosts[3];
	uint8_t body[FZN_RECORD_BODY_MAX];
	fzn_catalog_purge_t row;
	size_t len = 0;
	size_t i;

	memcpy(hosts[0].b, hostA, sizeof(hosts[0].b));
	memcpy(hosts[1].b, hostB, sizeof(hosts[1].b));
	memcpy(hosts[2].b, hostC, sizeof(hosts[2].b));

	CHECK(fzn_catalog_purge_encode(hosts, 3, body, sizeof(body), &len) ==
	          FZN_CATALOG_OK,
	      "encoding a three-host command was refused");
	CHECK(len == FZN_CATALOG_PURGE_HEAD_LEN + 3u * FZN_CATALOG_PURGE_HOST_LEN,
	      "the body is %zu bytes, not head + three keys", len);
	CHECK(body[0] == FZN_CATALOG_OBJECT_PURGE,
	      "the body does not carry the purge object tag");

	CHECK(fzn_catalog_purge_decode(e1, sizeof(e1), body, len, &row) == FZN_CATALOG_OK,
	      "decoding what was just encoded was refused");
	CHECK(row.hosts == 3, "the decoded set is %zu hosts, not 3", row.hosts);
	CHECK(memcmp(row.entity, e1, sizeof(e1)) == 0,
	      "the entity did not come from the caller's pointer");
	for (i = 0; i < 3; i++)
		CHECK(memcmp(row.host[i].b, hosts[i].b, FZN_CATALOG_PURGE_HOST_LEN) == 0,
		      "pinned host %zu did not survive the round trip, so hosts would "
		      "disagree about which set must close", i);
	CHECK(row.agreed[0] == 0 && row.agreed[1] == 0 && row.agreed[2] == 0,
	      "agreement arrived in the command, and only its recipients can say "
	      "that");

	/* RE-ENCODING THE DECODED FORM IS BYTE-IDENTICAL, which is the half
	 * that catches a slack length or an ignored trailing byte while every
	 * field still looks plausible. */
	{
		uint8_t again[FZN_RECORD_BODY_MAX];
		size_t again_len = 0;

		CHECK(fzn_catalog_purge_encode(row.host, row.hosts, again, sizeof(again),
		                               &again_len) == FZN_CATALOG_OK,
		      "re-encoding the decoded command was refused");
		CHECK(again_len == len && memcmp(again, body, len) == 0,
		      "a command does not re-encode to itself, so two byte strings "
		      "decode to one command and a peer could re-sign a different "
		      "spelling");
	}

	/* WHAT DECODE REFUSES, each a second spelling turned away. */
	{
		uint8_t bad[FZN_RECORD_BODY_MAX];

		memcpy(bad, body, len);
		bad[0] = FZN_CATALOG_OBJECT_ATTRIBUTE;
		CHECK(fzn_catalog_purge_decode(e1, sizeof(e1), bad, len, &row) ==
		          FZN_CATALOG_ERR_MALFORMED,
		      "a body tagged as an attribute decoded as a purge");

		memcpy(bad, body, len);
		CHECK(fzn_catalog_purge_decode(e1, sizeof(e1), bad, len + 1u, &row) ==
		          FZN_CATALOG_ERR_MALFORMED,
		      "a trailing byte was ignored rather than refused");
		CHECK(fzn_catalog_purge_decode(e1, sizeof(e1), bad, len - 1u, &row) ==
		          FZN_CATALOG_ERR_MALFORMED,
		      "a body one byte short of its own count decoded");

		memcpy(bad, body, len);
		bad[1] = 0;
		CHECK(fzn_catalog_purge_decode(e1, sizeof(e1), bad, len, &row) ==
		          FZN_CATALOG_ERR_MALFORMED,
		      "a command pinning nobody decoded, and it would close instantly");

		memcpy(bad, body, len);
		bad[1] = (uint8_t)(FZN_CATALOG_PURGE_HOSTS_MAX + 1u);
		CHECK(fzn_catalog_purge_decode(e1, sizeof(e1), bad, len, &row) ==
		          FZN_CATALOG_ERR_MALFORMED,
		      "a count past what a command can carry decoded");

		CHECK(fzn_catalog_purge_decode(e1, sizeof(e1), body, 1, &row) ==
		          FZN_CATALOG_ERR_MALFORMED, "a truncated head decoded");
		CHECK(fzn_catalog_purge_decode(e1, FZN_CATALOG_ENTITY_LEN - 1u, body, len,
		                               &row) == FZN_CATALOG_ERR_MALFORMED,
		      "a short entity was accepted");
	}

	/* WHAT ENCODE REFUSES. */
	CHECK(fzn_catalog_purge_encode(hosts, 0, body, sizeof(body), &len) ==
	          FZN_CATALOG_ERR_ABSENT,
	      "an empty pinned set encoded, and such a command closes instantly");
	CHECK(fzn_catalog_purge_encode(hosts, FZN_CATALOG_PURGE_HOSTS_MAX + 1u, body,
	                               sizeof(body), &len) == FZN_CATALOG_ERR_RANGE,
	      "more hosts than a command can carry encoded");
	CHECK(fzn_catalog_purge_encode(hosts, 3, body, 4, &len) == FZN_CATALOG_ERR_RANGE,
	      "a body was written past the caller's buffer");
	CHECK(fzn_catalog_purge_encode(hosts, 3, body, sizeof(body), NULL) ==
	          FZN_CATALOG_ERR_MALFORMED, "encoding with nowhere to put the length");
}

/* AGREEMENT IS AN ATTRIBUTE, and the value binds it to one command. */
static void test_agreement_is_derived(void)
{
	fzn_catalog_assertion_t set[4];
	fzn_catalog_source_t who[4];
	uint8_t id1[32], id2[32];
	size_t n = 0, dropped = 0, i;

	memset(id1, 0x11, sizeof(id1));
	memset(id2, 0x22, sizeof(id2));

	/* A and B agree to purge id1; C agrees to a DIFFERENT purge of the same
	 * entity; A's agreement is repeated, as a re-delivery would be. */
	for (i = 0; i < 4; i++)
		curated(&set[i], hostA, e1);
	set[0].issuer = hostA; set[0].value = id1; set[0].value_len = sizeof(id1);
	set[1].issuer = hostB; set[1].value = id1; set[1].value_len = sizeof(id1);
	set[2].issuer = hostC; set[2].value = id2; set[2].value_len = sizeof(id2);
	set[3].issuer = hostA; set[3].value = id1; set[3].value_len = sizeof(id1);

	CHECK(fzn_catalog_purge_agreements(set, 4, e1, sizeof(e1), id1, sizeof(id1),
	                                   who, 4, &n, &dropped) == FZN_CATALOG_OK,
	      "deriving agreements was refused");
	CHECK(n == 2 && dropped == 0,
	      "two hosts agreed to this purge and %zu were counted -- a repeated "
	      "agreement is a re-delivery, not a second host", n);

	/* THE VALUE IS WHAT BINDS IT. Without it, C's agreement to another
	 * purge of the same entity would count towards this one. */
	{
		size_t m = 0, d2 = 0;

		fzn_catalog_purge_agreements(set, 4, e1, sizeof(e1), id2, sizeof(id2),
		                             who, 4, &m, &d2);
		CHECK(m == 1,
		      "the other purge's agreement set is %zu, not 1 -- agreements are "
		      "not bound to the command they were given for", m);
	}

	/* A RETRACTED AGREEMENT IS NOT ONE. */
	set[1].live = 0;
	n = 0;
	fzn_catalog_purge_agreements(set, 4, e1, sizeof(e1), id1, sizeof(id1), who, 4,
	                             &n, &dropped);
	CHECK(n == 1, "a retracted agreement still counted (n=%zu)", n);

	/* And a buffer too small reports the remainder rather than silently
	 * under-counting, as holders does. */
	set[1].live = 1;
	n = 0; dropped = 0;
	fzn_catalog_purge_agreements(set, 4, e1, sizeof(e1), id1, sizeof(id1), who, 1,
	                             &n, &dropped);
	CHECK(n == 1 && dropped == 1,
	      "a one-slot buffer did not report the rest (n=%zu dropped=%zu)", n, dropped);
}

int main(void)
{
	fixtures();
	test_the_wire_form();
	test_agreement_is_derived();

	test_the_cycle();
	test_the_set_is_pinned();
	test_only_holders_are_pinned();
	test_refusals();
	test_near_misses();

	printf("purge_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
