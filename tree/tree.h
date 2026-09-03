/* A tree of signed nodes, where the structure replicates and the content does
 * not mean anything here.
 *
 * WHAT THIS IS FOR. A consumer wants notes that nest, on several of a user's
 * own hosts, converging without a server. sec 5 says the SHAPE of a
 * consumer's objects is configuration rather than design, and a note's shape
 * is the clearest case of that yet: a title, a colour, a checklist, a pin, a
 * reminder and an archive flag are one product's model of a note, and mean
 * nothing to a router holding an annotation against an interface.
 *
 * So this module owns exactly two things a consumer cannot express in an
 * opaque body -- **which node is a node's parent, and where it sits among its
 * siblings** -- and treats everything else the way `record/record.h` treats
 * `kind`. A struct arriving here with a `title` in it would be one project's
 * taxonomy called a model, and the right answer to it is no.
 *
 * A NODE IS A RECORD. There is no new signed object and no second encoder:
 * a node is an `fzn_record_t` whose `subject` is the node's id -- 32 opaque
 * bytes, which is what `subject` already means -- and whose BODY carries the
 * two fields above followed by the consumer's own bytes. Everything
 * `record/` guarantees about authenticity and order is inherited rather than
 * restated, including that a node is a view over the buffer it was parsed
 * from and that buffer must outlive it.
 *
 * THE BODY LAYOUT. Big-endian, fixed width, fixed fields first and the one
 * variable field last -- `record/record.h`'s layout rules, one level in.
 *
 *      off  size  field
 *        0    32  parent        (all-zero means "a child of the root")
 *       32     8  order         (position among siblings)
 *       40     2  content_type  (the consumer's registry, opaque here)
 *       42     n  content       (opaque, n = body_len - 42)
 *
 * So a node body is 42 bytes plus its content, and a node record is at most
 * FZN_RECORD_MAX_LEN like every other record. `content_type` is two bytes
 * here and an enum NOWHERE here: sec 18 refused a realm enum for the same
 * reason `chain.h` refused a capability ladder, and a content-type registry
 * is the consumer's for exactly that argument.
 *
 * AN UNKNOWN CONTENT TYPE IS SHOWN AND RE-PUBLISHED UNCHANGED, NEVER
 * DROPPED. Signalled by the first consumer as the rule most likely to be got
 * wrong, and it is a property of the split above rather than of any one
 * consumer: `parent` and `order` are this module's, so they parse whatever
 * the content turns out to be, and **a node's PLACE is knowable even when its
 * content is not**. Hosts do not upgrade together. A consumer that discarded
 * what it could not read would silently delete a newer host's nodes on every
 * sync -- and would do it worst to the user with the most devices, which is
 * the user most likely to have one host ahead of the others. Carry the bytes,
 * render what you can, and hand them on.
 *
 * WHAT A CONTENT BUDGET ACTUALLY IS, since it decides more for a consumer
 * than it looks. `FZN_RECORD_BODY_MAX` is 512 for reasons that predate this
 * module, so content is 470 once these fields are in. The first consumer
 * measured what that leaves them: 442 after their own note header, which
 * holds a sticky note and does not hold a paragraph. **So a consumer with
 * variable-length content should expect the blob layer to be its ordinary
 * path rather than an escape hatch**, and should size the decision that way
 * rather than filing long content as the exception. This module does not
 * size itself around one consumer's content and 470 is not a target; it is
 * stated here so the arithmetic is done before somebody designs against a
 * number they assumed.
 *
 * ================= WHAT THIS MODULE REFUSES TO DECIDE =================
 *
 * TWO HOSTS CAN REPARENT THE SAME NODE, AND THIS DOES NOT PICK A WINNER.
 * The tempting rule is last-writer-wins on `issued_at`, described as the
 * supersession `state/` already does. **`state/` does not do that.**
 * `state/state.h` says ORDER WITHIN A WRITER, NEVER ACROSS: a statement from
 * a different issuer is a conflict and a different stream of the same issuer
 * is cross-stream contention, and it resolves neither. The measurement
 * behind that refusal is in its header -- the same two records in two orders
 * leaving two different values, which is convergence failing.
 *
 * So resolving here would be inventing the total order `state/` declined to
 * invent, and it would be inventing it out of a clock. sec 47 records what
 * that costs: a device returning from a long absence with a regressed clock
 * cannot publish a usable prekey and is already close to unreachable. Order
 * its moves by `issued_at` as well and it silently loses every reparenting
 * race for as long as it is behind -- and a device returning from a long
 * absence is precisely the population a healing estate has to serve. **A
 * tie-break that quietly disenfranchises the returning host is worse than a
 * conflict somebody can see.**
 *
 * WHAT THAT MEANS MECHANICALLY, AND IT IS NOT A SOFTENING. Because nothing
 * is resolved, a node may carry MORE THAN ONE parent claim -- one record per
 * claiming writer, all valid, all signed. The applied set is therefore not a
 * tree and not even a forest: it is a directed graph that may contain
 * cycles, and `fzn_tree_children` will report the same node under every
 * parent that claims it. A consumer showing a note in two places at once is
 * this working, not this failing.
 *
 * THE COST LANDS ON TRAVERSAL, WHICH IS WHY THE SCRATCH IS NOT OPTIONAL.
 * With one parent per node a walk needs no memory and a cycle is a rare
 * repair. With several, a walk that does not remember where it has been does
 * not terminate. So `fzn_tree_reachable` takes a caller-supplied mark array
 * and terminates by construction; sec 2 says nothing here allocates, and
 * this is the module where that constraint is visible in the signature
 * rather than hidden in an implementation.
 *
 * AND NOTHING IS EVER REPAIRED BY WRITING. Reachability is a pure function
 * of the applied set, so two hosts holding the same records compute the same
 * answer -- the one property `state/` guarantees and the only one this leans
 * on. It writes nothing, so a repair cannot itself replicate or race. And it
 * deletes nothing: a node the root cannot reach is REPORTED as unreachable,
 * for the consumer to show at top level, so a user who caused a cycle sees
 * their notes in the wrong place rather than not at all.
 *
 * A SIMPLER PRIMITIVE THAN THE ONE THAT WAS PROPOSED. The design this was
 * built from repaired cycles by finding the lowest id in each cycle and
 * reparenting it to the root for the duration of a traversal. That needs
 * cycle MEMBERSHIP, which needs the walk to distinguish the loop from the
 * tail leading into it. Reachability needs neither: everything the root
 * cannot reach is shown at top level, whether it is in a cycle or merely
 * orphaned because its parent has not arrived yet. Same user-visible
 * outcome, one pass, no cycle enumeration -- and it answers the
 * not-yet-arrived case, which the repair rule did not.
 *
 * ORDER IS A KEY, AND THE TOTAL ORDER IS (order, id). Two hosts inserting
 * between the same pair of siblings will pick the same midpoint and collide.
 * That is not a defect to design out: ties are broken by node id, which both
 * hosts hold, so the result is deterministic everywhere and the worst
 * outcome is two notes in an order nobody chose. That was already the
 * accepted worst case; making the id part of the order is what makes it the
 * worst case rather than a coin toss per host.
 *
 * WHICH IS ALSO WHY EXHAUSTION IS NOT AN ERROR. `order` is 64 bits, so
 * repeated insertion between one pair of neighbours runs out of midpoints
 * after at most 63 of them. `fzn_tree_order_between` says so --
 * FZN_TREE_ORDER_EXHAUSTED -- and still writes a usable key, the low
 * neighbour's own, which ties and is therefore ordered by id. So an
 * exhausted insert degrades to exactly the outcome above instead of
 * refusing, and a consumer that cares can renumber, which is writing records
 * and so is not this library's business.
 *
 * THE NAMING FOLLOWS `state/state.h`: a code carrying `ERR_` wrote nothing.
 * FZN_TREE_ORDER_EXHAUSTED has no `ERR_` because it writes its output, for
 * the same reason FZN_STATE_ABSENT lost its.
 *
 * WHAT IS DELIBERATELY NOT HERE:
 *
 *   - **A note.** No title, no colour, no checklist, no reminder. See above.
 *   - **A content-type enum.** The registry is the consumer's, sec 18's
 *     split for realms applied unchanged.
 *   - **Import.** Neither source a consumer named has a hierarchy: Keep
 *     Takeout is per-note JSON with flat labels and a note may carry
 *     several, so a label cannot be a parent, and KNotes is flat VJOURNAL.
 *     The hierarchy is the user's to build and an importer must not invent
 *     one. It is host-side work with files in it, and this library has no
 *     I/O.
 *   - **Authorisation.** Whether an issuer may claim a parent is a
 *     capability question for `fzn_chain_verify`, exactly as in `record/`.
 *   - **Sharing.** Publishing a subtree read-only is cheap for one reason
 *     worth saying out loud -- there is a single writer, so every hazard
 *     above is a hazard of two and none of them arises. That makes it a
 *     consumer decision about which records to hand over, not a mechanism
 *     here.
 *   - **Allocation.** Per sec 2. The caller owns the node array, the output
 *     array and the mark array, and every function that can run out of room
 *     reports how much it examined rather than silently stopping.
 */

#ifndef FZN_TREE_H
#define FZN_TREE_H

#include "../record/record.h"

#include <stddef.h>
#include <stdint.h>

/* A node id is a record subject, and the same width for the same reason. */
#define FZN_TREE_ID_LEN FZN_SUBJECT_LEN

/* Body offsets, stated so a reader and the code cannot disagree. */
#define FZN_TREE_OFF_PARENT       0u
#define FZN_TREE_OFF_ORDER        (FZN_TREE_OFF_PARENT + FZN_TREE_ID_LEN)
#define FZN_TREE_OFF_CONTENT_TYPE (FZN_TREE_OFF_ORDER + 8u)
#define FZN_TREE_OFF_CONTENT      (FZN_TREE_OFF_CONTENT_TYPE + 2u)

#define FZN_TREE_BODY_HEADER_LEN FZN_TREE_OFF_CONTENT

/* What is left of a record body once this module's fields are in it. */
#define FZN_TREE_CONTENT_MAX \
	((size_t)FZN_RECORD_BODY_MAX - (size_t)FZN_TREE_BODY_HEADER_LEN)

typedef enum fzn_tree_err {
	FZN_TREE_OK = 0,
	/* The body is too short to hold this module's fields at all. */
	FZN_TREE_ERR_SHORT_BODY,
	/* Content longer than a record body can carry. */
	FZN_TREE_ERR_CONTENT_LEN,
	/* A null pointer where one is required. */
	FZN_TREE_ERR_NULL,
	/* An output buffer too small to write into at all. */
	FZN_TREE_ERR_CAPACITY,
	/* Neighbours given the wrong way round (lo > hi). Refused rather
	 * than swapped: a caller holding them reversed has a bug this would
	 * hide, and the swap answers a question nobody asked. */
	FZN_TREE_ERR_RANGE,
	/* The record is not open; `fzn_record_open` refused it or was never
	 * called. Checked because a closed record's accessors are not
	 * meaningful and the mistake is silent otherwise. */
	FZN_TREE_ERR_CLOSED,
	/* No key exists strictly between the two neighbours. WROTE ITS
	 * OUTPUT, hence no `ERR_`: see the header comment. */
	FZN_TREE_ORDER_EXHAUSTED
} fzn_tree_err_t;

/* A node, as a view. Every pointer aims into the record's own buffer, which
 * must outlive this and anything holding it -- `record/record.h`'s rule,
 * inherited rather than restated. */
typedef struct fzn_tree_node {
	const uint8_t *id;      /* FZN_TREE_ID_LEN bytes: the record subject */
	const uint8_t *parent;  /* FZN_TREE_ID_LEN bytes; all-zero = root */
	const uint8_t *content; /* content_len bytes, opaque to this module */
	size_t content_len;
	uint64_t order;
	uint16_t content_type;
} fzn_tree_node_t;

/* What a walk did, so that running out of room is reported rather than
 * looking like an answer. `fzn_manifest_plan_offer` has the same shape for
 * the same reason. */
typedef struct fzn_tree_walk {
	size_t emitted;   /* entries written to the output */
	size_t examined;  /* nodes considered, whether emitted or not */
	int truncated;    /* non-zero if the output ran out before the input */
} fzn_tree_walk_t;

/* THE ROOT IS ALL-ZERO AND IS NOT A NODE. It has no record, so nobody signs
 * it and nobody can move it. A consumer wanting a named top level makes a
 * node whose parent is the root. */
int fzn_tree_is_root(const uint8_t id[FZN_TREE_ID_LEN]);

/* Parse a record's body as a node. Layout only -- this never touches a key,
 * on `record/record.h`'s split between shape and semantics, so a malformed
 * body costs no public-key operation. The caller decides which records are
 * node records; `kind` is never read here, because it is the consumer's. */
fzn_tree_err_t fzn_tree_open(fzn_record_t record, fzn_tree_node_t *out);

/* Build a node body for signing. The counterpart to `fzn_tree_open`, and the
 * only encoder -- `record/record.h` records what having zero encoders cost
 * when nothing produced the bytes a verifier checked. */
fzn_tree_err_t fzn_tree_body(const uint8_t parent[FZN_TREE_ID_LEN],
                             uint64_t order,
                             uint16_t content_type,
                             const uint8_t *content, size_t content_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

/* A key strictly between two neighbours, or the low neighbour's own key with
 * FZN_TREE_ORDER_EXHAUSTED when none exists. Writes `*out` on both of those
 * and on neither error. `lo` greater than `hi` is FZN_TREE_ERR_RANGE. To
 * insert before everything pass lo = 0; after everything, hi = UINT64_MAX. */
fzn_tree_err_t fzn_tree_order_between(uint64_t lo, uint64_t hi, uint64_t *out);

/* Compare two nodes in sibling order: (order, id), which is total because id
 * is unique per node and both hosts hold it. Returns <0, 0 or >0. */
int fzn_tree_cmp(const fzn_tree_node_t *a, const fzn_tree_node_t *b);

/* Every node claiming `parent`, in sibling order, into a caller-owned array
 * of pointers. A node claimed by two parents is reported under both, which
 * is the unresolved-conflict case working as described above.
 *
 * A CONSUMER'S OWN STORE MUST BE KEYED BY (subject, issuer). Keying it by
 * subject alone makes the second claim overwrite the first, which resolves
 * the conflict this module refuses to resolve -- silently, and by arrival
 * order, which is the one rule nobody would choose. `nodes` must be able to
 * hold both claims or the two-parent case above cannot arise for it to
 * report.
 *
 * SPELLED AS AN INSTRUCTION HERE BECAUSE THE ARGUMENT ABOVE DID NOT CARRY.
 * The refusal is stated at length as a design position, and the first
 * consumer read it, agreed with it, and then shipped a store keyed by
 * subject -- having taken the section to be about whether to pick a winner
 * rather than about how their own storage must be shaped. That is a
 * reasonable reading of prose in a rationale, and it is why the mechanical
 * consequence now sits next to the function instead. Reported by that
 * consumer after they had found and fixed it themselves. */
fzn_tree_err_t fzn_tree_children(const fzn_tree_node_t *nodes, size_t count,
                                 const uint8_t parent[FZN_TREE_ID_LEN],
                                 const fzn_tree_node_t **out, size_t out_cap,
                                 fzn_tree_walk_t *walk);

/* Mark which nodes the root can reach. `mark` is caller-owned, one byte per
 * node, and is what makes this terminate on a cyclic set; on return
 * `mark[i]` is non-zero exactly when `nodes[i]` is reachable from the root.
 *
 * Everything left unmarked is unreachable, and this module does not
 * distinguish WHY -- in a cycle, or waiting for a parent that has not
 * arrived. A consumer shows both at top level, so the distinction would be
 * one it could not act on.
 *
 * `walk->emitted` is how many nodes are reachable and `walk->truncated` is
 * always zero -- nothing is written to a bounded output here. `walk->examined`
 * counts NODE VISITS ACROSS PASSES rather than distinct nodes, so it exceeds
 * `count` on any tree deeper than one level; it is the work measure, and it is
 * the number to watch if a consumer ever holds a deep tree. */
fzn_tree_err_t fzn_tree_reachable(const fzn_tree_node_t *nodes, size_t count,
                                  uint8_t *mark, size_t mark_cap,
                                  fzn_tree_walk_t *walk);

const char *fzn_tree_err_str(fzn_tree_err_t err);

#endif /* FZN_TREE_H */
