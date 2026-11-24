# fuzznet's journal: what was true once

Moved out of `project.md` under the holder's rule of 2026-11-20: dated
state-of-play sweeps, session narrative and closed findings, so that
`project.md` stays readable enough to be authoritative. Oldest first,
appended to and never rewritten. **A section here keeps its number**, so
a `sec N` citing it resolves here -- `make cites` reads both files'
headings (project.md sec 1403).

## 23. A host that loses its memory, 2026-08-30

The lens came from the two defects above, both of which were **a double that
could not express the failure**. Applied to the simulation, it lands
immediately: seventeen scenarios, and every one keeps its hosts alive from
the first line to the last. `persist/` exists for exactly one reason -- four
kinds of state must survive a restart -- so **the one question that module
answers was the one question the simulation could not ask**, and `persist`
appeared nowhere in the file.

`persist_test.c` round-trips each blob and checks its fields, which proves
the PACKERS. It cannot prove the SET is sufficient, because sufficiency is a
property of a host trying to carry on afterwards. That is the
correct-function-versus-working-feature split, and `scenario_restart` is the
missing half: host 1 exchanges three messages, writes down its secret, its
pinned peer and its receive chain, has every byte of its live state filled
with 0xdd, comes back from the blobs alone, and must follow message four and
the four after it.

Five mutations on the format, all caught: a chain that forgets its sequence,
a chain that forgets its key, a peer that forgets the prekey, and an adopted
anchor coming back pinned. The last is the provenance-laundering case, and it
was worth having twice -- `persist_test.c` holds it for a bare trust, and this
holds it for a peer that has been through a real pinning.

### Two controls, because one control covered one claim

The scenario asserts BEFORE restoring that the scrubbed host cannot follow
the conversation. Without that, a scrub that quietly failed to land would
leave the restore looking like it worked when nothing had been lost.

**One control was not enough and the mutation said so.** The first version
checked only the chain. Removing the secret's scrub left the suite green,
because the re-establish half would then have passed on memory that survived
rather than on the blob -- the two are indistinguishable from the output. A
second control was added for the secret, and **it did not work either**: it
used the scrubbed peer's prekey, so the establish failed on the garbage
prekey whether or not the secret had survived. It was testing the
CONJUNCTION of two scrubs and reporting it as either. Using host 0's live
public key is what made it discriminate, and only then did removing the
secret's scrub turn the suite red.

Two attempts, both plausible, both green, neither testing what its message
said. The general form is already in this document twice this week: **a probe
gets checked against the mechanism its author had in mind rather than against
the failure it is meant to catch.**

### The two remaining scrubs are model faithfulness, not evidence

Removing the peer's scrub or the root's changes no result, measured. That is
not a gap: their restore overwrites the same storage, so there is no leftover
for a later assertion to pass on. It is only true while the restore is TOTAL,
and nothing said it was.

So that is asserted as a relationship rather than a value -- open one blob
into two buffers poisoned differently and require the results to be identical.
**And the check's reach was then measured rather than assumed, which changed
what the comment beside it says.** A field an opener forgot comes back as
`fzn_prekey_peer_init`'s value from both poisons, so the check stays green:
correct, because with the init in place that is a wrong VALUE and the
packer tests own it, not a leak of the caller's bytes. Dropping the init
alone is also green, since the openers do write every field. Dropping the
init AND forgetting a field is caught. The first draft of the comment claimed
the check caught a forgotten field outright; it does not, and saying so is
the difference between a fact and a fact with its method.

## 24. Four correct bindings are not a working host, 2026-08-30

Same lens, one layer down. There are four Monocypher tests -- Ed25519,
BLAKE2b, ChaCha20-Poly1305, X25519 -- and **not one of them calls a
composition function in this library**, while `sim/test/network_test.c`,
which calls all of them, runs entirely on stubs. So "a real host can complete
a conversation" was held by nothing. `sim/test/real_crypto_test.c` holds it:
prekey to session to chains to ratchet to a sealed frame, on real keys, in
one binary, and it is the only binary that links all four bindings at once.

### The hazard it was written for was already held, and by a better guard

The file was written for a hazard one constant wide.
`fzn_commitment_derive_root` asks the hash seam for FZN_DERIVED_LEN bytes in
one call; that is **64 today and 64 is BLAKE2b's maximum**, so `mono_hash`
refuses anything larger while the FNV stub produces any length for ever.
Grow the constant and no real host can establish a session.

**Checked rather than told, and it failed.** Growing the constant turns
`session/test/commitment_test.c:165` red with Monocypher switched OFF: that
stub is not a passive fake, it COUNTS WHAT IT WAS ASKED FOR and asserts on
the number. The story was good and the guard already existed.

### The honest result: no unique catch, measured over five mutations

The search was widened rather than dropped. Five mutations -- the agreement
binding's arguments swapped, the hash binding's length cap raised, the
derived length grown, a chain seed asking for 65 bytes, one asking for zero
-- and **not one is caught by the new file and missed by the rest of the
suite.** Each fell to the binding's own test, to a stub that counts, or to
the sanitizers. The 65-byte case looked unique until the sanitized run with
Monocypher off was tried, which is the instrument the first comparison
skipped.

**And the first comparison was invalid for a second reason worth recording**:
`MONOCYPHER_DIR ?= $(MONO_VENDORED)` since sec 15c, so "with stubs" and "with
real crypto" were the SAME configuration and the two runs differed in
nothing. A comparison whose two arms are identical reports agreement no
matter what is true. `MONOCYPHER_DIR=` is the off arm.

So the file is kept as a judgement rather than as evidence, and its own
header says so at length: it is a positive control for the COMPOSITION,
which is the argument `sign_monocypher_test.c` already makes for one seam,
applied to the chain of seams. The mismatch it would catch is between two
modules that each pass their own tests. Anybody citing it as coverage should
cite one of the guards above instead.

### One thing did change in the library

`session/hash_monocypher.c` now carries
`_Static_assert(FZN_DERIVED_LEN <= 64)`. `commitment_test.c` remains the real
guard, because it holds with no Monocypher present at all; the assert adds
earliness, turning the growth into a failure to build the binding that could
not serve it. Confirmed to fire by growing the constant and reading the
compiler's message, rather than by trusting that it would.

### What is left

Nothing in the store. See sec 25: half of what sec 16 staged as "the
transfer protocol" turned out to be decided already and is now built.

## 25. A deferral that had already been decided elsewhere, 2026-08-30

Sec 16 staged the transfer protocol out of stage 1 and gave a reason: its
WANT needs a return-routability cookie, and "that belongs with the rest of
the amplification work in sec 13c". **Sec 13c is about bounding revocation
admission and says nothing on the subject.** The pointer went nowhere and
nobody followed it, which is what a deferral is for.

**The decision had been taken, under a different name, in `record/sync.c`.**
That module had already met the identical problem for records -- a cheap
query must not buy an expensive answer -- and answered it three ways, each
paid for by something that went wrong:

- **A request naming nothing gets nothing.** Sync's own measured defect: an
  absent position used to mean "send me your whole history", so the cheapest
  message in the protocol was the amplifier in it. A zero-length digest
  bought 64 ranges over 32,768 records, at least 5 MB, from an input with
  nothing in it.
- **A ceiling, because the peer chooses the number.** 1024 positions, with
  the 200,000-position measurement behind it: 8.8 MB of digest buying 2.05
  seconds of somebody else's CPU.
- **Zero is refused rather than meaning unlimited.**

This is `working-practice.md`'s rule paying out exactly as written -- **check
whether the project has already decided it somewhere else under a different
name** -- and its companion, that a working sibling explaining itself is a
cheaper source of a project's decisions than the document is. Nobody found it
because everybody was looking for the name rather than for the shape.

`spool/plan.c` is the two planners, `fzn_spool_plan_want` and
`fzn_spool_plan_offer`, inheriting all three rules rather than re-arguing
them. Policy over the bitmap: no allocation, no I/O, no wire format, so it is
core like the rest of `spool/`.

### What is still open, stated so it does not get deferred a second time

**The cookie is genuinely undecided and is not settled by any of the above.**
Bounding the answer caps the GAIN; it does not stop a reflection at a spoofed
victim. Those are different halves and only the first is done. What the
planners contribute toward the second is the property that makes the cheapest
spoofable packet worthless -- an empty want buys nothing, so a zero-effort
forgery has a gain of zero rather than a blob. A cookie is about WHOM to
answer; this is about WHAT, and the first is a protocol change belonging to
whoever owns the transport.

The batch is also still out: sec 16's stage 2 is "HAVE, WANT, the batch", and
how many leaves ride in one message is `chunk/`'s question and depends on a
transport this library does not choose.

### Eight mutations, seven caught, and the eighth was a guard that cannot fail

Removing the zero-length-want-range check changed no result, because `left`
becomes zero for such a range and the inner loop does not run. It is removed
rather than kept: a guard that cannot fail is how it stops being possible to
see which guards matter. The BEHAVIOUR is still asserted in `plan_test.c`,
since it is a rule a later rewrite must not lose even though this shape gets
it free.

**And one test case was written that could not have failed.** The check that
a peer's range count is capped originally sent many identical ranges and
asserted on the output length -- which fills the caller's array at 16 whether
or not the cap exists, so it would have passed against a planner with no cap
at all. The fixture now names an absent leaf in every range inside the cap
and a held one in the eight past it, so the cap is the only thing that
decides the answer, and a second case checks the planner is capping rather
than merely mute.

## 26. What a consumer cites to freeze a vector, 2026-08-31

Written after a peer session relayed that the holder was low on tokens and
asked every tree to fold session-held knowledge into its records. Two of the
three things it named turned out to be recorded already, and saying so is the
point of this section: **the next session should not spend an hour
rediscovering that.**

### The frame layout's history is not at risk, and here is where it lives

The message's central worry was that the per-pair to per-frame commitment
move lives only in a session, so the next consumer would freeze a golden
vector against the old shape. Measured against this file: the move and its
reasoning are in **sec 13e**, which sets out the three-way trade in a table
-- a long-lived commitment key filters a stranger in 592 ns and LOSES the key
commitment, deriving it from the DH keeps the commitment and costs 158 us,
carrying both tags keeps everything for 48 wire bytes -- and **sec 13a**
carries the per-pair privacy argument that started it. `session/commitment.c`
carries the same reasoning at the code, including why the root label says v2.

### The golden frame goes the other way, which matters for who owes whom

The message has fuzzypickles waiting on a sealed frame from this tree.
**It is the reverse**, and sec 15a records it: this project HOLDS a golden
frame that fuzzypickles produced, in `wire/test/golden_frame_test.c`, and
that section's own correction says why it is kept rather than generated --
"the vector's value was that an independent implementation produced it, which
no generator can supply".

So there is nothing outstanding in that direction from here. If fuzzypickles
now wants a vector against the CURRENT layout, that is a new ask and the
section below is what it needs.

### The gap that was real: the spans, by name, in one place

Nothing here listed **which constants fix the frame's spans**, and that is
exactly what `evidence.md` says a consumer must be given rather than left to
derive -- its worked failure is a sibling's per-frame overhead stated as 98
by arithmetic over a layout when the owner's constants said 106.

The frame is 144 bytes of overhead and the constants that say so are, in wire
order:

| span | constant | today |
|---|---|---|
| hop | `SITU_FZN_HOP_SIZE_FIXED` | 5 |
| head | `SITU_FZN_HEAD_SIZE_FIXED` | 91 |
| sealed capability | `SITU_FZN_FRAME_SEALED_CAPABILITY_COUNT` | 32 |
| tag | `SITU_FZN_FRAME_TAG_COUNT` | 16 |
| **total overhead** | `FZN_SEAL_OVERHEAD` = `SITU_FZN_FRAME_SIZE_MIN` | **144** |

Inside the head, the three a vector's reader will want by name:
`SITU_FZN_HEAD_SENDER_COUNT` 32, `SITU_FZN_HEAD_NONCE_COUNT` 24 (which is
`FZN_AEAD_NONCE_LEN`), `SITU_FZN_HEAD_COMMITMENT_COUNT` 16 (which is
`FZN_COMMITMENT_LEN`). The payload ceiling is
`SITU_FZN_HEAD_LENGTH_VALUE_MAX` 1024, so a frame runs 144 to
`SITU_FZN_FRAME_SIZE_MAX` 1168.

**The decomposition was checked rather than asserted**: 5 + 91 + 32 + 16 is
144, which two independent constants agree on -- the hand-written
`FZN_SEAL_OVERHEAD` and situ's generated `SITU_FZN_FRAME_SIZE_MIN` -- and
144 + 1024 is 1168, which `SITU_FZN_FRAME_SIZE_MAX` agrees with. Two
generated numbers and one hand-written one meeting is the corroboration;
either alone would be this file deriving a number nobody can re-take.

**Cite the names, not the numbers.** The numbers above are true on
2026-08-31 and are printed so a reader can sanity-check an implementation,
not so anybody can copy them. `make schema` is what holds the generated half
to the committed contract.

### What is genuinely unwritten: the CI position, measured 2026-08-31

The holder asked whether `gh` access works for CI. It does, and there is no
CI:

- `gh` 2.46.0, authenticated as `funklord` through the keyring, git over SSH.
- `funklord/fuzznet` is private, default branch `master`, and **Actions is
  enabled** -- `{"enabled":true,"allowed_actions":"all"}`.
- **No `.github/workflows/`, `actions/workflows` total_count 0, no runs
  ever.** Eight private siblings carry a workflow and this tree does not.
- The token's scopes are `admin:public_key, gist, read:org, repo`. **There is
  no `workflow` scope**, so `gh` cannot create or update a workflow file
  through the API. Git here is SSH and GitHub's workflow-scope rule applies
  to token-authenticated pushes, so an SSH push should go through --
  **untested, and recorded as untested.** One push settles it; `gh auth
  refresh -s workflow` is the fix if it is refused.
- The peer reports a billing block affecting six trees and says it does not
  touch this one. That is a claim about other trees and is recorded as
  reported rather than measured.

**And there is a design point already sitting here, which is why this is
worth writing down rather than rediscovering.** Monocypher is a submodule
pinned at `ab2b16d` (4.0.3), and `git archive HEAD` carries no submodule
contents -- the property `harmonization.md` records for beerssh, where the
container structurally checks what the working tree cannot. Here the two
build arms fall out of the checkout mode for free:

- checkout **without** submodules exercises the `MONOCYPHER_DIR=` arm, the
  stub-only build;
- checkout **with** `submodules: recursive` exercises the real-crypto arm,
  including `sim/test/real_crypto_test`.

Both are arms that were run by hand through 2026-08-30 and neither is run by
anything that does not depend on somebody remembering. `make schema` is the
one gate needing a second repository (`SITU_DIR`), so a workflow either skips
it or checks situ out beside this tree.

No workflow was written: it runs on the holder's account and spends their
minutes, which is theirs to authorise.

### Attribution: already done, both surfaces

`harmonization.md`'s directive wants the holder named in `--version`, in an
About window, and in the README. This is a library with no `--version`, so
the surface is the symbol a consumer prints, and both are already in place:
`FZN_COPYRIGHT` in `version/version.h:68` and the line in `README.md:66`.
`version/version.h` also records why it is a SEPARATE symbol rather than
appended to `FZN_VERSION_STRING` -- `make style` extracts that string by
regex and `version_test.c` strcmps it, so appending would break both.

Recorded so that the next pass reading the directive can stop here.

## 31. Adoption gaps and open items, folded down 2026-08-31

Written so a session starting cold does not have to reconstruct this from a
conversation. Sections 22 to 30 hold the work; this holds what is LEFT, and
one pattern about how this week went wrong.

### The one measured gap a consumer is actually blocked on

netcfgd's `doc/shared-protocol-brief.md` says it consumes `wire/` and nothing
else -- envelope, capabilities, signing, verification, chunking, reassembly --
and everything on that list is built. **Read at f7a7fdf on 2026-08-31, and
the holder says that tree is diverging fast, so treat the citations as dated
rather than current.**

**Its first explicit ask is already satisfied, and its brief may not know.**
Section 5 there asks: *"please make expiry mandatory for commands rather than
optional"*, on the reasoning that commands expire and grants do not.
`frame/freshness.c:81` refuses a command carrying `expires_at == 0`, and
`:227` lets a grant legitimately carry none. `freshness.h:195` names netcfgd
as the reason it exists. Nothing to do.

**Its second explicit ask is the real gap, and it is one function.** The same
section asks for chunking *"with retransmission of missing pieces"* and calls
it "the largest single piece of new work and the highest-risk part".

`fzn_partial_t` already carries `seen[FZN_REASM_MAX_CHUNKS / 8u]` -- a 32-byte
arrival bitmap. **`seen_get` and `seen_set` are `static` in
`chunk/reassembly.c`, and the six public functions are `init`, `slot_init`,
`expire`, `accept`, `release` and `err_str`.** So a receiver knows exactly
which chunks it lacks and has no way to tell anybody. Verified twice.

**The template is already in the tree**: `spool/plan.c` does this over the
spool's bitmap, carrying `record/sync`'s three anti-amplification rules -- a
request naming nothing gets nothing, a ceiling because the peer chooses the
number, zero refused rather than meaning unlimited. A `fzn_reasm_plan_want` is
the same shape over a different bitmap, and it should carry the same rules
rather than re-deciding them.

Worth knowing beside it: the largest reassembled message is
`FZN_SPLIT_MAX_PAYLOAD` 1024 x `FZN_REASM_MAX_CHUNKS` 256 = **256 KiB**.
Whether a twelve-interface router's `status` fits under that is netcfgd's
measurement, not one to take on their behalf.

### Two consumer questions answered without code

**QR pairing is already the model rather than a feature to add.** `trust/`
separates `FZN_TRUST_PINNED` -- confirmed out of band -- from
`FZN_TRUST_ADOPTED`, and refuses to let a rotation launder one into the other.
A QR code IS the out-of-band channel, so scanning one is what makes a pin
PINNED. The payload is a `fzn_prekey_record_t`, `FZN_PREKEY_LEN_TOTAL` bytes,
self-signed. The only thing arguably missing is a text alphabet, which is the
consumer's choice.

**Users overlapping hosts is a non-problem here.** This library has no user
type and no host type; there are keys, and a grant is (root, grantee,
capability). Nothing types a key, so one key may be a grantee under several
roots, a root itself, or both. There is no partition assumption for the
overlapping case to violate -- see sec 28 for the estate invariant that sits
above this.

### The pattern this week, stated once because it recurred

**Four times a decision already taken was argued from first principles**, and
three of them cost real effort:

- sec 24: a hazard already held by `commitment_test.c:165`, whose stub counts
  what it was asked for;
- sec 25: a deferral `record/sync.c` had already decided, three ways;
- sec 28: an estate structure already sitting in sec 4.2's table -- and missed
  three days after writing the rule about it;
- and then positioning, where sec 5i WAS read first and immediately answered
  the whole "absorb a positioning service" ask with "there is nothing to
  absorb".

**The one that went right is the one where the search happened before the
reasoning**, which is the whole lesson. The search that works is for the
SHAPE, not the name: `record/sync` did not say "amplification policy for blob
transfer", and sec 4.2's table did not say "estate model". A working sibling
explaining itself is a cheaper source of this project's decisions than this
document is, because it is where the decision is being obeyed rather than
where it was written.

### Open items, in one place

Each names whose decision it is, so none of them reads as settled.

**Blocked on the holder:**

- ~~**Multi-peer assignment**~~ -- **decided, sec 33.** Not blocked by
  `sched/` after all, and not built yet for a stated reason: what it adds
  over `from`-based de-correlation is rarest-first, which pays late in a
  swarm.
- ~~**The position indirection's depth**~~ -- **decided: one hop, sec 33.** Original text: -- "my position follows that host",
  one hop or arbitrary? One hop kills the cycle and compounding-staleness
  problems outright and covers the multi-host-one-site case; arbitrary depth
  is more general and brings all three failure modes. See sec 30.
- ~~**Recipe digest per record**~~ -- **dissolved, sec 33**: it is a consumer encoding choice, not this library's.
- ~~**Shared algorithm vocabulary**~~ -- **deferred with a named trigger, sec 33**. Original text:
  a cross-project naming decision, which `harmonization.md` says is not one to
  take in passing.
- ~~**CI**~~ -- **built, sec 34**, and it corrected sec 26 and found a latent
  bug before its first run. Original text: `gh` works and Actions is enabled with no workflow present; sec 26
  has the two-arm design and the missing `workflow` scope. It spends the
  holder's minutes, so it is theirs to authorise.

**Unblocked, and the next code I would write:**

- ~~**`fzn_reasm_plan_want`**~~ **-- BUILT, see sec 32.** It turned out to be
  one accessor over a bitmap that already existed, and the sender side needed
  nothing at all.
- ~~**Exercise `chunk/reassembly` in `tool/consumer_check.c`**~~ -- done,
  see sec 32, and shown to refuse rather than merely to pass.

**Deliberately not being done:**

- The multi-root anchor set, retired by sec 28's invariant.
- Deriving `record/sync`'s ceiling from estate size, withdrawn in sec 29 --
  it is wrong under cross-estate sync.
- Relay bounded by estate membership, withdrawn in sec 29 -- it would delete
  fuzzypickles' relay.

## 32. The missing accessor, built 2026-08-31

Sec 31 named `fzn_reasm_plan_want` as the one unblocked piece of code and the
thing netcfgd's brief calls "the largest single piece of new work and the
highest-risk part". **Almost all of it was already built.** `fzn_partial_t`
has carried a `seen` bitmap since reassembly existed; `seen_get` and
`seen_set` are static, and `fzn_reasm_accept` points `*out` at a slot only on
COMPLETION. So a receiver has always known exactly which chunks it lacked and
had no way to say so -- loss recovery on this path could only ever be "wait
and hope the sender repeats itself".

**The sender side needed nothing.** `fzn_split_at` already yields the bytes
for any index and refuses one at or past the total, so a peer answering a
retransmission request walks the ranges and rejects a fabricated index without
help. What looked like the largest piece of new work was one accessor.

### What was NOT copied from `spool/plan.c`, and why

The template was next door and the temptation was to mirror it. Two things
were deliberately left out:

- **No `from` argument.** It exists in `spool/plan.h` for playback order and
  to de-correlate a thousand peers fetching one blob. Neither applies to one
  message from one sender: there is no playhead and there is only ever one
  peer to ask. Copying an API's shape where its reason does not transfer is
  how a parameter nobody can explain gets added.
- **No offer side.** For a blob both peers hold a bitmap; for a message the
  sender holds the whole thing and needs no plan.

What WAS inherited is the rule rather than the code: zero refused rather than
meaning unlimited, which `record/sync.h` decided and `spool/plan.c` also
inherits rather than re-deciding.

### `FZN_REASM_ERR_ABSENT`, and the pin that caught it

Absent needed its own code: a caller asking what it still needs must tell
"nothing outstanding" from "I could not look", and a completed message is
released, so absence is ordinary rather than a fault.

**Adding it failed `wire/test/err_str_test.c`**, which pins how many codes
each renderer emits and walks until the fallback answers. That gate was not
written for this and caught it anyway -- a renderer that grows a code and
forgets to render it, or renders one twice, fails there. The table went from 8
to 9.

### Seven mutations, and the seventh needed a case only mutation would find

Caught: the trailing run dropped, the sender not matched, a zero bound
allowed, absent reported as OK, the split bound ignored, and `cap` ignored.

**Dropping the `live` check survived**, and working out why is the finding.
`fzn_reasm_release` zeroes a whole slot and `fzn_reasm_expire` goes through
it, so a dead slot's `msg` is 0 and its sender is all zeroes -- which means
the released-message case could not catch it, because release had already
zeroed the id that case queries. **The only query that can reach a non-live
slot is a zeroed sender with id 0**, and the failure is fail-open: the walk
finds a slot whose `chunks` is 0, emits nothing, and returns OK -- and OK with
no ranges reads as "I have everything". That case is now in the suite and the
mutation is caught.

**`chunk/reassembly` was not exercised by `tool/consumer_check.c` at all**,
despite being one of the two halves a consumer takes from `chunk/`. It is
now, and the case walked is the one a consumer reaches by FORGETTING --
ignoring the return code and reading the range count as the answer. A plan
for a message the table does not hold must be ABSENT rather than
OK-with-nothing, because OK with zero ranges reads as "I have every chunk".

**Confirmed it can fail**: with `plan_want` returning OK for an absent
message, `make installcheck` exits 2. A consumer check that has never been
seen to refuse anything is a compile test wearing a gate's clothes.

## 34. CI, and two things it corrected before it ran, 2026-08-31

Two jobs, because there are two builds. `core` builds with no crypto binding
at all -- the arrangement an embedded target uses and one nobody exercises by
hand, because a developer's tree always has the submodule. `full` builds
against the vendored Monocypher and adds sanitizers and the fuzz harnesses.

`make schema` is in neither, deliberately: it needs `SITU_DIR` pointing at a
situ checkout, and a second repository is a cost this workflow does not pay to
duplicate a gate that runs locally.

The fuzz sweep is reduced from 200000 cases to 20000. What CI proves is that
the harnesses still run; the long sweep belongs where it costs nobody's
minutes.

### Sec 26 said the two arms come free from the checkout mode. They do not.

That section recorded that a checkout WITHOUT submodules would exercise the
`MONOCYPHER_DIR=` arm, since `git archive` and a submodule-less checkout carry
no submodule contents. **Measured before writing the workflow: it fails.** An
un-checked-out submodule leaves `monocypher/` present and EMPTY, and the
Makefile refuses that by name rather than falling back --

    MONOCYPHER_DIR=... has no src/monocypher.c. Leave it unset to use the
    vendored monocypher/, or set it to empty to build without the bindings.

**That refusal is correct and better than what sec 26 assumed.** Silently
building something other than what was asked for is the worse behaviour. So
the arm is not free from the checkout mode: `MONOCYPHER_DIR=` is passed
explicitly, and a job that merely omitted the submodule would fail on its
first target.

### And a latent bug the workflow found by trying to use it

**`make installcheck MONOCYPHER_DIR=` did not work at all.** Fixed the same
day; the diagnosis below stands and what followed from it is at the end of
this subsection.
`tool/consumer_check.c` includes the four binding headers UNCONDITIONALLY,
which is deliberate and argued in that file -- a header that cannot compile
without a dependency it does not name is the fault the target exists to find,
and guarding the includes put them out of reach of the only arm that could
catch it. But those headers are only INSTALLED when the bindings are built, so
the installed-headers arm cannot find them.

Nothing has ever run that combination, which is why it has never been noticed.

**~~Not fixed here, deliberately.~~ Fixed 2026-08-31, and the deferral was
the right call at the time**: the fix is either to install the binding
headers unconditionally -- they include no Monocypher header and compile
standalone, so this is defensible -- or to narrow the target. Both change
installation semantics, and doing that as a side effect of adding a workflow
is the kind of unrelated change that makes a commit hard to review and a
revert hard to scope. So it waited until it was the subject of a change
rather than a passenger on one.

**One correction to the description above, found by running it.** It says
"the installed-headers arm cannot find them", singular. Two arms compile
with `-DFZN_CONSUMER_INSTALLED`, and the failure lands on the FIRST of them
-- "the core alone, with no Monocypher anywhere" -- which is the arm the
target most exists for. The paragraph was written from the code and is off
by one arm; the reproduction says so in one line.

**The first option was taken: `HDRS += $(MONO_HDRS)` moved out of
`ifdef MONO_ON`.** What decides it is not that the headers compile
standalone, though they do. It is that **the gate is a property of the
CHECKOUT rather than of the platform.** `MONO_ON` is off when nobody ran
`git submodule update`; `persist/` and `spool/` are off when the target has
no POSIX, which is why THEIR headers are rightly conditional and are not a
precedent here. An installed header set that varies with whether somebody
fetched a submodule is describing a working copy rather than a library --
and this project installs headers and nothing else, so a consumer compiles
the sources itself and whether OUR tree had the submodule is not a fact
about what THEY can build.

**Narrowing the target was rejected, and it is worth saying why, because it
is the cheaper-looking option.** It changes no installation semantics at
all and it matches an idiom this tree already has -- `MONO_SKIP`,
`PERSIST_FILE_SKIP` and `SPOOL_FILE_SKIP` all skip loudly rather than
silently. But what it would skip is the no-binding consumer arrangement in
the one job that exists to exercise it, so the `core` job would have been
left running two gates and declining the third for want of the thing that
job is defined by NOT having. A skip is honest about a subsystem that was
not built; it is not honest about the whole point of an arm.

**The sources stay conditional, and the asymmetry is the fix.** A source is
compiled or it is not, and `MONO_SRCS` has nothing to compile against
without the submodule. A header is a declaration.

**The style gate is now the regression test for it**, which fell out rather
than being designed. Its header walk used to union `MONO_HDRS` into the
known list *because* `HDRS` gained it only under the conditional -- so the
walk was structurally unable to report the very gap that made
`installcheck` fail: four headers in the tree, absent from what `install`
shipped, and named by the union anyway. Asking `$(HDRS)` alone was checked
by putting the append back inside the conditional and watching
`make style MONOCYPHER_DIR=` fail at exit 2, naming all four and saying
"'make install' would not ship them."

**And `installcheck` runs in the `core` CI job now.** That is the whole
value of the fix: the bug existed because nothing had ever run that
combination, and the job that wanted to is the reason it was found.

Four configurations were run rather than reasoned about --
`installcheck` and `style`, each with and without Monocypher, all green,
plus `make test` unchanged at 63 binaries and 6600 checks.

**Every command in the workflow was run locally before it was committed**, in
both arms, rather than discovered by a red first run.

### Two of sec 26's open items are now measured

**SSH does bypass the missing `workflow` scope.** Sec 26 recorded the token
as carrying no `workflow` scope, said an SSH push of a workflow file *should*
go through, and marked that **untested** rather than claiming it. Tested: the
push succeeded and the workflow registered. No `gh auth refresh` is needed.

**The billing block DOES reach this tree**, and sec 26 recorded the peer's
"it does not touch you" as reported rather than measured. It was true only
because there was no workflow to block. Run 33386232739 created both jobs and
neither started:

    The job was not started because recent account payments have failed or
    your spending limit needs to be increased.

**Nothing is wrong with the workflow** -- both jobs were dispatched, and the
refusal is upstream of anything this repository controls.

**The file is left in place rather than reverted**, and that is a judgement
worth stating because the other reading is defensible. A permanently-red CI
is the "switched off by instalments" hazard: a gate that is always red is one
nobody reads, and it will mask a real failure later. Against that: the
workflow is correct and reviewed, it starts working the moment billing is
resolved with no further action, and the red X is itself the signal that
billing needs attention -- which is a truer state than silence. ~~If billing
is not going to be resolved soon, deleting the file is the better call, and
that is the holder's to make.~~

**RESOLVED by 2026-09-03: billing was sorted and the jobs execute.** The
advice above is retired rather than acted on. A red run since then is a red
run of the steps, and is to be read as one -- measured 2026-09-26 with
`gh run view`, which lists the steps that ran; `gh run list` prints `failure`
for a job that never started as well.

**And it has been red for real since 2026-09-17**: the last green run is
`b7c4c6e`, and every push from `4cfbc2d` to `a051815` failed, about ninety
runs. The earliest failed at the style gate and at `installcheck` for
reasons not recovered here (the logs need admin rights this machine's token
lacks); the latest, diagnosed by reproducing both jobs locally, is sec 373.
Nobody read it, which is this section's own hazard -- "a gate that is always
red is one nobody reads" -- arriving through a gate that was red for a
reason rather than for billing.

## 35. A guard that runs after the damage, 2026-08-31

`build-and-commit.md` asks a `clean`-like target to verify its directory
before deleting: non-empty and relative, never something that could resolve
to a source tree, a home directory or `/`. Two targets here did that and two
did not, which is the ordinary half of this finding. **The useful half is
that one of the two that did could not work.**

### What each target would have run, from `make -n` rather than from reading

    make installcheck BUILD_DIR=   mkdir -p /constant_time/
                                   cc ... -o /constant_time/constant_time.o
    make schema BUILD_DIR=         rm -rf /.situ-head && mkdir -p /.situ-head
                                   (six sites, `/.gen.new` as well)
    make analyze BUILD_DIR=        rm -rf -analyze
    make coverage BUILD_DIR=       BUILD_DIR is empty; refusing

`make -n` is the whole method and it is worth naming: it expands the recipe
without running it, so the dangerous expansion can be read rather than
triggered. Nothing was executed to obtain the lines above.

### The one that could not fire

`installcheck` opens with `test -n "$(BUILD_DIR)" || ... exit 1`, written
against exactly this hazard and correct as a line of shell. Its
prerequisites are `$(HDRS) $(SRCS) $(OBJS)`. **make builds prerequisites
before it runs the recipe**, and `$(OBJS)` under an empty BUILD_DIR is
`/constant_time/constant_time.o` -- so the objects are attempted at the
filesystem root, and the guard's own line is never reached. It is the
`evidence.md` shape almost exactly: a check that cannot be the thing doing
the refusing is a check nobody is measuring. What made it invisible is that
the guard is not wrong, and reading it tells you nothing -- only asking
*when it runs relative to everything else* does.

`coverage` has the same guard and it does fire, because that target has no
prerequisites. **Two identical lines, one load-bearing and one decorative,
and the difference is not in either line.**

### The fix is at parse time, and only for the empty case

`ifeq ($(strip $(BUILD_DIR)),)` with `$(error)` beside the definition. Make
reads the file before it does anything else -- before a recipe, before a
prerequisite, and again in a sub-make that re-enters with
`BUILD_DIR=$(BUILD_DIR)-coverage` -- so one check covers all four targets
and every target added later. Verified across the seven targets that exist:
each refuses at parse time, and `make -n installcheck BUILD_DIR=` prints
zero root-path commands where it printed two.

The recipe checks stay. They are correct and cost nothing, and removing a
guard to tidy up is how the next one goes missing.

**ONLY THE EMPTY CASE WAS HOISTED, and the restraint is the decision.**
`coverage` and `installcheck` also refuse an ABSOLUTE BUILD_DIR, and that
stays local to them -- installcheck's staging tree has to sit inside the
tree it stages. Hoisting it would newly forbid `make BUILD_DIR=/tmp/x` for
an ordinary build, which works today and which nobody asked to remove.
**Refusing a value that can only be a mistake is not the same act as
withdrawing a capability**, and a safety pass that quietly does the second
under cover of the first is how a build system loses options nobody meant
to spend.

### And a third instance: a gate a comment could satisfy

The same lens, run once more because two of three paying out is not a
reason to stop. `installcheck` requires every installed header to be one
`tool/consumer_check.c` actually includes -- the check that stopped two
headers being installable and unverifiable. It asked
`grep -q "$h" tool/consumer_check.c`, which is the header's NAME anywhere
in the file. **A mention in a comment satisfies that exactly as loudly as
an include**, so the gate could report a header checked while nothing
compiled it.

**Measured before changing anything, with a positive control, because a
clean result from a probe that cannot speak is worth nothing.** The probe
classifies each of the 40 entries by whether any line matching it is an
`#include`; the control appends a prose-only mention and requires the
probe to flag it. Control fires; **zero of the 40 are currently satisfied
by prose.** So this closes a class rather than fixing an instance -- and
the class has bitten here before, in the dead-`#ifdef` form recorded
above, which was fixed by hand and caught only because a Makefile edit
aborted and the gate went green anyway.

The gate now wants an `#include` line, with an optional `fuzznet/` so one
pattern covers both forms the file carries. All 40 already matched it,
measured before the edit, so nothing that passes today is newly refused.

**Proved on the discriminating case rather than by watching it pass.**
Demoting both includes of `chain/manifest.h` to a comment that still
names it leaves the old gate's question answered yes -- `grep -q` finds
the name -- and makes the new gate refuse at exit 1, naming that header.
That is the one input on which the two gates disagree, which is what
`evidence.md` asks for and what watching either of them pass would not
have supplied.

**What it still cannot do, stated rather than implied.** It cannot tell a
live include from one in a branch the arrangement does not compile. Only
asking the compiler for its dependency list would, and that is a larger
change than the present gap justifies: `persist_file.h` and
`spool_file.h` are the two conditional includes, and the Makefile turns
their define on in the same place it appends them to `HDRS`, so the two
cannot disagree. If a third conditional header ever arrives whose define
and whose `HDRS` entry are decided in different places, that reasoning
expires and the dependency-list check is what replaces it.

## 36. A sabotage sweep aimed by the last bug, 2026-08-31

The build-system findings above were all one shape -- a check that cannot
report the gap it exists for. `working-practice.md` says to derive the next
lens from the last bug rather than from a list decided in advance, so the
same lens was pointed at the library: **a guard whose removal nothing
notices.** Seven mutations, each rebuilt through `make test`.

### The harness, and the two things it had to get right

**A mutation that does not apply and a check that cannot fail are
indistinguishable from the output.** Sec 4 of this file already records one
of those -- a pattern for `peer.c` that matched nothing while the sweep
reported a clean result. So every mutation is asserted to have changed the
file's hash on disk before the build starts, and every restore is asserted
to bring the hash back.

**Everything goes through `make test`.** `build-and-commit.md` is explicit
that a claim about a test must not come from a binary the build step did not
rebuild, and this is exactly the sweep that would otherwise re-run 63 stale
ones.

### The controls, because here a GREEN suite is the finding

This is the inverted case and it is worth naming, because the usual
instinct is backwards. Everywhere else a passing check is the thing to
distrust; in a sabotage sweep the *survivor* is the result, so a harness
that silently mutated nothing would report seven findings and be wrong about
every one of them.

Two controls, chosen to fail through different machinery:

    CONTROL-wipe        removes an fzn_wipe    -> codegen_gate, "2 + 1 wipe calls"
    CONTROL-delegable   inverts delegable      -> chain_test's assertions

Both were caught, and by the two different gates, so the suite and the
codegen tripwire were each shown to be live before any survivor was
believed.

### Four caught, three survived, and the shape of the split

    hop-sig-zero             CAUGHT     chain_test
    hop-refused-clear        CAUGHT     chain_test.c:1634
    manifest-sig-zero-sign   SURVIVED
    manifest-refused-clear   SURVIVED
    prekey-peer-zero         SURVIVED

**`chain/chain.c`'s guards are defended and `chain/manifest.c`'s identical
ones are not.** Same guard, same comment almost word for word, one module
held to account and its sibling not. That is what makes the gap a test gap
rather than a design question: nobody has to decide whether the guard is
wanted, because the answer is already written down next door.

**And the machinery was already there.** `manifest_test.c`'s stub carries a
`can_sign` flag; `fixture_init` sets it to 1 and **nothing has ever set it
to 0**, so the refusal branch of `fzn_manifest_issue` was unreachable from
that file. The flag was written for a test that was never finished.

**One mechanism was nearly attributed wrongly, which is worth keeping.**
`fail_on_call` in `chain_test.c` is only ever reset to 0, never set, and no
`manifest_fuzz` exists -- so the obvious explanation for the chain half
being defended was `chain_fuzz`, whose line 604 asserts that a refused chain
leaves `*out` untouched. Plausible, and wrong. Re-running the single
sabotage and reading which binary failed named `chain_test.c:1634` instead.
**A comfortable explanation that ends an investigation is more expensive
than no explanation**, and this one cost a single build to disprove.

### What was written

**`manifest_test.c` gains the refusing-signer case**, modelled on the chain
one including the part that matters: **the buffer is dirtied with `0xab`
first.** Against a zeroed buffer the guard is indistinguishable from its own
absence, because the bytes it writes are the bytes already there -- so the
obvious version of this test passes with the clear deleted and proves
nothing. Proven both ways: 263 checks green on correct code, and
`FAIL manifest_test.c:886` with the `memset` removed.

**`prekey_test.c` gains "init is total".** `fzn_prekey_peer_init` zeroes the
struct and then calls `fzn_trust_init` on the trust half, so the zeroing
contributes exactly `prekey` and `created_at` -- both written before they
are read on every path through `fzn_prekey_pin`, which is why removing it
changed nothing. It is kept and tested rather than deleted, because the
"written before read" argument is a property of TODAY's `fzn_trust_t`: a
field added that `fzn_trust_init` does not set would be caught by this
zeroing and by nothing else, and would surface as a peer inheriting a stale
`created_at`, which `fzn_prekey_pin` reads as a rollback and refuses. A
legitimate rotation dropped because the caller's memory was dirty.

The test compares a peer initialised from `0xab` memory against one from
zeroed memory and asserts the whole struct rather than the two fields --
naming them would go stale the moment a third is added, which is the
failure being defended against. Proven both ways: 154 checks green, and
`FAIL prekey_test.c:285` with the `memset` removed.

### The third survivor is NOT a defect, and saying so is the point

**`manifest-sig-zero-sign` is genuinely unobservable, and it is recorded
here so the next sweep does not spend a day rediscovering it.**
`fzn_manifest_issue` zeroes the signature area, opens the bytes it just
wrote to check their ordering, then signs into that area. Every path
overwrites or clears it: signing succeeds and the signature lands on top;
signing is refused and the whole record is cleared a few lines below; the
open fails and the buffer is not a manifest either way, the signed range
excluding the signature field so its contents cannot change what `open`
decides. The suite passing without it is correct rather than a gap.

**No test was written for it, deliberately.** A test manufactured to reach
an unreachable state would assert something the code does not promise, and
a suite that grows those is one nobody can read for intent later.

### What this sweep did not do

Seven guards out of 347 error returns across 39 sources. The seven were
chosen by the lens -- cleanup on a refusal path, and a predicate that might
duplicate a parser -- and not by coverage, so **this is a sample and the
three findings are what one afternoon of one lens produced**, not a census.

**The harness is `tool/sabotage.py` and `make sabotage` runs it**, on the
holder's instruction. What a standing harness buys is not care but the
removal of the moment where care is a choice, which is `evidence.md`'s
argument and the reason this one was not left in a scratch directory.

**It is not part of `make test`, and the reason is not that it is slow.**
It REWRITES TRACKED FILES IN PLACE, which is not something a routine gate
should do in a tree more than one session works in. So it **refuses
outright when the files it edits have uncommitted changes**: it restores
from memory, so a hard kill leaves `git checkout` as the recovery, and
CLAUDE.md is emphatic that a discard is unrecoverable in a way a bad commit
is not. Requiring those files to be clean first is what makes that recovery
safe to recommend. It restores on SIGINT and SIGTERM too, since the suite is
the long part of every iteration and an interrupt almost always arrives with
a file mutated.

**Two exit codes that are not degrees of the same thing.** 1 means a guard
nothing catches. 2 means the run itself cannot be trusted -- a control that
was not caught, a pattern that matched nothing, a restore that did not
reproduce the original, a git that would not answer. The second does not
qualify the output above it; it says that output means nothing.

**`manifest-sig-zero-sign` is carried as an EXPECTED_SURVIVOR** rather than
deleted from the list, so a clean run reads as clean while the question
stays asked. If something ever does catch it the tool says so and asks for
it to be taken off the list, which is the direction that would otherwise go
unnoticed.

**And landing it cost a lesson about this tree's own style gate.** The file
was written with four-space indents and converted with
`unexpand --first-only`, which turns EVERY leading blank into tabs --
including the alignment under an open paren, which `code-style.md` reserves
spaces for. The result rendered identically at tab width 4 and moved at any
other, which is precisely what the tabs-and-spaces split exists to prevent.
**`make style` passed it**, because its own message says what it checks:
whitespace and indentation "except under-indentation". Over-indentation by
tab where a space was meant is not in its remit. The fix converts structural
depth to tabs and the remainder to spaces, proved the way
`harmonization.md` asks -- expanding the tabs at width 4 reproduces the
original columns on every line, and the non-whitespace content is
byte-identical -- rather than by the gate agreeing.

**One structural observation, whose decision it is not mine to take.** There
are eleven fuzz harnesses and none for `manifest/`, which is the module both
test gaps were in. Whether that is worth a twelfth is a question about where
this library's risk actually sits, not one to settle from inside a sweep
that happened to land there.

## 37. A second sweep, and what it taught the harness, 2026-08-31

Sec 36's sweep chose seven guards by shape. This one was aimed by **where
the first one landed**: both gaps were in `chain/manifest.c`, which has no
fuzz or guided harness of its own. Measured by matching each library
source's basename against `FUZZ_BINS` and the guided drivers, **30 of the 39
are in that set**, so it is a population rather than a coincidence. Five more
guards drawn from it, same two shapes -- a clear on a refusal path, and an
init that zeroes a struct before filling part of it.

    trust-init-zero              CAUGHT     trust adoption provenance
    seal-open-clears-out         CAUGHT     seal_test, on a wrong-key open
    ratchet-init-zero            CAUGHT     ratchet_test, once written
    persist-install-clears-out   SURVIVED   -> the guard was the fault
    sync-clear-plan              HUNG       -> the harness's fault, below

**`trust-init-zero` being caught is worth as much as either survivor**,
because sec 36's prekey test rests on it. That test keeps
`fzn_prekey_peer_init`'s zeroing on the argument that a field added to
`fzn_trust_t` and missed by `fzn_trust_init` would be caught by nothing
else. Had `fzn_trust_init` itself been unheld, the argument would have been
resting on air. It is not.

### `fzn_ratchet_init(chain, NULL, seq)` is supported and nothing calls it

**The line above now reads CAUGHT**, and this is what closed it.

`fzn_ratchet_chain_t` is a key and a sequence number. The init zeroes the
struct, copies the key **only if it is non-NULL**, and sets the sequence. So
with a key the struct is written in full and the zeroing cannot be observed;
with NULL it is the only thing putting `key` in a known state.

**Nine call sites, measured, and not one passes NULL** -- two in
`session_test.c`, one in `tool/consumer_check.c`, one in `persist.c`
restoring from bytes, five in `ratchet_test.c`. The branch is never
executed, which is why removing the zeroing changed no result. What it costs
is not a wrong error code: a chain initialised with no key would carry
**whatever the caller's memory held**, and every key the ratchet derives
comes off that.

`ratchet.h` documents the struct and the meaning of `seq` and **says nothing
about a NULL key** -- the `if (key)` in the .c is the only statement that
the case exists. So the test asserts DETERMINISM rather than a value: init
from dirty memory must equal init from clean memory. That pins what the
zeroing provides without inventing a promise about what a keyless chain
contains, which is not a test's to make, and it does not have to be
rewritten if the holder later decides a NULL key should be refused outright.

It carries the with-a-key case too, which **passes with the zeroing
deleted**. That half is there to show the asymmetry, not to guard it; a test
that only did that would prove nothing. Proven both ways: 179 checks green,
and `FAIL ratchet_test.c:160` with the `memset` removed.


### One that is not a test gap: two modules promising opposites

**`fzn_persist_secret_open` zeroes the caller's secret before an operation
that can refuse, and `session/agree.c` says in terms that this must not
happen.**

    memset(out, 0, sizeof(*out));
    if (fzn_agree_secret_install(out, agree, bytes + OFF_BODY) != FZN_AGREE_OK)
            return FZN_PERSIST_ERR_BACKEND;

`fzn_agree_secret_install`'s comment, above the check that makes it true:
*"DERIVED BEFORE ANYTHING IS DESTROYED. A binding that refuses must leave
the caller holding the secret it had, not a wiped struct and no replacement
-- which would be a host that cannot decrypt its own queued traffic because
a key derivation failed."* It orders its work so a refusal touches nothing.
The `memset` above it undoes that from outside: install is careful not to
destroy the caller's secret on the way to refusing, and persist has already
destroyed it before install is called. The named consequence is reachable by
the route agree.c names, since `public_of` returning false is a real binding
failure over material read from disk rather than a programming error.

**It was put to the holder as three defensible readings and came back as an
instruction to fix it.** Two of the three turned out to be the same answer,
and one fact decided which:

**`fzn_persist_secret_open` disagreed with itself.** Its other two refusals
-- a null argument, and a header it does not recognise -- leave `out`
untouched. Only the binding's refusal cleared it. **Two of three preserving
is an accident rather than a policy**, and the odd one out was the one
contradicting a promise another module states in terms. That is what settles
it without anybody having to weigh how often a caller passes a live secret.

**The clearing is gone, and nothing is lost on the success path.** Install
writes every field of `fzn_agree_secret_t` -- secret, public_key, generation
and live -- so the `memset` was never what made a restored secret whole. The
only thing it influenced was install's `next`, computed from `sk->live`, and
the line below it overwrites the generation with the stored one regardless.
Measured, not reasoned: `persist_test` is green with the clearing removed.

**And the contract is now written down, which was the other reading.** It
was absent from `persist.h` entirely, and that absence is what let the three
refusal paths drift apart in the first place -- so stating it is not an
alternative to removing the clearing but the thing that keeps the three
together. What it buys a caller is the retry: a host restoring from a backup
while running, or making a second attempt after a refusal, may pass a live
secret and still hold it afterwards. Without it the safe way to call this
was to restore into a scratch struct and copy on success, a discipline no
signature asked for and no sibling `_open` needs.

**The test drives the refusal with a null `agree`**, which is the one
refusal that happens INSIDE install rather than before it -- persist checks
`bytes` and `out` and deliberately does not check `agree`. Proven both ways:
60 checks green, and `FAIL persist_test.c:214` with the clearing put back.

**The sabotage entry is inverted rather than deleted.** It used to remove
the `memset` and report SURVIVED; it now PUTS IT BACK and must be caught. A
guard that turned out to be the fault leaves a hole in the sweep exactly
where the question was, and an inverted entry is what keeps asking it.

**What makes it worth the section is how it was found.** The sabotage was
filed expecting a missing test, on the model of the two sec 36 closed. The
survivor meant the opposite of what a survivor usually means here: not "this
guard is unheld" but "this guard may be the fault". A sweep that only ever
produces tests is one whose findings are being read through a single lens.

It is left **unsuppressed** in `tool/sabotage.py`, unlike
`manifest-sig-zero-sign`, so `make sabotage` reports it every run. An open
question is not a settled one.

### The third answer, and two faults it found in the harness

**`sync-clear-plan` did not fail the suite. It hung it.** Removing
`clear_plan`'s `memset` in `record/sync.c` takes `sim/test/network_test`
past any sensible bound -- 40 binaries complete, the 41st does not return.

**THE FAST TEST FOR IT ALREADY EXISTED, which is why none was written.**
`record/test/sync_test.c` carries "THE PLAN IS CLEARED BEFORE THE ARGUMENTS
ARE CHECKED": it fills a plan with `0x33`, forces a refusal, and asserts
every byte came back zero, citing the measured
`request_count = 3689348814741910323` as "a length a caller iterates". Run
alone against the sabotage it fails in under a second, on that assertion by
name and twelve others. Writing a second test would have duplicated a better
one -- and the first draft of this section said the guard "wants a test that
fails fast", which was the wrong diagnosis stated confidently.

**The defect was the harness, twice over.** `sim/test/network_test.c` walks
`plan.request_count` at three sites, which is what a real consumer does --
and with a corrupt plan that is an unbounded loop over memory nothing wrote.
Worse, it runs BEFORE the unit tests of the modules it composes, so the
twenty-two binaries after it never ran, `sync_test` among them. **The cost
of trusting that number was not this scenario; it was every diagnostic
behind it.**

`sync.h` promises `request_count <= out_cap` and `add_range` keeps it, so
the harness can check it for one comparison. It does now, and the sabotage
went from a 600-second timeout to **1.8 seconds and 639 named failures**.
`running-code.md` is the general form: the bound that matters lives inside
the program, because a wrapper only guards the way somebody did not run it.

**~~The ordering is worth stating and is not fixed here.~~ Taken on the
holder's instruction.** An integration harness that runs before the unit
tests of what it integrates will always report the vaguer failure first, and
here it prevented the precise one entirely. The bound above makes that
harmless for THIS defect and not for the next one, which is the argument for
moving the order as well as bounding the loop.

`TEST_BINS` now appends the composed suites -- `sim/test/network_test` and
`sim/test/real_crypto_test` -- **after every conditional block rather than
inside the list**, because the subsystem and Monocypher appends come after
it and anything placed in the list would still have unit tests behind it.
`$(MONO_REAL)` moved out of the Monocypher append for the same reason and
expands to nothing when the bindings are off.

The invariant is stated so it can be checked rather than read: **every
per-module suite runs before every composed one.** Measured in both
configurations -- with the bindings, 61 per-module then 2 composed; without,
`network_test` last of 57.

**What it buys, on the defect that motivated it.** The same sabotage that
once hung the suite for 600 seconds with no output now stops it at
`record/test/sync_test` in 1.7 seconds, 43 binaries in, naming the
assertions written for exactly that fault. `runtests` stops at the first
failure, so the order decides which diagnostic a reader gets; sim/ says a
session did not converge, and the per-module suites say which function broke
and on what input.

That is a real answer about the guard and it broke the harness twice.

**A timeout was a crash rather than a result.** `TimeoutExpired` propagated
out of the loop, so the run ended in a traceback, `prekey-peer-zero` never
ran, and the report was lost. A hang is now recorded as HUNG and the sweep
carries on. It is deliberately **not** folded into CAUGHT: a hang does stop
a green suite, but as a detection it names nothing, costs the whole timeout,
and in CI reads as infrastructure rather than as a fault. A guard whose
absence hangs the suite wants a test that fails fast, and calling it CAUGHT
would retire that.

**And the timeout leaked a runaway, which is the worse of the two.**
`subprocess`'s timeout signals the process it started -- `make` -- and not
its children, so the recipe's `for t in ...; do $t; done` shell and the
looping binary were reparented to init and went on running. Found by
`ps --ppid 1` afterwards rather than by anything in the run: **one shell
loop alive for 34 minutes.** `running-code.md` is about exactly this, and
names the shape -- a bound that stops the supervisor while the work
continues is worse than no bound, because it turns a runaway into an
invisible one. The harness starts `make` in its own session now and kills
the process group; verified by re-running the hang and finding nothing under
init afterwards.

**The default per-entry timeout came down from 1800s to 600s** in the same
pass. A healthy `make test` here is about a minute, so half an hour was
headroom for nothing and bought a single hang thirty minutes.

**A full run therefore costs its timeout on top of the builds**, for as long
as this entry stands. That is the finding rather than a fault in the target,
and `ARGS=--only ...` narrows it meanwhile.

**That stopped being true the same day**, and this paragraph did not notice
for two. `a1af82d` bounded the plan count `network_test` walks, so the
sabotage now fails on an assertion instead of looping; measured on
2026-09-03 at under ten seconds. Sec 52 has the measurement and what the
stale note cost.

**One correction to sec 36's own text, measured here:** it said the tool
exits 1 for a finding and 2 for a run that cannot be trusted, which is true
of the tool and not of `make sabotage`. Make reports any failed recipe as
its own exit 2, so through the target the distinction survives in the
printed text and not in `$?`. Run the tool directly where a script needs to
tell them apart.

## 38. What a refused call owes the caller, audited, 2026-08-31

Sec 37's persist finding was a module's behaviour toward its OUTPUT on a
refusal contradicting a promise made elsewhere. That is a lens rather than
an instance, so it was pointed at every function that can refuse.

**Thirty-two public functions take an output and can refuse.** Thirteen
write that output at all; **three can still refuse after writing it**, which
is the persist shape exactly:

    fzn_blob_leaf_open     blob/blob.c           memcpy(out, ...)
    fzn_reasm_accept       chunk/reassembly.c    *out = NULL
    fzn_seal_open          wire/seal.c           memset(out, ...)

**All three are correct**, and that is the finding rather than a
disappointment. `fzn_reasm_accept` and `fzn_seal_open` clear the output
BEFORE any refusal can happen, so a refused call leaves a known state.
`fzn_blob_leaf_open` cannot -- it decrypts in place, so the caller's buffer
holds ciphertext by the time the AEAD can refuse -- and it wipes on that
path, with a comment saying why: *"a caller that ignores the return value
must not find plausible-looking bytes there."*

**So the tree has one convention and follows it: a refused call leaves no
plausible bytes in the caller's output.** That is worth more than a fourth
defect would have been, because it changes what sec 37's persist fix was.
It was not a choice between three defensible readings; it was **restoring
the invariant the other twelve functions already keep.** The reading that
would have kept the clearing and documented it in `persist.h` would have
made persist the one module that answers this question differently.

### The instrument was wrong first, and in a way worth recording

The first pass reported `fzn_persist_secret_open` as still writing its
output before a refusal -- the function that had just been fixed. It was
matching `memset(out, 0, ...)` **inside the comment explaining why that
`memset` had been removed.** A probe that reads code must read code:
comments and string literals are now stripped before matching, which took
the candidate list from four to three and removed the one that was a
quotation of history rather than a fact about the present.

That is the fourth probe this session to need correcting after it fired, and
every one was caught by reading what the hits WERE rather than by counting
them. `evidence.md` names the pattern: a control proves a probe can fire,
not that it is aimed at the right population.

### And then: are the correct ones HELD?

An audit says the code is right today. It says nothing about whether
anything would notice if it stopped being. Both were put through
`make sabotage`:

    blob-leaf-auth-wipe        CAUGHT     blob_test.c:678
    reasm-accept-clears-out    SURVIVED

**`fzn_reasm_accept`'s `*out = NULL` is documented, load-bearing and was
held by nothing.** `reassembly.h` states the contract and, in the same
sentence, the reason a caller depends on it: *"When the message completes,
*out is pointed at the slot and the caller owns its bytes until it calls
fzn_reasm_release. Until then *out is left NULL, so 'did this finish
something' needs no second call."*

That last clause is what makes the gap expensive rather than untidy. The
header invites a caller to keep one `fzn_partial_t *` and test it after
every accept, which is the natural way to write the loop. Without the clear,
a refused accept leaves that pointer naming the slot from the LAST
completion -- released by then, possibly re-sized for another sender, and
read as "this finished something". **A use-after-release reachable by
following the header's own advice.**

**The refusal has to happen after the clear**, which decided the test's
shape: a malformed-argument refusal returns before `*out` is touched, and
correctly so, since a null `out` is among the things it is refusing. The
expiry branch sits below the clear and needs only a chunk whose deadline has
passed. Proven both ways -- 215 checks green, and
`FAIL reassembly_test.c:321` with the clear removed.

## 39. Four guards that are one decision, 2026-08-31

Batch four took the sweep into the modules it had never touched -- `state/`,
`log/`, `link/`, `sched/`, `spool/` and `record/journal.c`. Five entries, one
caught and four survived, and **the four survivors are one finding rather
than four.**

    spool-want-ceiling            CAUGHT     plan_test.c:382
    state-init-zeroes-entries     SURVIVED
    log-init-zeroes-entries       SURVIVED
    link-init-zeroes-entries      SURVIVED
    journal-init-zeroes-entries   SURVIVED

`fzn_state_init`, `fzn_log_init`, `fzn_link_table_init` and
`fzn_journal_init` are the same eight lines with four names: refuse a null
or zero-capacity argument, `memset` the caller's entry array, then set
`entries`, `capacity` and `used = 0`.

**Measured rather than reasoned: every loop in the four modules is bounded
by `used`, and none by `capacity`.** Ten loops across the four files. So no
path reads an entry past `used`, and the zeroing cannot be observed through
the API as the code stands. That is why removing it changes no result.

### ~~Why they are listed rather than tested~~ Why they are tested after all

**They were listed first, and the argument for listing them was wrong.** It
is kept here because the error is a useful one: it looked like a judgement
about cost and was a confusion between two different things.

The tree's precedent points at a test. Sec 11 records reassembly's
`admit_first`, where `release` already did the clearing; secs 36 and 37 did
the same for `fzn_prekey_peer_init` and `fzn_ratchet_init`, both on the
argument that "written before read" is a property of TODAY's code. That
argument holds here exactly.

What was offered against it was that **four near-identical determinism tests
would carry one rationale four times**, and that a suite growing four copies
of one paragraph is one nobody reads for intent.

**That conflated the test with the paragraph.** The assertion is three lines;
the rationale is the length. This tree already cross-references -- comments
here cite `sync.h`, `frame.situ` and numbered sections of this file
constantly -- so four short cases each pointing at THIS section costs four
pointers, not four paragraphs. The reasoning lives once, where it already
was.

**And the cost of listing them was higher than it looked.** An entry in
`EXPECTED_SURVIVORS` makes `make sabotage` say nothing about a guard, which
is the same shape as an ignore list on a gate: the question is still asked
in principle and nobody hears the answer. Four of the nineteen entries
quiet, for tedium rather than for a reason like
`manifest-sig-zero-sign`'s, is how a sweep stops covering what it claims to.
`evidence.md` calls it switched off by instalments, and it does not stop
being that because the person doing it wrote down why.

So the four are tested and delisted, and each case asserts DETERMINISM
rather than a value -- init from dirty memory must equal init from clean.
None of the four headers promises anything about what a fresh entry
contains, and a test is not the place to invent it. Each carries a control
asserting the two arrays differ BEFORE init, since otherwise the comparison
after it cannot fail.

    state-init-zeroes-entries     CAUGHT
    log-init-zeroes-entries       CAUGHT
    link-init-zeroes-entries      CAUGHT
    journal-init-zeroes-entries   CAUGHT

**The risk they guard is still not a runtime fault**, and that is why the
comment in each names it: nothing can observe these memsets today, so the
exposure is that the next person to measure what is measured above concludes
they are dead and removes them. The tests are what make that a red suite
rather than a plausible cleanup.

### The one that was caught is worth a line

`spool/plan.c`'s `want_count > FZN_SPOOL_MAX_WANT` ceiling is held by
`plan_test.c:382`, which drives 264 ranges at a 256-range bound and asserts
what comes back. That is the anti-amplification rule `record/sync` paid for,
tested where it is spelled -- so the sweep's first pass through `spool/`
found its bound already defended.

## 40. The ceilings, audited, 2026-09-01

This file records amplification as a measured defect class more than once --
sec 25's zero-length digest answered with 32,768 records is the sharpest --
so the ceilings are worth asking about as a set rather than one at a time.
**Twenty are declared across the public headers. Sixteen are compared in a
non-test source.**

The four that are not are derived sizes rather than gates, and three of them
are held anyway: `FZN_RECORD_MAX_LEN` by `_Static_assert` in both `record.c`
and `record_test.c`; `FZN_CHAIN_MAX_LEN` by `chain_test.c` sizing buffers at
it and at `+ 1`; `FZN_SPOOL_FILE_PATH_MAX` by `snprintf` against
`sizeof(buffer)`, which is the better idiom because `sizeof` cannot drift
from the array it measures.

### The instrument was wrong first, again, and the same way

The first pass reported **six** unenforced ceilings. Five were artifacts: the
pattern required the constant immediately after the comparison operator, and
the code casts -- `if (leaves > (uint64_t)FZN_SPOOL_MAX_LEAVES)`,
`if (jump > (uint64_t)FZN_RATCHET_MAX_ADVANCE)`. Every one was found by
reading the SIX rather than trusting the count, which is the fifth probe
this session to need correcting after it fired and the fifth caught the same
way.

Worth stating as a pattern rather than five incidents: **the probes that
failed all failed by being too literal about syntax** -- a regex over source
text matching a comment, a cast, a tab, an alignment. The ones that held
asked a tool that parses the language instead: `tokenize` for Python
statements, `make -n` for what a target would run, `make --eval` for what a
variable expands to. Where a probe must read C, it is reading a language
nothing here parses, and the correction is to widen it and then read every
hit -- not to trust it.

### `FZN_MANIFEST_MAX_LEN` was the subject of nothing

The fourth is the finding. It is defined as
`FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS)`, it is public, and a consumer
would size a buffer with it -- and **it appears in no source and no test in
the tree.**

`manifest_test.c` does check the quantity, and checks it well, both at the
bound and past it:

    _Static_assert(FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS) <= FZN_REASSEMBLED_MAX, ...)
    _Static_assert(FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS + 1u) > FZN_REASSEMBLED_MAX, ...)

**But it spells the quantity out rather than naming the constant, so it
recomputes what the constant is defined as and the constant itself is a
bystander.** A wrong redefinition of `FZN_MANIFEST_MAX_LEN` leaves both
assertions passing, because neither mentions it.

Proven in both directions rather than argued. Redefining it to
`FZN_MANIFEST_LEN(FZN_MANIFEST_MAX_PAIRS + 1u)` -- one pair too many, the
plausible slip -- and building:

    old spelling, wrong definition    builds clean
    new spelling, wrong definition    static assertion failed
    new spelling, right definition    builds

The first assertion names the constant now. That is not the tautology that
asserting it equals its own definition would be: it is checked against a
bound owned by another module, what reassembly will carry, so a wrong
definition fails and a consumer's buffer size is the thing being defended.
`record/` never had this gap -- it asserts `FZN_RECORD_MAX_LEN` itself, in
two places.

### And manifest is the odd one out for the third time today

Sec 36 found `chain/manifest.c` missing the refusing-signer case its sibling
`chain/chain.c` had; sec 36 also noted there are eleven fuzz harnesses and
none for `manifest/`; and this is a third instance of the same shape --
three sibling maximum-length constants, two held and the manifest one held
by nothing.

**Three independent findings in one module is a fact about the module rather
than three coincidences.** Whether it wants a fuzz harness is sec 36's open
question and still the holder's; what this adds is that the case for one is
no longer a single data point.

## 41. manifest_fuzz, and the four mutations that justify it, 2026-09-01

Sec 40 closed with three independent findings in `chain/manifest.c` in one
day and the observation that eleven fuzz harnesses covered every module but
that one. This is the twelfth, built on the holder's instruction.

**Model-based, following `revocation_fuzz`.** An independent shadow of what
`fzn_manifest_admit` should do, compared against the module after every call
in both directions. The rules it has to get right are admit's tail, where
they interact: a pair the store covers is skipped, so is one the deficit
table holds, one that will not fit sets the issuer's overflow flag and the
walk CONTINUES, and the flag clears only when nothing was dropped AND the
manifest is at least as large as the largest that issuer has shown.

    20000 cases, 76127 admitted, 53092 unknown issuer, 13456 bad signature,
    4784 covered, 6948 duplicate, 17325 full, 325 cleared,
    3589 rollbacks refused, 6284 satisfied, model agreed throughout

Runs in 0.45s, so `make fuzz CASES=20000` pays almost nothing for it.

### Whether it earns its place, asked properly

**A harness that catches only what the unit tests already catch is
decoration**, so the question was put as a measurement rather than left to
the fact that fuzzing is generally good. Nine mutations of `manifest.c`,
each built and run against `manifest_test` and `manifest_fuzz` separately.

**The first five said the harness was decoration**, and that is worth
recording because it was nearly the answer:

    drop the already-in-table skip      test caught    fuzz caught
    drop the already-covered skip       test caught    fuzz caught
    never set the overflow flag         test caught    fuzz caught
    never record a drop                 test caught    fuzz caught
    never raise the high-water mark     test caught    fuzz caught

`manifest_test` covers admit's individual rules well. Had the measurement
stopped there the honest report would have been that the harness adds
nothing, and the entry below would not exist.

**The next four are the justification, and they are all one class:**

    overflow flag lands on issuer 0     test PASSES    fuzz caught
    high-water mark lands on issuer 0   test PASSES    fuzz caught
    clearing lands on issuer 0          test PASSES    fuzz caught
    deficit lookup ignores the issuer   test PASSES    fuzz caught

**Per-issuer state written to, or read from, the wrong issuer.** Every one
compiles, every one is a plausible slip, and `manifest_test` reports all
four green.

**The reason is the one `revocation_fuzz` already wrote down and this tree
had not carried across.** That harness records naming two roots as "not
breadth for its own sake": with a single key every entry carries it and the
issuer term in the comparison is decided by nothing, *proven by deleting the
comparison and getting byte-identical output*. `manifest_test` exercises the
overflow and high-water rules an issuer at a time, so the issuer term in
`entry->overflowed` and `entry->pairs_seen` was decided by nothing in
exactly the same way. This harness follows two issuers and does not follow a
third, so the same (capability, grantee) under two keys is an ordinary
state and the term is load-bearing on every case.

**The lesson generalises past both modules: a rule that is per-something is
only tested by a fixture that holds two of that something.** A suite can
cover every branch of such a rule and still decide nothing about which
instance it wrote to.

### What the coverage floors cost, and what they bought

`cov.rollback` is sec 13d's replayed older manifest -- smaller than the
largest that issuer has shown, so it drops nothing and must still not clear
the flag. `cov.cleared` is its honest twin: without both, a rule that never
cleared and a rule that always did would look identical from here.

**The floors failed the harness three times before it passed**, which is
them working. `cleared` came in at 4 per 20000 because nothing in the
harness ever freed a deficit slot -- so `fzn_manifest_satisfy` was added to
the round, which is also the only coverage this module's satisfy path has.
Then at 16, then at 325 once each case ran eight rounds against one evolving
state rather than four. A harness given a fresh state every few admissions
cannot reach a transition that needs a history.

**Tuning the fixture rather than the floor is the whole of it.** The floor
that keeps failing is a fact about what the harness reaches, and lowering it
to fit is how a counter stops meaning anything -- `evidence.md`'s switched
off by instalments, arriving through the one door that looks like
arithmetic.

### The lens run across the other five tables, and manifest was the outlier

"A rule that is per-something is only tested by a fixture holding two of
that something" is a lens rather than a fact about manifest, so it was
pointed at every keyed table: `state/`, `log/`, `record/journal.c`,
`chunk/reassembly.c` and `link/`. Each lookup's KEY TERM was made always
true, so the first entry answers for every key.

**All five are caught**, and by assertions that name the case exactly -- "and
the second subject is bob's", "the second twin's own first record was
refused as a duplicate", "reading since 0 for the second twin is not its own
two records". Those suites already hold two of the thing they are keyed by.

So the lens found nothing new, which is the useful half: **manifest was the
outlier rather than one of six.** The entries are kept in `tool/sabotage.py`
regardless -- they are the net that keeps those terms held when a lookup is
next refactored, and they record that the question was asked of every table
rather than of the one that failed.

### And the sabotage list keeps the reason alive

`manifest-overflow-wrong-issuer` is in `tool/sabotage.py` now: the flag
landing on issuer 0, which `manifest_test` passes and the harness catches.
It is there so that the harness's REASON is held rather than just the
harness -- if manifest_fuzz ever stops modelling two followed issuers, that
entry goes quiet and `make sabotage` says so.

## 42. The wipes a caller can see, 2026-09-01

This library makes 32 `fzn_wipe` calls. **Sweeping them all would have been
the wrong instrument**, and saying why is most of this section: a wipe of a
LOCAL is unobservable through the API by construction, so its sabotage
survives whatever the code does, and thirty survivors that mean nothing bury
the ones that do. `session/agree.c` already records its own as
"unreachable-by-test today ... kept, and recorded as conditional rather than
load-bearing".

The subset worth asking about is the wipes that clear a buffer **the caller
owns**, on a path that returns an error. There a missing wipe is a real leak
into somebody else's memory, and a test can say so. Four of the 32:

    agree-degenerate-wipes-shared    CAUGHT     agree_test.c:241
    session-hash-fail-wipes-out      SURVIVED   -> tested, below
    session-half-pair-wipes-send     SURVIVED   -> tested, below
    seal-refused-build-wipes-frame   SURVIVED   -> prospective, below

**`session/agree.c` was defended and `session/session.c` was not**, which is
the third time today a guard turned out to be held in one module and not in
the one beside it -- after `chain/` against `chain/manifest.c`, and
`record/` against `chain/manifest.c` again.

### What the two session wipes cost

`chain_for` wipes the caller's `out` when the hash refuses, and
`fzn_session_chains` wipes the send chain when the second derivation fails
after the first succeeded. Neither was held: removing either left all 64
binaries green.

They are not defence in depth. A caller who ignores the return value is left
holding a **partial chain key**, or a send chain with no receive chain --
and session.c's own comment names that second one: it "would ratchet forward
into a conversation it cannot hear".

**The stub has to write before it refuses, or neither case can fail.**
`agree_test.c` makes the same argument for its degenerate binding: a real
binding computes into the caller's buffer and only then finds it cannot
certify the result. A stub that refuses without writing leaves the caller's
bytes untouched, the wipe has nothing to remove, and the test passes with it
deleted. The fixture also dirties the buffers with `0x33` first, for the
same reason, and carries a control asserting an honest derivation produces a
NON-zero key -- otherwise "it is all zero" is satisfied by a call that never
derived anything.

Proven both ways: `FAIL session_test.c:593` and `:609` with the respective
wipe removed, 266 checks green with them in.

### The third is prospective, and the code said so first

`wire/seal.c`'s wipe of the whole frame on a refused build survives, and
**that is not a gap.** Its own comment carries the measurement: it was
re-taken on 2026-08-28 and every shape refusal now returns BEFORE the
capability is copied in, so the wipe's own reproduction cases no longer
reach it. The likely cause is named too -- a redundant validate was removed
from that file and removing it moved when a refusal surfaces.

It is kept because the hazard returns the moment any refusal surfaces after
the copy, and the comment gives its reason as wanting "the next reader who
mutates it and sees nothing fail" to delete it knowingly rather than
believing a stale paragraph. **That reader is this sweep**, so the entry is
an `EXPECTED_SURVIVOR` pointing at the comment rather than a finding.

That is the second legitimate suppression, beside `manifest-sig-zero-sign`.
Both have a measured reason in the code; neither is the tedium that sec 39
wrongly suppressed four entries for.

## 43. How much sweeping is left, measured rather than felt, 2026-09-01

Six shapes were swept deliberately (secs 36 to 42) and the last two found
nothing: the key-term lens across five keyed tables, and the documented
check-orderings, which are held by thirteen call-count assertions tree-wide.
**Two consecutive null lenses is the point at which guessing a seventh
becomes manufacturing work**, so the question changed from "what else can I
think of" to "how much is left", which is answerable.

### The method, recorded so it can be re-taken

Every one-line `if (cond)` whose next line is a bare
`return FZN_..._ERR...;`, comments stripped, keeping only those whose exact
text occurs once so a mutation is unambiguous: **254 in the library**. Each
turned into `if (0)` so the guard never fires -- a mutation that always
compiles, unlike editing a condition. Systematic sample of every tenth, 25
guards, each rebuilt through `make test` with the harness's disciplines
(clean tree required, mutation asserted to land, process group killed on a
timeout, restore verified).

    caught 19    survived 6    hung 0    did not build 0

### The six survivors are redundant, and the check that decided it was wrong

Three of the six are minimum-length or bounds guards on parsers, which
looked like a memory-safety class: disable `len < FZN_MANIFEST_MIN_LEN` and
the count is read at offset 34 of a buffer that may be shorter. So they were
re-run under `make SANITIZE=1 BUILD_DIR=san test`, expecting ASan to catch
what the plain suite could not.

**ASan caught none of them, and the reason is the finding.** A test passes a
SHORT LENGTH with a FULL-SIZE BUFFER -- `manifest_test` opens at
`FZN_MANIFEST_MIN_LEN - 1`, which is 67 bytes claimed against an allocation
of the full manifest. Reading offset 34 is inside the allocation, so there
is no out-of-bounds access for a sanitizer to see. **The mutation tests a
logic redundancy and ASan answers a memory question; pointing it at this was
asking the wrong instrument.**

What actually happens is that a later check refuses the same input.
`manifest.c:157`'s `len != FZN_MANIFEST_LEN(count)` rejects every length
that is not exactly right, short ones included, so `MIN_LEN` is defence in
depth. `record_test` proves the same for `record/` from the other side: it
sweeps `SHORT_LENS = {1, 2, 3, 4, 91, MIN_LEN - 1}`, so short buffers ARE
fed, and the suite still passing with the guard disabled means something
else refused them.

### What the number actually says

    the guard's EFFECT is held                     25 of 25
    this specific LINE is what refuses             19 of 25

**That distinction is the whole result.** A survivor here is not a gap; it
is a guard whose sibling covers the same input. Six in twenty-five is a
measure of how much defence in depth this library carries, which is a
property somebody chose, not a deficiency.

**So further blanket sweeping has low expected yield**, and the reason is
not that the tree is perfect. It is that the survivors a blanket sweep
produces are mostly redundant guards, and telling those from real gaps costs
a manual investigation each -- the six above took one sanitized run and two
readings to classify. The sweeps that paid were aimed by a SHAPE derived
from the last bug, and every one of the eight findings in secs 36 to 42 came
from those rather than from breadth.

**What would change this** is a new shape, and the honest way to get one is
the way the others arrived: from the next real defect, not from a list
written in advance.

## 44. A capability is a type now, 2026-09-01

Sec 14 recorded `FZN_CAP_ID_LEN == FZN_PUBKEY_LEN == 32` as a confusion no
fixture could catch: "closing that needs the constants to differ or a
compile-time distinction between the two types, and no test can do it."

**It was right that no test can, and it was measured rather than assumed**
before anything changed. `fzn_chain_mint(root, capability, grantee, ...)`
with two arguments exchanged compiled clean under `-Wall -Wextra -Wpedantic
-Wconversion` and produced an object.

### Wrapping one side, and why that is enough

`fzn_cap_id_t` wraps the thirty-two bytes. **A struct and a
`const uint8_t *` are incompatible in BOTH directions**, so typing the
capability makes a key passed for one, and one passed for a key, equally a
hard error -- and the keys stay byte arrays. That is 188 mentions across 22
files rather than 779 across 52, for the same guarantee.

Proven both ways, with the object removed first so no stale artifact could
answer: the swap fails to compile and writes nothing; the correct call
compiles and produces an object.

### By pointer, and the cheaper option deletes a contract

By value would have removed roughly **132 of the 189** test errors, because
`mint(root, grantee, cap, ...)` stays textually correct when `cap` is a
value. It was tried and reverted.

`if (!capability)` becomes meaningless for a value, and **a null capability
is documented behaviour**: `authz.h` says "a null capability is a caller
that has not decided", the library refuses one with MALFORMED, and
`test_every_guard_refuses_its_own_argument` asserts it. The cheaper option
removes an API contract, which is not a cost a mechanical convenience gets
to pay.

### The casts live in three accessors and nowhere else

`fzn_hop_capability`, `fzn_manifest_capability` and
`fzn_revocation_capability` each cast a pointer into a wire buffer to the
type those bytes are. **That containment is the design, not an
implementation detail.** This library's style is views into wire buffers, so
the type has to reach a caller without copying -- and a cast at each call
site instead would have reintroduced the confusion at every boundary, which
is precisely where a capability arrives from a stranger.

`wire/seal.h` keeps raw bytes deliberately: `wire/` sits below `chain/` and
never includes it, so typing that field would invert the layering. It is
also the right place to stop, since a capability becomes bytes on the wire
on purpose and a caller assigning one now writes `.b` rather than having it
converted silently.

### What it does not close, which is the likelier confusion

**`fzn_chain_mint` takes `root` and `grantee` adjacently and both are public
keys.** Exchanging those is still invisible, and no width-based type can
separate them: a grantee becomes a grantor in the next hop, so they are the
same kind of thing and a distinct type would be a lie. A caller can also
still defeat the check with an explicit cast.

So this closes the confusion sec 14 named and leaves a neighbouring one
open, and the neighbouring one is arguably more likely. That is worth
knowing before anyone reads the type as making argument order safe.

### Typing the keys as well is the intended end state

The capability side is a strict subset of typing both, so nothing here is
wasted if `fzn_pubkey_t` follows. **The tree is asymmetric until it does**,
and that asymmetry is a real cost -- capabilities are structs while keys are
arrays, which every reader and both consumers meet. It was taken in this
order because the capability side is a quarter of the work for the whole
guarantee, and because a compiler-guided refactor either builds or does not,
so each half can be landed green.

### The proof that behaviour did not move

Mechanical changes carry a proof, and this one's is that nothing observable
changed: **master and the converted branch both run 64 binaries and 6643
checks at rc 0.** The wire format cannot have moved -- `wire/generated/`
mentions neither constant, `make schema` passes against situ HEAD, and a
struct of one `uint8_t[32]` has the size and alignment of the array it
replaces. `style`, `installcheck` in both Monocypher arrangements, the
sanitized build and `make sabotage` all pass.

**The refactor also found a bug that had nothing to do with it**, recorded
in the commit that fixed it: converting the headers should have broken every
dependent object and `make` reported success, because the default goal was
`monocypher.o` and a plain `make` built no library at all.

## 51. A ceiling that was compared and not held, 2026-09-02

`fzn_manifest_issue` derives a manifest from the issuer's own store, so the
bounds it keeps are about **what this host holds** rather than what a peer
sent. Three of them had no case:

    count >= FZN_MANIFEST_MAX_PAIRS        the store outgrew one manifest
    out_cap < FZN_MANIFEST_LEN(count + 1u) the buffer outgrew by one pair
    if (duplicate) continue                a pair the store holds twice

The suite's existing ceiling case is `fzn_manifest_open`'s, which is the
same number answering a different question -- how much work a **peer** may
set. The largest store anywhere in the file held eight entries.

### The first version of the case passed with the guard cut out

Sized `out_cap` at the test's whole scratch buffer, deleting the ceiling
changes nothing a caller can see. The loop runs on, writes a count of 4095,
and reaches the `fzn_manifest_open` that this function performs **on its own
bytes** before signing -- which refuses the oversized count. Same error,
same absent manifest, and a case that asserts the outcome learns nothing.

**At exactly `FZN_MANIFEST_MAX_LEN` the two answers diverge**, and the
divergence is what the guard is for:

    guard present   FZN_MANIFEST_ERR_SHAPE      your store outgrew a manifest
    guard absent    FZN_MANIFEST_ERR_MALFORMED  your buffer is too small

A consumer that sized `out` with the public constant for the largest
manifest this library carries has a **correct** buffer. Told MALFORMED, it
goes to enlarge something already at the ceiling and finds no size that
works. So the guard is not redundant with the re-open; it is the only thing
that answers truthfully, and only a buffer at the bound can observe it.

### Sec 40's criterion counted this ceiling as enforced

That audit asked, of twenty declared ceilings, **which are compared in a
non-test source**. `FZN_MANIFEST_MAX_PAIRS` is compared in two, both in
`chain/manifest.c`. It passed.

The property wanted was that each ceiling is held to account. The criterion
measured whether the constant is mentioned in a comparison, which is
satisfied by a comparison nothing tests -- and the guard here was one. This
is the same substitution as the coverage sweep's literal-offset rule, which
called `revocation` and `manifest` unprotected for spelling an offset as a
constant: a proxy applied to a system that satisfies the real property
somewhere the proxy cannot look, or fails it somewhere the proxy does not
look. **The correction is the same one sec 40 already drew about its own
regex and did not extend to its result:** read every hit, and ask what the
hit proves rather than that there was one.

### The re-open shadow is one module's, not a pattern

Three functions here open their output before signing it -- `hop_sign`,
`fzn_revocation_issue`, `fzn_manifest_issue` -- and the practice is right:
it is where an encoder and its accessors would be caught disagreeing. It
also puts a second, stricter judge downstream of every guard above it, which
is how a guard becomes invisible.

Both other sites were checked rather than assumed. `fzn_revocation_issue`
has nothing above its re-open but the argument check its encoder repeats,
and there is no ceiling in a fixed-length record. `hop_sign`'s
expires-before-issued guard, cut out, fails `chain_test` twice. So the
shadow fell on one function.

**It is nonetheless the fourth finding in `chain/manifest.c`.** Sec 36 found
its missing refusing-signer case, sec 40 its unheld maximum-length constant
and the absent fuzz harness; this is a bound its sibling modules do not have
to keep. Sec 40 called three findings in one module a fact about the module.
A fourth does not change that conclusion, but it does say the module went on
producing them after the observation was made -- which is an argument for
the harness sec 36 left open rather than more findings of this kind.

### The three guards are in the sabotage table now

A measurement taken once is a fact about a Tuesday. Batch four of
`tool/sabotage.py`:

    manifest-issue-ceiling      CAUGHT   manifest_test.c:1033
    manifest-issue-out-cap      CAUGHT   manifest_test.c:1086
    manifest-issue-dedup-skip   CAUGHT   manifest_test.c:1133

with `CONTROL-wipe` and `CONTROL-delegable` both CAUGHT in the same run, so
the sweep was mutating. The entry text records **why the buffer size
matters**, because an entry is worth exactly as much as the case that feeds
it: a later edit that enlarges `out_cap` in that test would turn
`manifest-issue-ceiling` into a survivor with nothing to explain it.

### The duplicate skip is written in directly, and that is the argument

`fzn_revocation_admit` deduplicates, so a store holding one pair twice
cannot be built through the public door. `manifest.c` handles it anyway, and
says why: a repeated pair is a manifest signed by this issuer that no
receiver's `open` will accept, from the one function meant to be unable to
lie.

The case writes the entries into the store rather than admitting them, on
the ground that `store_sound` is the whole of what this module asks about a
store, and one pair twice satisfies it -- `used` within `capacity`, `entries`
not NULL. The state is inside what the module accepts, so what it does with
it is the open question. The alternative, treating "admit cannot produce
this" as coverage, is exactly the reasoning that left the guard unexecuted
while the comment above it explained itself.

The ceiling case, by contrast, grows its store **through** `admit` -- 4095
signed records through the public door -- because there the point is that
the bound holds against reachable behaviour. Two fixtures, two different
arguments, and neither generalises to the other.

## 52. The sweep run in full, and the entry that had stopped testing, 2026-09-03

Forty-two entries, every one of them:

    CAUGHT        39
    SURVIVED       2   both on the expected list, sec 36 and sec 42
    PATTERN-MISS   1   -> the finding

Tool exit 2, which means the sweep is incomplete rather than that a guard is
undefended. Read through `tee`, so the shell's `$?` was the pipe's; the code
came from `PIPESTATUS[0]`. Sec 37 already records that `make sabotage`
flattens both outcomes into make's own 2 -- this is the same trap one layer
out, and the same answer: ask the tool.

### `seal-open-clears-out` had been testing nothing for two days

The entry matched a bare `memset(out, 0, sizeof(*out));` in `wire/seal.c`
and requires exactly one occurrence. There are two:

    wire/seal.c:135   fzn_seal_open   1e0d7da, 2026-08-18   the intended target
    wire/seal.c:252   fzn_seal_peek   3131bc0, 2026-09-01   the collision

`3131bc0` is the commit that made `peek` read the whole plaintext head. It
gave `peek` the same clear on the same argument name, and in doing so retired
the entry -- which then sat in a table of thirty-nine reading as coverage.

**The harness was right and nothing was wrong with it.** It refused to guess
which `memset` was meant, said so, and set the exit code that means the
output cannot be trusted. What failed is that a sweep is the only thing that
asks, and none had been run since the collision landed.

### Two entries now, both spelled with their neighbours

`fzn_seal_peek`'s clear is a promise `seal.h` makes to callers, so it earns
an entry of its own rather than disambiguation alone:

    seal-open-clears-out   CAUGHT   an open refused for the wrong key left pointers behind
    seal-peek-clears-out   CAUGHT   seal_fuzz, on case 0

The rule the table now carries: **a pattern is spelled with enough context to
name one call site even where the bare line is unique today.** A module
growing a second caller of the same idiom is ordinary, and it must not be
able to silently retire an entry.

### The gate that makes this cheap, and why it could not be `sabotage`

`make sabotage` is outside `make check` for a good reason -- it rewrites
tracked files, and nothing that reads as "check my work" should. That reason
is about the *mutations*, and it was quietly taken to cover the table as
well. Everything needed to catch `3131bc0` on the afternoon it landed was a
substring count.

`sabotage.py --verify` opens no compiler and writes no byte. It checks that
each entry's text matches exactly one site in a file that exists, that no
entry replaces its text with itself, and that every id exempted in
`EXPECTED_SURVIVORS` still names an entry -- the same rot pointed the other
way, where a rename leaves an exemption behind ready to silence a real
survivor. `make style` runs it; the whole check is 43 substring counts.

Proven to discriminate rather than asserted, by patching the table in memory:

    matches nothing            reported, exit 2
    matches two sites          reported, exit 2      <- the real defect
    replaces its text with itself   reported, exit 2
    names a file that is gone   reported, exit 2
    stale survivor exemption    reported, exit 2

and then against the real gate: inserting one blank line into `fzn_seal_peek`
made `make style` fail, naming the entry. `wire/seal.c` restored byte-identical.

**One probe in that sequence did not apply** -- an anchor assumed unique was
not -- and the `make style` run after it came back clean. That clean run is
worth nothing, and it is the shape sec 40 names: a mutation that did not land
and a check that cannot fail are indistinguishable from the output. It was
caught only because the probe asserted its own match count first.

### Two claims that outlived their fix

Sec 37 and the `sabotage:` comment in the Makefile both say `sync-clear-plan`
hangs, costs a full timeout, and that a complete run is priced accordingly.
Measured today: **CAUGHT in under ten seconds.**

`a1af82d` bounded the plan count that harness walks, on 2026-08-31 -- the same
day sec 37 was written. The note describing the hang as a standing condition
was stale within hours of being recorded, and the Makefile's estimate has been
telling every reader since to budget half an hour that was never needed.

Worth naming as its own small lesson: **a note that says "for as long as this
stands" is a claim with no expiry check on it.** The commit that fixed the
hang did not know a paragraph elsewhere described it as permanent, and nothing
connects the two. Where a document states a current condition rather than a
decision, it wants either a measurement beside it or nothing at all.

## 53. The sources the sabotage table had never touched, 2026-09-03

Sec 52 fixed an entry that had stopped matching. The obvious next question is
the one that fix does not answer: **which guards have no entry at all.** The
table grew by shape -- a clear on a refusal path, an init that zeroes, a
protocol constant -- and never by coverage. Counted: of thirty-four library
sources, **nineteen had an entry and fifteen had none**, and that is a list
anyone could compute and nobody had.

Five parallel readings of those fifteen, each told to propose a mutation, name
the assertion it expected to fail, and **verify its own snippet matched
exactly one site**. Seven guards came back predicted unheld. All seven were
confirmed with `sabotage.py --probe` before a line of test was written, and
three CAUGHT predictions were probed alongside them -- a method checked only
where it predicts failure is not checked.

### Three were unheld behind a test that names them

This is the shape the last three days keep producing, and it is worth seeing
the three side by side because the mechanism differs each time.

    revocation_test.c   the ceiling case ran against a store whose `used`
                        was zero, so the loop the ceiling guards never ran
    split_test.c        both disagreeing plans were refused by an EARLIER
                        guard, returning the same error either way
    spool_test.c        `has` was asked for index 6 against a one-byte
                        bitmap, so the out-of-range read stayed in byte 0

None is a careless test. Each names the right property, and each is defeated
by a detail of the fixture rather than of the assertion -- an empty store, a
guard order, a bitmap that rounds up. **A test is only as sharp as the state
it puts the code in**, and that state is the part nobody re-reads.

### What the four with consequence actually cost

`fzn_revocation_covers_chain`'s hop ceiling is the worst. It is the only bound
protecting a consumer that parsed a chain itself -- the caller its own comment
names, and the one `fzn_chain_verify` never plays, since verify bounds the
count before calling. Without it the walk reads `hops[]` and **writes
`revoked[]`** past the end of both, on the authorisation path.

`chunk/split.c`'s count agreement is the only one of four sibling plan checks
the other three do not imply. Its own comment names the shape it exists for --
`{total = 10, chunk_size = 4, chunks = 100}` at index 2 -- and no test built
it. Accepted, that returns offset 8 length 4 over a ten-byte message, because
index 2 is not the last of a hundred and so gets a full stride: a two-byte
overread at the caller's `memcpy`, off-module.

`spool/spool.c`'s `want = cap < FZN_BLOB_SEALED_MAX ? ...` is the only thing
bounding a write into the caller's buffer, and **all five call sites in the
tree pass `cap == FZN_BLOB_SEALED_MAX`** -- exactly the value at which
dropping the term changes nothing. A relay asking for a short read got a full
1056-byte slot.

`fzn_spool_has`'s index bound is the same story one size down: the bitmap is
the caller's, and the bound is what keeps `bit_get` inside it.

### Two that are unheld for reasons worth stating rather than fixing

`fzn_ct_memeq`'s NULL refusal had **no test anywhere**. The commit that added
it records "NULL compares without crashing" -- measured by hand, once, and
never again. It is now driven, and the detection is a crash: the guard exists
to stop a dereference, so with it gone the only observable difference is
whether the process survives. The `len == 0` answers are identical either way,
because an empty loop leaves the accumulator at zero. That is inherent, and
the case says so rather than leaving a reader hunting for a stronger assertion
than it can carry.

`covers_chain`'s `break` -- the one that makes entitlement start at a key's
**first** grant rather than its last -- could not be reached by any fixture in
the tree. Every one seeds grantor `i` and grantee `i + 1`, and `chain_fuzz`
cannot build a counterexample either: a chain that verifies must be linked, so
its grantors are pairwise distinct by construction and smallest equals
largest. The case builds the shape by calling `covers_chain` directly, which
does not check linkage. The failure direction is fail-open -- taking the last
appearance lets a chain that re-uses a key escape a withdrawal that should
bite the hops between.

### One prediction was wrong, and only probing found it

`session/random_linux.c`'s null-buffer guard was predicted SURVIVED on the
reasoning that `getrandom(NULL, 24, 0)` returns `EFAULT`, so the function
returns 0 either way and `random_test.c`'s assertion passes. It came back
CAUGHT. Reproduced directly: **SIGSEGV**. The assertion that appears to hold
that guard never executes at all -- the process dies inside the call, and the
message it would print cannot print. The guard is held; the test that looks
like it holds it does not.

Kept as the reason the CAUGHT predictions were probed too. Six of seven
agreed; the seventh was a confident, well-argued, wrong mechanism, and no
amount of re-reading it would have shown that.

### Two things the readings found that were not guards at all

**A test asserting on uninitialised memory.** `tree_test.c` declared
`fzn_tree_walk_t walk;` and then asserted `walk.truncated == 0` after the
call. Correct today only because the function writes the field; a version that
reset nothing would have been judged by whatever the frame held. The walk is
dirtied first now, which is the same discipline manifest_test.c's refused-signer
case already carries.

**A limitation that mutation testing cannot reach.** Sec 5g records that
`sched/`'s `usable` is boolean and that this costs a host in backoff its only
link. The guard around `usable` is tested in both directions; there is no
backoff clamp anywhere in `sched/sched.c` to sabotage. **The limitation is a
MISSING guard, and this technique finds unheld guards, not absent ones.** Worth
stating because a table growing by coverage invites the assumption that a
covered module is a complete one.

### The two sources that pass left behind, and how they were nearly lost

`frame/freshness.c` and `wire/relay.c` were in the fifteen and their reading
came back with three unheld guards -- and none of them was confirmed in that
pass, because **the probe batch running them was killed mid-run** and the
work moved on to the modules whose probes had finished. The findings sat
unverified for the rest of the day behind a summary that did not mention
them.

Worth recording as its own small lesson: **an interrupted measurement is not
a null result, and it does not announce itself as one.** What the killed job
left behind was one line reading `got ?`, in a file nothing re-read. The
recovery was going back to a list, not remembering.

Confirmed on the second pass, all three SURVIVED, and two of them are gaps
with the same shape as the rest:

**`wire/relay.c`'s `frame_len > UINT32_MAX`.** `situ_msg_init` takes a
`uint32_t`, so a `size_t` length above it truncates on the way in and every
bounds check downstream is computed against a number that is not the
buffer's. No case in the tree ever passed such a length. The case now does,
with a **real buffer and a lying length** whose truncated value is
`sizeof(frame)` -- so the sabotaged run SUCCEEDS and answers a budget rather
than crashing, which is the failure worth catching. A case that crashed
instead would be measuring the sanitizer.

**`frame/freshness.c`'s `!window->entries`.** The case aimed at it copies a
freshly initialised window, so `used` is zero, the compaction loop runs no
iterations, and 0 comes back with or without the term. Two claimed entries
inside a capacity of four passes the fields-agree test below it and leaves
the term as the only thing between the call and `entries[0]` through a null
pointer.

**And `wire/relay.c`'s hop-header minimum is an expected survivor rather
than a gap.** `situ_view_at` bounds-checks before any accessor reads, so a
frame too short for the hop header is refused there and this returns the
same 0 either way. Kept rather than deleted, and the distinction is worth
stating because this file has deleted redundant defence twice on the
argument that a reader should not have to work out which check is
load-bearing: **that argument is about two checks in one file.** This one
guards against a change in a schema compiler that lives in another
repository and is not covered by any gate here, which is a different risk
and not one to trade away without the holder.

### The census is enforced now, not remembered

Batches five to eight closed it: **sixty-four entries over thirty-three of
the thirty-four library sources**, with `version/version.c` the only
exclusion -- three accessors returning macros, no branch, no bound, no
clear, nothing to remove.

Nothing stopped that reopening. A module added tomorrow joins the build, the
suite, the style gate and `.gitignore`, and this table would not have
noticed -- which is how it came to cover nineteen sources in the first place.
`--verify` now reads `make manifest` and requires every library source to
have an entry or to be named in a `NO_GUARDS` list with its reason. It runs
in `make style`, builds nothing, and the `manifest` target is pure `echo`
with no prerequisites, so it cannot recurse.

**A failure to read the source list is a failure and not a skip**, stated in
the code because the alternative is the exact shape this file keeps meeting:
a coverage check over an empty list passes as loudly as a real one. Shown to
discriminate in three directions -- a source losing its only entry, an
exclusion naming a file that is no longer a source, and the list being
unreadable -- each reported by name, each exiting 2.

**The last one found was the one its header is written around.**
`chain/authz.c`'s `if (!policy.spelled) return FZN_AUTHZ_DENIED;` is the line
authz.h opens with, and deleting it left the whole suite green. Both
assertions aimed at it use a `memset` policy, which the ORIGIN gate already
denies -- a zeroed `origins` reaches nothing. The header says so approvingly,
"a forgotten policy now denies on two independent counts rather than one",
and **that redundancy is what hid the fact that only one of the two counts
was under test.**

The state `spelled` decides alone is the half-filled policy: `origins` set,
`spelled` forgotten. It is also the likelier mistake, because `origins` is
the field the arity change made a consumer think about. Without the check it
reaches the origin gate, passes, finds `guarded` clear, and answers
GRANTED_UNGUARDED -- the failure the header opens with, arriving through the
half-filled struct rather than the empty one.

### The one entry no assertion catches, and how thin its margin is

`fzn_ct_memeq`'s accumulate-then-compare loop is the module's whole reason
for existing, and the mutation that matters preserves every RESULT while
destroying the timing property: replace the accumulator with an early exit
on first mismatch. Measured 2026-09-03 -- `secret_flow_test` passes 10 of
10, and `codegencheck` fails inside `make test`. **The catch is entirely in
the object code and no assertion sees it.**

Pinned as `ct-memeq-accumulator`, and the entry is there to hold the GATE to
account rather than the function. `tool/codegen_gate.py` exits 0 and reports
SKIPPED for a non-x86-64, sanitized or `-O0` object, so a SURVIVED here on
some future machine means the gate skipped rather than that the function
changed.

**IT DOES NOT CATCH IT ON CLANG, and the first version of this paragraph
said otherwise.** What was written here on 2026-09-03 was that the margin is
"thinner than expected" but "not a defect today", from one measurement on
one compiler at one level. Challenged from outside the tree -- if gcc
keeping the conditional set is compiler-specific, the margin is a property
of gcc-on-this-box and might be four-deep elsewhere -- and measured across
eight cells rather than argued:

    real function                     mutant (early exit on first mismatch)
    gcc   -O1  FAIL (2 return)        gcc   -O1  FAIL
    gcc   -O2  FAIL (2 return)        gcc   -O2  FAIL
    gcc   -Os  pass                   gcc   -Os  FAIL (2 return)
    gcc   -O3  FAIL (2 return)        gcc   -O3  FAIL
    clang -O1  pass                   clang -O1  FAIL
    clang -O2  pass                   clang -O2  FAIL
    clang -Os  pass                   clang -Os  PASS  <- "shape unchanged"
    clang -O3  pass                   clang -O3  FAIL

**At clang -Os the gate reports "shape unchanged" for a mutant that has
destroyed the only property this module exists for.** `-Os` is this build's
own optimisation level, clang is installed here and is what `make fuzz` and
`ctcheck` already use, and `codegen_gate.py` skips for a non-x86-64,
sanitized or `-O0` object but not for a compiler.

**The discriminator is present in the output and deliberately unused.** Real
and mutant differ at clang -Os only in the conditional branch count, 3
against 4 -- the one number the gate prints and does not fail on. That
decision was correct and should stand: across the eight cells the REAL
function's branch count ranges 3 to 5, so failing on it would refuse honest
builds. There is no stable invariant in the gate's vocabulary separating
these two objects.

The gcc column is the other half of the same fact. At -O1, -O2 and -O3 the
gate fails the UNMUTATED function, so it is calibrated to the level this
project builds at rather than being a general property of the source.

**What does catch it is `ctcheck`, and it is in neither `make test` nor
`make check`.** Run against the mutant it fails with the frame named:

    ==27344==    at 0x10981E: fzn_ct_memeq (constant_time.c:38)
    ==27344==    by 0x1094AE: compare_secret (secret_flow_test.c:92)

That is portable in a way the tripwire cannot be, because valgrind OBSERVES
a branch on secret data rather than inferring from shape. So the standing
arrangement is: `make check` carries the tripwire and not the witness, and
the tripwire has a measured hole at this project's own optimisation level on
an installed compiler. Whether `ctcheck` joins `check` is a build-policy
question for the holder -- it needs valgrind present, and the Makefile's
list of deliberate exclusions from `check` does not mention it either way.

**The correction is the point, not the finding.** The first paragraph was
written from one cell and read as a property of the gate. It took somebody
declining to accept it into a document to turn eight cells into a
measurement -- and the measurement says something stronger and in a
different direction than either of us guessed.

### The gate now says when it cannot tell, and the control took three goes

A false pass is the one verdict this file argues nothing may produce, so
`codegencheck` gained a positive control: a known-bad `fzn_ct_memeq`,
compiled with the SAME `CC` and `CFLAGS`, which the gate must reject before
its verdict on the real object counts for anything. Rejected, the toolchain
can discriminate. **Accepted, the gate says so and SKIPS**, pointing at
`ctcheck`, rather than reporting a shape unchanged. It exits 0 like the
other three skips: a compiler whose codegen blinds a tripwire is not a fault
in the source and must not fail a build.

Asking by experiment is what makes it work at all. The existing skips read
DWARF's producer string, and that cannot answer this one -- **clang records
only its version there, with no flags**, which is written in the tool's own
comment as the reason a "no -O seen" rule was removed. Nothing in a clang
object says `-Os`. Compiling a control with the flags in hand needs to know
neither the compiler nor the level.

**The first control was hand-written and did not reproduce the hole.** An
early-exit memeq, written from scratch, is REJECTED at clang -Os -- so the
gate would have announced "this toolchain can discriminate" while the real
mutant sailed through. It differed from the real function by dropping
`volatile uint8_t diff`, which is enough to change what clang emits. A
control that is not the real function minus one line is a different program.
That is a non-discriminating check inside the fix for a non-discriminating
check, which is the third instance in a day.

So it is derived by substitution from `constant_time.c` instead, and the
recipe asserts the pattern matches **exactly one** line -- stronger than
checking the output differs, because two matches would build a control with
two mutations and zero would build one identical to the real function, and
those fail for different reasons.

**The second version wrote a `.c` into the source tree.** `BUILD_DIR`
defaults to `.` for the in-place build, so `$(BUILD_DIR)/tool/ct_control.c`
is `tool/ct_control.c`, and `make style` refused it on its indentation. The
gate catching a generated file is the gate working; the answer was to stop
generating the file rather than to add an exclusion, so the substitution now
pipes straight into the compiler and only the object lands.

### Why the wipe check was never blind, which is the transferable half

The same eight cells were run against `check_wipe`, deleting one
`fzn_wipe` call from `fzn_commitment_derive_root`. **All eight reject it.**
It has a control now anyway -- "measured robust in a session" and
"re-measured every build" are different things, and it costs one compile --
but the null result is worth more than the control.

**The two checks fail differently because they ask differently.** The ct
check INFERS a property from instruction shape, and shape is a function of
the toolchain: which is exactly how clang at -Os came to accept a mutant.
The wipe check COUNTS CALLS TO A NAMED SYMBOL, and a call to an external
function is not something an optimiser is free to reshape away -- `fzn_wipe`
lives in another translation unit, so without LTO there is nothing to
inline.

Both are tripwires over compiled output and only one is toolchain-shaped.
So the question to ask of a gate is not whether it passes but **what its
verdict is a function of**, and "the compiler" is an answer that makes a
green result a statement about the machine rather than about the source. A
check anchored to something the language guarantees survives; one anchored
to what the optimiser happened to emit does not.

Visible in one build: under clang -Os the ct check skips and the wipe check
discriminates, in the same run, on the same object files.

**And the control argument is required rather than optional**, which it was
not for the first hour. Optional, dropping it from the Makefile invocation
would have left the tool checking the real object and reporting a pass with
the control silently absent -- a safeguard removable without a failure,
which is a convention rather than a mechanism. Both modes have one, so
nothing needed the permissive form. Checked at the edges too: a missing
argument and an unreadable control object both exit 1, so a typo in the path
cannot quietly disable the check it was meant to arm.

### And the pattern rule from sec 52 paid for itself three times

Three of the five readings hit a snippet matching two sites while constructing
their proposals -- in `wire/relay.c`, `spool/spool.c` and `tree/tree.c`. Each
would have produced an entry that tested nothing, exactly like the seal entry.
They were caught because each reading was required to count its own matches
before proposing, which is the same check `--verify` now runs over the table.

**One correction taken here rather than shipped:** the first `examined`
assertion read `== 3` for three nodes and failed against unmutated code.
`examined` counts each still-unmarked node once per fixed-point pass, so three
nodes give five. The assertion is a range bounded by the module's own
documented cost, because the exact number is the loop's schedule and not a
promise -- freezing it would make a legitimate improvement look like a
regression.

## 54. A control that passed for the wrong reason, 2026-09-03

The two feature probes in the Makefile ran `$(CC)` bare -- no CPPFLAGS, no
CFLAGS -- while every real rule passes both, and neither had a control.
Reported from outside this tree, in a sweep for **diagnostics naming a cause
the code never tested**, which is sec 52 and sec 53's family arriving in the
build system instead of the library.

The consequences are two, and only the first is obvious. A toolchain needing
a flag the user keeps in CFLAGS **builds the library and fails the probe**, so
the notice blames the platform's POSIX for a flag mismatch. And a `CC` that
cannot link against libc at all fails it too, for a third cause reported as
the second -- while the comment beside the notice was arguing that "off" and
"you have no POSIX" are different problems with different fixes.

Following the notice made it worse: `FZN_PERSIST_FILE=1` turned the skip into
a hard error naming the same wrong cause. **The advice tracks the cause now**,
because insisting is the right next step for a platform that genuinely lacks
the API and useless for a toolchain that could not be asked.

### The fix needed two things the report did not have

**`-MMD` breaks the probe the moment CPPFLAGS is passed through.** Against
`-o /dev/null` it tries to open `/dev/null.d` and fails with "Permission
denied". All three probes went to `no` on a machine whose library builds
fine. `$(filter-out -MMD -MP -MD,$(CPPFLAGS))` is the fix: a probe wants the
build's SEARCH and LANGUAGE flags, where a `-I`, a `-D` or a `--target`
lives, and not its dependency bookkeeping. Taken as reported, the
recommendation would have switched optional backends off silently in any tree
that copied it.

**And the first control did not control.** It was
`int main(void){return 0;}`, which links under `-nostdlib` -- no libc, no
POSIX, nothing -- **because it references nothing**. So it passed, and the
notice went on blaming POSIX for a toolchain with no C library: the exact
case being fixed, unfixed, behind a green control. It calls `strtol` now,
which is ISO C rather than POSIX and therefore separates "cannot link against
libc" from "libc is here and lacks the file API" -- the two the notices must
not confuse.

**The generalisation, and it is the part worth keeping:** the test of a
control is not whether it passes on a good machine but **which failure it
distinguishes from which**. One that passes everywhere is a constant. This
tree has spent three days on checks that answer without discriminating, and
the first control written to close one had the same defect, one level out and
about four minutes old.

### Which inverted a claim about this tree

The same report noted that `test -d .git` is the "is this a repository" test
in sixteen of the seventeen Makefiles here and that fuzznet is the only tree
without it. Checked rather than adopted: **fuzznet does not have the bug that
test has.** `tool/style_gate.py` asks git -- `rev-parse --is-inside-work-tree`
-- and consults `.git` only as a fallback, deciding whether an unreadable
`.git` should stop the run rather than fall through to a filesystem walk.
That fallback is `(root / ".git").exists()`, which is **true for a regular
file**, and `.git` is a regular file in a worktree and in a submodule
checkout. `test -d` is false in both.

So the majority form is the broken one and copying it here would have been a
regression. The central record was amended after the other session verified
it against a live submodule rather than taking my word for it, which is the
right way round for a claim that had already been wrong once.

**Worth recording about this tree rather than about the finding:** four
sweeps of it for this class returned one finding, and it was in a `$(shell)`
call rather than in the library. The gates are not the weak part; the thing
that measures the gates was.

## 55. A real defect, and a fix in the wrong layer, 2026-09-03

`fzn_peer_groups_parse` scans a `Groups:` line to the next newline **or to
`len`**, so a line running to the end of the buffer is taken for a whole
line. `fzn_peer_from_fd` reads `/proc/<pid>/status` into 8192 bytes with one
`fread` and hands over what it got.

**A short read is not a failed read**, so `ferror` sees nothing and a longer
file comes back full and clean. The `Groups:` line is early in that file and
is also the LONGEST line in it -- a few hundred supplementary groups runs it
into the kilobytes -- so the many-groups case is exactly the one where the
cut lands inside it. Every gid before the cut then parses, `groups_known`
comes back 1, and the number AT the cut may be half a number: **250 read as
25**, a wrong entry rather than a missing one, indistinguishable from a real
25.

The result is a definite `FZN_PEER_NOT_MEMBER` for a real member, which is
what `peer.h`'s tri-state exists to prevent -- and the parser guards the
OTHER way a list gets truncated, `FZN_PEER_MAX_GROUPS` overflow, with exactly
that reason written beside it.

### The first fix was wrong, and the test that said so was right

The obvious repair is in the parser: a line whose end cannot be seen cannot
be understood, so refuse. Written, and it failed two things.

`test_bad_arguments` asserts that eight bytes reading `Groups: ` parse as a
KNOWN empty list. And `peer_fuzz`'s model -- **an independent
reimplementation of the parsing rules** -- encodes the same rule and
disagreed on case 11065.

Both were right. `fzn_peer_groups_parse` receives `(text, len)` and **`len`
does not say whether it means "the whole file" or "as much as fitted"**. Only
the caller knows which. A caller holding a short unterminated text has a
complete last line; a caller holding a filled buffer does not; the bytes are
identical. Refusing in the parser makes a pure function guess at something
outside its own input, and breaks the first caller to serve the second.

**Which is this library's own rule, stated everywhere else.** `chain.h` keeps
a store's fields away from the side that must not reach into them. Sec 51's
bounds separate what THIS host holds from what a peer sent. Sec 53's whole
census is about guards placed where the information is. The decision belongs
to the layer that can see the input, and here that is `fzn_peer_from_fd`.

### What it nearly cost, which is worse than the wrong fix

The next step after "the model disagrees" is to edit the model. It is one
line in `peer_fuzz.c`, it would have gone green, and **the model and the code
would then have been written by the same hand within the same hour** --
`evidence.md`'s two documents that are one witness. The fuzz harness would
have kept running 20000 cases a build and stopped being evidence of anything.

A disagreeing independent model is the witness working. The temptation is to
silence it, and it is strongest exactly when you are confident, because then
the disagreement looks like a defect in the model.

### The repair, and the sentence that was missing

`fzn_peer_from_fd` trims to the last newline whenever its read filled the
buffer -- rather than discarding the read, so a large status file whose
`Groups:` line arrived whole is still answered. Nothing surviving means
`got == 0` and "could not tell", which is what this function already answers
for a file it cannot open.

`peer.h` now states whole lines as a **precondition**, says it cannot be
checked there and why, and names who satisfies it. `peer_test.c` pins the
unterminated case as contract rather than defect, and says what the plausible
wrong turn is, because the hazard is real and a reader finding it with
nothing beside it concludes it was missed.

### And the fix shipped without a test, for an hour

The repair above went in with nothing exercising it. Reaching it needs a
`/proc/<pid>/status` past 8192 bytes; this process's own is about a tenth of
that and no test can grow it. So the commit that fixed a wrong definite
answer on an authorisation path was verified by compiling -- **which is the
family this file has spent three days on, with the discriminating step
replaced by the running step and committed by the person writing about it.**

The repair for that is `fzn_peer_whole_lines`, and making it public is not a
concession to testability. peer.h states whole lines as a precondition only a
caller can satisfy; a precondition every consumer implements by hand gets
implemented three ways and one of them wrongly, so the library that states it
should supply the four lines that meet it. The trim is now exercised
directly, including the case that matters -- the same `Groups:` line cut one
byte short, parsed twice, once as a KNOWN list ending in a gid this process
is not in and once, after the trim, as "could not tell" -- with a control
proving a whole line still survives the trim.

**What remains unheld is stated rather than implied.** Sabotaged, the trim's
logic is CAUGHT and the CALL to it in `fzn_peer_from_fd` SURVIVES, because
nothing drives that path. Both are in the table, the second as an expected
survivor naming the reason. A single entry covering "the fix" would have read
as though the whole of it were held.

**That is the second time in one day that an absent precondition was read as
an oversight** -- `record/sync.h`'s append-only requirement was the first,
found by a consumer who derived it from the semantics rather than reading it.
Both were true all along and neither was written down. A precondition that
lives only in the author's head is indistinguishable, from outside, from one
nobody thought of.

## 59. The gate held where the defect lives, and a guard nothing held, 2026-09-04

Sec 58 built the stage-2 gate and held it in `chain/test/manifest_test.c`,
where the manifest state is assembled by hand beside the chain it gates.
**The defect it closes is a network condition** -- a host that joined this
morning, was offline, or is partitioned -- and `sim/test/network_test.c`
passed NULL at every one of its call sites, so the harness that walks this
library through a lossy network with per-host stores could not tell the gate
from its absence.

`scenario_incomplete` is that arrangement. A host installs a manifest state,
the others do not, and one ungated host receives every send as the control.

    a state installed, following nobody   delivers -- an empty union is a
                                          zero deficit, not a closed gate
    a deficit about a STRANGER issuer     delivers -- the scoping
    a deficit about THIS chain's grantor  refused, as INCOMPLETE and not
                                          on authority
    the missing revocation admitted       delivers again

**The first leg is what stops the other three being satisfied by an
uninstalled state**, and the last is sec 58's "recovers issuer by issuer"
as an observation rather than a claim: the stranger's deficit is asserted to
be still outstanding after the root's has drained, so the recovery is one
issuer draining and not the table being cleared.

**The pair revoked belongs to a THIRD host, deliberately.** Revoking the
sender would make the last leg unreadable -- the host would drain its deficit
and then refuse on the revocation it had just admitted, and "still refuses"
would be satisfied by the gate never having opened.

### Both sabotages are caught, and by the leg written for each

Measured against `sim/test/network_test` alone, the file saved first and
written back afterwards, so that the report is about this scenario rather
than about whichever suite runs earliest:

    the gate removed        leg 3 and leg 4 fail; leg 2 stays green,
                            correctly -- an absent gate refuses nothing
    the gate unscoped       leg 2 fails, by name: "the gate is not scoped to
                            this chain's grantors and every returning device
                            refuses everything"

**NEITHER OF THOSE TWO IS A GUARD THAT WAS UNHELD**, and saying so is the
point of measuring the suites separately. Sec 58 pinned the gate, and its own
scoping control in `chain/test/manifest_test.c` catches the unscoped variant
first when the whole suite runs -- `tool/sabotage.py` reports
`manifest_test.c:2312` for `chain-gate-unscoped`, not this scenario. What
these two legs add is a SECOND holder in the arrangement the defect lives in:
a unit test asks the question with the state built beside the chain, and this
asks it of a host on a lossy network with its own store, which is where a
returning device actually is.

`chain-gate-unscoped` is a new entry in `tool/sabotage.py` all the same. The
unscoped gate is one line from the built one, it is sec 13d's "returning
device refuses all" which that section costed as a brick, and a guard held by
one suite and named by no sabotage is a guard nobody will notice losing.

### AND THE DECISION LAYER'S FORWARDING WAS HELD BY NOTHING

`fzn_authz_decide` gained the manifest argument in sec 58 and passes it to
`fzn_chain_verify`. **Replacing that argument with NULL in `chain/authz.c`
left the entire suite green** -- `make test`, exit 0, 103 seconds, measured at
HEAD before this scenario existed. `chain/test/authz_test.c` does not contain
the word `manifest`; the 53 call sites that were made to fail to build all
pass the state IN, and nothing checked that the function passed it ON.

So the gate was reachable through `fzn_chain_verify` and absent from the call
a consumer actually makes, and no test in the tree could tell.

It is caught now, and by one check with a name: `sim_receive` asserts on every
delivered frame that the decision layer agrees with the verifier it wraps, and
with a gated host on the network the two disagree the moment the forwarding is
dropped. `tool/sabotage.py` carries it as `authz-drops-manifest`.

### And a consumer following this tree's own example never met the gate

`tool/consumer_check.c` exercises the manifest end to end -- follow, issue,
open, admit, the deficit, the resumable form, the drain, the serve side -- and
passed **NULL for the manifest at every one of its `fzn_chain_verify` and
`fzn_authz_decide` calls.** So the file that exists to answer "can a consumer
USE this" showed a consumer the argument spelled NULL everywhere and no
demonstration that a state does anything.

That is the state sec 56 describes the withdrawal API being in before that
section closed it -- declared, compiled against, never called -- arriving one
feature later in the same file. **The gate is the harder case of the two**,
because a consumer that never calls a function notices nothing, while a
consumer that passes NULL to an argument it has not understood believes it has
the protection.

Three legs beside the deficit the block already computes: no state is no gate,
a state with a deficit refuses as INCOMPLETE, and once the deficit drains the
same chain verifies again. Each leg is run twice, through `fzn_chain_verify`
and through `fzn_authz_decide`, and the pairing is the point rather than
thoroughness -- a consumer calls the decision layer, so a gate only the
verifier honours is a gate no consumer has.

Both discriminate, measured against `make installcheck` on a copy restored
afterwards:

    the gate removed              consumer_check: failed check 301
    authz drops the manifest      consumer_check: failed check 302

So the forwarding now has two independent holders -- the network harness and
the consumer gate -- and the second is the one a consumer would have found
first.

**The lens that found it is the one this document keeps arriving at from the
other end.** Sec 55's is that a precondition true and unwritten looks exactly
like one nobody thought of; this is its sibling for arguments -- **a parameter
threaded through a call is not a parameter that arrives**, and the compiler
checks that every caller supplies one, never that the callee uses it. The
53-call-site failure sec 58 counted as the loud failure is loud about the
callers and silent about the body.

### Three places said stage 2 was unbuilt, a day after it was built

Found by reading what sec 58 changed against what still pointed at it:

    sec 13d   "Stage 2 waits on the holder"                     rewritten
    sec 13d   "A contradiction ... flagged rather than resolved" rewritten
    sec 47    the build table's NOT BUILT row, and "It does not
              choose"                                            rewritten
    sec 56    "The design question is open and is the holder's"   rewritten
    manifest_test.c   a comment saying the gate "waits on the
                      copyright holder", above the function that
                      asserts it                                 rewritten

The last is the sharpest: sec 58 renamed `test_stage_one_does_not_gate` to
`test_stage_two_gates_on_this_chains_grantors` and left the comment above it
saying stage 2 was blocked. **A rename moves the name and not the paragraph.**

None of the five was wrong when written, and that is the whole of the failure
mode -- `evidence.md` has it as a claim outliving its subject, and
`working-practice.md` as closing an entry updating the entry and not the
pointers. What is worth adding is WHERE they were: sec 58 is a careful,
complete record of the decision, and every one of the five sits in a section
sec 58 cites. **The pointers that go stale are the ones the new work read**,
because reading them is what makes them feel already accounted for.

## 60. The forwarding lens, and the three drains nobody could reach, 2026-09-04

Sec 59's finding gave a shape: **a parameter threaded through a call is not a
parameter that arrives**, and the compiler checks every caller and never the
body. Sec 43 says a sweep is worth running when it is aimed by the last real
defect rather than chosen from a list, so this one was.

### The population, and why it is small

Every place a function hands one of its own parameters straight to another
function: **66 sites** in the library, tests and tools excluded, enumerated by
script. Most are REQUIRED arguments -- a hash, a signer, an output buffer --
where dropping one makes the callee refuse and the suite goes red loudly.
Those are not the class. The class is the argument for which **NULL is legal
and meaningful**, because there the drop is silent and changes behaviour
rather than causing a refusal.

**Cutting 66 down to that class is a READING, not a script**, and the first
pass got it wrong -- see below. Eleven sites, each probed by replacing the
argument with NULL and running the whole suite:

    verify -> covers_chain          revocations   CAUGHT   chain_test.c:725
    delegate -> verify              revocations   CAUGHT   chain_test.c:1750
    admit -> satisfy, stale copy    manifest      SURVIVED
    admit -> satisfy, unchained     manifest      SURVIVED
    admit -> satisfy, reissue       manifest      SURVIVED
    admit -> satisfy, already held  manifest      CAUGHT   manifest_test.c:2385
    admit -> satisfy, stored        manifest      CAUGHT   manifest_test.c:1873
    merge -> admit                  manifest      CAUGHT   manifest_test.c:2399
    admit -> lookup                 store         CAUGHT   manifest_test.c:1177
    plan_offer -> known             store         CAUGHT   manifest_test.c:3173
    vocabulary_admit -> verdict     peer          CAUGHT   vocabulary_test

**Three survivors, and they are the same three branches**: every path in
`fzn_revocation_admit` that drains a deficit while the store holds a WITHDRAWN
entry for the pair.

### The last three rows were missed by the first selection, and that is the lesson

The sweep first reported EIGHT sites and stopped. The three rows above were
added afterwards, by re-deriving the cut rather than re-running the probe --
and all three are optional by the same test as the other eight.
`fzn_manifest_admit`'s store is documented NULL-able and `tool/consumer_check.c`
passes NULL to it; `fzn_manifest_plan_offer`'s is the same store one function
over; `fzn_vocabulary_admit`'s peer is a pointer a caller can legally omit.

**Nothing in the result changed** -- all three are caught, and the three
survivors are still one function's -- which is exactly why it is worth writing
down. A miss that changes no conclusion leaves no symptom, and the next
person quoting "eight optional sites" would be quoting a number whose
DETECTOR was one session's afternoon reading of eleven headers.
`evidence.md` names this: a count inherits its detector, and the detector
inherits whatever the first instance made salient. Here the first instance was
sec 59's `manifest` argument, so `manifest` arguments were what got looked
for, and two `store` arguments and a `peer` sat in the same list unread.

**The remedy that worked was re-deriving the cut, not re-running the probe.**
Re-running would have re-probed the same eight and agreed with itself.

### What the survivors cost, which is more than a lingering deficit

`chain/manifest.c` states the rule they implement, in the comment above the
comparison that records a deficit: *"asking when I am in fact ahead fetches a
record that is refused as stale or unchained, and without the drain this entry
would be re-recorded on every comparison and re-fetched for ever"*. Two files
argue for these calls and nothing held them.

**Since sec 58 that is not a wasted round trip.** `fzn_manifest_pending` never
returns to zero, so the stage-2 gate refuses every chain that issuer grants
in, permanently, on a host that has done nothing wrong -- sec 13d's brick,
reached by a route nobody costed. The gate made three unheld guards
load-bearing without anybody noticing that it had.

### Why no fixture reached them, which is the interesting half

`test_a_withdrawn_pair_is_not_a_deficit` runs the ORDINARY order: revoke,
withdraw, then meet a peer that is behind. There the ids match, this host
reads as ahead, and **no deficit is recorded at all** -- which is correct, and
is why these branches look unreachable from every fixture in the tree.

They need the withdrawal to have arrived FIRST, before there was anything to
compare it against: the manifest admitted against an empty store records the
pair as missing, the withdrawal lands as a tombstone, and only then does a
revocation of that pair turn up. `revocation.h` calls that ordering ordinary
rather than exceptional on a mesh, and it is the one arrangement no test
built.

**So the guards were not merely unheld, they were unreachable by construction
from the fixtures that existed** -- and the test that explains why is the one
sitting next to them. A reader checking whether the drains were covered would
have found a test about withdrawals and deficits, correctly green, answering a
different question.

### Held now, and each by the leg written for it

`test_the_withdrawal_paths_drain_the_deficit` builds that arrangement three
times, once per branch, because each leg drains the deficit it was given and
re-admitting the manifest cannot restore it -- by then this host holds what
the manifest names, so the comparison correctly finds nothing missing.

    rev-drain-stale-copy        manifest_test.c:2543
    rev-drain-unchained         manifest_test.c:2568
    rev-drain-chained-reissue   manifest_test.c:2592

All three are `tool/sabotage.py` entries and all three were watched failing.
Each leg also asserts which branch it took -- the pair is still withdrawn
after the stale copy, the un-chained record is refused by name, the pair is
revoked again after the chained reissue -- so a leg cannot pass by reaching
some other drain.

### What the lens is worth, stated so it is not re-run blind

Eleven probes, three findings, one afternoon. That is a better yield than sec
43's blanket guard sweep, and the reason is not that the lens is cleverer: it
is that **the population was cut by a property that predicts silence.** A
required argument fails loudly and needs no test to notice; an optional one
fails quietly and needs one. Sec 43's sweep could not make that cut because a
guard is a guard.

**The lens is now spent for this tree.** Eight of the eleven sites are in
`chain/`, the survivors were all one function's, and re-running it will report
the same 66 with the same verdicts until somebody adds an optional parameter.
What would refresh it is exactly what refreshed sec 43: the next real defect.

**What is NOT spent is the enumeration**, which is a script and re-runs in a
second. A site added later is a site nobody has probed, and the cut from 66 to
eleven is the part that has to be done by hand again -- which the miss above
says is the part to distrust.

## 61. Every error code, against every test that names one, 2026-09-04

`evidence.md` gained a section this evening reporting situ's measurement:
**93 of 302 `error(...)` call sites are never produced by any test**, and what
an unproduced diagnostic loses is not the refusal but the WORDING. The C
analogue is cheaper to ask than situ's, because an error code is a symbol
rather than a sentence: which codes does this library produce that no test
ever names, and which does it declare that nothing can produce?

    error constants declared                117
    produced somewhere in the library       116
    named by some test, fuzz or tool        116

**That is a healthy answer and it agrees with sec 43**, which found this
tree's guards mostly held and its survivors mostly redundant. Two items fell
out of it, and they are different kinds.

### `FZN_BLOB_ERR_FULL`: produced twice, named by nothing

The only code of the 117 the library returns and no test observes.
`blob.h` says it "needs FZN_BLOB_MAX_LEAVES leaves and therefore cannot happen
to a caller who is not trying", which is true -- the bound is 2^40 -- and is
**not** a claim that it cannot be tested. A tree is caller-owned memory whose
fields that header publishes, so the state is constructible in one assignment,
and a test is exactly the caller who is trying.

`test_the_tree_refuses_when_it_is_full` takes both bounds separately, each
with the other slack so that deleting one guard cannot pass on the survivor,
and each with its own just-under case so that `>=` becoming `>` is caught as
well as a guard going missing. Both are `tool/sabotage.py` entries and all
three mutations were watched failing at the check written for them.

**And the depth bound turned out not to be dead code**, which is worth
recording because the source says otherwise in passing: the fold's comment
argues that the binary-counter invariant "is why the stack cannot exceed the
depth bound". True of a tree built by pushing; the guard defends a tree
somebody hands you, and with a constructed stack it fires. A guard that is
unreachable through the front door and reachable through the struct is not
redundant, it is the struct's guard.

### `FZN_PERSIST_ERR_ABSENT`: declared, and nothing can produce it

The other direction, and it is not a test gap. The code carries a rationale:

    /* Nothing stored under that slot. An ordinary state on first run, and
     * its own code so a caller can tell it from a backend failure --
     * which is the distinction that decides whether to mint a fresh
     * prekey or to stop and shout. */

**No library function returns it, and the seam it would have to come from
cannot express it.** `fzn_persist_ops_t::load` returns `int`; the file backend
answers 0 for a slot that is absent and 0 for one it could not read, and
`persist_file_test.c` asserts exactly that. So the distinction the comment
says a caller needs is not available to a caller anywhere.

**The consequence is the one the comment itself names, pointing the wrong
way.** A consumer that cannot tell absent from broken must choose a default,
and the two errors are not symmetric: treating a broken store as a first run
MINTS A FRESH PREKEY AND DISCARDS A LIVE IDENTITY, while treating a first run
as broken stops a host that would have worked. The comment exists because
somebody saw that; the mechanism it promises does not exist.

**Three answers and they are not equivalent**, which is why this went to the
holder rather than being fixed in passing:

    widen the seam    `load` reports absent distinctly -- a public API
                      change, and every consumer's backend implements it
    delete the code   honest, and throws away a distinction that was
                      thought worth having
    say it is theirs  document the code as one a CONSUMER's layer may
                      return, which this library never does

The first is the only one that delivers what the comment promises, and it is
a change to a published seam and to what every consumer must implement.

**ASKED AND ANSWERED, 2026-09-04: leave it recorded.** No seam change, no
deletion, and the header keeps the comment it has. **That is a decision and
not a deferral**, which is the distinction this file has been burned by twice
in two days -- sec 58's stage 2 sat "pending the holder" in three places for a
day after it was built, and sec 56's design question stayed "open and the
holder's" after sec 57 answered it. An entry that reads as an unanswered
question gets asked again by whoever picks this up, in this tree and in each
of the four consumers, and the asking is the cost the record exists to avoid.

**So what a later session should take from this entry is the finding, not a
task.** The gap is real and is written down: a consumer cannot tell a first
run from a broken store, and the default it must therefore choose is the one
that mints a fresh prekey over a live identity. What is settled is that
nothing changes here today. What would reopen it is a consumer meeting the
case for real -- which is the evidence this entry does not have and the
holder does not owe.

### The instrument was wrong first, in the direction that inflates

The first pass matched `return FZN_..._ERR_...;` literally and reported SIX
codes as never returned. Five of the six are produced by an assignment or a
ternary -- `err = FZN_RATCHET_ERR_HASH;`, `... : FZN_COMMITMENT_ERR_MISMATCH`
-- and are tested. Only one of the six was real.

**A five-in-six false positive rate, all in the direction that makes the
finding look bigger**, which `evidence.md` names as the error least likely to
be questioned. What caught it was reading each hit against the source before
writing any of them down -- the same discriminator as sec 60's correction, and
the same one that section says to distrust: the cut, not the enumeration.

## 62. Nine claims that a test could not exist, 2026-09-04

`evidence.md` argues for sweeping a document for claims of IMPOSSIBILITY
rather than of absence: they are rarer, so the precision is better, and the
harm is worse in kind -- an absence claim that has been closed wastes a
reader's time, while **an impossibility claim that was never true tells the
next person not to write a test that would work.** Its workspace score is one
confirmed deterrent in thirty.

Run over this file -- "no test can", "cannot be tested", "untestable",
"invisible to any check" and their neighbours -- **nine hits over eight
distinct claims, and one of the eight is live.** The correction is in sec 11,
where the sentence is, rather than here.

    sec 11   grantor-against-previous-grantee cannot be near-missed   LIVE
    sec 5h   a design that assumed it could would be untestable       hypothetical
    sec 11   dead code that cannot be tested is not depth             a principle,
                                                                     and applied
    sec 22   short read, short write, and that fsync reaches disk     a real limit:
                                                                     needs a signal
                                                                     mid-syscall or
                                                                     a power cut
    sec 22   data fsync ordering, and rename over write               the same limit
    sec 44   no compile-time distinction between the two types        measured, and
                                                                     the next line
                                                                     says it was
    sec 55   `/proc/<pid>/status` past 8192 bytes                     limit, and the
                                                                     remedy is in
                                                                     the next line
    sec 61   FZN_BLOB_ERR_FULL "cannot happen to a caller who is
             not trying"                                             says outright
                                                                     it is not a
                                                                     testability
                                                                     claim

**Seven of the eight are fine and the reason is the same one `evidence.md`
gives: the deterrent is the impossibility claim with NO REMEDY BESIDE IT.**
Every one of the seven is followed within a sentence or two by the workaround
it motivated, the argument it carries in prose instead, or the measurement
that settled it. The live one is the only one that stops there.

**THE FIRST VERSION OF THIS TABLE PUT THREE OF THEM IN THE WRONG SECTION** --
sec 5h as 5g, both of sec 22's as 21 and 22, and sec 44's as 33 -- because the
sections were read off line numbers taken before this session's own edits had
moved them. Nothing in the finding changed and the table would have been
quoted anyway, which is the whole hazard: a row that sends a reader to the
wrong section costs them the search and tells them nothing is there. Rebuilt
by walking the file and carrying the last heading seen, which is the same
"ask the artifact" move sec 60's correction turned on its own population.

**Recording the eight is the point of writing this down at all.** A sweep with
no record licenses nothing: somebody re-runs the same grep in a month, reads
the same nine lines, and cannot tell which were looked at. The lens is spent
for this document until somebody adds a sentence of that shape.

**One note on running it here.** This document is a LOG rather than a STATUS
document -- entries open by stating a gap and close by fixing it -- and
`evidence.md` says the absence sweep is close to worthless against that genre
for exactly that reason. The impossibility sweep survives it, and the nine
hits above are why: a claim that a test cannot exist is not the setup sentence
of a remedy, so the genre does not manufacture them.

## 63. One module list in three places, two of them ungated, 2026-09-04

Fixing sec 11's stale counts turned up the same inventory twice more, and all
three were wrong in the same direction:

    project.md sec 11   14 rows   ungated    fixed, and now gated
    project.md sec 8     7 rows   ungated    reframed: it is the scope
                                             decision, not the inventory
    README.md            7 rows   ungated    replaced by a pointer to sec 11

The tree has **twenty** modules. Sec 8's table dates from a rewrite whose own
note says it was redone "because five of its seven rows were stale" -- so it
had drifted once as an inventory before drifting again. The README's was
written 2026-08-18 and edited twice on 2026-09-01 without either its table or
its "25 binaries -- suites and eight fuzz harnesses" being re-counted; on
2026-09-04 that is 74 and 14.

### Why the gate saw none of them

`style_gate.py`'s `doc_paths` skips a token ending in `/`, because a directory
is not a file to open. **Every row in all three tables named a directory**, so
a gate that has been running over this document on every build was inspecting
none of them.

**And the number that would have said so is three days old, not "all along"**
-- the first version of this sentence claimed the latter and was checked
rather than published. The gate began printing its path count beside its
verdict in `86a8b8e` on 2026-09-01, which is the change `style_gate.py`'s own
docstring credits to fuzzypickles noticing their tables held no paths on the
first run after it landed. Sec 8's directory table has been there since
`8c9e3e1` on 2026-08-14. So for eighteen days there was nothing to read, and
for three days there was a number nobody here read.

That is the same blind spot sec 11's own fix walked into an hour earlier: the
first version of its replacement table wrote `blob/` and the path count did
not move. **A table of directories reads exactly like a table of files and is
checked by neither the gate nor the eye.**

### What was done, and what was deliberately not

One inventory, in sec 11, naming a header per module so the gate reads it. The
other two point at it rather than repeating it -- which is the rule this tree
already applies to counts, arriving at prose: *the remedy for a fact you quote
often is to stop quoting it.*

**Sec 8 keeps its table**, because it is not a duplicate once it is read
correctly: its rows carry what each module is FOR and which half of the work
is situ's, which is the scope argument this document was written to make. What
it needed was a sentence saying it is that and not an inventory. **Deleting it
would have thrown away the argument to fix the label.**

**And the README does not get a gate**, because the shared `style_gate.py`
takes a single `doc_file` and pointing it at a second document is a change to
a tool sixteen other projects carry. Signalled rather than made, per
`harmonization.md`; the pointer costs nothing and the duplicate is gone
either way.

## 64. The harness run in full, 2026-09-04

    83 entries    79 caught    4 survived    0 hung    0 pattern misses

**All four survivors are the four in `EXPECTED_SURVIVORS`**, each carrying its
reason in `tool/sabotage.py`: the manifest's zeroed signature field (sec 36),
`seal.c`'s refused-build wipe, which that file's own 2026-08-28 re-measurement
made prospective, `relay-hop-header-min`, redundant with a bounds check in
situ's generated code and kept because that code lives in another repository,
and `peer-linux-trim-call`, whose logic is held and whose placement no test can
reach. No unexpected survivor, which is the result the harness exists to
produce.

**The date is the point of writing this down.** The previous full run was at 76
entries on 2026-09-03; seven were added on 2026-09-04 and each was verified
alone with `--only` as it was written, which says nothing about the other 76
after three test files had changed under them. A per-entry check is not a
sweep, and the sweep is what licenses "every guard is held to account by
something" -- the line the harness prints and this document quotes.

**All seven new entries were caught in the full run**, each at a named check:
the stage-2 gate and its scoping at `manifest_test.c:2269` and `:2311`, the
three withdrawal drains at `:2543`, `:2568` and `:2592`, the two blob capacity
bounds at `blob_test.c:792` and `:808`, and the decision layer's forwarding
through the network harness.

**What a green sweep does NOT say**, since the run is quoted more often than it
is read: `runtests` stops at the first binary that fails, so the harness
reports which suite caught a mutation first and not which was written for it.
It licenses "held by something", which is its claim; a per-guard attribution
needs the `--only` run that each entry got when it was written.

**Cost, so the next session can size it:** about twenty-five minutes for 83
entries on a machine at load 80 to 110 from other sessions, because a caught
mutation fails fast -- `runtests` exits at the first binary that catches it --
and only a survivor pays for the whole suite. It is far cheaper than the
83 x `make test` the arithmetic suggests, and cheap enough to run after any
pass that adds entries.

## 65. The one line in `revocation.c` that had never run, 2026-09-04

`make coverage` re-measured after the sanitized suite came back clean. Sec
11's table was three days old; the diff against it is there. One file had
slipped: **`chain/revocation.c`, from 94.20% of 138 branches to 89.72% of
214** -- the withdrawal work of secs 56 and 57 added 76 branches and the
tests did not follow all of them.

Turning that percentage into a list found **one never-executed LINE** in the
file, and it is not a defensive guard:

    if (!fzn_ct_memeq(id, entry->id, FZN_REVOCATION_ID_LEN) &&
        fzn_ct_memeq(fzn_revocation_supersedes(record), entry->id,
                     FZN_REVOCATION_ID_LEN))
            memcpy(entry->id, id, FZN_REVOCATION_ID_LEN);

A reissue chained to the revocation this store already holds advances the
stored id to the new record. Every other uncovered branch in the file is a
null-argument check.

### Why nothing reached it, which the code's own comment predicts

The branch needs a store holding the pair as LIVE and a record that is
neither the same one nor unchained. The withdrawal cases build a WITHDRAWN
entry, the duplicate cases re-admit the SAME record, and the chaining cases
exercise the REFUSAL. **This is the one arrangement that changes the store
while leaving the authorisation answer alone** -- the pair was revoked and
stays revoked -- which is exactly why the comment there opens by saying it
"looks like nothing worth storing".

### What it costs is worse than the comment says, measured

The comment states the consequence as *"the pair would then be revocable,
reissuable, and unwithdrawable"*. Removing the line and running the new case
gives three failures, and the first two are a different and worse defect:

    a withdrawal naming the SUPERSEDED revocation was applied
    and it un-revoked the pair on the strength of it
    the issuer's withdrawal of its own CURRENT revocation was refused

**Only the third is the documented cost.** The first two are a FAIL-OPEN: with
the stored id left at the superseded record, a genuine signed withdrawal of
THAT record still matches, so replaying it un-revokes a pair the issuer has
since re-revoked. A revoked host is authorised again on the strength of a
record that withdrew something else.

That is the hazard sec 57 refuses at the manifest level -- *"replaying an old
signed manifest would un-revoke everything the issuer added since"*, and the
replay needs no key because the signature is genuine -- arriving one layer
down, at a single record, and defended by this line. **The line is not
bookkeeping about which id is current; it is what makes `supersedes` a
ratchet.**

### Held now

`test_a_reissue_over_a_live_revocation_advances_the_id`, with the superseded
withdrawal as its control: asserting only that the current withdrawal is
admitted would pass against a store that admits any withdrawal at all, and
the pair of assertions is what shows the id MOVED rather than that the store
is lax. `tool/sabotage.py` carries it as `rev-reissue-advances-id`, watched
failing.

### The coverage diff, which is why this was looked for at all

Sec 11's table, re-derived 2026-09-04 against 2026-09-01: **fifteen files
improved, two slipped, eleven unchanged**, over the 28 rows that table held. The improvements are the last
three days' work, this session's included -- `persist.c` +11.11,
`constant_time.c` +12.50 to 100%, `wire/seal.c` +5.49, `manifest.c` +2.12,
`blob.c` +1.86. The two that slipped both GREW: `revocation.c` above, and
`local/peer_linux.c` by two branches for sec 55's whole-lines fix, whose
placement `sabotage.py` already records as unreachable.

**A file that slips while growing is the signal; a file that slips while
static would be a deleted test.** Neither is visible from a single
measurement, which is the argument for re-deriving the table rather than
quoting it -- and the table now carries the date it was taken.

**AND THE FIRST DIFF WAS WRONG, in a way worth keeping.** Sec 11 holds TWO
coverage tables -- the current one and the superseded 2026-08-18 one it
records going stale -- and a parser taking the LAST row per file compared
`peer_linux.c` and `random_linux.c` against the older, smaller tree. It
reported `random_linux.c` as having slipped when it has not moved at all.
Caught by counting the rows parsed, 28 against the ~15 the table shows, which
is `evidence.md`'s *check the membership, not the count* pointed at my own
instrument.

## 66. A clamp for a state the line above it forbids, 2026-09-04

`record/journal.c`'s `fzn_journal_anchor` ended with

    e->received = seq;
    if (e->applied > e->received)
            e->applied = e->received;

and the assignment was the only never-executed line in the file. **It is
unreachable, not merely unheld**, which is the difference from sec 65.

### The proof is four lines up

An anchor refuses to move backwards -- `if (seq <= e->received) return
FZN_JOURNAL_ERR_DUPLICATE;` -- so `received` only ever increases. `applied` is
raised only by `fzn_journal_confirm`, which refuses anything above `received`
with `FZN_JOURNAL_ERR_NOT_RECEIVED`. By exhaustion over the three writers,
`applied <= received` holds at every point; at the clamp the state is
`applied <= old_received < seq == received`, strictly. The condition is false
by construction.

**`record_guided` is the independent witness.** Its model mirrors a successful
anchor as `m.received = seq` and does NOT clamp its own `applied`, then
asserts `pending == received - applied`. Had the clamp ever fired, model and
code would have diverged. It has now run 200,000 cases without doing so.

### Deleted, on this project's own precedent

Sec 11 records the same call over `admit_first`'s unreachable bound check:
*"dead code that cannot be tested is not depth, and leaving a wrapping
multiplication in the file for a reader to puzzle over is worse than not
having it."* The clamp is the same shape -- a repair for a state the function
above it refuses to create.

**What replaced it is the argument, not nothing.** The invariant is stated
where the clamp was, because whoever later lets an anchor move backwards has
to come here anyway, and a repair firing at one instant would not have saved
them: a caller that pokes `applied` past `received` in its own entry array has
already broken `fzn_journal_pending`, which underflows to something enormous,
and no anchor it may never make repairs that.

**The prediction was wrong and that is worth keeping.** This line was picked
out before it was investigated as the likeliest sibling of sec 65's defect --
same shape, only dead line in a file at 98.73%. It is the opposite: sec 65's
line was reachable and unobserved, this one unreachable and therefore
unobservable. **A shape match is a reason to look, not a finding**, and the
two outcomes look identical from the coverage report that produced both.

## 67. The sweep that walked one family of enums, 2026-09-04

`wire/test/err_str_test.c` exists so that an error code's TEXT is read by
something. It walked **17 renderers; the library defines 26.** Nine were
outside it, and with them **33 arms that had never rendered** -- a third of
every never-executed line in the library.

### The signature is clean, which is what makes it worth recording

    in the sweep      16 error enums, every one counting DOWN from OK = 0
                      plus fzn_peer_verdict_t, which counts up
    outside it        blob, authz, prekey, ratchet, agree, session,
                      spool, persist, tree -- every one counting UP

**The sweep covered the `0, -1, -2` family entirely and the `0, 1, 2` family
not at all**, and the reason is a hand-written `step` column. The walk itself
is derived and always was -- it renders `0, step*1, step*2 ...` until the
fallback answers, which is why the ARM lists never rotted. The ROSTER was a
literal table, so a table of one family looked complete, and a row added with
the wrong sign would have been walked away from its own enum and reported as
rendering one code.

**It is not the usual "written before those modules existed" excuse.** The
test was last edited 2026-09-03, after all nine modules had landed, and none
was added.

### What was actually lost, which is the wording and not the refusal

**No enumerator is dead in both directions.** Every one of the 33 is genuinely
produced on a live path and genuinely reaches consumers -- the refusals are
covered. What had never happened is anyone reading the sentence that comes
back. `FZN_RATCHET_ERR_IN_PLACE` is raised, and `tool/consumer_check.c`
asserts on it -- as an integer. Its text, *"advanced a live chain in place:
derive, verify, then commit"*, a sentence that tries to teach the caller the
fix, had never been produced by any run.

**And `fzn_spool_err_str` is worse than untested: nothing calls it.** Two hits
in the whole tree, the definition and the declaration. A consumer holding a
`FZN_SPOOL_ERR_*` has no path in this tree that turns it into a sentence.
Recorded rather than fixed; the sweep calls it now, which is coverage and not
use.

### Fixed in three parts, and the third is the one that lasts

**The nine rows**, with a predicted count stated before the run: 461 checks
over 26 renderers, from `2 + n(n-1)/2` per enum. It printed exactly that,
which is what shows the roster is complete rather than merely bigger.

**The direction is derived**, by probing both sides of zero: exactly one of -1
and 1 must render something other than the fallback, and an enum answering in
BOTH is mixed-sign and refused rather than half-covered. The hand-written
column is gone.

**A `make style` gate holds the roster against the library**, and it creates
no second list. The left side is `nm --defined-only` over `CORE_SRCS`'s
objects filtered to `fzn_*_err_str` and `fzn_*_verdict_str`; the right side is
the `SUBJECTS[]` name literals grepped out of the test itself. A renderer in
one and not the other is named. It carries the control this tree insists on --
an empty left side is a refusal, not a pass -- and it was watched failing:
removing the `fzn_spool_err_str` row gives *"style: error renderers the sweep
does not walk: fzn_spool_err_str"*, exit 2.

That is the `-Wswitch` argument one level up. The compiler names an enumerator
with no case; this names a renderer with no row.

### What it still does not do, said plainly

The sweep checks distinctness, non-NULL, and that the fallback is reached. **It
never compares a rendered string to an expected one.** Coverage moves from 104
dead lines to about 37 and the prose remains something no assertion has read:
swap two codes' texts and every check still passes, because both are still
unique and neither is "unknown". Pinning the wording means a per-arm expected
text, which is the hand-maintained list this test was built to avoid. **That
tension is not resolved here**, and it is the honest residue: this closes the
`-Wswitch`-shaped half and leaves `evidence.md`'s half open.

## 69. The harness at 94, and what three runs in a night showed, 2026-09-04

    94 entries    90 caught    4 survived    0 hung    0 pattern misses

**The four survivors are the four in `EXPECTED_SURVIVORS`, unchanged across
all three runs tonight.** Sec 64 names them and their reasons; nothing here
supersedes it. What this run adds is the growth:

    83 entries    79 caught    4 survived     the state sec 64 recorded
    84            80           4              after rev-reissue-advances-id
    94            90           4              after the provisioning legs

Ten added, ten more caught, the exception set untouched. **That is the shape a
growing harness should have** -- the denominator moves and the exceptions do
not -- and it is worth stating because the alternative reads identically in a
tally: a survivor set that grows alongside the entries is a table quietly
acquiring waivers.

### The new entries pin rather than cover, and the table should say so

Nine of the ten were caught by suites that predate this week -- `chain_test`,
`persist_test`, `prekey_test`, `ratchet_test`, `spool_test`, and the relay,
seal and sync suites. `runtests` stops at the first failing binary and the
per-module suites run before the composed ones, so those guards were already
held and the entries pin them.

**One is first-held by the new file**: `persist-pinned-anchor-refused`, which
is the `persist.c` line sec 65's coverage sweep found had never executed.
Every other fixture in the tree packs an ADOPTED trust, so a bad body only
ever reached the other arm; `sim/test/provision_test.c` has the only genuinely
pinned anchor there is.

So the ten do not make the provisioning legs look better than they are. What
those legs added is one line nothing could reach, and a second holder for the
rest.

### Predictions stated before the run, which is what made them worth making

Three, written down before it started: the same four survivors and only those
four; the new entries reporting per-module catchers rather than
`provision_test`; and no pattern misses. All three held.

**The value is not that they held.** It is that a prediction made afterwards
cannot fail, and this file has spent a week recording the cost of comfortable
explanations that arrive after the evidence. A tally read against nothing is a
number; a tally read against three stated expectations is a test of whether
the harness is understood.

### The cost is the machine, not the table, and sec 64 said otherwise

Sec 64 priced it at "about twenty-five minutes for 83 entries on a machine at
load 80 to 110". Measured here: **94 entries in 16 minutes 22 seconds**, with
load falling from 103 to 8 across the run. Thirteen per cent more entries in
thirty-five per cent less time.

So the entry count is not what sizes this. A caught mutation fails fast --
`runtests` exits at the first binary that catches it -- and what varies is how
long each of those binaries takes under whatever else the machine is doing.
**A sweep deferred for load is deferred for the right reason**, and one run at
a bad moment is not evidence about what it costs at a good one.

## 70. Two samples of one number, and the difference nobody read, 2026-09-04

The post-run orphan check `running-code.md` asks for turned up a beerssh
process reparented to init, and it was flagged to them as a 3h40m orphan. **It
was four minutes old and perfectly healthy.**

`ps` prints `etime` as `[[DD-]HH:]MM:SS`, so `04:56` is four minutes
fifty-six seconds. Read as hours and minutes it becomes a four-hour orphan.
That much is a mundane unit slip.

### What is not mundane is that the disproof was already in hand

The column was sampled **twice**, ninety seconds apart: `03:02`, then `03:40`.
Under the wrong reading those two observations are thirty-eight minutes apart,
which is impossible for measurements taken a minute and a half apart. **The
delta between two of my own numbers contradicted my interpretation of both,
and I never put them side by side.**

That is the transferable part, and it costs nothing: **two samples of one
quantity test the reading of it.** A single value can be misread in any unit
and looks fine; two values carry a difference, and the difference has to agree
with the wall clock. Nobody looks, because each reading individually seems
self-explanatory.

### And the discriminating command was run, and its answer not read

`ps --ppid 20900` was issued -- the right question -- and returned three
unrelated shells aged twenty-two days, none of them a child of that pid. That
output did not answer the question it was asked, and the check moved on as
though it had. The real chain was `sh -c` -> `make` -> `check-ci.sh` ->
`docker run`, intact and visible the whole time.

So both instruments were used and neither was read: one whose two readings
disproved each other, and one whose output did not match its own filter. This
is `evidence.md`'s *a failing check is not evidence either* with the failure
in the READING rather than in the probe.

### The error is symmetric, and the dangerous direction is the other one

Over-reporting cost one cross-tree message and one command of somebody's time,
and beerssh's reply was that they would rather have it: *"the cost was one
command"*. Reading a genuine `3:40:00` as three minutes forty would dismiss a
real orphan -- which is the 693 GB incident's exact shape, three orphaned
binaries found hours after the fact. **A session doing the orphan check is
reading that column under precisely the conditions that make the mistake
expensive**, and the cheap direction is the one that happened here.

### What replaced the reasoning

For containers, `ps` is the wrong instrument entirely: PPID 1 is beerssh's
DESIGN -- they `nohup` the supervisor so that a harness-side stop cannot kill
it while the container carries on, which is the failure `running-code.md`
records from that tree. Their own check is
`sg docker -c 'docker ps -a --filter name=bssh-check-ci'`, and the `--name`
exists because docker's generated names make a stranded container and a live
run indistinguishable.

The general form is this file's own habit arriving from outside: **ask the
object you mean.** A process table is a proxy for a container, and it was
wrong about the one thing being asked.

### Two additions from beerssh, one of them theirs to have made

**They made the same class of error three times the same night, on the other
axis.** Mine was misreading a value; theirs was measuring the wrong set --
`pgrep -f 'python3 tool/sabotage.py'` matching a runner in another tree,
`pgrep -x make` returning makes from three unrelated builds, and all of it
also matching their own shell, because the pattern sits in the command line of
the process doing the matching. That last is the self-match
`running-code.md` documents for watchers, arriving inside the check written to
find watchers. Their discriminator is `readlink /proc/PID/cwd`, since every
tree runs the same script name.

**The remedies rhyme, and that is the point of recording both:** the second
observation I did not compare, and the cwd they did not read, were each
already in hand. Neither case needed anything re-run.

**And a fix for the instrument rather than the reader, offered untested.**
`ps -o etime=` omits the units it is using, which is the whole ambiguity;
`ps -o etimes=` gives seconds as a plain integer with no field structure to
misparse. It cannot be read as hours by accident, and a comparison between two
samples becomes arithmetic instead of interpretation. **Recorded as untested**
-- beerssh said so themselves, having told rather than adopted -- and it is
the better shape than either of the disciplines above, because it removes the
reading rather than asking somebody to do it carefully.

## 73. A correct assertion nobody could check, and the hole in its replacement, 2026-09-04

The object tags were asserted PAIRWISE, and the block was complete. It was
replaced anyway, and the replacement had a hole that the original also had and
that neither of them would have shown.

### The block was right, and only a script could say so

Seven tags need 21 clauses. Six of them were added by hand on 2026-09-04 when
`FZN_OBJECT_PROVISION` was allocated, and the natural check -- read them --
does not work: nobody can hold 21 unordered inequalities and see which one is
absent. So it was checked by parsing the header, enumerating `C(7,2)`, and
differencing.

    pairs needed 21, pairs asserted 21, missing none

**That result is not the finding. The method is.** A correct assertion that
can only be verified by writing a program to verify it is one that will be
wrong later and look exactly the same, and the growth is the reason: the
clauses go up as the square while the thing they protect goes up linearly. The
eighth tag needs seven more, and **a partial addition compiles, passes, and
looks finished.**

### Reported by fuzzypickles, who paid for it in the other direction

Their account, in their words rather than my reading of it: they gave a notes
frame `sub_type` a number an asset-key ack already had, in a set declared
across two hundred lines "so it is nowhere visible at once". Every asset-key
ack routed into the notes handler and was refused; the sharer's owed-key
ledger never retired and would have re-sent for ever. Their unit gates all
passed, because **a value clash is not a type error**, and one end-to-end
scenario out of 74 caught it -- the one that happens to exercise both
families. Their fix is a `_Static_assert` chain over all eleven sub_types,
strictly increasing, "so it states the rule as well as checking it".

That last clause is what a pairwise block cannot do. Tags here ARE allocated
in ascending order, and only the chain says so; distinctness is the weaker
property that happens to follow. An out-of-order allocation is now refused
rather than accepted, which is deliberate: having to come to this file and
argue for reusing a retired number is the price of an assertion a reader
checks by running one finger down two lists.

### Then it was sabotaged, and the chain has the same hole pairwise had

    duplicate value, PROVISION = 133                      caught
    out of order, PREKEY = 134 and PROVISION = 132        caught
    an eighth tag appended, chain not extended            NOT caught

**A chain says nothing about a tag it does not name.** An enumerator appended
past its end compiles in silence -- which is fuzzypickles' own failure, a
value added to a set nobody can see whole, surviving the fix written for it.
Pairwise had the identical hole and nobody had asked, because the question
only arises once you try to make the check fail.

`evidence.md` is blunt about this and it earned its bluntness here: a check is
untested until it has been seen to fail, and running a probe against a
known-good case says nothing about whether the gate would have spoken if the
answer had been different. Two of three sabotages went red immediately, which
is exactly the amount of reassurance needed to stop before the third.

### What closes it is a number the compiler writes

`FZN_OBJECT_NEXT_FREE`, last in the enum with no explicit value, and one
assertion pinning it to `FZN_OBJECT_PROVISION + 1`. Any enumerator added
anywhere moves it, that assertion fails, and whoever added the tag is standing
three lines from the chain they have to extend. All three sabotages now fail.

**And the positive control matters as much**, because a check that refuses
everything is not a check: an eighth tag added correctly -- value 135, chain
extended, marker re-pinned -- compiles clean, and that was run rather than
assumed.

It also removes a second thing to remember. The one-byte bound used to name
the newest tag, so allocating a tag meant renaming it; it names the marker
now, and `FZN_OBJECT_NEXT_FREE <= 256u` says every real tag fits a byte
without caring which is last.

**It is free HERE and might not be elsewhere**, which is worth stating rather
than recommending blind. This enum's type is declared and used nowhere -- the
tags travel as the single byte a transcript gives them -- so there is no
exhaustive `switch` to grow a `-Wswitch` arm. In a tree where such an enum IS
switched on, the marker costs an arm per switch and that trade belongs to
whoever owns it.

### The generalisation, which is not about enums

Three checks in this tree now have the same shape and it is worth naming
once: **an assertion whose completeness cannot be seen is an assertion that
will rot, and the remedy is to make the artifact witness itself rather than to
be more careful.** The marker is the compiler counting for us; `sabotage.py
--verify` refusing a library source with no entry is the same move; so is the
renderer gate comparing `nm --defined-only` against the table. In every case
the thing that would have been checked by a diligent person is instead checked
by something that cannot forget.

## 74. A value clash is not a type error, so a gate has to be, 2026-09-04

Sec 73 answered fuzzypickles' clash for the object tags, with a chain and a
compiler-computed marker. That covers one enum. This covers the other 37, and
the ones nobody has written.

### The sweep, and the two things wrong with its first version

Every enum in the tree, parsed, looking for two enumerators sharing a value.
First answer: **32 enums, zero clashes.** Both halves were wrong in the way
this document keeps recording.

**The detector was uncontrolled.** A parser that matched nothing would have
printed the same zero. Injecting a duplicate into `fzn_provision_err_t` and
requiring it to be found took one command and is the difference between a
measurement and a sentence.

**The population was short.** A raw count of `enum` in the tree gave 41
against the sweep's 32 -- nine enums the sweep never saw, because the pattern
required `typedef enum ... { ... } name;` and because an enum whose values
were not integer literals was **silently skipped**. That second one is the
worse of the two: a method that drops what it cannot read reports a clean
tree in exactly the words a clean tree uses.

Rewritten to accept any spelling and to REPORT what it cannot evaluate:
**38 enums, none skipped.**

### And the reconciliation of 41 against 38, which nearly became a finding

Three unaccounted, so they were looked at rather than assumed away -- and all
three are bare `enum op` TYPE REFERENCES in one test's function signatures,
matched by an opening-brace pattern that ran forward to the next `{`. There
are 38 enum declarations in this tree and there always were.

**The instrument inflated, which is the direction to expect and the one
hardest to question.** Had the reconciliation been skipped, the report would
have said "three enums unexamined" -- a gap that does not exist, in a
document about gaps that do.

### The one hit, and why it is not one

    sim/test/provision_test.c   POSITIONS and REQUESTS both 4

Two array-size constants in a test that happen to be the same size. Not a tag
space, no dispatch, nothing routed. It is waived -- **by file, enum, value AND
both names**, so a different clash arriving at the same place stops matching
the waiver and fires. A file-level exclusion would have absorbed it silently,
which is how a waiver list becomes a switched-off gate by instalments.

### So it is a gate rather than a result

`tool/enum_gate.py`, run by `make style`. A sweep that found nothing today is
worth almost nothing; the same sweep run on every commit is worth what the
next clash would have cost. It refuses two things:

    two enumerators sharing a value, unless waived by name
    an enum it could not evaluate

**The second is what keeps the first honest**, and it is the direct lesson of
the first version's nine silent skips.

**Its control is inside it and runs first.** Two fixtures, one clean and one
with a deliberate clash; if the clash is not found or the clean one is
flagged, it prints that the control failed and reports nothing about the tree
at all. A control that lives beside a tool is run when somebody remembers.

Four sabotages, each watched failing before this was written:

    a real clash in provision/provision.h        caught
    an enum with a computed initialiser          refused as unevaluated
    the clashing control made clean              refused to report anything
    the waiver's names changed                   fired on the waived case

### What it costs, stated rather than discovered

**Enum initialisers must be integer literals**, or the gate refuses the file
and says so. Nothing in the tree does otherwise today, and a future
`FZN_X_MAX = FZN_X_LAST` would have to become a literal or teach the tool.
That is a real constraint bought deliberately: the alternative is evaluating
expressions in a parser nobody has reason to trust, and a tool that guesses
wrong about a value is worse than one that declines to guess.

**And it is not in `style_gate.py`.** That file is the shared tool spread
verbatim into sixteen trees from `~/.claude/tool/`, and changing it is a
cross-project pass rather than something to do while standing in one project
-- `harmonization.md` is explicit. This is fuzznet's own gate in fuzznet's own
`tool/`, beside `sabotage.py`. If the shape turns out to be worth sixteen
trees, that is a signal and not a commit.

## 75. The one seam that cannot report a failure, 2026-09-04

`fzn_aead_ops.seal` returns `void`. Every other seam in this library returns
an int and says which way round it is -- and `session/commitment.h` records
that the hash seam was fixed precisely because it did not. This one has no
result to describe, which reads as an omission and had never been examined.

### The lens, and where it came from

Not from a sweep. From my own near-miss: `provision.c` was written with both
signer calls inverted, because `chain.h`'s seam returns **nonzero for
success**, which is not C's usual convention for an int. Caught by reading
before compiling, and the question it left is the lens -- **a consumer fills
five of these vtables; do they all agree?**

    fzn_sign_ops.sign / .verify     int, nonzero success
    fzn_hash_ops.hash               int, and the header says so explicitly
    fzn_agree_ops.*                 int, "Non-zero on success"
    fzn_random_ops.fill             int, and `out` is unusable on 0
    fzn_aead_ops.open               int, and must not write `text` on 0
    fzn_aead_ops.seal               void

They agree. The odd one out is not a disagreement about convention but the
absence of one.

### What a failing seal actually does, measured

`session/aead.h` constrains `open` in four careful lines -- verify before
writing, never hand back unauthenticated plaintext -- and says **nothing at
all** about `seal` failing.

Both callers copy the plaintext into the caller's buffer and encrypt IN
PLACE. `wire/seal.c:610` for a frame's capability and payload;
`blob/blob.c:168` for a leaf. So a `seal` that does nothing leaves the
plaintext exactly where the ciphertext was going to be, and neither caller
can tell: `fzn_seal_build` finalises the tag and returns OK,
`fzn_blob_leaf_seal` sets `*out_len` and returns OK.

Probed with a `seal` whose body is `(void)` casts and nothing else:

    fzn_seal_build returned      : 0 (ok)
    bytes the caller will send   : 168
    PAYLOAD in the clear         : YES
    CAPABILITY in the clear      : YES

**It is not a denial of service, it is a confidentiality failure on the
sending side**, and the sender has no way to learn it happened. The blob case
is worse than the frame case, because a sealed leaf is what a seeder hands to
strangers by design, where a frame at least goes to one peer who will refuse
it on the tag.

### The mechanism is IN-PLACE ENCRYPTION, not the void return

Corrected by fuzzypickles the same day, and the correction is worth more than
the finding it sharpens. Their measurement of their own tree: `crypto_aead_lock`
reads from `plaintext` and writes to `out_buf + NONCE_LEN`, **separate
buffers**, so a no-op seal there would leave `out_buf` unwritten -- *"garbage
sent rather than the message sent in clear. Still a bug, and a much less bad
one."* They also report `fzn_blob_leaf_seal` unused in their tree and all 13
`fzp_prekey_channel_seal` call sites reading the return.

So a void return alone is not what puts plaintext on the wire. **A void return
over an IN-PLACE seal is.** The two have to be named together or the next
reader closes the wrong one.

And their own conclusion about themselves is the part to carry: *"That is luck
rather than design. Nothing says the buffers must stay separate, and the
obvious optimisation -- seal in place, drop a copy -- would hand us your
hazard with no diagnostic anywhere."* They have written it down beside the
function, because a load-bearing property nobody recorded is one somebody
removes while tidying.

### Which makes it structural here rather than a call-site choice

The seam takes ONE text pointer:

    void (*seal)(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                 const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                 size_t aad_len, uint8_t *text, size_t text_len,
                 uint8_t tag[FZN_AEAD_TAG_LEN]);

**`text` is read and written, so the seam is in-place BY SIGNATURE.** Neither
caller chose it and neither can decline it: for an in-place AEAD the plaintext
must already be sitting in the buffer that will hold the ciphertext, which is
why both of them `memcpy` it there first. fuzzypickles' escape is not
available to fuzznet's own call sites while the seam looks like this.

**So there are two ways to close it, not one, and the holder should see
both.** Give `seal` an int to return, or give it separate `in` and `out`
pointers. The first is one line in each of three consumers' vtables and a
check at two call sites here; the second changes every call site and both
buffers' sizing, and only downgrades plaintext to garbage rather than
reporting anything. **The cheap one is also the strictly better one**, which
is not the usual shape of that trade and is worth saying plainly.

**And a stale vtable would not slip through, which was fuzzypickles' specific
worry.** Measured rather than assumed: initialising an `int (*)(...)` field
with a `void (*)(...)` function is `-Wincompatible-pointer-types`, an ERROR by
default in gcc and not a warning, exit 1 with no flags at all. A consumer who
missed the change would fail to build rather than ship something in the
clear.

### The tree already knew this hazard, through the other door

`wire/test/seal_test.c` asserts that a REFUSED build leaves no capability in
the caller's buffer, and its comment is exact about why: *"Sealing happens in
place, so the capability and payload are copied into the caller's buffer in
the clear before the seal runs ... A caller reusing the buffer, or ignoring
the return, holds or transmits it."*

That is this hazard, recognised, tested, and closed -- **for the path that
returns an error.** The path that returns OK was not considered, because
until you ask whether `seal` can fail there is no such path.

### Nothing is exposed today, and the distinction is the point

Monocypher's `crypto_aead_lock` returns void and cannot fail, and it is what
all three consumers use. **The seam exists so that they need not.** A token
that is absent, a key handle that has expired, a hardware engine returning an
error -- all things a consumer's own backend does and this signature cannot
express.

Same shape as `wire/frame.situ`'s version byte, which says of itself: *"It is
SAFE TODAY AND LATENT, and the distinction is the whole reason this comment is
here."* Written at the declaration, because that is what the person adding a
backend will be looking at.

### What was done, and what was not

**Done: the precondition is stated**, in `session/aead.h` beside the
declaration. Until the signature says otherwise, an implementation whose
sealing can fail must ABORT rather than return -- returning is
indistinguishable from success, and the difference is whether the plaintext
goes on the wire. `evidence.md`: an unstated precondition and an absent one
look identical from outside, and the second reader pays either way.

**~~Not done: the signature.~~ DONE 2026-09-04 on the holder's instruction --
sec 85 has the change, the two call sites' different treatment of the
plaintext, and a claim it caught me writing into the source before checking
it.** What follows was the case for it.

`void (*seal)` to `int (*seal)` is a change to
this library's public API. It breaks every consumer's vtable -- three of them,
each needing `return 1;` -- and fuzznet is at 0.1.0 with consumers building
against it. The option, its cost and whose it is: change the seam so a failure
can be reported; roughly a one-line edit in each of three trees plus a check at
two call sites here; and it is the holder's, being an API break rather than an
implementation detail.

**A mitigation inside the current signature was looked for and there is
none.** Nothing can distinguish a `void` function that worked from one that
did not: comparing the buffer before and after is unsound, since a correct
AEAD may in principle produce any bytes, and checking the tag is non-zero is a
heuristic that a failing backend could satisfy by leaving old bytes behind.
The seam has to report, or nobody can know.

## 76. A status reported and dropped, and a detector that lied about where, 2026-09-04

Sec 75 found a failure that CANNOT be reported. This is the same class one
step out -- a failure that is reported and thrown away -- and the answer is
zero, which took two attempts to establish and one of them was actively
misleading.

### One in five, and it is the one already carried here

    status-returning functions           131
    library sources discarding one         0
    tests and tools discarding one        82

**No library source in fuzznet throws away a status.** Controlled: an ignored
`fzn_provision_open` added to `provision/provision.c` is found, at the right
line. Without that the zero is a sentence rather than a measurement.

### The detector was wrong twice, and the second way was worse

**Too loose.** The first pass matched any line beginning with a call, which
caught every continuation line of a multi-line `if` -- 133 hits, most of them
`fzn_ct_memeq(...)` as the second operand of a conjunction. Fixed by requiring
the previous non-blank line to END a statement.

**And it reported true faults at false addresses.** It stripped comments and
then computed line numbers from the STRIPPED text, so every number pointed
somewhere else. Two of them were opened as candidates -- `chain/chain.c:82`
and `chain/revocation.c:535` -- and both turned out to be ordinary code that
had nothing to do with the hit. The fix is one line: blank comments out with
spaces and keep the newlines.

That is the sharper half. A detector that over-matches costs a reader one
look; **a detector that points at the wrong line costs them the look AND the
belief that the tool knows where things are.** `evidence.md` says to send the
quoted phrase rather than the line number, and this is why -- except here the
tool could simply be made to tell the truth.

### The 82, and why they are counted rather than swept

Almost all are `fzn_*_init` in a fixture: `fzn_reasm_init(&table, &slot, 1, 1,
REASM_MAX_HOLD)`, `fzn_journal_init(&h->journal, h->jentries, SIM_HOSTS)`.
Those refuse a null pointer or a zero capacity and nothing else, and **a
literal cannot be either**, so they cannot fail as written.

The hazard they would otherwise carry -- a fixture that silently did not
build, then asserted over it -- is the one `REQUIRE` was added for, with its
own incident recorded at `prekey_test.c`. Sweeping 82 sites to restate it
would be a large mechanical edit against a risk the suites already answer by
going red. Counted, reasoned about, and left.

**Counted rather than excluded** matters: the number is printed on every run,
so if it starts climbing somebody has a reason to look.

### The gate, and what it cannot see

`tool/status_gate.py`, run by `make style`. It is a heuristic on line shape
rather than a parser, and its limits are pinned in the file so nobody quotes
it for a guarantee it does not make:

    a discarded call that is not first on its line
    a status assigned to a variable that is then never read
    a call through a function pointer, or generated by a macro

Four sabotages, and **one of them did not apply, which is the part worth
recording.** The `sed` that was meant to break the control matched nothing, so
the gate ran normally and printed a pass -- and a sabotage that did not land
looks exactly like a check that cannot fail. `evidence.md` says to confirm the
substitution; re-run with an `assert` on the replacement, the control failed
as it should:

    a library source discards a status         caught
    the discarding control made clean          refused to report anything
    the clean control made to look discarded   refused to report anything
    (the first attempt at the second)          did not apply -- looked like a pass

### Why a gate rather than a note

Same argument as sec 74 and the same answer: a sweep that finds nothing today
is worth almost nothing, and the property is worth what the next dropped
status would cost. Three of this tree's gates now have one shape -- **make the
artifact witness itself rather than resolve to be careful** -- and this is the
third: `enum_gate.py` for a value nobody can see clash, `status_gate.py` for a
failure nobody can see dropped, and the compiler-computed marker in
`wire/bytes.h` for a tag nobody can see added.

## 77. The newest parser had no harness, and it eats what a camera produces, 2026-09-04

`provision/` was the only wire object in this tree without a fuzz harness, and
it is the one whose input arrives most directly from outside: a string
somebody's camera read off a poster, then the bytes that come out of it. Every
other decoder of stranger bytes here has one -- chain, revocation, record,
reassembly, freshness, peer, vocabulary, blob, prekey, tree, seal.

### The property it exists for is canonicality, not memory safety

A sanitizer catches an overrun. **Nothing catches two strings decoding to one
card**, and that is the failure this decoder can have: 677 characters carry
one bit more than 423 bytes, so the padding bit is refused rather than
ignored, and that refusal is one line. It is exactly the kind of line a later
edit removes as redundant.

So the assertion is a round trip in both directions, checked on every accepted
string:

    from_text(s) accepted  =>  text(that card) is byte-identical to s

If that ever fails, "the code I scanned" has stopped naming one thing, and a
signature over the bytes cannot repair it.

### The generator mutates real cards

A uniformly random 423-byte buffer is refused at the version byte and reaches
nothing; a uniformly random string is refused at the prefix. Both are
generated -- a decoder must survive them -- but the cases with teeth are a
genuine card with one bit bent, and a genuine string with one character
lowercased, raised, deleted or replaced.

Floors are on STATES rather than call counts, for `prekey_fuzz`'s reason: a
run that never lowercased a character has not tested that a scanned card is
uppercase, however many strings it decoded.

    20000 cases   8491 text ok        11509 text refused
                 17491 bytes ok        2509 bytes refused
                  8431 verified        6241 bad signature
                  2819 expired         2134 lowercased
                  2500 padding bit     2500 truncated

### Sabotaged before it was believed, and it is sharp

Each substitution was asserted before running, after sec 76's reminder that a
sabotage which did not apply looks exactly like a check that cannot fail.

    the padding bit no longer checked        FAILED on case 2
    lowercase folded rather than refused     FAILED on case 1
    a refused open leaves a stale view       FAILED on case 7

The third is not about the text at all. `fzn_provision_open` memsets the
caller's view before it validates, so a caller who ignores the status reads
zeroes rather than last card's pointers -- the hazard `wire/seal.c` already
records for its own refusals, checked here because the harness had the state
to check it with.

### What it does not cover

The signer is a stub keyed on the public key's first byte, so "verified under
the root the card names" has content -- but a stub is not Ed25519, and this
harness says nothing about the real primitive. `sim/test/provision_test.c`
under Monocypher is what covers that, and the two are deliberately different
witnesses.

Nothing here fuzzes `fzn_provision_pack`. It takes three fixed-length buffers
from the caller and cannot be handed a malformed one without the caller
already being wrong, which is `FZN_PROVISION_ERR_MALFORMED`'s job and the unit
suite's.

## 78. A harness for the planner, and the defect it did not catch on the first try, 2026-09-04

`record/sync.c` had no fuzz harness, and it is the worst place in this library
not to have one: `fzn_sync_plan_offer` and `fzn_sync_plan_fetch` take **a
peer's digest**, which is the most attacker-shaped input here. The peer chooses
how many positions, what is in them, whether they repeat, and in what order.
Nothing about the argument is verified because there is nothing to verify -- a
digest is a claim, not a signed object.

It is also the surface with the worst history, which is what earned it a
harness rather than more unit cases. Both defects are recorded in `sync.c` at
the lines that carry them: the **amplifier**, where an absent position was read
as a position of zero so a digest containing nothing asked for everything --
64 ranges over 32,768 records, from a message with no content; and the
**ordering**, where `theirs_for` kept the last matching position rather than
the largest, so a peer chose the answer by putting one of them last.

### The first version caught one of the two, and passed the other

Three sabotages, restoring the real defects against copies of `sync.c`:

    theirs_for keeps the LAST hit      FAILED on case 9
    a refused call leaves the plan     FAILED on case 0
    an absent position read as zero    SURVIVED 20000 cases

**The amplifier survived, and it had to.** The harness checked order
independence, duplicate independence, and bounds -- and the amplifier violates
none of them. Offering from zero for an unmentioned stream does not raise
`request_count` above `journal.used`: there are at most that many streams to
offer. **The harm is the VOLUME of each range, not the number of them**, and no
bound can see it. The counters even moved in a reassuring direction: 15075
plans instead of 10330, which reads as more coverage.

That is `evidence.md`'s *a suite assembled to confirm correct behaviour will
mostly not notice incorrect behaviour, because nothing selected its cases for
that* -- arriving in a harness written specifically to catch this defect.

### What fixed it was a model, not a tighter bound

The rule is modelled in the words `sync.c` uses at the line it lives on: an
absent position is not a position of zero. For an OFFER, a stream the peer did
not mention produces no range **and is counted**; for a FETCH,
`unknown_issuers` counts the peer's positions this host does not follow --
the mirror rule and a different quantity, so the model has to know which
direction it is in.

Both halves are asserted, because the count alone would pass a planner that
counted correctly and offered anyway:

    plan->unknown_issuers == the model's own count
    no request names an (issuer, stream) absent from `theirs`

With that, the amplifier fails on **case 1**.

### Two coverage holes the harness reported about itself

The first run printed `0 truncated` and `0 ignored` -- two paths its own header
claimed to check, never reached, and **not floored**, so it reported success.

    OUT_CAP was 8 over a journal of 8, so `request_count <= journal.used`
    made truncation unreachable by construction.  OUT_CAP is 4 now.

    positions_ignored needs more than FZN_SYNC_MAX_POSITIONS, which is 1024
    and not reachable from a stack array sized for the ordinary case. One
    case in sixteen now sends a static array of 1025 or more, and the excess
    is checked to account exactly.

Both are floored now, so the harness cannot report success without reaching
them. **A counter nobody floors is a path nobody exercises**, and printing it
is not the same as requiring it -- the first run proves that, because the
number was on screen and read as fine.

Raising the truncation rate needed the generator changed rather than the floor
lowered: uniform 0..8 entries reached truncation 102 times in 20000, below any
honest floor. Half the cases now fill the journal, and it lands at 290 against
a floor of 200.

### The model is a second implementation, deliberately

`mentioned()` and `followed()` walk the arrays themselves rather than calling
anything in `sync.c`. A model that asked the module what it did would agree
with it always, including when both are wrong, which is
`evidence.md`'s two-documents-one-witness with the documents written in C.

## 79. A wipe label two paths walked past, and the comment that said otherwise, 2026-09-04

Chosen by measurement rather than by hunch: `session/session.c` had the
poorest branch coverage of the security-critical modules -- 75.00% of 84 --
and it is the protocol's core. Asking WHICH branches turned out to be worth
more than the number.

### Fifteen lines, and they were nearly all one family

    guard second-operands in compound null checks     8 lines
    seam-failure paths (agree refuses, hash refuses)  4 lines
    a transcript refusal only a null can cause        1 line
    a prekey with no public half                      1 line
    an err_str switch arm                             1 line

**The seam-failure family is project.md sec 75's, one layer up.** Those are
the paths a consumer's own crypto takes when it fails, and not one of them had
ever executed -- because the suite's stubs succeed and the sim tests use
Monocypher, which cannot fail.

### The finding is not a missing test, it is a comment that was false

`fzn_session_establish` ends at a label whose comment reads **"BOTH ARE WIPED
ON EVERY PATH."** Two paths above it returned without reaching the label, and
one of them was the agreement's own failure:

    aerr = fzn_agree_shared(self_prekey, agree, peer_prekey, shared);
    if (aerr != FZN_AGREE_OK)
            return FZN_SESSION_ERR_AGREE;      /* past the wipe */

**The two v2 derivations do `goto out` at the identical step.** So the same
operation was written two ways in one file, and the version that skipped the
wipe was the one whose comment claimed the wipe was universal.

### It was safe, and safe for a reason that lives in another file

`fzn_agree_shared` wipes `shared_out` itself before returning
FZN_AGREE_ERR_DEGENERATE, and on its other refusals -- MALFORMED, OPS,
ABSENT -- never writes it at all. So no secret this call computed was left
behind.

**That is a load-bearing property of `session/agree.c`, relied on in
`session/session.c`, and stated in neither place at the point of reliance.**
Exactly the shape fuzzypickles reported the same day about their own separate
buffers: *"luck rather than design. Nothing says the buffers must stay
separate, and the obvious optimisation would hand us your hazard with no
diagnostic anywhere."* A new failure mode in `fzn_agree_shared` that wrote
before refusing would make this a leak, with nothing anywhere to notice.

**And the fix is not purely cosmetic.** On the paths where `shared_out` is
never written, `shared` is an uninitialised local -- so returning leaves that
stack slot holding whatever it held before. Wiping zeroes it. The `goto out`
therefore removes a cross-module dependency AND clears a slot that was
otherwise left as found.

### What changed

v1 now matches v2: `err = FZN_SESSION_ERR_AGREE; goto out;`. The label's
comment says what it means -- wiped on every path that could have written
either -- and notes that the unqualified version was false. Behaviour through
the API is identical, which is the point: this closes a gap between what the
file says and what it does.

### And the tests the measurement asked for

Two families, each with a control, because every assertion in them is a
REFUSAL and a stub that had stopped working would satisfy all of them.

**The second agreement in each v2 derivation.** The first one's failure was
already covered by the 2026-09-02 work `session.h` records; a stub that always
refuses fails that one and never reaches the other. A counting stub that
refuses on call two reaches it -- and in the initiator **that second agreement
is the EPHEMERAL one**, which is the whole of what a later compromise of the
prekey cannot reproduce. A derivation continuing past its refusal would
produce a session with no forward secrecy in it and no way for either side to
tell.

**The hash seam refusing mid-establishment.** `REFUSING` existed and was
pointed only at `fzn_session_chains`. A hash that refuses while a session is
being derived had never happened. It must surface as ERR_HASH and not ERR_AGREE,
because a consumer told the wrong one looks in the wrong place.

### The population caveat, which was worth running rather than assuming

The standalone run said 70.24% before and 75.00% after -- and **75.00% is
exactly what the full-suite table already said**, which is the shape of a
wrong claim. `session_test` alone was reaching 70.24% while the whole suite
reached 75.00%, so other binaries were covering branches this one was not, and
"70.24 to 75.00" would have been an improvement to the project's number
measured over the wrong population. That error is in this document four times
already.

So `make coverage` was re-run rather than inferred from, and the answer is
that the gain is real and is not the standalone delta:

    branches never taken both ways   15 lines -> 11
    session_test alone               70.24% -> 75.00% of 84
    THE WHOLE SUITE                  75.00% -> 79.76% of 84
    lines, whole suite               95.29% -> 99.42% of 172

**One row moved and no other.** The comparison was made against every row of
the table rather than the one being looked at, because a change that moves a
neighbour is exactly what a targeted re-measurement does not see.

## 80. The deepest tree nobody had walked, 2026-09-04

The same measurement as sec 79, pointed at the next module: `blob/blob.c` at
76.40% of 161 branches was the largest remaining gap, and its sealed leaves
are what a seeder hands to strangers.

### Twenty-seven lines, and the same family as session's

    guard second-operands in compound null checks    10 lines
    hash-seam failures propagated out of a helper     9 lines
    bounds and capacities never reached               7 lines
    an err_str switch arm                             1 line

Nine seam failures again, which is sec 75's family for the third time: the
paths a consumer's own hash takes when it refuses, none of them ever executed
because the stubs succeed.

### The three that were worth chasing

`fzn_blob_proof_verify` carries a depth bound, and `blob.h` says what it is
for: *"the bound is what stops a crafted proof making a verifier iterate
without end"*, on the **keyless** verifier -- *"`fzn_blob_proof_verify` checks
a leaf against the root WITH NO KEY AT ALL"*, which is the one strangers use.

It had never fired, and the interesting question was whether it COULD.

**It cannot, and the reason is worth more than the answer.**
`FZN_BLOB_MAX_LEAVES` is *defined* as `1 << FZN_BLOB_MAX_DEPTH`, and
`leaf_count` past that is refused before the loop starts. So the deepest tree
this function will look at has exactly `FZN_BLOB_MAX_DEPTH` levels and fills
`path[0 .. 39]` -- **the last slot and not one past it.** The two constants
cannot drift apart, because one is written in terms of the other.

That makes it the same category as `provision/`'s two unreachable refusals in
sec 76: unreachable, and kept. **A repair that cannot fire hides the bug that
would make it fire; a refusal that cannot fire costs one comparison and guards
an array write whose bound lives in a `#define` two hundred lines away in
another file.** Deleting it would move the safety of `path[depth]` out of the
loop that does the writing.

### So the test is about the tightness, not the guard

    leaf_count = MAX_LEAVES, MAX_DEPTH siblings     reaches the climb
    one sibling short                               refused
    one level too long for its tree                 refused
    one leaf past the maximum                       refused outright
    an ordinary two-leaf proof                      reaches the climb (control)

`sibling_count != depth` is a refusal, so the first case passing is the
statement that the descent counted **exactly** forty levels -- the two
constants agreeing, expressed as a behaviour rather than as a tautological
`_Static_assert` over a macro defined in terms of the other.

**Nothing anywhere else goes near it.** `blob_fuzz` generates at most forty
LEAVES, which is a tree six levels deep, so its descents are nowhere near
forty. Under `make test SANITIZE=1` this is a real bound check on a
stranger-facing function and it is the only case that puts one there.

The proof cannot be genuine -- building one needs 2^40 leaf hashes -- so what
is asserted is WHICH refusal comes back. Reaching the climb and failing at the
root says the descent ran; a SHAPE or a MALFORMED would mean it was refused
before walking at all.

### And one thing that looked like a defect and is not

A proof one sibling short of its tree returns `FZN_BLOB_ERR_PROOF` rather than
a shape error, which read as a misclassification until the code was read:
`sibling_count != depth` returns PROOF deliberately, and *"the inclusion proof
does not reach the root"* is exactly what a short proof is. The probe was
written expecting SHAPE and the expectation was wrong, not the library.

## 81. A decision table with a row nobody had reached, 2026-09-04

Sections 79 and 80 took one module each. This took the whole library at once,
to answer a question those two had raised and neither could settle: **are
seam-failure paths systematically untested, or were `session/` and `blob/`
outliers?**

### The measurement, and what it says

Every source built with coverage, every branch never taken both ways
classified by what its line does:

    guard   70   45%   compound null checks whose later operands are unreached
    other   45   29%   the classifier could not place them
    seam    21   14%   a consumer's hash, AEAD, agreement or signer refusing
    bound   19   12%   a capacity, depth or count limit
    TOTAL  155

**So the seam family is real and is not the story.** Twenty-one branches, nine
of them in `blob/` which sec 80 already read. The dominant category is guard
second-operands, which are reachable, untested, and worth very little
individually.

**The 29% the classifier could not place is the honest part of this table.** It
is reported rather than folded into "other things, probably fine", and looking
at it is what produced the finding below. `wire/seal.c` alone holds 17 of the
45, and they turn out to be defensive handling of the GENERATED code refusing
-- `situ_fzn_frame_view`, `situ_fzn_frame_tag_covered`, `!tag`,
`covered_len < head_len` -- at call sites where the caller has already
established the precondition. Unreachable by construction, kept for sec 80's
reason.

**The percentages are a heuristic's output and not a taxonomy.** A classifier
that cannot place 29% of its input has not earned one, and the value here was
in where it pointed rather than in what it counted.

### Which is how the actual finding turned up

Checking the classifier by hand against `chain/manifest.c`'s fourteen found
two it had placed wrongly -- and they are the two halves of ONE comparison,
one filed as a `guard` because it begins with a `!`, the other as the file's
single `other`. Neither is a guard. Together they are the comparison at the
centre of `fzn_manifest_admit`, which has a three-row decision table written
out above it:

    same record, both withdrawn  -- I am ahead
    same record, they withdrew   -- they are ahead, a record I would refuse
    different records            -- neither of us can tell who is ahead from
                                    hashes alone, so ask

    memcmp(mine, theirs) != 0     branch 1 taken 0% of 4790 evaluations

**The third row had never been exercised.** Every case in the suite revokes at
the fixed instant 1000, so two hosts revoking one pair always produced
byte-identical records and the ids always matched. The row was unreachable
from the fixtures, not from the protocol.

### Why the row matters

Two hosts revoking the same grant independently is an ordinary network event
rather than a corner: a stolen device is revoked by whoever notices first, and
a second holder who has not heard yet revokes it too. Their records differ --
different instants, different ids.

If this host read "different id" as "I am ahead", **it would never fetch the
record it lacks** -- and the one it lacks might be a withdrawal, or a
revocation covering more than its own.

The library gets it right. The test passes as written, which is the ordinary
outcome of covering a documented path: what it buys is that the row cannot
stop being true without something going red.

    memcmp(mine, theirs) != 0     0% -> 14%

**The control is the same test with one number changed.** Revoking at the same
instant makes the ids identical, this host IS ahead, and no deficit is
recorded. Without it a deficit of one would be consistent with the comparison
never running at all.

### And the row that is still not reached

`!mine_withdrawn`, the second operand at line 540, is evaluated 1480 times
across the suite and is true every time: **the case where the peer has
withdrawn a record and this host has withdrawn it too has never occurred.**
That is the first row of the table.

~~Recorded rather than forced. It needs a fixture where both sides withdraw the
same underlying revocation, which is more machinery than the finding currently
justifies.~~

**COVERED, AND THAT ESTIMATE WAS MADE WITHOUT LOOKING.**
`revoke_then_withdraw` was already in `manifest_test.c`, forty lines above the
sentence declining to write it; the fixture is two calls. Sec 90 has it, and
has the two other cost judgements from the same day that went the same way.

### And the style gate caught the edit that found it

Worth one line because it is the third time tonight. The REQUIRE-to-CHECK
rewrite was done with a regular expression, and it produced blocks indented
one tab short -- twelve violations, refused by `make style` before anything
was committed. The function was then written out by hand instead.

A mechanical edit to satisfy a mechanical check, done mechanically, and wrong.
`evidence.md` asks a bulk change to carry a proof; the cheaper answer for
twelve lines is not to make it a bulk change.

### What this closes

**The systematic question is answered: there is no systematic seam-testing
debt.** The remaining 155 are mostly guard operands and unreachable defensive
branches, and chasing them module by module would be work with the shape of
progress and none of the substance. The two modules that did have real gaps
have been done, and this one -- found by checking a classifier rather than by
trusting it -- was worth more than either.

## 82. A guard protecting floors that were not there, 2026-09-04

Found while reading a long fuzz run rather than by looking for it. Every
harness at 200000 cases -- ten times the default -- and one line stood out:

    seal_fuzz: 200000 cases; 134797 refused, 65203 accepted, 100000 near
    misses, 1 length sweeps, 134797 peek/open comparisons

**One length sweep in 200000 cases**, where every neighbour is in the tens of
thousands. It looked like a path that had stopped being reached.

### It was not, and reading settled it in one step

`length_discipline` is called ONCE from `main`, before the case loop: it
builds one frame and offers `fzn_seal_peek` every length from 0 to
`built_len + 8`, requiring exactly one to be accepted. One is the whole
population, and its floor of `!= 0` is the right floor for it.

The suspicion cost one file read and was worth having -- but the finding is
what the read turned up next.

### The floors were "at least one", and the guard above them said otherwise

    if (cases < FUZZ_MIN_CASES) {
            "the coverage floors below are cleared by single lucky hits,
             so this run will not report success"
    ...
    if (cov.refused == 0u || cov.accepted == 0u || cov.near_miss == 0u ||
        cov.length_sweeps == 0u || cov.open_agreed == 0u)

**`FUZZ_MIN_CASES` was refusing short runs to protect floors this file did not
have.** Every floor was `== 0u` -- cleared by a single hit at any case count,
which is exactly the condition the refusal is worded against. Every other
harness here scales them: `prekey_fuzz`, `blob_fuzz`, and the two written
today.

Same shape as sec 79's wipe label, and the third time tonight: **a stated
property the code does not have, in a file careful enough to state it.** The
sentence is right, was written for the right reason, and nothing checked that
the code below matched it.

### What it cost, and when

Nothing yet, and that is the point of fixing it. With a floor of one, a
generator change dropping `accepted` from 65203 to 3 leaves this passing --
and `accepted` is the path where a frame is actually PARSED rather than
refused. A fuzz harness whose accept path has quietly stopped being reached
is a harness that only proves the refusal path still refuses.

### The floor chosen, and why it is not a target

An eighth of `cases`, against the measured shares over 200000:

    refused              134797   67%
    accepted              65203   33%
    near misses          100000   50%
    peek/open agreements 134797   67%

so the tightest has better than a two-fold margin. **A floor is a tripwire for
a generator that has stopped reaching a state, not a number to tune against**
-- set it where a real regression trips it and ordinary variance does not.

`length_sweeps` keeps its floor of one, with the reason written beside it, so
that the next person does not "fix" the inconsistency by making every floor
proportional and refusing every run.

### Watched failing, and I nearly graded it on the wrong output

    seal_fuzz 1000  (the minimum)   674 / 326 / 500 / 674   floor 125   exit 0
    seal_fuzz 20000 (the default) 13476 / 6524 /10000 /13476 floor 2500  exit 0
    the floor raised to cases/1     REACHED TOO LITTLE                   exit 1

**The first attempt at that third line read `cut`'s exit status through a
pipe**, printed `exit 0`, and I was about to record "the floor fires" on the
strength of the message having appeared. The message printing is necessary and
is not the thing: the REFUSAL is. Re-run reading the binary's own status, it
is 1.

That is this document's own rule about pipelines, met while writing up a
finding about a guard that did not guard. Twice in one file.

### And the run itself found nothing

Sixteen harnesses, 200000 cases each, no invariant broken and no model
disagreement. That is a recorded negative rather than a silence: the
harnesses that carry models -- prekey, revocation, manifest, peer, sync --
agreed with the library throughout, and the ones that carry invariants held
them.

## 83. The sweep sec 82 asked for, and two sabotages that did not bite, 2026-09-04

Sec 82 found `seal_fuzz` refusing short runs to protect coverage floors it did
not have. The obvious question was whether its fifteen neighbours were the
same, and three of them were.

### The sweep

    harness            proportional floors   == 0u floors   MIN_CASES guard
    tree_fuzz                            0              7               yes
    seal_fuzz (sec 82)                   2              1               yes
    manifest_fuzz                        4              0                no
    freshness_fuzz                       3              0                no
    the other twelve                   2-8              0               yes

**`tree_fuzz` is sec 82's defect in sec 82's words.** Its guard says *"every
coverage floor below that is cleared by a single lucky hit"*, and all seven of
its floors were `== 0u` -- cleared by a single hit at any case count. Two
files, one sentence, one gap. Scaled to an eighth against the measured shares
over 200000 cases, where the tightest (truncations, 29%) keeps better than a
two-fold margin.

### The sabotage that applied and did not bite

Raising `cov.opened`'s floor to `floor_of(cases, 1u)` -- the whole case count --
and the harness still **passed**. The substitution was asserted, so it had
landed; it simply did not create the condition. `opened` is 29560 in 20000
cases, because one case can open more than one tree, so a floor of 20000 was
still comfortably met.

`evidence.md` says to confirm a sabotage landed, because one that did not
apply and a check that cannot fail are indistinguishable. **This is a step
past that: it applied and was still not a sabotage.** Asserting the
substitution is necessary and is not sufficient -- what has to be confirmed is
that the edit makes the thing FAIL.

Repeated against `truncated` (5805 in 20000), the floor fires: exit 1,
`REACHED TOO LITTLE`.

### And the second one, which was in the write-up rather than the code

`manifest_fuzz` and `freshness_fuzz` had no minimum-cases guard, and the
comment first written into both said a short run "could report success on a
sweep that proves nothing".

**Measured with the guard disabled, that is true of one and false of the
other.**

    freshness_fuzz 3   EXIT 0   15 admitted, 7 replays, 2 stale
    manifest_fuzz  3   EXIT 1   REACHED TOO LITTLE, covered 0

`manifest_fuzz`'s proportional floors bottom out at one, and one of its
counters reaches zero at three cases, so it refuses on its own. **The guard is
a real fix there and a consistency fix here**, and the comments now say which
is which.

The claim was written into two source files before it was checked, and
checking it took two commands. It is the same error as sec 71's -- a sentence
that reads as measured because it sits next to measurements -- and the reason
it was caught this time is that the write-up named a specific number a command
could contradict.

### What the sweep leaves

Sixteen harnesses: all now have a minimum-cases guard, and all now have floors
proportional to `cases` except the run-level flags that cannot be
(`seal_fuzz`'s `length_sweeps`, which is one sweep per run by construction).

**Nothing here found a defect in the library.** It found three harnesses that
would have gone on reporting success after a generator stopped reaching a
state -- which is the failure a fuzz harness is least able to notice about
itself, because its output looks the same either way.

## 84. The lens three findings pointed at, swept, 2026-09-04

Three of the night's findings were one shape, arrived at from three
directions:

    session/session.c   "BOTH ARE WIPED ON EVERY PATH"    two paths returned past it
    session/aead.h      constrained `open` in four lines  said nothing about `seal`
    wire/seal_fuzz.c    "cleared by a single lucky hit"   every floor was == 0u

**A comment or a guard message asserting a property, with nothing checking
that the code below it agrees.** Each was found by accident, so the lens was
pointed deliberately.

### The detector, and what it costs

    grep -rniE 'on every path|every path|all paths|in every case|on every call|
                never .* without|always .* before|every one of them|
                without exception' --include=*.c --include=*.h

Twenty-five hits across the tree; five make a checkable universal claim about
control flow in library code. The rest are test prose and design commentary.

**It is a grep, and the check is a person.** There is nothing mechanical here
and there should not be: whether a sentence matches the code beneath it is not
a property a tool can decide, which is exactly why this class survives gates
that catch everything else.

### The result

    session/session.c:186    WRONG, and fixed in sec 79 before this ran
    ratchet/ratchet.c:169    correct -- every failure path goes through `out`
    wire/seal.c:176          correct, and already argued in place
    frame/freshness.c:190    correct, and a record of this class biting before
    local/peer_linux.c:80    correct

One in five, and the one is the one this document already carries. **The
detector finds it**: `session.c:186` is in the hit list, so a sweep run
yesterday would have caught what took a coverage measurement to notice.

### Two of the four are records of the same class having bitten already

`frame/freshness.c` reclaims expired entries before anything that can return
early, *"so 'reclaimed on every call' is true rather than nearly true"* -- and
says why: it used to sit below two returns, so traffic made entirely of grants
or entirely of stale commands left dead entries holding slots indefinitely.
**Found by that module's own fuzzer, against the invariant that every live
entry is unexpired.**

`wire/seal.c` carries three guards it establishes as unreachable, records that
`make coverage` reports them as never taken, explains that they are the
boundary between this file's reasoning and the generated code's, and tells a
future reader hunting the last branches not to spend a fixture on them. That
is the analysis sec 80 did for `blob/`'s depth bound, written before it.

**So the class is not hypothetical and the tree is mostly clean of it** --
which is the useful shape of this result: a lens worth having, a detector
worth keeping, and no backlog behind it.

### Why it will not become a gate

A gate would have to decide whether prose matches code. What it could check --
that a comment saying "every path" sits in a function whose returns all reach
one label -- is a pattern match on a shape this tree deliberately varies, and
would fire on `ratchet.c` and `seal.c`, which are correct.

The honest arrangement is what `evidence.md` recommends for a one-off sweep
against a standing gate: **this is read once, entirely, by the person who ran
it.** Recorded here so the next person can re-run it rather than re-derive it,
with the phrasing list as the thing worth keeping.

## 86. A view that outlived its buffer, and the gate that is not in `make check`, 2026-09-04

Run at the end of the night as a check on the night's work rather than as new
work: `make test SANITIZE=1` over a tree whose `wire/seal.c`, `blob/blob.c`,
`session/session.c` and eight vtable implementations had all changed.

It found a defect. Not in any of those -- in `sim/test/provision_test.c`, from
earlier the same day.

    ERROR: AddressSanitizer: stack-use-after-scope
      #0 fzn_record_is_open   record/record.h:284
      #1 fzn_tree_open        tree/tree.c:51
      #2 main                 sim/test/provision_test.c:1806

### What it was

The tree leg sealed a record and opened it inside a block:

    {
            uint8_t frame[FZN_SEAL_OVERHEAD + FZN_RECORD_MAX_LEN];
            ...
            fzn_record_open(got.payload, got.payload_len, &node_rec);
    }
    fzn_tree_open(node_rec, &carried);        /* frame is gone */

`fzn_record_open` and `fzn_tree_open` both hand back **views**, and
`record.h` says in as many words that the buffer must outlive them.
`node_rec` pointed into `frame`; `carried.content` pointed into `frame`
through `node_rec`. The array died at the block's closing brace and both were
read for another ten lines.

### Why nothing caught it, which is the part worth keeping

**The bytes are still on the stack after the brace**, because nothing has
reused the slot yet. Every read returned the right answer, every assertion
passed, and the suite was green -- through `make check` a dozen times tonight,
`make fuzz` at 200000 cases, and three coverage runs.

Only `stack-use-after-scope` separates *correct* from *correct by luck*, and
the only thing that reports it is `make test SANITIZE=1`, **which is not part
of `make check`.** Everything else built tonight went through that gate
repeatedly; this went through it too, and was wrong the whole time.

### And it is sec 84's shape one layer over

Sec 84 swept for comments asserting a property the code beneath them does not
have. This is a property the LIBRARY states about its own API, which a
consumer of that API -- a test in this same repository -- did not hold.

The contract is correct, in the right file, and was read by the person who
then broke it: `provision/provision.h` was written earlier the same day with
*"A VIEW RATHER THAN A COPY ... The buffer must outlive the record"*, and the
violation is three hundred lines away in another file by the same hand.

**A stated precondition does not protect the person who states it.** What
protects them is a tool that observes the lifetime, and this tree has one that
it does not run by default.

### The fix, and the sweep that came free with it

The array is declared in the enclosing scope now, where the views taken
through it are read, with the reason written at the declaration rather than
left for the next person to rediscover under a sanitizer.

**And there is no need to grep for other instances of this class**, which was
the obvious next move and the wrong one: ASan observes every lifetime in every
test that runs, so a clean sanitized suite IS the sweep, and it is a better one
than any pattern match could be. Re-run after the fix:

    79 binaries, exit 0, no diagnostic of any kind

**The first run reported 78, and that number was not a sweep.** ASan aborts the
process on the fault, so `provision_test` died and `make` stopped -- the
binaries after it in the order never ran at all. A count taken from an aborted
run describes where it stopped, not what it covered, and reading 78 against 79
as "nearly everything" would have been the same error as reading a red CI run
as a failure when the job never started.

### And two harnesses are WRITTEN for a sanitizer that nothing runs

`make fuzz SANITIZE=1` was run afterwards -- the cross product, randomised
inputs into decoders with a tool watching memory, which neither
`make fuzz` nor `make test SANITIZE=1` is on its own.

    16 harnesses started, 16 completed, 20000 cases each
    zero sanitizer diagnostics, make exit 0

A recorded negative over the whole attack surface, and the count is of
harnesses that REPORTED rather than started, after the 78-against-79 above.

**The finding is what the harnesses say about themselves.**
`blob/test/blob_fuzz.c` lays its offered proof *"FLUSH AGAINST THE END OF THE
BUFFER, so that a verifier reading one sibling too many runs off the array and
a sanitizer says so"*. `wire/test/seal_fuzz.c`'s first property notes that its
pointer checks are *"also what catches a read past the end"* under a
sanitizer, with the arithmetic as the fallback when there is not one.

**So that placement is elaborate setup for a check that cannot fire in any
target this project runs by default.** Two authors wrote for a configuration
nothing invokes.

`evidence.md` has *a gate that needs the thing it checks for is weakest where
it matters*. This is that inverted and it is worse: the harness is STRONGEST
exactly where it is least often run, so the value is real, built deliberately,
and collected only when somebody remembers a command.

### And the run reported itself failed, having succeeded

The task notification for that run said **failed, exit 1**. `make` exited 0 and
all sixteen harnesses passed. The compound command ended in `grep -c` for
sanitizer diagnostics, which prints `0` and **exits 1 when it finds nothing** --
so the shell's status was the grep's, and the absence of any fault was reported
as a fault.

The same class as everything else recorded today, and for once it fell the safe
way: a clean run looking broken rather than a broken one looking clean. Worth
the sentence because the safe direction is the one nobody investigates, and
this would have been read as "the sanitized fuzz run fails" by anybody who
stopped at the notification.

### It is in `make check` now, and the hole was closed rather than accepted

Instructed by the holder the same day. The obstacle recorded here was real:
`make codegencheck` SKIPS a sanitizer build outright -- it reads the emitted
shape of two security-critical functions and instrumentation deliberately
changes that shape -- so a sanitized `test` would run the codegen gate, have
it decline, and **report a pass over a check that inspected nothing.**

    check: style test installcheck ctcheck sancheck

    sancheck: $(MAKE) runtests BUILD_DIR=$(BUILD_DIR)-san SANITIZE=1

**`runtests` and not `test` is the whole care in the target.** `test` is
`codegencheck runtests`; running only `runtests` under the sanitizer leaves
`codegencheck` where it means something, on the plain build. The gate that
would have been made vacuous by strengthening the suite stays honest, which
was the objection and is now answered rather than traded away.

A separate `BUILD_DIR`, derived from the caller's so that
`make check BUILD_DIR=out` sanitizes into `out-san`, because the header at the
top of the Makefile says the objects are not interchangeable and mixing them
produces a link nobody can explain. `/san/` was already ignored -- it arrived
with `SANITIZE=1` in August -- and `/*-san/` covers the derived spellings.
The tree is KEPT between runs, unlike `coverage`'s, because a gate that
rebuilt the whole suite under a sanitizer every time would cost what nobody
would pay; `clean` removes it, by directory and after checking the path is
non-empty and relative.

### And it was watched catching the thing it was added for

Not a contrived fixture: **the defect from this same section**, put back into
`sim/test/provision_test.c` and run through both gates on one tree.

    make test   (unsanitized)   EXIT 0     passes it, as it did all night
    make sancheck               EXIT 2     stack-use-after-scope,
                                           record/record.h:284

A negative control and a positive one in a single run. The first line is what
makes the second worth anything: it establishes that the existing gate cannot
see this, rather than leaving that assumed from the morning's run.

`evidence.md` -- *a check is untested until it has been seen to fail* -- and
the reason it applies with force here is that adding a gate is the easiest
kind of change to leave unverified. A gate that runs and passes looks
identical to a gate that runs and cannot fail.

## 88. The three guard operands, and what removing them actually does, 2026-09-04

Instructed by the copyright holder. Sec 75 listed three branches in
`provision/provision.c` that `make coverage` reported as never taken both
ways, and sec 76 recorded the decision to report them rather than close them:
*"Those are reachable and untested, and saying so is cheaper than pretending
otherwise."*

Closing them changed my estimate of what they are worth.

### Why they were unreached

Each is the second operand of a conjunction, and the suite failed the first:

    if (!sign || !sign->sign)              pack, on a null signer
    if (!card.base || !card.root)          verify, on a card never opened
    if (!verifier || !verifier->verify)    verify, on a null verifier

`fzn_provision_pack(..., NULL, ...)` returns before `sign->sign` is ever
looked at. So the guards were doing work no case had asked them to do.

### The states are real, which is the part I had underweighted

**A vtable with a null member is what a partially initialised consumer has** --
a struct zeroed at declaration and filled in later, with one line not yet
written or a branch that skipped it. That is not a caller passing NULL by
mistake; it is a caller who believes they have a signer.

A card view with a base and no root is the same shape one level up:
`fzn_provision_open` sets both or neither, so this is a caller assembling the
struct by hand -- which the type being public permits and nothing prevents.

### And removing them does not produce a wrong answer

    the signer's member no longer checked      exit 139
    the card's root no longer checked          exit 139
    the verifier's member no longer checked    exit 139

**139 is SIGSEGV.** Each guard stands between a half-filled vtable and a null
call or a null read inside a crypto library -- not between a caller and a
misleading return code, which is what "an untested guard operand" sounds like
and is what I had taken them for.

So sec 76's judgement was defensible on the evidence it had and wrong on the
value: the sentence weighed them as tidiness. What settled it was removing
them and looking, which cost three minutes and was available the whole time.

### The coverage, and where it stops

    branches never taken both ways   7 lines -> 4
    provision.c                      91.76% -> 95.29% of 85

The four that remain are the ones sec 76 established as unreachable BY
CONSTRUCTION -- a card is a fixed 423 bytes, so `bits` is never zero and `n`
is always exactly the total -- and kept, because a refusal that cannot fire
guards an array write whose bound lives in a `#define` elsewhere. **That is
the floor this file's structure allows**, and it is worth saying so: a later
reader chasing the last four will be chasing something that cannot be reached
without changing the format.

### No sabotage entries, and the reason rather than the omission

The three were sabotaged by hand and the results are above. They are NOT added
to `tool/sabotage.py`, because their detection is a crash rather than an
assertion: the suite dies at that point and every later case goes unrun, which
`prekey_test.c` already records as the thing `REQUIRE` exists to avoid -- *"a
crash IS a failure, but it stops the run, names nothing, and buries the one
line that said what was actually wrong."*

A harness entry whose caught-signal is a segfault reports the right verdict
for the wrong reason and makes every other entry's output harder to read. The
guards are held by the three cases added to `provision_test.c`; the harness is
for guards a passing suite would not notice losing.

## 89. The harness the new module owed, 2026-09-04

Sec 77 argued that every decoder of stranger bytes in this library has a fuzz
harness, and listed them. Sec 87 added `disclose/` hours later, which made
that sentence false and the module its only exception.

`fzn_disclose_verify` is a decoder in the strict sense: **every argument
arrives from the sender** -- the committed field, the index it claims, the
number of fields the statement has, the sibling hashes, and the root. A
recipient verifies nothing about any of them beforehand, because there is
nothing to verify. A disclosure is a claim.

### The properties are about binding

A sanitizer catches an overrun, and `make check` now runs this suite under one
(sec 86). None of these would be caught by either:

    a disclosure is bound to its PLACE       what verifies at i must verify
                                             nowhere else
    a disclosure is bound to its STATEMENT   a different field count is a
                                             different root
    a refusal hands back nothing             not the last field that verified
    what comes back is a VIEW                the caller's buffer past the
                                             salt, not a copy

The place check offers **every** wrong index rather than sampling one, which
`MAX_FIELDS` of eight makes affordable and which matters because a
recipient told the street is the bearing has been told something specific
rather than something random.

    20000 cases   20000 verified      20000 refused
                   4892 bent fields    4983 bent salts
                   4396 bent proofs    5729 bent roots
                  17501 wrong indexes 18047 wrong counts
                   1833 empty fields

### And a sabotage in another module was caught by it

Three, each substitution asserted before the run:

    the leaf ignores the salt                    FAILED on case 1
    verify hands the field back before proving   FAILED on case 1
    blob's root stops binding the field count    FAILED on case 15

**The third is in `blob/blob.c`, not in `disclose/`.** Removing `leaf_count`
from `finalise_root` makes every statement fold the same number into its root,
so a disclosure verifies under a count it does not have -- and the harness for
a module two directories away is what says so.

That is worth more than a third caught sabotage. It shows the statement
binding is not `disclose/`'s property at all: it is blob's finaliser,
contributed by fuzzypickles for content addressing, load-bearing here for a
reason nobody had in mind when it was written. **A harness that only exercised
its own module could not have noticed it going.**

## 90. Three cost judgements in one day, all wrong the same way, 2026-09-04

Two findings today came from the same place, and finding the second by
accident was enough to look for a third deliberately. There was one, it was
mine, it was hours old, and the tool it said did not exist was forty lines
above where it said so.

### The three

    sec 5j    selective disclosure struck off as   built in a test; the
              "an encoding sec 2 keeps out"        elimination was wrong
                                                   (sec 72)

    sec 76    three guard operands as "reachable   removing any of them is
              and untested, and saying so is       SIGSEGV, not a wrong
              cheaper than pretending otherwise"   return code (sec 88)

    sec 81    a fixture as "more machinery than    `revoke_then_withdraw`
              the finding currently justifies"     already existed in that
                                                   file (this section)

**None of the three was carelessly written.** Each records a reason, and each
reason is the kind that reads as diligence -- a scope rule, a cost, a
proportion. `working-practice.md` says exactly this about the class: *a
wrongly-deferred question is caught by nothing and looks exactly like
diligence.*

### What they have in common is not the topic

All three are **a judgement about COST made without the measurement that
would have settled it**, and in all three the measurement was available and
cheap:

    open project.md and read sec 2               one minute
    delete the guard and run the suite           three minutes
    grep the test file for a withdrawal helper   ten seconds

And all three erred in the same direction: **the work was priced too high and
its value too low.** That is not a coincidence of mood. A cost estimate is
made by the person who would have to pay it, at the moment they are deciding
whether to, and the estimate that ends the deliberation is the one that
finishes the deliberation.

### The one this section is about

Sec 81 declined a fixture for `!mine_withdrawn` -- the first row of
`fzn_manifest_admit`'s decision table, the case where the peer has withdrawn a
record and this host has withdrawn it too. It is now two calls to a helper the
same file already had:

    revoke_then_withdraw(&f,    f.root, &cap, grantee);
    revoke_then_withdraw(&peer, peer.root, &cap, grantee);

    !mine_withdrawn   never taken both ways  ->  50% / 50%
    manifest.c        89.52%  ->  90.73% of 248 branches

The row matters for the reason the table gives. Both hosts hold the same
revocation and both have withdrawn it, so nothing is behind and nothing should
be asked for. **Getting it wrong re-records the pair on every comparison with
every peer** -- the re-fetch loop the drain exists to stop, on the pairs most
likely to be compared, which are the settled ones. Sabotaged by having the
comparison stop consulting `mine_withdrawn`: the new case goes red.

The control is the same test with only the PEER withdrawing, which must record
a deficit. Without it the zero is consistent with a comparison that records
nothing at all.

### The rule this leaves

**A cost estimate in a project document is a claim, and it is the one kind
nothing downstream re-derives.** A wrong number gets caught because something
uses it. A wrong scope claim gets caught when somebody acts on it. A wrong
estimate of what work would cost ends the conversation, and the conversation
is the only thing that would have checked it.

So: **when declining work on cost, spend one minute establishing the cost.**
Not as a rule about diligence -- as the observation that all three of today's
were settled in under three minutes each, by a command, after the judgement
had already been written down and published.

## 91. The guard-operand sweep, and four ways the count was wrong, 2026-09-04

Section 88 closed three guard operands and measured what one is worth.
This is the sweep that followed it across the library, and the useful
part is not the coverage -- it is that the SCOPE NUMBER was wrong four
separate times, each time in the direction that made the job look
bigger, and none of them was caught by reading it back.

**First count: "153 uncovered lines across 24 files."** Produced by a
parser that read `gcov -t` output and never split on the `Source:`
marker. gcov emits a section per file it has line data for -- the `.c`
AND every header whose inline functions were compiled into it -- so
`record/record.h`'s eight inline guards were attributed to `state.c`,
`tree.c`, `log.c` and `record.c` alike, once per translation unit that
includes it. The tell was in the output and was read straight past:
`record.c` is 195 lines long and the report named line 388.

**Second count: 167, same parser, same fault.** Re-running the
enumeration is what `evidence.md` warns is not a second measurement --
the same instrument reproduces its own blind spot exactly. What found it
was checking one line against the file, which cost one `sed`.

**The honest figure is 116 lines in 20 files**, with the header inlines
counted once each rather than per includer: `wire/generated/frame.h` 19,
`record/record.h` 8, `wire/generated/situ.h` 6, `wire/bytes.h` 1.

**Third: the per-file percentages in commit `7314739` are a narrower
population than they read as.** They were measured by running that
module's own suite, and the whole-run figure is higher, because other
suites exercise the same code -- `spool.c` is 100% of its branches in a
full run and the message says 92.41%. Both numbers are real. The
message does not say which question it answered, which is the whole of
the defect.

**Fourth, and the one that would have been expensive: the sweep's own
edit nearly deleted 212 lines of committed work.** The script inserted
each new test by slicing from a comment header to `int main`, and the
comment header it searched for was one an EARLIER commit in this same
sweep had already written into that file. `index()` returned the first
occurrence, the slice ran from there to `main`, and two existing test
functions were carried out of `spool_test.c` and into `plan_test.c`.
The compiler caught it immediately -- two undeclared functions -- but it
would not have caught the reverse case, a slice that landed entirely
inside dead space. **An anchor is unique at the moment of the edit, not
by nature, and a sweep that writes the same anchor into many files is a
sweep that destroys its own uniqueness as it runs.**

### Where it ended up

Measured on the full run rather than per suite, which is the population
the earlier numbers got wrong:

    blob.c         77.91% -> 95.09% of 163 branches
    revocation.c   90.65% -> 95.79% of 214
    session.c      79.76% -> 97.62% of 84
    manifest.c     90.73% -> 97.98% of 248
    reassembly.c   96.67% -> 99.33% of 150
    persist.c      77.78% -> 100.00% of 72
    spool.c        68.35% -> 100.00% of 79
    record.c, sync.c, link.c, ratchet.c, agree.c    100.00%

**Three of the cases found something a null argument could not.** They
are the reason the sweep was worth more than its coverage number:

  - **`fzn_agree_secret_generation` reads `sk->live` after the null
    test.** A rotation leaves the struct present and not live, so a
    caller asking which generation they hold must be told zero rather
    than the number the wiped struct still carries.
  - **`fzn_sync_digest` clears `dropped` BEFORE its guard**, because
    sync.h forbids the function being silent -- so a refused digest has
    to leave a zero behind rather than the caller's stale value.
  - **`hold_until` saturates rather than wrapping**, and the test that
    proves it has to send BOTH chunks of a message at `UINT64_MAX - 1`.
    A wrapped deadline expires the slot between the two calls, and the
    symptom is a message that never completes -- a lost message, not an
    error anybody sees. The first version of that test asked only
    whether the first chunk was accepted, which a wrapped deadline
    passes.

**And one assertion was written with a security polarity backwards.**
`fzn_revocation_covers` answers **1** for a store it cannot scan, which
the comment above the guard explains: failing open there means a
withdrawn capability keeps working. The test asserted 0, taken from the
wrong half of that comment, and failed. Had it been "fixed" by editing
the source, a fail-closed authorisation check would have become a
fail-open one in the function `fzn_chain_verify` rests on. **The
disagreement was the witness working**, and the cheap wrong move -- one
line in the source -- was right there.

**Two predicates in this library have several readers that answer them
with DIFFERENT values on purpose**, and nothing asserted the difference
until now. `corrupt()` in revocation: covers 1, known 1, lookup 0.
`state_sound()` in manifest: pending 0, overflowed 1. In both cases two
readers agree by VALUE and not by REASONING, so each test also checks a
sound-but-empty structure where they must diverge -- without it, a
change collapsing two readers into one would pass.

### What is deliberately NOT closed, and why

Six of the 116 are unreachable by construction and stay that way. They
are defence in depth, which is a thing this library does on purpose, so
a test forcing them would be asserting that a lie can be told:

    state.c:156, log.c:112   seq 0 past `fzn_record_open`, which refuses it
    chain.c:375, chain.c:384 re-opening bytes this function just encoded
    relay.c:65               `hop_view` after `fzn_relay_budget` ran it
    tree.c:58                a null body behind a passing `body_len`

**And one is not defence in depth -- it is dead.** `tree.c:124` reads

    *out = lo + (hi - lo) / 2u;
    if (*out == lo && hi - lo <= 1u)

The second operand cannot be false when the first is true: `*out == lo`
holds exactly when `(hi - lo) / 2 == 0`, which is exactly `hi - lo <= 1`.
The comment above it already says so -- "the midpoint equals `lo`
precisely when hi - lo is 0 or 1, so this is the whole exhaustion test"
-- and then the code tests it twice anyway. The coverage report is
correct that the branch is never taken both ways, and no input will ever
take it. **This is the one case in the sweep where the right change was
to the source and not to the suite.**

**Removed on the copyright holder's instruction, 2026-09-04**, with
three things done rather than one, because deleting half a condition in
a binary search is not a test change:

  - **The equivalence was checked away from the code that assumes it.**
    Two million random `lo <= hi` pairs plus every gap from 0 to 8 at ten
    bases including `UINT64_MAX`: zero disagreements between `mid == lo`
    and `hi - lo <= 1`. Arithmetic in a comment is a claim like any
    other, and this one is load-bearing for a deletion.
  - **The test asserts the RELATIONSHIP, not either operand.**
    Exhaustion is reported exactly when the gap is 0 or 1, swept across
    six bases including the top of the range where a `(lo + hi) / 2`
    implementation wraps -- and where exhaustion is reported, `*out` is
    still the low neighbour's key, which is the promise sec 4.2 rests on
    and the reason the code is not spelled `ERR_`.
  - **It was seen to fail before it was believed.** Two wrong
    simplifications were compiled and run: keeping only a stricter
    `hi - lo == 0u` gives 7 failures, and an operand that disagrees with
    the midpoint gives 13. Each sabotage was confirmed to have landed by
    grep before its result was read, and the source was restored and
    diffed byte-for-byte afterwards.

`tool/sabotage.py` gained `tree-order-exhaustion` in the same change.
**A guard that has just been simplified is exactly the one worth proving
is still load-bearing** -- otherwise the argument that an operand was
redundant is indistinguishable, a year later, from an argument that the
whole condition was.

**And two platform backends are left alone deliberately.**
`local/peer_linux.c` has six and `session/random_linux.c` three, and
every one is a guard against the KERNEL misbehaving -- a `getsockopt`
that succeeds without answering, a `read` that returns zero from
`/dev/urandom`. Reaching them needs the libc call replaced, and **a test
that fakes `getsockopt` proves the fake**: it would assert that this
file handles a case the real kernel is what decides. `blob/`'s two
`FZN_BLOB_MAX_DEPTH` backstops are the same shape from the other end --
the source itself calls one "a backstop against a future change rather
than a live possibility", and forcing it would mean building a tree
deeper than the type can address.

The honest summary is that the sweep closed what a caller can reach and
stopped where the remaining operands are held by something that is not
a caller.

## 92. The two platform backends, measured instead of asserted, 2026-09-04

Section 91 left `local/peer_linux.c` (6) and `session/random_linux.c` (3)
open, on the grounds that reaching them "means replacing the libc call --
at which point the test proves the fake". **That was asserted, not
measured, and it was wrong in both directions.** One of peer_linux's six
is reachable with ordinary kernel behaviour and is now closed. The other
eight are unreachable for reasons that have nothing to do with faking,
and knowing WHICH reason is the whole value of having looked.

The claim was also the fourth cost judgement this workspace has recorded
being wrong the same way -- see sec 90 -- and it has the same shape as
the other three: a plausible reason not to do the work, produced without
running the one command that would settle it.

### The one that was reachable

**A peer that has exited.** `SO_PEERCRED` is captured at connect time and
does not change when the peer dies, so an accepted socket goes on naming
a pid that has been reaped; `/proc/<pid>/status` then cannot be opened
and `fzn_peer_from_fd` takes the `if (!f)` branch. peer.h's promise is
that this is NOT an error -- the credentials are known and the groups are
not, which is the tri-state this module exists for -- so the case asserts
`== 0` with `groups_known` clear, not a refusal.

**`peer_linux_test.c`'s own header said this was unnecessary** and was
right about every other case: an `AF_UNIX` socketpair has both ends in
this process, so no fork is needed. It is wrong about exactly this one,
because a socketpair's peer is us and `/proc/self` always opens. The
case needs a real `connect()` from a child that then exits -- measured
before it was written, because the socketpair route reports the PARENT's
pid and fopen succeeds, which would have made a green test that never
reached the guard.

### The eight that are not, and why each

    peer_linux  len != sizeof(cred)     the kernel always writes 12
    peer_linux  snprintf(...) < 0       cannot fail into a 64-byte buffer
    peer_linux  ferror(f)               needs /proc to fail mid-read
    peer_linux  cred.uid == (uid_t)-1   never true while pid != 0, and
                                        pid == 0 short-circuits first
    peer_linux  got == sizeof(status)   needs a status file over 8192
                                        bytes; this machine's is 1558,
                                        and growing it means adding
                                        supplementary groups, which
                                        needs privilege
    random_linux  n == 0                the loop is `while (got < len)`,
                                        so a zero return needs getrandom
                                        to answer 0 to a NONZERO request,
                                        which it does not do
    random_linux  n < 0                 see below
    random_linux  errno == EINTR        getrandom does not block for a
                                        small request from an initialised
                                        pool, so nothing interrupts it

**The `n < 0` one is worth the paragraph, because the obvious route
exists and does not work.** `getrandom` into an unwritable page should
return `EFAULT`, and the raw syscall does:

    SYS_getrandom(PROT_NONE page, 16)   ->  -1, errno 14 (Bad address)

But `linux_fill` calls glibc's wrapper, and on this machine that resolves
through the vDSO, which runs in userspace and **faults instead of
returning**. Measured at five sizes -- 8, 256, 257, 4096 and 8192 bytes,
each in a forked child so the crash could be observed rather than ending
the run -- and every one died on SIGSEGV. So the guard cannot be reached
through the function that contains it, and the reason is not "you would
have to fake libc" but "the fast path faults before the syscall is
made". Those are different facts and only one of them is true.

**None of this is a defect and none of it wants fixing.** A guard against
`getrandom` failing is correct to have; what has been established is that
no test on this machine can produce the failure, which is sec 91's
distinction between a claim of absence and a claim of impossibility --
and this is the second kind, with the experiment named so the next reader
can re-run it rather than take it on trust. `evidence.md` asks for the
method beside the fact, and the method here is `probe3.c`'s shape: fork,
call, report the signal.

**What would change the answer**: a build that calls `syscall(SYS_getrandom, ...)`
rather than the wrapper would make `n < 0` reachable, and that is a
decision about the source rather than about the suite -- so it is not
taken here.

## 93. The two file backends, and three cases that ran nothing, 2026-09-04

`persist_file.c` and `spool_file.c` were the library's two lowest-covered
sources, and the reason is the same in both: nearly every remaining branch
is a filesystem refusing something, and the suites ran against a filesystem
that works.

    persist_file.c   67.31% -> 92.31% of 52 branches
    spool_file.c     73.26% -> 96.51% of 86

**Every refusal below is produced by the real kernel.** That matters here
more than usual, because sec 92 had just recorded the opposite conclusion
about two other files -- and the distinction is not "real versus fake" as a
matter of taste. A stub for `open` would assert that this code handles a case
the FILESYSTEM is what decides, so the test would be about the stub. These
five put the kernel in the state instead:

    /dev/full            every write returns ENOSPC, and reads still work
    a pipe as the fd     fsync refuses a descriptor it cannot sync
    RLIMIT_FSIZE = 0     creation succeeds, the flush fails with EFBIG
    a directory at 0500  open(O_CREAT) inside it fails
    a directory at the   rename fails AFTER the bytes are safely written,
    target name          which is the only route to the late unwind

None needs privilege, and the last is the only way to reach the code that
runs after a save has otherwise succeeded.

**The `/dev/full` case asserts that the READ still works on the same
descriptor**, which is what makes it evidence about the write path rather
than about a broken fd. Without that line, "the write failed" could mean
anything about the descriptor and the case would prove nothing in
particular -- the control-that-can-fail rule from `evidence.md`, applied to
a device instead of a probe.

**The RLIMIT cases prove the restore by writing, not by reading a return
code.** A limit left at zero fails every subsequent write in the process --
including gcov's own `.gcda` at exit -- so a case that forgot to restore it
would corrupt the measurement that justified writing it. The assertion after
each is a real save that must succeed.

### Three cases ran nothing and passed

The find worth keeping. Round two added a case for the rename-over-a-
directory path, and `make coverage` reported that line still uncovered
afterwards. The block reads

    if (mkdir(f.bits, 0700) == 0) { ... }

and a checkpoint earlier in the same function had already written a FILE at
that name, so `mkdir` failed, the block was skipped, and the case reported
success. **The check count still rose**, because other cases in the same
block did run -- so the suite's own output could not distinguish it, and the
green line looked identical either way.

This is the third distinct vacuous skip in this session's test-writing, and
the shape is always the same: **a case guarded by a setup `if` reports
success when the setup fails.** The idiom is used throughout these suites
and is correct where the setup cannot realistically fail; what was different
here is that the setup depended on state an earlier case in the same
function had changed. An `unlink` before the `mkdir` is now load-bearing and
says so.

**Nothing but the coverage report could have caught it.** That is the
argument for measuring after writing a test rather than trusting that it
passed -- and it is the same argument sec 91 makes for measuring rather than
asserting a scope number, arriving from the other direction.

### What is left, and why each

Seven lines across the two files, and all seven are unreachable rather than
untested:

    both files    fdopen() failing            needs an allocation failure
    both files    fclose() != 0               the flush it would report has
                                              already failed and been seen
    persist       cap < NAME_MAX_LEN          `name_for` is static and every
    persist       !name_for(...)              caller passes sizeof(name),
                                              which IS NAME_MAX_LEN
    spool         the header fwrite failing   41 bytes always buffers, so
                                              the failure lands in the
                                              flush and never in the write

The persist pair is an internal invariant rather than a guard: the only
caller passes a buffer whose size is the constant being compared against, so
the comparison cannot be false. It is left alone rather than deleted --
unlike sec 91's `tree.c` operand, this one would become live the moment a
second caller passed a smaller buffer, which is what it is there to catch.

## 94. seal.c wants nothing, and the report that hid it, 2026-09-05

A sweep over `wire/seal.c`'s 21 uncovered lines, which ended with no test
written. Recorded because the next reader will otherwise measure it again:
the file reports 84.72% of 144 branches and **every one of the missing
outcomes is either deliberate or not this file's code at all.**

    196, 199, 212       the boundary where `fzn_seal_open` stops assuming
    599, 602, 608       `validate` and `tag_covered` agree; the same pair
                        again in `fzn_seal_close`
    448, 450, 452       the same for `fzn_seal_build`'s three views
    501                 the tag-dirty check, which verifies the setters
                        above it were the coverage-aware ones
    227-229, 486-496    NO CONDITIONAL IN seal.c AT ALL -- every branch on
                        these lines belongs to an inlined generated
                        accessor and is attributed to the call site
    57                  its own condition is covered 52/48; the unreached
                        branch is inside an inlined `situ_view_at`

**The file had already said so, and said it to whoever came next**: "So:
uncovered on purpose, provably unreachable today, and cheap. If a future
reader is hunting the last few branches in this file, these are three of
them and they are not worth the fixture it would take to force them."
Reading that first would have saved the exercise, which is the cheapest
lesson available here -- the comment was addressed to exactly the person
who ignored it.

### A per-line coverage report hides which branch is missing

The part worth carrying. A case WAS written -- frames below
`SITU_FZN_FRAME_SIZE_MIN`, on the hypothesis that the sub-minimum path was
unreached -- and it passed, and it was nearly reported as a coverage win.

It closed nothing. Branch counts before and after are identical, **122 of
144 either way**, and only the execution count moved, 90270 to 90286.
`seal_fuzz` already drives that check 52/48 with thousands of lengths.

What made it invisible is that **line 57 carries four branch records** and
the report names the line. Two are the length check, already covered; the
unreached one is inside a function inlined into it. "Line 57 uncovered" was
true before and after, and meant something different from what it looked
like. Every per-line figure in sections 91 through 93 has the same property,
and the ones acted on there were checked by re-measuring afterwards --
which is what caught this one too.

**The test was dropped rather than kept.** It made a named assertion where
there was incidental fuzz traffic, which is a real if small argument, and it
does not outweigh carrying a case whose comment has to open by saying it
buys no coverage. A redundant test is not free: it reads as load-bearing to
whoever meets it next.

**What would change the answer**: `seal.c` is measured through inlining, so
a build that did not inline the generated accessors would attribute those
branches to `frame.h` where they belong and this file would report higher
without a line of it changing. The percentage is a property of the
toolchain here as much as of the source -- `evidence.md`'s "a gate's verdict
can be a property of the toolchain" arriving in a coverage report rather
than in a gate.

## 97. situ has moved, and `make schema` is red today, 2026-09-05

Relayed from `claude-guidelines` on the copyright holder's instruction:
situ has improved substantially and the trees using it should take the
improvement. What follows is the measurement rather than the instruction,
because "situ is better now" is not something anybody can act on.

**Measured against situ at `0b1a25e`**, extracted read-only with `git
archive` -- this repository's own `schema` target's method, and for its
stated reason, that a working tree is whatever a session over there left
it as. situ's tree was in fact dirty while this was taken, and the pin is
why that did not matter. 536 commits since 2026-08-01.

**`make schema SITU_DIR=../situ` exits 1.** It stops at its first check,
so the rest were run by hand rather than left unmeasured:

    wire/frame.situ.wire     STALE   signature format v0 -> v1
    wire/frame.situ.map      same    byte for byte
    wire/generated/frame.c   STALE   54 lines
    wire/generated/frame.h   STALE   39 lines
    frame_relate.c, .h       same
    frame_tamper.h           same
    wire/generated/situ.h    STALE   7 lines, against situ's runtime
    wire/generated/situ.c    STALE   1 line

**None of it is a wire change.** `situc wire --check` calls it "changed
compatibly", the capability map is byte-identical, and the contract file
differs by its version line and a paragraph saying that a construct whose
contract is a list -- a variant's arms, a tlv grammar, an indexed region's
offset table, the bytes a tag covers -- now states it one entry per line,
so a diff names the entry that moved.

**What regenerating buys, which is the part worth reading.**

- **A failed check has a name.** `situ_fzn_head_check(view, &which)`
  writes the id of the member that refused, the ids being macros --
  `SITU_FZN_HEAD_LENGTH_CHECK`, `SITU_FZN_HOP_VERSION_CHECK`. No strings
  in the generated code: the id is the contract and the name is a macro.
- **`SITU_ERR_CHECKSUM`, separate from `SITU_ERR_TAG`.** situ's runtime
  states the reason in this library's own terms: a tag refusing is a
  hostile or corrupt message, a checksum mismatch is corruption or
  truncation, and a receiver that logs the two alike reports a disk error
  as an attack. That is the distinction the consumer-side entry about a
  `default:` arm is about from the other end, and it is now a value this
  library can hand over rather than a convention each consumer keeps.
- **Value bounds as constants**, `SITU_FZN_HOP_VERSION_VALUE_MIN` and
  `_MAX`, so a caller states the range without repeating the number.

**And the features bearing on this schema's shape rather than its
output**, named because a signal that says "read the changelog" is not a
signal. Imports are resolved rather than parsed and ignored (`8030185`),
which is the code-reuse route this file has none of today; `std/` carries
`image.situ`, `kernels.situ` and `codecs.situ`; a byte run is a value and
an enum may be `u8[k]`, spelled `u8 magic[4] [must_eq = "KSTR"]` in
situ's own keystore example, with `preamble` for fixed bytes that generate
no accessor; `compute` honours `self_as` so a checksum computes itself
(`4cb5405`); and `situc` has grown `gen-derived` (Rust and Python from one
description), `gen-fuzz`, `gen-dissector`, `advise` -- ranked, costed
schema suggestions -- and `diff`, which reports capability changes between
two revisions and is the tool for asking what any of this would cost.

**What is NOT measured.** Whether the suite passes after a regeneration;
nothing was regenerated here. Whether adopting a language feature moves
the wire, which `situc diff` answers and nobody has run. What the table
above establishes is that regenerating as things stand is byte-neutral on
the wire, and nothing more than that.

## 98. The delivery ledger, measured rather than assumed, 2026-09-05

Asked to make this library ready for what fuzzypickles requires, a survey of
their tree returned a ranked list of gaps. Most are boundaries this library
drew on purpose -- group chat is absent by design per `ratchet/ratchet.h`,
command vocabulary is the consumer's under sec 2, replication for a
compacted store is excluded by `record/sync.h` in writing, NAT traversal is
declared never (superseded: the holder put reachability in fuzznet's order
on 2026-10-13, sec 608, and sec 621 builds it). **One row was marked unsure
and it is the only one that
turned out to be a real gap.**

### What fuzznet has, and the axis it does not

Asked as a shape rather than a name -- *per peer, what have they confirmed
of mine* -- nothing here has it. Measured by reading the structs:

    record/journal.h   per (issuer, stream): what I RECEIVED and applied
    state/state.h      per (subject, kind): the current value
    link/, sched/      per link: latency, loss, mtu -- transport, not records
    record/sync.h      `fzn_sync_position_t` is what a peer ADVERTISES, and
                       it is computed for one exchange and consumed there

The missing axis is the PEER. `journal` is indexed by who WROTE a record;
the ledger is indexed by who has ACKNOWLEDGED one. And a peer's positions
exist here only in flight -- `fzn_sync_digest` produces them and
`fzn_sync_plan_offer` consumes them, and nothing holds one over time.

**Nothing in this document records a decision to leave that out**, which is
what separates it from the other rows. It is an unstated gap rather than a
boundary.

### What theirs actually is, in their words

Quoted rather than paraphrased, from `core/src/delivery_internal.h` in their
tree, read 2026-09-05:

> A delivery ledger: for each (recipient, subject), the highest version that
> recipient has confirmed holding.
>
> Extracted from the manifest and config-sync paths once both had been built
> and shipped, rather than designed up front ... the two independent
> implementations agreed on more than expected, which is what makes this
> worth sharing rather than a coincidence being enshrined.

They also name what does NOT travel with it -- the frame and its crypto, the
recipient set, and what a SUBJECT is, because "the manifest is a single
document, so its subject is empty ... Config has many settings, so its
subject is a setting".

**That provenance is the strongest evidence for sharing anything this
workspace has produced.** `harmonization.md` asks for one piece of shared
infrastructure motivated by real use across several consumers rather than
several bespoke ones designed on speculation. This is that, from the other
side: two implementations built independently, shipped, then found to agree.
It now serves four scopes in their tree -- manifest, config, group, and a
realm-absorption one.

### And it would not be a copy, which is why it is not taken here

My measurement, in my voice: their API is
`fzp_delivery_ack_get`/`_set`/`_behind`, each taking a
`fzp_storage_ops_t *` and addressing rows by a string key of the form
`ack_<scope>_<kind>_<recipient>.<subject>`. **Every table in this library is
a caller-owned array of fixed-width structs with no strings and no storage
seam** -- `persist/` is a separate concern reached deliberately, not a
parameter every call carries.

So an adoption is a redesign into this library's idiom rather than a lift:
the key becomes fields rather than a formatted string, the storage seam
comes out, the scope becomes something a caller supplies. That is exactly
what `harmonization.md` means by an extraction being its own deliberate
piece of work with the whole picture in view, and by not extracting a shared
library in passing.

### The decision, and whose

**Not taken here.** The option is a fifth table in this library keyed on
(peer, subject) holding one integer, in the shape `fzn_state_t` and
`fzn_journal_t` already use. Its cost is another module in a library whose
scope sec 2 keeps narrow, and the argument against is that "who has
confirmed what" may be distribution rather than protocol -- the same line
that keeps transport out.

The argument for is the provenance above, and it is unusually good: this
would be the first thing adopted here because two consumers built it
separately and agreed, rather than because one asked.

**It is the copyright holder's**, and it is recorded with its cost and its
evidence rather than built, because the thing being proposed is somebody
else's working code and the proposal is worth more than my version of it.

## 99. A test that ran two thirds of itself, 2026-09-05

`record/ledger.c` was written, tested, sabotaged and nearly committed with a
suite that silently skipped 25 of its 73 assertions. The defect is worth a
section because **nothing in the output distinguished it from a suite that
ran everything** -- not the exit code, not the failure count, and not the
check count, which was identical either way.

### What happened

The file's `REQUIRE` macro evaluated its condition twice:

    #define REQUIRE(cond, ...)          \
        do {                            \
            CHECK(cond, __VA_ARGS__);   \
            if (!(cond))                \
                return;                 \
        } while (0)

and it was handed a call with a side effect:

    REQUIRE(fzn_ledger_confirm(&l, a, s, 1u, 5u) == FZN_LEDGER_OK, "confirm");

The first evaluation inserted the row and returned OK, so the `CHECK` passed.
The second re-confirmed version 5 -- which the monotonic rule this very
module implements correctly calls `FZN_LEDGER_ERR_STALE` -- so the condition
was false and the case **returned there**. Every assertion after it, in that
function, never ran.

**The module was right and the test was wrong, and the module's own
correctness is what broke the test.** A ledger that accepted a repeat would
have hidden this.

### Why it survived a sabotage pass

Seven properties were mutated and five were caught. Two reported as not
caught, and the conclusion available at that moment -- that those two
properties are not held by the suite -- was wrong and was about to be
written down.

They were never reached. The sabotaged code sat past the early return.

**The instrument that failed is one this document has recommended.**
`evidence.md` says to confirm a sabotage landed, because a mutation that did
not apply and a check that cannot fail are indistinguishable from the output;
the confirmation used here was a `grep` for the mutated text. **That proves
the SOURCE changed. It says nothing about whether the assertion ran.** A
third state exists between "did not apply" and "cannot fail": applied, in
code the test does not reach.

What settled it was a `fprintf` at the function's entry and another at the
assertion. The first printed and the second did not, which is a fact no
amount of reading the file would have produced -- and reading the file is
what was tried first, three times.

### The count was the tell and it pointed the wrong way

48 checks clean, 48 sabotaged. That equality was read as "the same
assertions ran, so the sabotage is not caught". It actually meant "the same
assertions ran, and neither run reached the sabotaged code".

**A check count is a measurement of one run, and comparing two of them
answers a different question from the one it appears to.** Two runs agreeing
on a total is not evidence that a particular assertion executed in either.
The population is what matters and the total does not name it.

### And the correct macro was already in the tree, nine times

Measured after the fix: nine suites spell `REQUIRE` with a single evaluation
into a local, and exactly one did not -- the file written that day. The
harness for it was taken from `chain/test/authz_test.c`, which has the safe
form. **It was retyped from memory rather than copied**, which is the same
failure as completing an identifier from a prefix: the tree held the right
answer and was not read.

That is four instances in one day of the same root -- a value or a shape
reproduced from expectation instead of from the file -- and the other three
were caught by a compiler, a header and a reviewer. This one was caught by
nothing until a probe was put inside the running program.

## 102. What this tree already has of the filestore, measured before asking, 2026-09-05

Before requesting anything from fuzzypickles, what is here. Their split said
18 of 61 entry points are format this tree already has and 43 are store,
propagation and streaming it has none of. **That second number is too high,
because it was measured against `blob/` alone and this tree also has
`spool/`.**

    blob/blob.h    9 entry points   the format: leaf and node hashing,
                                    sealing, opening, tree push and root,
                                    proof build and verify
    spool/spool.h  6               the STORE: open, place, read, has,
                                    complete, next_missing -- a have-set
                                    over leaves with verified placement
    spool/plan.h   2               plan_want, plan_offer

So the have-set exists, and so does one half of the wire conversation.
Mapping their names onto it:

    have_init/add/contains/missing/is_complete   fzn_spool_open, _place,
                                                 _has, _next_missing,
                                                 _complete
    transfer_next_want                           fzn_spool_plan_want
    chunk sealing and ingest                     fzn_blob_leaf_seal /
                                                 _leaf_open + fzn_spool_place

**What is genuinely absent is propagation and streaming, not the store:**

- **The have-set on the wire.** `spool/` holds a bitmap and deliberately does
  not say how one travels -- `have_encode`/`have_decode` have no counterpart.
- **The wire vocabulary**: `want`, `have`, `have_query`, `data` and their
  parsers. This is the part their message flags as most likely to carry their
  peer model, and the part that must be neutral.
- **A transfer state machine**: `on_data`, `on_proof`, `commit`, `abandon`.
  `spool/` places a verified leaf; nothing here sequences a transfer or says
  what each step promises on failure.
- **`scrub`**, and there is no equivalent anywhere.
- **Read-at-offset streaming**, source and sink. `fzn_spool_read` reads one
  leaf by index; a stream wants a byte offset and a deadline.
- **The return-routability cookie.**
- **Tier namespaces**, which are policy and may not travel as theirs.

### The question this measurement raises, and it is the first design decision

`spool/` addresses by LEAF RANGE over a bitmap. fuzzypickles addresses by
TREE NODE, and declined `spool/` for that reason -- recorded before this
decision existed, so it is evidence rather than a position taken about it.

Both cannot be the addressing. Either `spool/` becomes node-addressed, or the
filestore is built beside it and one of the two is retired, or leaf-range
addressing is right and their reason for declining needs re-examining against
what the second consumer needs. **Nothing here decides that**, and it is the
thing to settle before an API rather than after -- the same shape as their
copy-stream versus pure-stream point, which is the other decision that must
precede the interface.

**Measured rather than asked**: this is what a request to them should be
narrowed by, so the four items sec 101 lists are asked for against a tree
whose contents are known rather than assumed.

### The second consumer has already written its requirement down, and it is not what either tree assumed

The holder's prompt -- "netcfgd hasn't started their migration yet, maybe
that is the missing link" -- was the correction. Both this tree and
fuzzypickles were treating netcfgd as a NAME that satisfied the two-consumer
test, and neither had read what it needs. Measured read-only in their tree,
2026-09-05:

**Their streaming use is Bluetooth AUDIO DEVICE HANDOVER**, asked for
2026-08-30 and recorded in their `project.md` and decision `0148`: "Bluetooth
audio with multiple in and out, ALSA only and no PulseAudio ... Later, audio
device handover over fuzznet's streaming."

**So fuzzypickles' open question is answered, and by the consumer rather than
by inference.** They asked whether netcfgd wants *pure stream* -- lossy,
deadline-driven -- rather than their own *copy-stream*, and guessed it would
be about latency. It is: live audio moving between devices mid-playback. The
propagation layer has to express both, which was their point and is now a
requirement rather than a possibility.

**AND THEY HAVE A HARD CONSTRAINT NEITHER TREE KNEW.** From
`doc/remote-access-feasibility.md`, listed as non-negotiable: "**Never build
or reintroduce a TCP-style ordered-byte-stream abstraction. Message
boundaries are preserved end to end.**"

That forecloses the obvious streaming API. A read-at-offset source and sink
-- which is what fuzzypickles has and what this document listed as absent
three paragraphs ago -- IS a byte-stream abstraction at the interface, even
if datagrams carry it. Designing streaming from the filestore's shape alone
would have produced exactly the thing their document refuses, and it would
have been found at adoption rather than at design.

**Their decision 0148 also states who owns a gap**: handover "is the one part
that is not netcfgd's protocol to design -- a gap found there is reported to
fuzznet rather than worked around here". So this tree is the one expected to
answer it.

**What is NOT recorded on their side: file sharing.** Searched their tracked
markdown for it and found nothing -- no filestore, no blob transfer, no file
distribution. The holder says netcfgd will share files; their documents say
audio handover and are silent on files. That is the same shape sec 10 step 5
already records for netcfgd's `agent/`: an instruction ahead of the
consumer's own document, which is not a contradiction and is worth knowing
before their absence is read as a requirement. **Their audio requirement is
written down and dated; the file one is the holder's word and has not reached
their tree.**

## 107. The transfer state machine: what fuzzypickles measured, before anything is built, 2026-09-05

**Nothing here is built.** Sec 102 left three filestore pieces unassigned --
the transfer state machine, `scrub`, and tier namespaces -- and this records
what the one existing implementation holds, asked for before designing rather
than after, so the design is not a rediscovery.

**Relayed, not measured here.** Every claim below is fuzzypickles reporting
their own tree, and they marked each for whether a test holds it. That
marking is theirs and is the reason it is worth quoting rather than
paraphrasing.

### Five properties, and the pair of sets is the one to read twice

- **TWO SETS, NOT ONE.** `pending` is what is held OR already asked for;
  `held` is what is actually held. Separate because of a failure case: an
  abandoned batch must return to the want-list, which means forgetting the
  ASK without forgetting the HOLDINGS. *"A single set cannot express that --
  clearing it loses data, keeping it re-asks nothing."* **Asserted in their
  tree.**
- **ASSIGNMENT IS SERIALISED THROUGH `pending`, before the next peer is
  asked.** That ordering is the whole mechanism preventing two peers being
  handed one range -- *"not an optimisation and not locking"*, but that the
  requester is the only party with global knowledge and must not consult a
  stale copy of its own intent. **Reasoning with a mechanism attached; they
  say plainly they cannot point at a test that would catch its reversal.**
- **A BATCH IS THE UNIT OF FOUR THINGS AT ONCE**: request, verification,
  retry and congestion, which is why their window counts batches rather than
  bytes. *"If your span is the unit of request but not of verification, or of
  verification but not of retry, you will need a second unit somewhere and
  the two will disagree under loss."*
- **THE FAILURE CONTRACT.** `commit` returns NO_MANIFEST when nothing is
  ready -- a normal "not yet" and the signal to stop looping, not an error --
  and MANIFEST_INVALID when a ready batch fails verification, after which
  nothing of it is stored, **that batch alone is dropped**, and its range
  returns to the want-list. One bad peer costs one batch, not the transfer.
  And commit is called in a LOOP, because several batches can become ready
  between polls. **Asserted in their tree.**
- **AIMD IN BATCHES WITH A FLOOR OF ONE.** Additive increase is one per
  WINDOW of successes rather than one per success, the latter being slow
  start, which they deliberately do not do. Decrease halves and never reaches
  zero: *"a transfer that cannot ask for anything can never learn the path
  recovered"* -- the same reasoning as demoting rather than deleting in a link
  table. **Asserted**, including the refusal at window one.

### The one place they say their shape is wrong for this tree, and it half lands

Their batch buffer is a fixed array of slots each holding a whole span, so
the 66 KiB is spent whether or not a transfer is active. They proposed that a
library serving consumers with different appetites should make the in-flight
count and the per-batch buffer **the caller's**, citing sec 106's own finding
that the bound is a memory-holding decision rather than a protocol constant.

**The argument is right and this tree already answers it, which is only
knowable by reading rather than agreeing.** `fzn_spool_place_span` takes
`const uint8_t *const *sealed` and copies no leaf, and
`fzn_msg_data_parse` refuses a span larger than the array it was handed -- so
the operative bound is the caller's `cap` and `FZN_MSG_MAX_SPAN` is a ceiling
above it. What the library fixes is 2 KiB of stack scratch.

Sec 106 is corrected accordingly: it said a caller must hold the whole batch
and left the impression the library did. **The memory-holding argument was
right about what decides the number and wrong about who pays it.** Nobody
would have caught that by re-reading sec 106, because the sentence is true of
the transfer either way -- which is the same shape as their own near-miss,
where both sentences were true and only one was about the system.

### A receipt that was invented, retracted before it landed

fuzzypickles followed the five properties with a message saying the
assignment-ordering property was now paid for: sabotage the record-as-pending
and *"nothing goes red in a single-peer test and everything goes red the
moment two peers are asked"*. They then ran that experiment and retracted it
-- with the no-op in place their suite reports **all passed, zero failures**,
because there is no two-peer test. The property is exactly as unpaid as their
first message marked it.

**It never reached this tree**, because the section above was written and
committed from the first message, which was the correct one. That is luck
rather than process and is worth saying so.

Their own account of the mechanism is the part to keep: they had genuinely
sabotaged three functions that day and got real red from two, so *"the memory
of having sabotaged supplied the shape of a result for a sabotage I never
ran"*. The frame had just been right twice and the answer arrived faster than
the evidence -- and a manufactured receipt is the strongest form the error
takes, because it reads as a marker of diligence rather than as a guess.

### The rule that came out of paying for it, and it is aimed at code not yet written

fuzzypickles wrote the two-peer test and it fails on exactly two assertions
with the record-as-pending removed -- the ranges are equal, and they overlap.
Nothing else in their suite moves.

**Why it was invisible is the part that transfers.** That suite ALREADY had
two tests asserting the property by name, and both were correct. Both call
the free planner and pass it a `pending` set **the test itself maintains**.
So the test did, correctly and on the planner's behalf, the bookkeeping that
production has to do -- and the planner was fine all along. What was untested
was the one caller responsible for recording it.

Their rule, and it is better than "test the caller too" because it names a
tell rather than an aspiration:

> A test that supplies the state the code under test should have recorded
> cannot see a caller that never records it.

The tell is a test that MAINTAINS a piece of state and passes it in. That
state is the thing production must produce, and handing it over is how the
test excuses the code from producing it. Nothing about reading those two
tests reveals it: they are about the right subject, they are correct, and
their names are accurate.

**Run against this tree, no hit, and the method matters more than the
verdict.** The candidate shape is an aggregate a caller maintains that the
library then trusts. `spool->have` is the only one: it is read by
`fzn_spool_complete` as `have == leaves`, and **`fzn_spool_open` recomputes
it from the bits rather than trusting a caller** -- already deliberate,
already documented in `spool.h`, and written for a different reason (a bitmap
truncated mid-write must not claim a blob is complete). Neither planner reads
it; both read the bitmap. The hand-built spools in `plan_test.c` and
`consumer_check.c` set `leaves` and `present` directly, and are corruption
fixtures rather than this shape -- they build a bad state on purpose to watch
a guard refuse it, which is the opposite pattern.

**Where it does apply here is the piece that does not exist yet**, which is
the cheapest moment to be told. When `spool/` grows a pending set, the test
for it must not maintain that set on the transfer's behalf; the transfer has
to record it and the test has to watch it happen. Their two fixture details
travel with the warning, and both are about whether the fixture reaches the
branch rather than whether the assertion is right:

- **Both peers must hold everything.** Different have-sets make the planner
  answer differently for reasons that have nothing to do with pending, and
  the test passes with the record removed.
- **The window must be opened first.** Starting at one, a second ask is
  refused for a window reason and never reaches the question. Their first
  draft did exactly this and would have passed identically with the pending
  step gone.

### What the paid/unpaid marking turned out to be for

The convention was adopted so this tree would not have to test four claims to
find the load-bearing one. What it actually did was **quarantine a false claim
that arrived forty minutes later**: sec 107 was written from the message where
the assignment ordering was marked UNPAID, so when a manufactured receipt for
that same property arrived, there was nowhere for it to land.

Neither tree designed it for that. Recorded because the argument for a
practice is usually made once, at adoption, and this is a second and better
one that only showed up in use -- and because the alternative reading, that
this tree has a mechanism which caught the error, is false. **The marking did
the work and nothing here would have.**

### The lens their commitment finding handed over, run here

They reported that sabotaging their commitment comparison to always MATCH
broke nothing while always REFUSE broke 57 assertions: the stranger filter was
called on every valid frame and had **never once been shown a frame it should
reject**. Accept arm covered, refuse arm not, and the suite reading as
thorough throughout.

Run against this tree's equivalent -- `fzn_commitment_check` in
`fzn_seal_open`, neutered to accept every commitment, full `make check`:

    seal_test: 147 checks, 6 failure(s)

**Caught.** A negative result, recorded with its method because an absence
with no method is indistinguishable from an absence of looking. It is a
sabotage entry now, `seal-commitment-refuses-a-stranger`, so the six failures
are a property of the suite rather than of the afternoon somebody checked.

### What this changes about the piece that is not built

Two of the five are shapes this tree cannot inherit and must decide:

- **The two sets are `spool/`'s bitmap plus something.** `present` is `held`.
  There is no `pending`, and `fzn_spool_plan_want` recomputes wants from the
  bitmap every call -- which is correct for a single peer and cannot express
  "asked, not yet arrived" at all. That is the first thing a second peer
  breaks, and it is a data-structure decision rather than a protocol one.
- **The retry unit cannot be finer than the VERIFICATION unit**, which is
  the corrected form of their third point and answers the question this
  entry first framed as "batch or chunk". That framing was wrong and so was
  the sentence behind it: this tree wrote that their batch is the unit of
  four things *because nothing sits between it and the wire*, and
  fuzzypickles corrected it by reading their own signature --
  `on_data` takes one sealed leaf per datagram, so a leaf sits between their
  batch and the wire exactly as a chunk does here. **The difference was
  invented, and it was invented in this tree's voice about theirs.**

  Their rule instead: a leaf there is a unit of framing and arrival and NOT
  of retry, because verification is per-batch and a failed batch does not say
  which leaf was wrong -- re-asking one leaf is asking for a byte you cannot
  check. So the question is *can a chunk be verified on its own*, and it is
  answerable by reading rather than designing.

  **Read here, the answer is no, and fuzznet's real answer is a third thing.**
  `chunk/split.h` is pure arithmetic that authenticates nothing, and a chunk
  is a fragment of a sealed frame -- authentic from the peer, and unverifiable
  against a blob root, because nothing checks a fragment. So chunking is
  framing only, which is their situation with a different word.

  What differs is that `spool/` has BOTH `fzn_spool_place` (one leaf, one
  proof) and `fzn_spool_place_span` (a span, one proof), so **the
  verification unit is a per-request choice and therefore so is the retry
  unit.** A per-leaf request retries per leaf at 62% overhead; a span request
  retries per span at 0.68%. That is sec 106's curve reappearing as a RETRY
  granularity trade rather than a bandwidth one, and it is sec 104's
  per-request delivery mode rather than a new axis.

  **Settled, on fuzzypickles' reading of that number back: there is no unit
  to choose.** Their tree has one answer baked in because verification is
  per-batch and nothing else is available. This tree has both because `place`
  and `place_span` both exist -- *"a capability rather than an unmade
  decision"* -- so the transfer exposes the choice and the caller pays for
  it. Same conclusion the buffer ownership reached by a different road, and
  the second time in two days that a question here dissolved into an
  interface rather than resolving into a value.

## 112. The gate's own control, wired in, and the hole it turned out to have, 2026-09-05

`tool/test_style_gate.py` arrived in `83cf7ff` from another session, copied
from `~/.claude/tool/`, with no caller. It runs first in `make style` now, at
about 8 seconds.

**Its test count is deliberately not recorded here.** It was 101 when this
was wired and 103 by the time the confirming run finished, because another
session synced two more controls in from the source meanwhile. A number
describing a file somebody else keeps in sync is stale by construction, and
this document corrected a different rotting count an hour earlier -- see sec
110, where "six" outlived the seven items it counted.

**The ORDER is the point rather than the inclusion.** `style_gate.py` is a
detector whose failure mode is silence: over a conforming tree it prints the
same sentence whether every rule is live or every rule has been deleted. So
its pass is evidence only once something has shown it can fail. Running the
suite AFTER the gate would let a gate that can no longer speak print "35 files
conform" first, and that is the sentence somebody quotes; running it first
means `make` stops before the sentence exists.

**Read before it was run**, per `running-code.md`: stdlib only, one bounded
subprocess per case with `timeout=120`, every fixture inside a
`TemporaryDirectory` context manager, termination being the fixed method list.
Run under `timeout 600`, and afterwards: no orphaned processes, and **zero
directories created in `/tmp` in the three minutes around the run** -- counted
rather than assumed, because the 32 already there belong to other sessions and
a leak would have hidden among them.

### And then the wiring was sabotaged, which is where it got interesting

A gate wired in is a gate whose wiring is untested. Neutering
`python_ascii_problems` so it returns no problems, then running `make style`:

    make style                  rc=0
    the gate's verdict          printed
    the suite (101 tests then)  Ran 101 tests ... OK

**The sabotage survived.** Checked that it was not an inert mutation, which
this tree has been caught by twice this week: `ascii_only = true` in
`.style-gate.toml`, so the path is live. Measured directly against a fixture
of the shape the rule exists for -- a valid Python file whose em dash sits in
a COMMENT:

    healthy gate    a.py:1:21: non-ASCII '-' outside a string literal
    neutered gate   style-gate: 2 file(s) pass: whitespace and indentation

So the gate really was silenced and the suite really did not notice. That
reading is a record of a measurement taken on 2026-09-05 and does not rot;
what rots is a present-tense count, which is why the paragraph above declines
to keep one. **The
reason is that the suite's own Python fixture is a syntax error**: line 319
is `{"a.py": "X = (\u2014,\n"}`, `ast.parse` calls it *invalid character
U+2014*, and `code-style.md` prescribes the whole-file byte check for a file
that will not lex. The case exercises the fallback and never reaches the
tokenizer path it appears to test.

**Signalled to `claude-guidelines`, not patched here.** That copy opens
"Copied from ~/.claude/tool/test_style_gate.py -- the source", so editing it
is drift, and editing the source is a change to a file spread into every
tree -- `harmonization.md`'s *who makes a harmonizing change*. The signal
carries the reproduction and one thing this tree did not check: whether the C
scanner, a separate implementation of the same rule, has fixtures that lex.

### Fixed at the source, and the signal was wrong twice about why

The holder said to fix it at the source, so the test is in
`~/.claude/tool/test_style_gate.py` and taken back here with
`sync.py fuzznet` -- named, because an empty project list means all sixteen
and that tool's own comment records `sync.py --help` once writing into
thirteen trees from somebody asking how to use it.

**Both of this section's explanations were wrong**, and the corrections are
worth more than the test. The unlexable Python fixture is DELIBERATE and its
own docstring says so -- "a file the tokeniser refuses is checked as bytes" --
so it was testing the fallback on purpose and correctly. And the C side was
ALREADY covered: `test_ascii_finding_does_not_shadow_indent_findings` uses a
valid C file with an em dash in a comment. So the finding was an ASYMMETRY,
C's tokeniser path tested and Python's not, rather than a mistaken fixture --
and the open question this tree sent along with the signal, whether the C
scanner had the same gap, is answered no.

The gap was real either way, measured both directions at the source: with the
new test removed and `python_ascii_problems` neutered the suite reports OK,
and with it present that test fails.

**This is the third time this week a finding of this tree's about somebody
else's file characterised it wrongly while getting the mechanism right.** The
mechanism -- a silenced checker the suite does not notice -- was right, and
both sentences about WHY were wrong, and both were about a file this tree does
not own. `claude-guidelines` already carries the signal about that pattern,
filed the same day, which is now three instances rather than two.

### The instrument this tree used all day cannot see a same-file collision

Fixing the suite at the source meant working in `claude-guidelines` while a
session was live in it, and it collided twice within the evening, in opposite
directions. Their commit `44b2eef`, subject "the column branch", swallowed
this tree's uncommitted test and mentions ASCII nowhere; hours later this
tree's `7a619f7` swallowed an uncommitted `project.md` entry of theirs -- the
entry that names the instrument, taken by the commit that took it. Both of us
had quoted the staging rule the same day.

**`git diff --cached --name-only` is what `CLAUDE.md` asks for before
committing, and it cannot catch this.** It printed `project.md`, which was
true and told nothing: staging by name protects a PATH, and two sessions
editing one FILE is a case a path list has no way to express. `--stat` shows
it in one line and costs nothing more:

    git diff --cached --name-only    project.md
    git diff --cached --stat         1 file changed, 63 insertions(+)

Sixty-three, where about fourteen were mine. **A count several times what you
wrote is the signal, and it needs no diff reading.** Recorded here rather
than only in the guidelines tree because every commit this tree made today
used the weaker form; whether the rule itself changes is that tree's entry to
decide, and it is theirs.

**And this closes a conclusion drawn a few hours earlier that was half an
answer.** Doing the sabotage in a scratch copy -- the fix recorded when the
first collision was found -- prevents the experiment colliding and does
nothing whatever about two sessions editing one document. Two hazards, two
remedies, and the first one was written up as though it were the pair.

### An invented count and a stale one are different failures, and this tree was swept for the first

`claude-guidelines` drew a distinction sharper than the one this tree offered
back to them, and it is worth keeping because the remedies differ:

- **A stale claim was measured, was true, and something moved.** Their
  "`sync --check` holds at every copy in step" was true when written and
  false when read -- their own next commit falsified it, and fuzznet was
  one of five trees behind. It costs its reader ONE COMMAND to disprove,
  which is what checking it rather than believing it cost here.
- **An invented value was never measured at all.** Their "105 green" was a
  number typed into a sync loop's echo while sixteen real runs happened
  behind it: the runs were evidence and the sentence describing them was
  not. It cannot be caught by measuring again, because every later run
  agrees with the loop that produced it -- `evidence.md`'s own entry, met
  in a report about a measurement rather than in the measurement.

So **a timestamp is a courtesy and not printing an untaken count is a rule**,
and this tree offered a charitable reading that flattened the two.

**Swept here for the second, and it comes back empty with its method.** Every
count this build prints is a computed shell variable -- `$$n` test binaries,
`$$n` headers, `$$n` test sources, `$$n` error renderers over `$$w` rows --
and the only literal numbers inside printed strings are section references
and the version-packing explanation at 2645. Nothing types a count.

The near miss is already recorded a few lines above that last one and is the
OTHER failure again: this check once printed "27 error renderers, all
walked", which was true of the objects that happened to be present and false
of the tree. Measured, true, and about the wrong population -- so this tree's
history holds the stale kind and the wrong-population kind, and not the
invented kind.

### What the line in the Makefile is worth, said in the Makefile

It bought a control over most of its cases and not over that one; since the
fix above it buys that one too. The comment beside it still says what it does
not cover, because the next hole will not announce itself either, because the alternative is a reader in six months quoting
"the gate has a test suite" as though that settled the question -- which is
this tree's own *a name that claims exhaustiveness is not a check that
achieved it*, met in a tool rather than in a test name.

**A control with a known hole, documented, is worth more than no control and
less than its docstring implies.** Saying which is the whole of it.

## 113. The sweep did not reach the modules written after it, 2026-09-06

`make coverage` on the four modules built for the filestore, none of which
had ever been measured:

    spool/message.c    100.00% of 197 lines   69.84% of 189 branches
    spool/scrub.c       97.67% of 129         72.07% of 111
    spool/transfer.c   100.00% of 108         84.62% of 104

**100% of lines beside 69.84% of branches is the shape that target exists to
report**, and its own comment says why: full line coverage is compatible with
every decision in the library having only ever gone one way.

### A wrong hypothesis, and the number that refused it

The first explanation was ready before any measurement. fuzzypickles' question
-- what value is every fixture in this suite on the same side of -- had found
two real gaps the day before, and `message_test`'s fixtures are an order of
magnitude below every ceiling they enforce: leaves of 48 to 97 bytes against
`FZN_BLOB_SEALED_MAX` of 1056, spans of four against a ceiling of 64, and an
8 KiB buffer that cannot hold a maximal DATA at all. **The largest message
that suite had ever built was about 351 bytes against a permitted 67,895** --
half a percent.

That was true, and it was not the cause. A maximal-message case was written
and coverage moved **69.84% to 70.37%: one branch.**

**Reading which branches, rather than hypothesising a second time, gave the
answer in one command.** Forty-two lines carried a conjunction whose later
operands no test had ever failed -- `if (!out_transfer || !out_cookie ||
!out_root || !out_first || !out_count)` is one operand tested and four
asserted by hope. **This tree ran exactly that sweep across the library
earlier in the same session, and these modules were written after it.** The
sweep did not fail; it finished before its subjects existed.

### What closing them found, beyond the number

    spool/message.c    69.84% -> 83.07%
    spool/transfer.c   84.62% -> 95.19%
    spool/scrub.c      72.07% -> 79.28%   (lines 97.67% -> 99.22%)

Three of the cases are behaviour nobody had exercised rather than arguments
nobody had nulled:

- **A disk that refuses is not a blob that rotted.** `cell_digest` returns
  BACKEND when a leaf the bitmap claims cannot be read, and `scrub.h` says
  that is deliberately distinct from CORRUPT. Both returns were never
  executed. A scrub treating an unreadable leaf as a bad one would hand a
  healthy cell back to the want-list every time a disk hiccuped. The
  behaviour is correct and is now asserted, with the leaf count checked
  after the failure.
- **The window stops at the caller's array.** `transfer.h` says the slot
  array is the memory bound AND the congestion ceiling; nothing had ever run
  the window up to it.
- **The optional outputs.** `fzn_scrub_seal` and `fzn_scrub_step` take
  counters a caller may omit, and every caller in the suite passed one. A
  NULL nothing ever passes is a branch asserted by hope like any other.

**And `message_test` had no positive control**, while all three of its
siblings did -- so a suite that had never been seen to fail was reporting the
same sentence whether it checked anything or not. That is the style gate's
own argument, one layer down, in this tree's own tests.

### The method, which is the part worth keeping

Two hypotheses, one wrong and one right, and the difference was not
cleverness. **The wrong one was the most recent lesson applied to the next
thing that looked like it** -- *a frame that has just been right is the
hardest one to drop*, and it had been right twice the day before. The right
one came from reading the instrument's own output instead of predicting it.

The maximal-message case is kept. It was a real gap, it holds the cap
arithmetic at equality rather than with three orders of magnitude of slack,
and its worth is not measured by the branch counter it failed to move.

## 114. The same sweep, one layer down, and the same wrong guess twice, 2026-09-06

`blob/blob.c` and `spool/spool.c` had the same shape sec 113 found: full line
coverage beside two thirds of branches, and the gap in the functions added
for the filestore rather than in the old ones.

    blob/blob.c    100.00% of 331 lines   84.21% -> 93.68% of 285 branches
    spool/spool.c   97.37% of 114         83.70% -> 89.63% of 135
                    (lines now 100%)

### The wrong guess, made a second time and for the same reason

Sec 113 records a hypothesis that cost a test and moved one branch. The
hypothesis HERE was different and wrong the same way: nine of `blob.c`'s
one-way lines were `if (err != FZN_BLOB_OK) return err;`, every one of them
propagating a hash failure that **no stub in this tree can produce**. That
looked like the answer and it is a real gap -- a consumer whose hash is a
hardware engine that can be busy meets those paths on its first bad day.

Written, and it moved **84.21% to 84.91%**. Then the operand guards moved it
to **93.68%**.

So the same wrong guess twice in two sections, and the shape is worth naming
rather than the instance: **the interesting failure path is the one that
comes to mind, and the boring conjunction is where the branches are.** Nine
propagation sites against fourteen guard lines, and the guards carry two to
five operands each. The arithmetic was available before either test was
written and neither time did anybody do it.

### What the failing seam bought, which is not a percentage

It is kept, and the version that survives is not the one first written. The
first draft guessed thresholds -- assert refusal for budgets 0 to 7 -- and
six of its thirteen failures were the function working correctly, because a
4-leaf span in a 16-leaf tree needs two combines and budgets 2 through 7 are
enough. **A guessed threshold turns a passing case into a failing assertion
that reads like a bug in the code.**

What replaced it measures each call's cost with an unlimited seam and then
asserts the RELATIONSHIP: one hash short must refuse, exactly enough must
not. That cannot be wrong about the number because it never names one, and
it holds the direction that matters -- a verifier which cannot compute must
REFUSE rather than accept.

### Three behaviours in spool.c that no test had reached

`make coverage` had all three one-way, and the first is a documented
promise nothing checked:

- **A span overlapping leaves already held rewrites none of them.**
  `spool.h` says a duplicate is ordinary on a lossy transport and an
  already-present leaf is accepted and not rewritten. Nothing had ever
  placed a span across leaves the store had.
- **A span that completes a blob syncs.** Only the single-leaf path had ever
  flushed. And the fixture could not have caught it either way, because
  `mem_sync` returned 1 and counted nothing -- **the assertion was
  unavailable, not merely unwritten.**
- **`fzn_spool_forget` counts what it actually cleared.** Forgetting an
  absent range must move nothing, which is what keeps `have` honest when a
  caller forgets twice; and a blob with leaves forgotten must stop reporting
  complete, which is the one lie that struct must never tell.

### What stays uncovered, and why it is not a gap

`blob.c`'s remaining one-way branches are the `FZN_BLOB_MAX_DEPTH` ceilings
-- `count >= 40`, `depth >= 40`, and the two `cap` checks beside them. Each
needs a tree of 2^40 leaves to fire. `test_the_deepest_legal_proof_is_walked`
already establishes that and says so; they are unreachable rather than
untested, which is a different sentence and the honest one.

## 115. scrub.c, and what a scrub must not conclude, 2026-09-06

Last of the six modules sec 113 measured.

    spool/scrub.c   99.22% -> 100.00% of 129 lines   79.28% -> 92.79% of 111

The operand guards were most of it again -- `seal` and `step` each carry a
five-operand null check that only its first operand had ever failed -- but
three of the cases are behaviour, and all three answer the same question:
**what may a scrub conclude when it cannot read or cannot compute?**

- **A hash that fails mid-scrub is not corruption**, the same distinction the
  refusing backend already had. `cell_digest` has two failure returns, one
  never executed and the other one-way, so the code handling a hash that
  cannot answer had never run. Both are asserted now, with the leaf count
  checked after: nothing is dropped.
- **Failing inside the leaf loop is a different site from failing at the
  fold.** A budget of `cost - 1` runs out on the last hash a cell needs,
  which is the span root; the leaf-hash call was still one-way afterwards.
  A budget of one runs out on the second leaf. **Two returns that look
  identical in the source are two branches to the instrument**, and only
  reading it says so.
- **A cell that is sealed and has since lost leaves is mid-repair and is
  skipped.** `fzn_spool_forget` is public, so a consumer reaches that state
  with no help from the scrub, and comparing a digest against bytes that are
  no longer there would drop a cell nobody had damaged.

**The cost was measured rather than guessed**, which is sec 114's lesson
applied on the first attempt rather than the second: the case runs one cell
with an unlimited seam to learn what a digest costs, then runs out one hash
short of it.

### The nine that remain, named rather than counted

    54, 180, 228   `if (len == 0u)`     cell_len returns 0 only past the end,
                                        and every caller has already checked
                                        `first < leaves`
    129            `count > CELL`       cell_digest is only ever called with
                                        cell_len's answer, which is <= 64
    69, 154        second operands      of conjunctions whose first operand
                                        decides every case a caller can build
    196, 254       the wrap             `cell == 0 && first == 0` after an
                                        advance that sets both together

These are defensive or structural rather than untested, in the same sense as
`blob.c`'s `FZN_BLOB_MAX_DEPTH` ceilings needing a tree of 2^40 leaves. The
distinction matters because **a percentage cannot tell an untested branch
from an unreachable one**, and this section is the only place that says which
these are.

### Where the six modules ended

    blob/blob.c      100.00% lines   84.21% -> 93.68% branches
    spool/spool.c     97.37 -> 100    83.70% -> 89.63%
    spool/message.c  100.00          69.84% -> 83.07%
    spool/transfer.c 100.00          84.62% -> 95.19%
    spool/scrub.c     99.22 -> 100    79.28% -> 92.79%
    spool/plan.c     100.00          97.06%  (untouched; it predates the sweep)

`plan.c` is the control for the whole exercise and nobody arranged it. It was
written before the library-wide operand sweep and was swept with everything
else, and it is the one module here that needed nothing.

## 116. The one decoder in this library that nobody fuzzed, 2026-09-06

With the six modules swept, the remaining branch coverage was read across
the whole library rather than guessed at. Two things came out of it, and the
second is the larger.

### The smaller: an argument that did not reach its second copy

`wire/seal.c` sits at 85.21% of 142 branches, and almost all of the gap is
already accounted for in its own comments -- three guards in `fzn_seal_open`
that "cannot fire for a frame that reached here", and two blocks in
`fzn_seal_build` kept as the place "this file stops assuming the generated
code agrees with the arithmetic above".

**`fzn_seal_close` carries the identical three guards and had no comment.**
Both functions reach them through `views()`, whose last act is
`situ_fzn_frame_validate`, so the argument transfers exactly -- checked
rather than assumed. A reader of `close` saw three guards no test exercises
and nothing saying why, while the explanation sat forty lines up in another
function. It now points at that argument rather than restating it, because a
duplicated argument is two things to keep true.

### The larger: twenty-nine parse-side branches, and what they were telling us

`spool/message.c` remained the lowest of the six at 83.07%, and reading the
twenty-nine one-way branches showed almost all of them on the PARSE side --
the half a PEER chooses and a caller cannot. Sec 113's operand sweep had
closed the encoder's guards, which are reached by passing bad arguments; the
decoder's are reached by receiving bad bytes, and nothing here receives bad
bytes on purpose.

Counted rather than assumed: **seventeen fuzz harnesses across eleven
modules, and `spool/` had none.** Every other thing in this library that
parses a stranger's bytes is fuzzed -- chain, record, wire, blob, chunk,
disclose, provision, prekey, local, tree, frame. The newest decoder in the
tree, the one whose whole job is untrusted input, was the exception.

`spool/test/message_fuzz.c` is that harness. Its invariants are the four the
headers claim:

- **Round trip.** Anything the decoder ACCEPTS, re-encoded from what it
  handed back, must reproduce the input byte for byte. That is the strongest
  property this format has and exactly what its exact-length refusals exist
  to protect -- two spellings of one message is how a receiver that
  de-duplicates by bytes sees two questions where a peer asked one.
- **Every value inside its bound**, ranges within the leaf count and spans
  within `FZN_MSG_MAX_SPAN`.
- **Every leaf pointer inside the message.** `fzn_msg_data_parse` hands back
  pointers rather than copies, so a wrong offset is a read past the buffer
  and the caller cannot tell.
- **Nothing written outside the caller's arrays**, which sit in canaries
  because ASan brackets objects and one static arena is one object.

    message_fuzz: 20000 cases, 10687 accepted (3427 have_query, 1641 have,
    2742 want, 2877 data), 9313 refused, every accepted message round-tripped

**Seen to fail before it was believed.** Accepting a trailing byte --
`len != need + body` weakened to `<` -- fails at case 125; dropping the
range bound inside a HAVE fails at case 2. Both print a reproducible seed.

**And it refuses a run too short to mean anything**, which is the other
harnesses' rule inherited rather than re-argued: a hundred cases clears every
coverage floor by luck, so the harness declines rather than reporting a
number.

### What the gate caught, which is the pleasing part

The harness was added to `FUZZ_BINS` and not to `TEST_SRCS`, and `make
style` refused: *"C sources in the tree and in no list: spool/test/
message_fuzz.c -- nothing reading SRCS, coverage, installcheck, can see
them."* A file that exists and is in no list is exactly the vacuous pass
this tree keeps finding, and the gate for it was already there.

## 117. Twenty scenarios and not one moved a blob, 2026-09-06

The filestore is seven modules, every one with unit tests and one with a
fuzzer, and **nothing proved they compose.** `sim/test/network_test.c` had
twenty scenarios covering provisioning, records, relays, revocation,
sessions, disclosure and an estate restore, and not one of them moved
content. The word `blob` appeared in that file only as a PERSIST blob -- a
packed struct -- which is a different thing wearing the same name, and is
why a grep for it looked reassuring.

`scenario_filestore` runs the whole conversation over a network that loses a
quarter of its datagrams and reorders a third: host 1 plans what it lacks,
asks, host 0 answers from its own store with one proof per span, host 1
verifies and places, and the transfer's bookkeeping decides what to ask next.
Then the scrub is pointed at the result, a byte is corrupted underneath it,
and the repair goes round the same loop.

    filestore: 28 rounds, 42 asked, 31 answered, 24 placed, 18 given up,
    18 dropped by the network; scrub checked 2 cells and condemned 1

**It is the only place `fzn_msg_data_parse`'s output arrays reach
`fzn_spool_place_span` across a network**, which is the claim `message.h`
makes and which a unit test can only stage.

### The fixture was wrong the first time, and it passed

At 16 leaves it ran green: 4 rounds, 4 placed, one drop, "scrub checked 1
cells and condemned 1". Every assertion held and the scenario was worth
much less than it looked.

**A 16-leaf blob is ONE scrub cell**, because `FZN_SCRUB_CELL` is 64. So
"one rotted byte condemns one cell" and "one rotted byte condemns the whole
blob" are the same sentence at that size -- the blast-radius property the
scrub exists for could not be expressed by the fixture, and the assertion
that looked like it was checking it was checking nothing of the sort. One
dropped datagram in four rounds is the same story for the retry path.

96 leaves is 64 + 32: two cells and a short tail. The numbers above are from
that fixture, and the neighbouring cell is now asserted intact.

This is fuzzypickles' question a third time -- what value is every fixture on
the same side of -- and the first time it has been asked of a fixture at the
moment of writing it rather than months later. **It still had to be asked
out loud.** Green was not what caught it; reading the summary line and
noticing "1 cells" was.

### Seen to fail

Two sabotages, both in modules the scenario only reaches through the network:

- **`fzn_transfer_expire` dropping nothing**: the transfer never completes,
  nothing is given up, and placed leaves cannot be read back. The abandon
  path is load-bearing on a lossy link and this is the only thing that runs
  it end to end.
- **The scrub comparing nothing**: all three scrub assertions fail, including
  the blast-radius one that the 16-leaf fixture could not have expressed.

### The floors, which are the point

A scenario that completes over a network that happened to drop nothing has
tested a reliable link. So it asserts that the network dropped something,
that something was given up, and that more was asked than answered -- and it
reads every leaf back and compares it against the sender's bytes, because
`fzn_spool_complete` answering yes is a claim about a bitmap rather than
about content.

## 118. One peer is not a swarm, and the scenario written yesterday had one, 2026-09-06

`scenario_filestore` moves a blob across a lossy network and asks ONE server.
`spool/transfer.h` exists for one problem -- two peers must not be sent the
same range -- so the entire reason that module is in the library went
unexercised by the scenario written to exercise the filestore, on the day it
was written.

`scenario_swarm` is two hosts holding the blob and a third fetching it,
asking both in turn:

    swarm: 28 rounds, 18 leaves from host 0, 6 from host 1,
    12 moments with two assignments live, 0 overlaps

**The property is checked after every assignment rather than once at the
end.** A pairwise walk of the live slots runs each time `next_want` answers,
so an overlap that exists for one round and is resolved by the next is still
counted. Checking at the end would have found nothing.

### Two floors, and the second is the one that was nearly missed

`overlaps == 0` is trivially true of a transfer that never had two
assignments live -- which is what a lossy link and a narrow window can
easily produce. So the scenario counts the moments when two WERE live and
asserts that number is non-zero. **Without it the assertion passes for the
wrong reason and reads exactly the same.**

And `from_host[0] > 0 && from_host[1] > 0`: a swarm scenario in which one
host happens to answer everything is a one-peer test wearing a swarm's
clothes, and it would satisfy every other check here.

### Seen to fail, and the neighbouring scenario stayed green

With `is_pending`'s exclusion neutered:

    FAIL: two peers were assigned overlapping ranges at once
    swarm: 32 rounds, ... 14 moments with two assignments live, 14 overlaps

`scenario_filestore` passed in the same run. That is the whole finding
restated as a measurement: **the one-peer scenario cannot see this defect,
and it is the scenario that existed.** fuzzypickles shipped exactly this bug
and reported it 2026-09-05 -- their driver answered "nothing left to ask"
while three ranges sat outstanding, and every test they had used one peer.

Their unit test and this tree's ask twice from two peer NUMBERS in one
process. This asks two HOSTS over a link that loses and reorders, which is
the arrangement the defect actually occurs in, and it is now a second
independent witness to a guard that had one.

## 119. Two modules the sim had never called, 2026-09-06

Asked mechanically rather than by eye: for every library source, how many of
its exported symbols does any sim scenario call? The first attempt was a bad
proxy and worth recording -- it matched `fzn_<module>_`, which is false for
`message.c` (`fzn_msg_*`) and `reassembly.c` (`fzn_reasm_*`), so it reported
zeros that were artifacts of a naming convention this tree does not have.
Extracting the actual exported symbols per file gives the real answer.

Setting aside the platform backends, which a sim replaces with its own fakes
by design, **two modules built this session are called by no scenario at
all**: `chain/chain_store.c` (0 of 5 exported functions) and
`record/ledger.c` (0 of 5).

`scenario_held_but_revoked` closes the first, and the chain store's own
header says why it needs a scenario rather than a unit test: *"FINDING ONE IS
NOT AUTHORISATION -- the caller still verifies."* That is a claim about two
modules together. The store is deliberately not revocation-aware, so a
revoked grant stays in it and `lookup` goes on returning it; what refuses is
`fzn_chain_verify` against the host's own revocation store.

    held-but-revoked: found before 1, found after 1,
                      verify before ok, after a grant has been revoked

**Both halves are asserted, because either alone is a different design.** A
store that dropped the chain would be revocation-aware and could not tell a
caller why a grant stopped working; a verify that accepted it is fail-open.

**The before-case is the control and is not decoration.** Without asserting
that the grant verifies BEFORE the revocation, the refusal afterwards could
be failing for any reason at all and would read identically.

### What the sabotage showed, including what it did not

Neutering the revocation consult in `fzn_chain_verify` -- every hop reported
live -- fires this scenario's assertion, and the printed line flips to
`after ok`, which is the fail-open made visible rather than inferred.

It also fires five other scenarios. **So this is not the only witness to the
consult**, and saying otherwise would overstate it. What is new is the
composition: no scenario had ever put a chain in a store, revoked it, and
asked both questions. The store half -- that `lookup` still returns it and
the count is unchanged -- is asserted nowhere else, because nothing else
called the store.

### And the sabotage that did not apply

The first attempt matched an `if (... fzn_revocation_covers ...)` that does
not exist -- the call is a statement filling a `revoked[]` array. It printed
`NOT FOUND`, and the run that followed was the unmodified code passing, which
looks exactly like a sabotage that was caught by nothing. **It was caught
because the script said so, not because the output differed.** That is the
reason `evidence.md` asks for an assertion that the substitution landed, met
here by printing the match.

`record/ledger.c` remains uncomposed and is the obvious next one.

## 120. The floor refused the scenario before I could believe it, 2026-09-06

`record/ledger.c` was the second module sec 119 found uncalled by any sim
scenario. `scenario_ledger` closes it: host 0 publishes twelve versions of a
subject to two peers, each acks what reached it, and the acks come back
through a network that reorders six times in ten.

    ledger: 12 rounds, 4 acks accepted, 6 arrived stale,
            0 moved backwards; host 1 at 12, host 2 at 12

### The floor fired on the first run, which is the point of writing it first

The property is that a confirmation never moves backwards, because *"a late
ack is reordering and not retraction"*. That rule is only consulted when an
ack arrives after a higher one -- so the scenario counts those and refuses to
pass without them.

**The first version reported `0 arrived stale` and the floor refused it.**
Not because the ledger was wrong: because the FIXTURE could not produce the
arrival order the rule exists for. It sent one version, drained it and acked
it before sending the next, so **no two acks were ever in flight together and
none could overtake another.** Every other assertion in the scenario passed.

Sending all twelve before reading any ack is the fix, and it is the whole
difference between a scenario that exercises the rule and one that reports a
number.

This is the third instance in two days of a fixture sitting on one side of a
boundary -- after `scrub_test` at exactly three full cells and
`scenario_filestore` at one scrub cell and one peer -- and **the first where
the floor caught it instead of a person.** The two before were found by
reading a summary line and noticing something odd. This one was refused by
the suite on its first run, which is the difference between a lens somebody
has to remember to point and a check that fires by itself.

### What it adds, stated narrowly

`ledger-monotonic` already exists as a sabotage entry and the unit test
already catches it, so **this is a second witness rather than a first.** What
it adds is the arrangement: the unit test calls `confirm(3)` then
`confirm(2)`, which is the author choosing the order; the scenario gets its
order from a reordering network, which is where the defect actually comes
from. Neutering the STALE refusal fires four assertions here, the first being
`a confirmation moved backwards`.

The other three checks are the ones the header calls the safe direction:
a peer is behind a version above the one it confirmed, a peer never heard
from is behind everything, and both resolve to "send it again" -- an
under-claim costs a retransmission, an over-claim silently withholds.

**And the substitution was confirmed to land before the result was read**,
which is sec 119's lesson applied one section later: the sabotage script
printed the site it matched, so a run that changed nothing could not be read
as a guard nobody needed.

## 121. The local hop, and a sabotage that landed on the wrong line, 2026-09-06

Nothing in the simulation had ever called `local/peer.h` or
`local/vocabulary.h`. `scenario_local_hop` runs them beside the chain and
changes one, because `record/record.h` states the design the pair exists for:
keeping authorisation out of the record layer "is what lets one project
authorise by chain, another by local uid, and a third by both", and a project
that is BOTH is where the two must not be confused.

    local-hop: alice 1, bob 0, carol 2 (unchanged by revocation);
               grant ok then a grant has been revoked

Three clients: one in the group a rule names, one in another, one whose
supplementary list could not be read at all. Then the host's grant is
revoked. **One decision changes and the other does not** -- a local verdict
is a fact about groups on this machine, a grant is a fact about a chain the
root signed, and a consumer requiring both now refuses.

**The third verdict is the one worth having.** `FZN_PEER_UNKNOWN` means "a
rule names this verb and I could not read your groups", and a daemon that
collapses it to a denial has thrown away the difference between *you may
not* and *I cannot tell*. The scenario asserts all three answers DIFFER,
which is the floor on the rules themselves: three clients answered alike
would pass every other check while discriminating nothing.

### A sabotage that landed, was confirmed to land, and changed nothing

Sec 119 records the lesson that a sabotage must be confirmed to apply,
because a run that changed nothing looks exactly like a guard nobody needed.
That lesson was applied here and **was not enough.**

`local/vocabulary.c` has three returns of `FZN_PEER_UNKNOWN`. The first
attempt matched the first of them -- an argument guard -- printed
`SITE FOUND`, replaced it, rebuilt, and the scenario passed with carol still
answering UNKNOWN. Everything the previous section asks for was done and the
result was still meaningless: the substitution landed on a line the case
under test does not execute.

The site carol reaches is
`return unknown_seen ? FZN_PEER_UNKNOWN : FZN_PEER_NOT_MEMBER;`, and
sabotaging THAT fires two assertions.

**So confirming a substitution landed is necessary and not sufficient; the
site has to be on the path the case takes.** The cheap check is the one that
was skipped: the printed line said which text was replaced, and reading it
against what the fixture actually exercises would have shown a null-argument
guard rather than the verdict fold. A first match is not a chosen site.

### And a hand-counted length, in the fixture

`fzn_peer_groups_parse` takes a length and its header is explicit that whole
lines are the caller's to guarantee. The first draft passed `30` for a
29-byte line, handing the parser the literal's own terminator. It happened to
work. `sizeof(...) - 1` replaces both counts, which is the same rule this
tree applies to anchors: a number typed from counting is a number that rots.

## 122. One convention, implemented twice, with nothing between them, 2026-09-06

The sweep in sec 119 left `disclose/disclose.c` at 0 of 4 exported functions
called by any scenario, with a file named `sim/test/disclosure_test.c` sitting
beside it. That looked like a naming coincidence and is not.

**That file hand-rolls the convention the module implements.** It carries
`#define SALT_LEN 16u` and builds `salt || field` itself, and it does not
include `disclose.h` at all. `disclose/disclose.h` carries
`FZN_DISCLOSE_SALT_LEN 16u` and the same layout. Two definitions of one
convention, agreeing today, with nothing comparing them.

**The failure that was available is the quiet one.** Had the module moved to
a 32-byte salt, this file would have gone on demonstrating a 16-byte one,
passing every assertion, and being cited as evidence -- it is the scenario
project.md's sec 5j discussion points at -- for a convention the library no
longer had.

### Not fixed by making the demonstration use the module

That was the obvious move and it is wrong. The file's whole argument is that
selective disclosure needs *"no second signature and no library change"*, so
building the commit by hand is the POINT; calling `disclose/` would answer a
different question and throw the argument away.

What it must not do is drift. So the constant is now
`FZN_DISCLOSE_SALT_LEN` rather than a second `16u`, and a case asserts the
two agree where they can be compared:

- the hand-built leaf hash equals `fzn_disclose_leaf` over the same salt and
  field -- **the same salt, deliberately, because what is being checked is
  the layout and the hash rather than the entropy**;
- `fzn_disclose_field` reads back the field the demonstration would have
  hidden, and reads it at `committed + SALT_LEN`, which pins where the salt
  ends as well as what the hash covers.

The demonstration stays independent of the module and is now pinned against
it, which is `evidence.md`'s *assert the relationship, not either value* --
and its converse, since two implementations that agree because one was copied
from the other are one witness, and these two were not compared at all.

### Seen to fail, and the site checked against the path

Moving `fzn_disclose_field`'s offset to `committed` fires both new
assertions. **The site was read against the case before the run**, which is
sec 121's correction one section later: there a sabotage landed on the first
matching line and that line was an argument guard the fixture never reached,
so `SITE FOUND` was printed over a result that meant nothing.

## 123. The frame's layout, written out by hand in five files, 2026-09-06

Sec 122's lens -- where else is one thing defined twice -- pointed at the
numeric `#define`s in test files. The largest group is not a coincidence:
`OFF_VERSION 0x00`, `OFF_KIND 0x05`, `OFF_SENDER 0x06`, `OFF_NONCE 0x2e`,
`OFF_COMMIT 0x46` and six more are **`frame.situ`'s layout written out by
hand**, and five files carry copies:

    wire/test/tamper_test.c        wire/test/seal_test.c
    wire/test/generated_test.c     chunk/test/agreement_test.c
    session/test/aead_monocypher_test.c

**What was pinned was the SIZE and not the positions.** `tamper_test.c`
carries `_Static_assert(SITU_FZN_HEAD_SIZE_FIXED == 91)` and three more like
it, so a head that changes length is caught at compile time in every tree
that builds. A schema change that keeps the head at 91 bytes and MOVES A
FIELD INSIDE IT passes all of them.

### Why that is worse than a stale constant

The five files would poke the wrong bytes, and the tests would go on passing.
`tamper_test` flips the byte at `OFF_NONCE` and expects `fzn_seal_open` to
refuse -- and after a field move it would flip some other authenticated byte
and **still get a refusal**, because every covered byte produces one. The
case would be green, its name would still say "nonce", and the thing it
asserts would have quietly become "some byte in the head is authenticated".

That is this tree's own recurring failure -- a test passing for a different
reason than the one it names -- with the schema as the moving part.

### The pin, and both limits on it

`tamper_test.c` already argues exactly this for the covered span: *"Two
derivations of one number, and a disagreement between them means the harness
below is flipping a set of bytes nobody in this file described."* The block
now extends it to the field offsets, comparing each constant against where
the generated accessor actually points.

**Four of the twelve, and both limits are the generator's rather than
choices.** situ emits a `_ptr` accessor for a byte array and none for a
scalar, so `version`, `kind`, `expires`, `msg`, `index`, `chunks` and
`length` cannot be located this way at all; and `capability` and `payload`
take a sealed gate rather than a view, so they are reachable only through an
opened seal, which is a later state than this check runs in.

Recorded because a reader who counts four checks against twelve constants
should find the reason beside them rather than infer an oversight.

### Seen to fail, in the direction available

Moving `OFF_NONCE` to `0x30` fires the pin first, ahead of the cascade it
causes. **That is the constant moving while the schema stays -- the reverse
of the risk**, since a schema move needs the schema edited and regenerated.
The assertion is symmetric, so it catches either; what has been demonstrated
is one direction, and saying which is the difference between a test seen to
fail and a test seen to fail at the thing it guards.

**The other four files remain unpinned copies.** One tripwire is enough to
make a field move loud, and the four are listed above so whoever hears it has
the set to fix rather than a grep to invent.

## 124. End to end, subsystem by subsystem: the plan, and the first one, 2026-09-06

**Instructed by the copyright holder 2026-09-06:** fuzznet is to test every
subsystem end to end -- *"start with simple tests for each one, then expand
what they test. This catches severe flaws earlier, and leaves less valuable
tests for later."* Broad and shallow first; depth afterwards.

### The worklist, measured rather than guessed

For every library source, how many of its exported functions does any sim
scenario call? Setting aside the four platform backends the sim replaces with
its own fakes by design -- `peer_linux`, `persist_file`, `spool_file`,
`session/random` -- the genuine zeros are:

    provision/provision.c   0/5
    spool/plan.c            0/2   (reached only through fzn_transfer_next_want)

and the thinnest are `local/peer.c` 1/4, `session/commitment.c` 1/3,
`chain/authz.c` 1/2 and `frame/freshness.c` 2/4.

### The first one, and it is the chain the holder asked about

*Does it have the local-to-root method* -- user GUI to root daemon -- was
answered piece by piece and nowhere as a whole. `scenario_gui_to_peer` is
that chain, deliberately simple: one verb, one setting, two hosts, no loss.

    gui-to-peer: refused not a member, admitted member,
                 1 setting across the wire, both ends at 1

Six steps, each a different subsystem: `local/vocabulary` decides whether the
GUI user may ask; `record/` signs it; `state/` applies it at the daemon;
`wire/` and `frame/` seal, send, open, check freshness and replay and verify
the sender's chain; **`record/journal` requires the peer to already follow
this issuer**; and `record/` + `state/` admit and apply it there.

**THE REFUSED PATH IS ASSERTED FIRST**, before anything succeeds, so nothing
it leaves behind can be mistaken for the admitted path's work -- and a
scenario walking only the happy path would pass with the admission check
deleted entirely.

### What the end-to-end pass found on its first run

The fifth step was not in the draft. `fzn_journal_admit` refused with
*"nothing received from this issuer"*, because a host must call
`fzn_journal_anchor` to decide it follows an issuer before anything from it
is admitted -- which `journal.h` states and which `record/sync.h` depends on.

**That is not an obstacle to route around and it is the point of the
exercise.** It is what stops a stranger who can reach the socket from
reconfiguring the machine, and it was invisible while every link was tested
alone: the journal's unit tests anchor as setup, so the requirement reads as
boilerplate rather than as a defence. Composed, it is a step with a security
property, and the scenario now asserts the refusal -- an unanchored peer is
sent a valid, authenticated, authorised setting and stays unconfigured.

Seen to fail: making `journal_admit` accept an unknown issuer fires exactly
that assertion.

### Why this order

A broad shallow pass finds a severed link; a deep test of one subsystem finds
a subtle fault in a link that may not be connected. The holder's instruction
puts the cheap discriminating test first, and the first one paid immediately
-- not by finding a defect, but by finding a step nobody had written down as
part of the chain.

## 125. The provisioning card, which had a story and no scenario, 2026-09-06

Second of sec 124's simple passes, and the largest zero on its worklist:
`provision/provision.c`, five exported functions and no scenario calling any
of them -- beside a file named `sim/test/provision_test.c` that tells the
provisioning story from `agree` and `aead` directly and never touches the
card. **The story was covered and the object that carries it was not.**

    provision-card: 423 bytes, 682 as text, round-tripped, verified,
                    and refused with a substituted prekey

Five steps: the sponsor packs a card; it goes out of band as the STRING a
code would carry and comes back; a device holding nothing opens and verifies
it; the anchor it was SHIPPED is the one the hop verifies against; and then
the assertion the envelope exists for.

### The envelope's whole job, quoted because it is the assertion

`provision.h`: *"Without the envelope a stranger takes a genuine hop --
public, and minted for a device the sponsor really did grant -- and pairs it
with their OWN prekey record, which is self-signed and therefore perfectly
valid."*

So the scenario substitutes a third host's genuine, self-signed prekey into
a genuine card. **Every part is valid and the card is not**, and only the
outer signature can say so. Neutering that check fires exactly that
assertion and nothing else.

Two floors around it, because the substitution is easy to make vacuous: the
forged bytes are asserted to DIFFER from the original, and the forged card
is asserted to still OPEN -- otherwise the refusal could be the parser's
rather than the envelope's, and would read the same.

### What the first run found, and what caught it

**The card is signed by the ROOT, not by the sponsor that hands it over.**
The first draft signed with the sponsor's key and `fzn_provision_verify`
refused a genuine card. `provision.h` says why in one line -- the envelope
"is signed by the root, which is the one key the scan authenticates" -- so a
card is a root's statement carried by a sponsor rather than a sponsor's own
claim, and a device pins what the root said.

**The before-case is what caught it.** The scenario asserts a genuine card
verifies before it asserts a forged one does not, and that assertion failed
while the forged-card assertion passed -- because a verify that refuses
everything refuses the forgery too. Without the control the scenario would
have gone green over a card nobody could have used.

### And a non-unique anchor, in the edit rather than the code

Adding a local to the scenario, the edit matched `fzn_agree_secret_t sk[2];`
in two other scenarios as well and declared a duplicate in each. The compiler
refused it, so nothing shipped -- but the script had no count assertion,
which `evidence.md` requires of exactly this and which every other edit in
this session carried. **The one edit written without the guard is the one
that needed it.**

## 126. What a hostile ask buys, which is the last zero, 2026-09-06

`spool/plan.c` was the third and last genuine zero on sec 124's worklist:
two exported functions, reached by scenarios only through
`fzn_transfer_next_want` and never called directly.

    planners: 2 ranges wanted, 2 offered covering 16 leaves;
              empty want bought 0, trillion-leaf want bought at most 4

Sec 25 records why they exist, and it is not scheduling -- a cheap message
must not buy an expensive answer, which `record/sync.c` learned the hard way:
*"a zero-length digest bought 64 ranges over 32,768 records, at least 5 MB,
from an input with nothing in it."* The planners inherited all three of
sync's rules rather than re-arguing them, and this is the first time any of
them runs between two hosts.

**No content and no backend, deliberately.** `plan.h` says these are "policy
over the bitmap: no allocation, no I/O, no wire format", so the fixture hands
`fzn_spool_open` a bitmap that already has bits in it -- the documented
resume path, with `open` recomputing `have` rather than trusting a caller. A
fixture that placed real leaves would exercise `blob/` and prove nothing more
about these two.

**The floor is that the honest exchange offers something.** Every refusal
below it -- empty want, clipped want, refused ceiling -- is indistinguishable
from a planner that answers nothing at all, so the scenario asserts a
non-empty offer covering exactly the sixteen leaves the asker lacks before it
asserts any refusal.

### The property with no line to sabotage

The empty want was the case worth attacking and there is nothing to remove:
`plan_offer` iterates the want array, so zero wants is zero iterations, and
the rule holds **by construction rather than by a guard.** That is the
stronger design, and `plan.c` had already written it down --

    "AND A WANT THAT NAMES NOTHING FALLS STRAIGHT OUT WITH NOTHING. There
     is no special case for it below and there does not need to be -- the
     loop runs zero times -- but it is the whole of `record/sync`'s
     measured defect, so it is named here rather than left to be inferred
     from the loop bound by whoever edits this next."

-- so the library anticipated the finding and said so at the site. What the
scenario adds is the assertion; what it cannot add is a sabotage, and saying
which is the honest half.

The ceiling IS a guard, and neutering the budget fires the trillion-leaf
assertion exactly.

### A sentinel printed as a measurement, in my own summary line

The first run printed `2 ranges wanted, 99 offered`. Ninety-nine is the
sentinel the scenario writes before each call, and the LAST case to touch
`offer_count` is a refusal, which correctly leaves it untouched -- so the
summary line reported a number no call had produced.

**That is the failure this tree spent an afternoon naming in somebody else's
output**, arriving in its own two sections later: a real run beside an
invented label, indistinguishable from a measurement, and caught by reading
the line rather than the exit code. The honest count is kept in its own
variable now, with the reason beside it.

**All three of sec 124's zeros are closed.** What remains are the thin ones
-- `local/peer.c` 1/4, `session/commitment.c` 1/3, `chain/authz.c` 1/2,
`frame/freshness.c` 2/4 -- which is the "then expand" half of the
instruction.

## 127. The thin four, and a hazard demonstrated rather than argued, 2026-09-06

The "then expand" half of sec 124's instruction. Four modules the sim called
but barely -- `local/peer.c` 1/4, `session/commitment.c` 1/3,
`chain/authz.c` 1/2, `frame/freshness.c` 2/4 -- and each unused symbol was
put where it actually composes rather than into a scenario invented for it.

    local/peer.c          4/4      session/commitment.c  3/3
    chain/authz.c         2/2      frame/freshness.c     4/4

Together with sec 124-126 that is every library module the sim can reach,
excluding the four platform backends it replaces with its own fakes.

### The truncation hazard, shown before the tool that prevents it

`fzn_peer_whole_lines` was the one worth the most, and `peer.h` states the
failure it exists for: a caller handing over a buffer its read merely FILLED
"gets every gid before the cut, `groups_known` set, and possibly a half-read
number at the end -- **250 as 25** -- which is a definite
FZN_PEER_NOT_MEMBER for a real member."

`scenario_local_hop` now parses one status text twice, cut mid-number, once
as a caller who did not trim and once as one who did:

- **untrimmed**: group 250 is absent, group **25 is present**, and the
  verdict is `NOT_MEMBER` -- *definite*, which is what makes it dangerous
  rather than merely wrong. A real administrator is locked out and nothing
  says why.
- **trimmed**: `groups_known` is false and the verdict is `UNKNOWN` -- the
  tri-state doing the only job it has.

Demonstrating the hazard before the tool is the point. A scenario that only
called `whole_lines` and checked the answer would prove the function works
and say nothing about what happens without it.

### What the others assert, stated narrowly

- **`fzn_replay_expire`** -- `freshness.h`: *"a receiver that has gone quiet
  should be able to hand memory back without waiting for a frame to
  arrive."* That is invisible to every scenario that keeps sending, so
  `scenario_quiet_receiver` fills a window, refuses a ninth nonce, advances
  the clock with nothing arriving, and finds room again. The floor is that
  all eight were admitted first: a window that refused them would make the
  reclaim meaningless.
- **`fzn_commitment_for_nonce` / `_check`** -- called on every frame inside
  `fzn_seal_open` and never asked directly. Two keys over one nonce: the
  same key agrees with itself, two keys do not. That is the stranger filter
  in two lines.
- **`fzn_authz_origin_permitted`** -- `authz.h` calls it *"an explanation,
  never a substitute"*, so the property is AGREEMENT rather than usability:
  where the explanation refuses an origin the decision must deny. And a
  zeroed policy reaches nothing, which the header says a forgotten one must
  mean.

### The pattern across all seven scenarios of this pass

Every one of them found its value in the same place: not in the happy path,
which was already covered by unit tests, but in **what the subsystem
refuses**, and in whether the fixture could tell a refusal from an absence.
Three of the seven needed a floor added before their central assertion meant
anything, and one -- sec 120's -- was refused by its own floor on the first
run.

## 139. A suite that does not name itself cannot be credited, 2026-09-06

Reported at the end of sec 138's work: `tool/sabotage.py` credited two of
trust's guards to `persist_test`, which reads as though trust's own suite did
not hold them. The copyright holder asked for that fixed.

**The first thing measured was whether it was true, and it was not.**
Breaking `trust/trust.c` and running `trust/test/trust_test` ALONE catches
every one of the four guards, first, with a specific message. The coverage
was there the whole time; what was wrong was the report. `evidence.md` says
to suspect the check before the code, and here the check was a reading of a
tool's output.

Three separate causes, and each is a defect in its own right.

### 1. The suite did not name itself

`trust_test` printed `FAIL: <what>` where every other suite in this tree
prints `FAIL <file>.c:<line>: <what>`. So nothing -- a tool or a person --
could attribute its failures, and a harness reporting one line per sabotage
had no way to prefer it.

**A test that does not name itself cannot be credited with what it catches.**
Fixed by routing both helpers through `__LINE__` macros, which is what the
other suites do.

### 2. The harness reported the LAST failing suite

`detail = named[-1]` -- so which line was shown was a fact about **run
order** rather than about coverage. It now prefers a line from the suite
named for the sabotaged file, by this tree's convention that `<dir>/<stem>.c`
is covered by `<dir>/test/<stem>_test.c`, and falls back to the last as
before.

**The fallback is now informative rather than misleading**: a report naming
another module's suite says no test in this module's own suite caught it,
which is a gap worth seeing.

### 3. A test in the wrong module fired first and took the credit

sec 138 had added, to `persist_test`, an assertion that a RESTORED self-root
still accepts the join. That is `trust/`'s rule, not `persist/`'s -- the join
is permitted exactly when the source is SELF, so it re-tested the line above
it -- and because `make test` stops at the first failing suite and persist
runs earlier, it fired first and hid trust's own coverage from the report.

**A test asserting another module's rule does not add coverage; it moves the
credit.** Removed, and the round-trip of the provenance, which IS persist's
own property, stays.

### What remains, and why it is right

`trust-self-records-its-source` is still reported through `persist_test`, and
that one is correct: recording a self-root as PINNED breaks persist's own
round-trip guarantee as well as trust's rule, so persist holds an independent
guard on it. **That is corroboration rather than masking**, and the
difference is whether the assertion belongs to the module making it.

### And the suite had no positive control

Found while fixing the above: `trust_test` carried none, where every other
suite here does. So "48 checks, 0 failures" was evidence that 48 things ran
and not that any of them could have said otherwise -- a suite never seen to
fail, which is the shape `evidence.md` opens with. It has one now.

## 142. Is there a catalog subsystem? No, and here is what it would be, 2026-09-06

Asked alongside sec 141: is there a catalog subsystem -- "a tree file/text
store which has slots for different (named, unique by hierarchy/name) files
pre-agreed or updated from an authority or extended/edited over time"? A list
of all movies or music; hydra's per-site filters; netcfgd's config. And
should it share routines with config, "or maybe not because config is
important for core functionality"?

**Measured: there is none, and nothing in the tree is catalog-shaped.** The
nearest four each answer a different question:

    state/       the current value of a setting, replayed from records
    record/      an ordered stream of signed statements
    spool/ blob/ content addressed by digest -- the NAME IS the content
    log/         a bounded, evicting stream

**What is missing is a NAMESPACE**: a hierarchy of names, each naming a thing
that can be replaced over time, where the name is chosen by whoever writes it
rather than derived from what it holds. `blob/` addresses content and cannot
express "the current filter list for example.com"; `state/` holds one value
per cell and has no hierarchy; `record/` orders statements without indexing
them by name.

### The question that decides its shape, and it is not sharing routines

**A catalog is `state/` with a hierarchical key and a large value.** That is
the honest one-line description, and it means the interesting question is not
whether to reuse config's code but **whether a catalog entry is a RECORD or a
BLOB REFERENCE.**

- **As records**, an entry is signed, ordered and replayable, and a catalog
  is `state/` with a path-shaped key. It inherits everything: authority,
  revocation, sync. It is bounded by FZN_RECORD_BODY_MAX at 512 bytes, which
  a filter list may exceed and a movie list certainly does.
- **As blob references**, an entry is a signed record naming a digest, and
  the bytes travel through `spool/`. Unbounded, deduplicated across
  consumers, and resumable -- but a two-step fetch, and an entry whose blob
  has not arrived is a name with nothing behind it, which is a state
  `state/` has never had to express.

**The second is almost certainly right and the first is what a first pass
would build**, which is worth saying now rather than after somebody has built
it.

### On sharing routines with config

**The holder's instinct is right, and the reason is stronger than
importance.** `state/` refuses a full table, and `log/` evicts, and
`record/journal.h` refuses a gap -- each because losing that particular thing
is a different kind of failure. A catalog is a fourth: **it should evict
nothing and refuse nothing, because a catalog entry that vanishes is a
feature the consumer stops offering, silently.**

So a catalog shares the RECORD layer with config, as everything here does,
and should not share `state/`'s table -- not because config is important but
because the two want opposite behaviour when full. `state/` refusing is right
for a setting; a catalog refusing to hold the ten thousandth film is a
different bug entirely.

**Not built, and not designed further than this.** It is a subsystem, the
holder has named three consumers with visibly different needs, and the
record-or-blob question above is theirs to settle first.

### Three further properties, 2026-09-06, and the third changes the shape

The copyright holder added: a catalogue needs **a wide variety of
configurable conflict resolution strategies**; permissions are needed **only
at whole-catalogue level** so far; and **most importantly, both directories
and files can be linked from several parents**, the structure must be easy to
edit, and **several directories can be combined as search terms** for that
reason.

**The third one means this is not a tree, and the word above was doing
damage.** A node with many parents is a DAG, and combining directories as
search terms is set intersection. Put those together and the honest reading
is that **a "directory" is a NAMED SET and the hierarchy is a view over
membership**, not a storage structure:

    an entry belongs to N sets
    a path is one way to name a set, not where the entry lives
    combining directories is intersecting their memberships
    editing is adding and removing memberships, never moving anything

That is why it is easy to edit, and it retires the "hierarchical key" framing
above: a hierarchical key has ONE parent by construction, so it cannot
express any of this. **The key is an entry identity and the structure is a
separate membership relation.**

**And it makes the conflict question easier rather than harder, which is the
opposite of what a first look suggests.** Membership is a set, and sets
merge: two hosts adding an entry to a directory commute, so most of what
would be a conflict in a last-writer-wins store is not a conflict at all.
What remains hard is add-versus-remove, which is the case a set design has to
name explicitly rather than the whole problem.

So the strategies the holder wants are a **seam**, in the shape this library
already uses for hashes and signers -- the consumer supplies the policy --
and the useful default for membership is union rather than last-writer-wins.

**Whole-catalogue permissions cost nothing extra**, because sec 129 already
supplies them: a catalogue is a service, and a capability is
`fzn_service_capability(service, product, name)`. No per-entry access control
is implied and none should be built before it is asked for.

**Still not built.** What has changed is that the record-or-blob question is
now clearly about ENTRY CONTENT, while the structure is a membership relation
whose conflict behaviour is a seam -- three decisions rather than one, and
they are separable.

## 143. The naming sweep: 47 files, and what the proof refused, 2026-09-06

Directed by the copyright holder 2026-09-06 after sec 141 measured the gap:
sweep every suite so its failure lines name it.

### The count was wrong, and the detector is why

sec 141 reported 61 suites. **47 files were actually changed**, and the
difference is the detector rather than the tree: it required the form
`FAIL <file>.c:<line>:` and therefore flagged suites that name themselves
another way. `blob/test/blob_fuzz.c` prints
`"blob_fuzz: FAILED on case %lu"` -- attribution served, in a form the
pattern did not accept.

A second false positive survived to the end: the last thing the corrected
detector reported was `"FAIL"` inside a COMMENT in
`chain/test/sign_monocypher_test.c`. The gate below therefore reads only
lines that PRINT, which is the difference between reporting on output and
reporting on prose.

**Both are `evidence.md`'s pattern-too-narrow and pattern-too-loose in one
sweep**, and both were found by running the detector again rather than by
reading it.

**And 57 stood here until the commit was being staged**, which is the same
rule a third time: it was inferred from the first detector's 61 rather than
counted from what changed, and the staged file list is what disagreed with
it. A scope number nothing downstream re-derives is the one that survives
wrong.

### The proof, and it failed first

A bulk edit carries a proof. This one is **output-only**, so the invariant is
that **every suite's reported check and failure counts are unchanged** --
captured from `make test` before, diffed after. 67 suites, identical.

**It failed on the first run, which is the proof working rather than a
setback.** The tool wrote `int ok` over every signature it matched, and
`tree/test/tree_test.c` calls its parameter `cond`, so the body referred to a
name the signature no longer declared. It did not compile, so no counts
existed to diff at all -- and a tool that had guessed right would have been
trusted for the wrong reason. The parameter name is captured now.

### Two passes, because one shape did not cover it

**The arithmetic, because a bare count is what rots**: the first pass
converted 30, the second touched 27, and 47 files changed -- so 10 received
both, a helper rewritten and a stray literal prefixed.

- **30 suites** route their assertions through a single
  `static void check(int ok, const char *what)` or `expect(...)`. Those got
  the treatment `trust_test` and `log_test` had: the helper gains a `line`
  parameter and a macro supplies `__LINE__`, so a failure carries a file AND
  a line.
- **27 files** carried something the first tool refused -- a second
  `expect_err`-shaped helper, or a scatter of one-off fixture messages. Those
  got a simpler edit: the literal is prefixed with the file's name. 71
  literals.

**The second pass carries its own proof**, and a stricter one: every string
literal is stripped from the before and after texts and the remainders must
be byte-identical, so no code outside a literal can have moved. Nothing was
refused.

**What the tools refused is the part worth reading**, since `evidence.md`
says a proof does not cover it. The first tool refused 30 files and named a
reason for each; every one was then handled by the second pass or was
already naming itself. Nothing was left half-converted, because a refusal
leaves a file exactly as it was.

### The gate, which is the durable half

A sweep fixes today. `make style` now requires every test source's printed
failure lines to name its suite, and **it was shown to fail**: un-naming one
literal in `journal_test.c` turns the gate red and naming it again turns it
green. 95 test sources.

Without it the next suite added starts the count again, which is how sec 139
came to find one at all.

## 151. The underscore style, removed -- and two stale numbers, 2026-09-06

The copyright holder, on reading sec 150: "I'm not sure we should disallow
spaces or convert them to underscores at all, this kind of behaviour is not
being done by software anymore. Who decided this and why?"

### Who decided, and the premise that was not true

**This session did**, from the holder's own sentence one turn earlier: "or
should we require underscores instead? ... Though I prefer underscores." That
was read as a question with a stated preference, so both styles were built
rather than one chosen.

**But nothing ever disallowed spaces**, and the record should say so plainly
rather than let the sentence stand: `usable_name` refuses only the C0
controls and DEL, sec 149's `usable_segment` refuses only a separator, a
traversal and an empty segment, and `AS_WRITTEN` was the zero value, so a
zeroed struct preserved them. Conversion happened only where a consumer
explicitly asked, and nothing in the library asked.

### Removed, on the holder's decision

The style is gone. A name renders as a person wrote it, full stop.

**What keeping it cost was not the code.** It was an opinion the library had
no reason to hold, a second path inviting a consumer to pick it, and paths
that would then no longer match what people typed. Any consumer still wanting
the transform has three lines over a name it already holds.

Two sabotages went with it, and one was renamed rather than dropped: the
bound on a segment survives, because a short buffer taking half a name still
writes a file under a name nobody chose.

### And two numbers this session got wrong the same way

**"59 suites still print FAIL with no file name" was stale when it was
said.** sec 143 swept them -- 47 files -- and the gate has enforced it since,
reporting "96 test sources, every failure line names its suite" on every run.
The 59 came from subtracting the two hand-fixed files from sec 141's
over-reported 61, and was never re-derived after the sweep that invalidated
it.

**It is the fourth scope number this session, and the worst of them**,
because it was repeated AFTER the work that made it false, in a message
recommending the holder size the job. The earlier three were wrong when
written; this one was made wrong and then said again.

**And a fifth, caught in the same minute.** An ad-hoc detector run to check
the claim flagged `chain/test/manifest_fuzz.c` -- where the only `FAIL` is
inside a COMMENT, which the real gate correctly ignores because it reads only
lines that print. sec 143 records that exact false positive and the fix for
it; the ad-hoc rewrite reintroduced it.

**The lesson is narrower than "re-measure", which was already written down
three times.** It is: **when a gate exists for a question, ask the gate.**
The gate had the right answer the whole time, in its own output, on every
run. What produced two wrong claims was reaching for a fresh grep instead of
reading the line the build already prints.

## 159. The log view's frame, and two controls that were wrong, 2026-09-07

The copyright holder: "fix the log view frame." sec 158 had reported a
`QPlainTextEdit` rendering only the left edge of its frame under qtty,
controlled it against a bare one, called it cosmetic and signalled it as
qtty's.

**The fix is one line and the interesting part is that it took three
measurements to say why, two of which were wrong.** This section is mostly
those.

### The first control changed two variables

sec 158's control was a bare `QPlainTextEdit` **with text in it**, against a
log view whose editor was **empty**. Composition and content both differed, so
it could not say which produced the frame. A matrix at one variable each:

    bare, empty                no frame
    bare, with text            no frame
    in a layout, empty         ┌ │ │ └
    in a layout, with text     ┌one │ │two │ └

The attribution was right -- it is the composition. The sloppiness cost
something else.

### What the empty fixture hid, and what that turned out not to mean

Put text in it and the lines **double-space**: every line gets a blank row
after it. sec 159 was first written saying the frame therefore cost CONTENT
rather than decoration, that a reader saw half as many entries as the terminal
had room for, and that the fix was justified on those grounds.

**That is true of the reproduction and false of this widget**, and the
difference is the font. Measured one setting at a time against the three the
log view sets:

    default (the matrix's case)        rows 2, 4
    monospace only                     rows 2, 3
    readOnly only                      rows 2, 4
    NoWrap only                        rows 2, 4
    all three (the log view)           rows 2, 3

**The monospace hint is the whole of it**, and this widget has set one since
sec 141 so a sequence column lines up. `readOnly` and `NoWrap` make no
difference. So the log view's entries were always consecutive, and the claim
that they were not came from a synthetic reproduction that had defaulted its
font -- the same error as the first control, one variable further along.

**The sabotage is what said so.** Putting the frame back left the render test
green, which is a guard failing to guard. Chasing that -- rather than
believing the tidy story already written -- is what produced the table above.

### So the fix stands on the reason that does not depend on qtty

`setFrameShape(QFrame::NoFrame)`. A border that draws one of its four sides is
worse than none, and it costs a cell of width and a row top and bottom on a
24-row terminal to do it. But the reason that survives whatever qtty does next
is that **a generic widget should not impose chrome**: this is the object
every consumer embeds -- sec 141 -- and a border around it is the consumer's
decision, reachable with a `QGroupBox` around the whole thing.

### The guard had to be repointed at what actually changes

The first version asserted the entries land on consecutive rows, which passes
with the frame and without it. It is kept -- consecutive entries are worth
holding on their own -- and **labelled in the source as not being the frame's
guard**, because a reader would otherwise take it for one and be wrong the way
its author was.

What guards the fix is an assertion that no box-drawing character appears in
the render at all. Putting the frame back turns exactly that red.

### The ASCII gate caught the write-up

`code-style.md` allows Unicode in a string literal and not in prose, and this
section's first draft put the box-drawing characters straight into a comment
explaining the frame. Four violations, refused.

Worth a line because of which half was already right by accident: the render
test compares against `QChar(0x250C)` rather than a literal, so it passed the
same gate without anybody deciding it should. The comment says the shape in
words now.

### The signal was corrected twice, in the tree that will read it

sec 158's report is in qtty's own `project.md`. It said "cosmetic and nothing
is blocked", which was wrong; the correction said "it is not cosmetic", which
was also wrong -- for their purposes it is the sharper fact that matters, and
the sharp fact is that **the doubling is font-dependent**. A proportional font
in a framed editor under a label double-spaces; a monospace one does not. That
is a clue about cell-height rounding and is worth more to them than either of
the two verdicts that preceded it.

**Their session had already committed our section**, sweeping it into
`8bfdf9d` under a message about the tray interface -- the shared-index hazard
running the other way, a day after we declined to commit their lines under
ours. Nothing was lost; what it costs is that `git log -S` for the arrival of
that report lands on an unrelated commit.

## 162. The loop closed, and the premise measured, 2026-09-07

The copyright holder: "do the decode through qtty next." sec 161 asserted that
the widget's modules land square on a cell grid and said plainly that this was
shape rather than readability, with the end-to-end check named as the next
thing. This is it.

### Widget, terminal, decoder

`make qtty QTTY_DIR=.. QUIRC_DIR=..` renders the QR widget onto a character
grid, rebuilds the pixels a terminal would actually show, and hands them to
quirc:

    screen: 464x464 px from 58x29 cells of 8x16
    quirc found 1 code(s)
    decode: Success
    payload off the terminal: "HELLO WORLD"  MATCHES

**Read through qtty's API rather than its snapshot text.** `render_once` into
a `CellBuffer` and `at(x, y)` per cell is a contract; parsing the snapshot's
colour section would have made this tree depend on a text format that exists
for people to read.

**No assumption about module size.** Every CELL becomes its own rectangle of
the reconstructed screen, so nothing in the check encodes how many cells a
module is meant to be. If the widget got that wrong the picture is wrong and
the decode fails, which is the whole point of not sampling module centres.

### The premise turned out to be measurable, and it had been a claim

sec 161 said "a module painted one cell each way arrives at a scanner
stretched two to one, and a stretched code is one a decoder MAY refuse". That
was reasoning. Rendering the same widget at one cell per module and asking
quirc turns it into a fact:

    one cell a module    232x464 px    quirc found 0 codes
    two cells a module   464x464 px    decodes, payload matches

So the stretched code is not merely riskier -- an independent decoder does not
find it at all. **The design decision was necessary rather than prudent**, and
that is worth the difference: a prudent choice invites somebody to simplify it
later.

### That control is what makes the pass mean anything

Both are asserted, and the second is the positive control `evidence.md` asks
for: *a check is untested until it has been seen to fail*, and a decode that
succeeds tells you nothing until you know the same instrument refuses
something. Here the thing it refuses is precisely the mistake the widget was
written to avoid, which is the strongest form the control can take -- it fails
the way the real defect would fail.

### Conditional, so the shape half still runs alone

`make qtty QTTY_DIR=..` checks shape and says so:

    qtty: QUIRC_DIR unset -- the render is checked for SHAPE only.
    qtty: add QUIRC_DIR=../fuzzypickles/quirc to decode it too.

Adding the second directory compiles quirc into the same binary and turns the
decode on. Two sibling checkouts is a lot to ask of a routine gate, and this
one is opt-in twice over -- but a target that silently did less when a
directory was missing would be `evidence.md`'s vacuous pass with a
configuration switch, so it says which of the two it did.

**84 checks against qtty `1c465d8`**, up from 82 -- the decode and its
control.

**quirc is C and had to be compiled as C.** It uses `new` as a variable name,
which a C++ compiler refuses, so the Makefile builds those four objects with
`$(CC)` and the header is wrapped in `extern "C"`. Worth a line because the
error it produces -- `expected unqualified-id before 'new'` -- reads like a
defect in quirc rather than a language mismatch.

## 166. The capabilities view, and a rule that was written twice, 2026-09-07

`gui/capability_view.{h,cpp}` shows one capability a host holds and what
state it is in. It is the last of the objects sec 139 named -- QR codes,
config, permissions, capabilities, log views -- and it follows sec 165's
rule: it renders the library's answers and computes none.

Two of those answers were the whole of the work.

### The rule that had two homes

A chain is expired when `expires_at != FZN_NO_EXPIRY && expires_at <= now`,
and **`FZN_NO_EXPIRY` is 0**. So the obvious shortening of that test is not
a weaker version of it. It is an inverted one for a whole class of input:
`expires_at <= now` reports every chain that never expires as the most
expired thing a host holds.

`chain_store.c` made the comparison twice -- in `find_expired` and in
`lookup` -- each site carrying its own paragraph about the sentinel, and the
eviction one saying in as many words that it was "the same comparison
`lookup` makes". Two copies of a rule, each with a comment explaining a trap
that the other copy also had to avoid.

The widget would have been the third writer. So the rule moved into
`fzn_chain_expired_at` in `chain/chain.h`, both existing sites now call it,
and their comments point at it instead of restating it. **The GUI is what
made the duplication visible**, which is the second time in this series that
building a consumer has been what found a thing about the library; sec 158's
fingerprint wrapping was the first.

It is deliberately named for expiry and nothing else. Revocation is a
separate store and a separate question, and a chain this answers 0 for may
still be revoked, unverified, or not have needed a chain at all.

### `covers`, never `known`

`revocation.h` keeps three predicates apart and says they must not be
confused. `fzn_revocation_covers` answers authorization; `fzn_revocation_
known` answers "must I still fetch this". They are one word apart at a call
site and they differ on **exactly one state**: an entry whose revocation has
since been WITHDRAWN, where `known` is 1 and `covers` is 0.

A widget asking the replication question would show a restored capability as
revoked -- which `revocation.c` calls "the outage the whole withdrawal
design exists to end". On any store that has never seen a withdrawal the two
agree perfectly, so nothing short of a withdrawal in the fixture can tell
them apart. The test builds one.

The store is passed straight through to the library rather than being
checked here, so a store that cannot be scanned reaches `covers` and gets
`covers`'s fail-closed answer. A widget that inspected the store itself and
passed NULL on finding it corrupt would fail OPEN, which is the polarity
that matters.

### Words that must not collapse

Three distinctions, all the same shape as sec 165's unspelled-versus-denying:

- **Expired and revoked** both mean unusable, and a screen saying "unusable"
  for both would be accurate and useless. One is a schedule running out; the
  other is somebody's decision about this key.
- **Revocation wins when both are true**, because expiry is passive and
  reversible by reissue while a revocation is the half somebody may need to
  act on, and it stays true after the dates stop mattering.
- **Holding nothing is its own state**, not a flavour of dead. A consumer
  handed no chain and one handed a dead chain have different things wrong.

And the live state is spelled **"usable", not "allowed"**. `fzn_chain_store_
lookup` shouts at its own callers that finding a chain is not authorisation;
the request is still verified and `fzn_authz_decide` is still asked whether a
chain was required. `gui/authz_view` answers that half.

### What is not shown, and why

**An expiry is printed as a number, not a date.** Nothing in this library
states an epoch: `now` arrives from the caller in every module that takes
one, and no code here reads a clock. A widget rendering these as calendar
dates would be choosing an epoch and a timezone on the library's behalf, and
would be wrong for any consumer that chose differently.

### The sabotage that was caught by the wrong case

All five guards were CAUGHT on the first run, and one of them was caught
for the wrong reason -- which the harness's own reporting is what showed.

`capability-view-revocation-wins-over-expiry` was written as `|| 1` on the
expiry branch, and it went red at `capability_view_test.cpp:96`: **"a chain
that never expires was shown as expired"**. That is the sentinel case, not
the precedence case. Forcing a branch to fire always does not model a
reordering; it breaks every input, so the first assertion in the file falls
over and the assertion about precedence is never reached.

It is the shape `evidence.md` names -- *a control has to be able to fail the
way the thing it controls for fails* -- and it survives a run that reports
CAUGHT, because CAUGHT only says something noticed. What made it visible was
the harness printing the FIRST failing line rather than the last, which was
sec 152's fix to the reporting and is now the second defect it has found.

The mutation is a reordering now: the revocation branch gains
`!fzn_chain_expired_at(chain, now) &&`, which is exactly "expiry wins
instead". Under it a revoked chain that has not expired still shows revoked
and every other case is unmoved; only the both-true assertion fails, at
`capability_view_test.cpp:149`. One case, and it is the case the guard is
about.

**A guard's mutation is worth reading even when the run is green.** Five
CAUGHT lines is a result about the tests; which line caught which is a
result about the mutations, and only the second says whether the guard is
aimed at anything.

## 167. The log view for a terminal, 2026-09-07

`cli/log_print.{h,c}` renders a log as text. sec 141 put a log in a widget;
this is the same two facts -- what is held and what is gone -- for a consumer
that has a pipe instead of a screen. `cli/qr_print.h` is the precedent and
this follows its shape: it writes into a caller's buffer, allocates nothing,
and prints nothing itself.

### Escaping stops being tidiness

`log/log.h` already argues that a viewer must render bodies through
`fzn_log_body_text`, and gives two reasons: a body carrying a newline and a
plausible sequence number draws a SECOND entry that no issuer ever signed,
and a body carrying an escape byte reaches the terminal the view is drawn on.

**On this side the second reason is the sharper one, and it changes kind.** A
widget handed an escape byte displays something wrong. A terminal handed one
OBEYS it: it can clear the screen, move the cursor back over the summary line
that says entries were evicted, recolour, or redefine what the next keystroke
sends. So a body is not merely displayed badly, it acts -- and the escaping is
the only thing between a signed body and the reader's terminal.

There is deliberately no branch in the renderer that writes `entry->body`.
The suite feeds a body of `\x1b[2J\x1b[H` and asserts no `0x1b` byte survives
into the output, which is a case that has no counterpart in the widget's
tests.

### What the journal is for, tested at last

The widget takes a journal and so does this, on `fzn_log_get`'s argument that
the position "is a parameter rather than a second call the caller is trusted
to remember". Writing the tests showed **the journal was load-bearing in
exactly one case, and neither view had been testing it.**

Eviction *inside* a stream is visible from the log's own range: `first > 1`
means the sequences below it are gone, and no journal is needed to say so.
Every case in the first draft of this suite would have passed with the
journal ignored entirely. The journal earns its place only when a stream is
evicted **entirely** -- the range is then all zeroes, the log knows nothing,
and only the journal can distinguish "five records were received and are now
gone" from "this host never followed that issuer". Those read identically
otherwise, and they call for opposite actions.

The fixture is a second issuer filling the log and pushing the first out,
which is how a real host loses a quiet stream to a noisy one. There is a
paired case for an issuer nobody follows, because a summary that invented a
loss there would pass the first case alone.

### A window is said, and it is the tail

`rows` is the caller's screen rather than the log's contents, so a log with
more in it than the window says `showing N newest`. **That word was nearly a
lie.** `fzn_log_read_since(log, ..., 0, window, rows)` fills from the OLDEST
entry after `since`, so asking it for a window from zero returns the oldest
rows -- and the summary would then have called them the newest. `since`
starts a window back from the last sequence held.

`rows = 0` asks for the summary alone, which is the question a health check
has: how much have I lost, without the content. That case is also why
emptiness is decided from the log's range and not from how many entries came
back -- deciding it from the count would report a full log as holding
nothing whenever nobody asked for rows.

An oversized `rows` is refused rather than clamped, because a silent clamp is
the unmarked shortening this module refuses everywhere else.

### Rendering twice to promise nothing is written

A body's length is not knowable without rendering it, so measuring means
rendering. The alternative -- writing while it fits and giving up part-way --
leaves a caller holding half a loss report. So the renderer runs twice
against one `struct sink` that may have no destination, and the two passes
agree by construction rather than by two pieces of arithmetic being kept in
step. A viewer is not a hot path and this is the cheap side of that trade.

### A duplication with nothing checking it -- settled the next day

**This subsection recorded an open question and the question was answered, so
it is rewritten rather than left standing.** What it said: the summary wording
was written twice, in `gui/log_view.cpp` and `cli/log_print.c`, matching by
hand with nothing checking that they still did; the options were to make the
widget depend on `FZN_CLI` the way `gui/config_view` already does, or to accept
that the words can drift; and it was the holder's call which.

The holder called it on 2026-09-07: the widget depends on `FZN_CLI` and asks
`cli/log_print` for the words. Sec 168 is the change. The widget asks for the
two halves rather than splitting one buffer at a newline, which would have made
it a parser of a format -- a new thing to get wrong rather than one thing
fewer.

**It then became the rule the next nine widgets were built to**, which is why
this entry is worth keeping in corrected form rather than deleting. Sec 193
states it: when a printer is added for a fact a widget already shows, the
widget changes in the same commit, because a CLI counterpart written for an
existing widget re-creates this duplication otherwise. Ten of the eleven pairs
consolidated on that rule; sec 201 is the one that measured and declined, and
sec 202 is the one where the widget earns the dependency by adding what a
single line cannot carry.

**Why it is rewritten and not appended to.** An entry recording a deliberate
non-decision decays exactly like one recording a fix and more quietly, because
nobody re-reads the open questions while closing one. Left as it was, a reader
would find a live-sounding "it is the holder's call which" beside a tree where
it had been called, and would believe the document -- the careful-sounding one
always wins. The stale half is quoted above so that `git log -S` on its own
words still finds the case.

### Three gates found what the tests did not

The suite was green before `make check` was run, and three separate gates
each named something real: the test binary was missing from `.gitignore`, and
`installcheck` refused because `cli/log_print.h` is installed but was not
included by `tool/consumer_check.c` -- the consumer that proves the installed
headers actually compile from outside the tree. An installed header nothing
includes is a header whose install is untested, which is the same shape as a
test source that builds and never runs.

### Reading which line caught which, again

sec 166 ended with the rule that a green sabotage run is a result about the
tests while *which line caught which* is a result about the mutations. Applied
here it raised a question and, this time, answered it the other way.

`log-print-escapes-the-body` was reported at `log_print_test.c:186` -- "a
body with a newline in it drew an entry no issuer signed". That is the
injection case, which the widget's suite also has. The terminal-escape case
is the one that only exists on this side and is the reason this file was
written, and it had not been seen to fail.

Running the mutation by hand rather than through the harness: **five checks
fail, at lines 186, 188, 189, 213 and 214.** The last two are "an escape byte
from a body reached the terminal" and "the escape byte was not escaped". Both
assertions are live and either would catch the defect alone; the harness
reports the first because sec 152 made it report the first.

So the guard was aimed correctly and nothing needed changing -- which is
worth recording precisely because sec 166's identical-looking observation
found a defect. **The reported line tells you which assertion fired first,
not which assertions can fire**, and the two questions are answered by
different commands. One sabotage, one report line, and five live assertions
behind it.

## 168. One wording for a log's screen, 2026-09-07

sec 167 recorded a duplication and named two ways out. The copyright holder
chose the first: **`gui/log_view` depends on FZN_CLI now**, and the summary
wording lives once, in `cli/log_print.c`.

The widget had composed both strings itself -- which sequences are held, how
many were evicted, one line per entry -- in wording that matched the CLI's by
hand. Two implementations of one screen, with nothing comparing them and no
reason either author would look at the other file.

### The halves, not the whole

`cli/log_print` grew `fzn_log_summary` and `fzn_log_entries` beside
`fzn_log_print`, which is now exactly those two in order. The widget needs
them apart because the summary goes in a label and the entries in a text
area, and one buffer cannot serve two widgets.

**Splitting `fzn_log_print`'s output at the first newline was the obvious
alternative and is worse.** It would make the widget a parser of a format --
a new thing to get wrong rather than one thing fewer -- and it would break
silently the day a summary needs two lines. The composed form being built
FROM the halves is what makes the three impossible to disagree.

### The assertion that keeps it true

The suite asserts the widget's `summary_text()` equals what `fzn_log_summary`
renders, and the same for the entries. That is a relationship rather than a
table: it survives the wording changing, and it goes red the moment somebody
composes a summary in the widget again. Asserting the words themselves would
have been a third copy of them.

This is what sec 167 could not offer. The duplication was recorded there as a
gap precisely because nothing could check it; the fix is not that the words
now match but that **there is only one place they can be written.**

### A budget, because the honest bound is absurd

`FZN_LOG_PRINT_MAX(256)` is **530561 bytes** -- every one of 512 body bytes
can escape to four characters. That is the true worst case and nothing like
the real one, and sizing a widget's buffer to it would spend half a megabyte
to show a screenful of short lines.

So the window adapts: a fixed 64 KiB, ask for 256 rows, halve on refusal
until they fit. It terminates because the window strictly decreases and zero
rows renders no entry lines at all.

**This is what sec 167's refuse-and-say-what-was-needed contract bought**,
and it was not designed for it. A renderer that truncated silently could not
support an adaptive window at all, because the caller would never learn it
had been shortened. What makes the shrinking safe is that the summary
declares the window it settled on -- so the summary is asked for the window
that FIT, not the one that was wanted, and a sabotage entry guards exactly
that.

Without a case for it the loop never runs: every other log in that suite
holds four entries. The fixture is forty entries of 0xfe bodies, which escape
four characters a byte, and it asserts the window was shortened as well as
declared -- `lines_of(...) < 40`, or the case proves nothing.

### Two smaller things the move turned up

**A guard moved rather than died.** `view-names-what-was-evicted` sabotaged
`if (first > 1u)` in the widget. That line is in `cli/log_print.c` now, so
the entry is `log-print-names-what-was-evicted` and it guards both screens at
once -- the widget's test fails too, because the widget shows those words.
The harness found it by refusing to verify a stale entry.

**Counting newlines was counting the wrong thing.** Two assertions read
`entries_text().count('\n') == 3`. The widget's text no longer ends in a
newline, because a trailing one is a blank row of the reader's screen, so
three entries make two newlines. Lines and newlines differ by whether the
last line is terminated, and the old form made the assertion depend on a
property of the text area rather than on what was rendered.

## 169. Vendoring quirc and qtty, 2026-09-07

Both were reached as live sibling checkouts through `QUIRC_DIR=` and
`QTTY_DIR=`. Both are submodules now, on the copyright holder's instruction,
and `harmonization.md`'s soft rule: prefer a vendored copy to a live sibling,
because a sibling is whatever its session left it as while a vendored copy is
a version you chose.

    quirc   https://github.com/dlbeer/quirc.git      927d680  (v1.2-7)
    qtty    https://github.com/funklord/qtty.git     1c0d649

### quirc: the edge was running backwards

`make qrcheck QUIRC_DIR=../fuzzypickles/quirc` had **this library depending
on its own consumer.** fuzzypickles vendors fuzznet; measured in their
`.gitmodules` rather than recalled. So the only independent witness the QR
encoder has -- the thing sec 162 exists for, since an encoder's tables are
worth nothing against a decoder we wrote ourselves -- lived at a path that
existed only if you happened to have cloned a different project next door.

It is vendored from **upstream**, not from fuzzypickles. The pin is the
commit fuzzypickles already carries, so a QR fault reported from there
reproduces here against the same decoder.

### qtty: pinned for a narrower reason than the rule

Nothing this library ships links qtty. It is a test instrument, used by an
opt-in target, so the dependency rule does not obviously reach it.

What reaches it is `evidence.md`: **a fact recorded without its method has a
shelf life**, and the method here includes which qtty. sec 158 and sec 159
record measurements taken THROUGH it -- the fingerprint's column floor, and
the frame that came out as a left edge and nothing else. `make qtty` pinned
to whatever the sibling's HEAD was on the day, so those findings were
measured against a moving target and could not be re-taken. The submodule
fixes that and nothing else.

**It is for this tree's widgets. It is not a shared dependency**, and a
consumer of fuzznet should not reach through fuzznet's build into fuzznet's
submodule to get it. Said plainly here because fuzzypickles asked.

### The single-list defect, three times in one afternoon

Vendoring two trees broke three gates, all the same way and all
independently: `tool/enum_gate.py` and `tool/status_gate.py` each carried the
literal string `monocypher/`, and the Makefile's `VENDOR_PRUNE` was
`-not -path './$(MONO_VENDORED)/*'`. Between them they reported fourteen of
quirc's C files as unlisted and three of qtty's enums as unparseable.

Each was a list that had to be edited whenever a submodule was added, with
nothing announcing that it existed. **`.gitmodules` already holds the
answer**, so all three read it now. That is the same move as sec 168's --
one place a fact can be written -- arriving from a different direction, and
the reason all three had it is that each was written when there was exactly
one submodule and one was indistinguishable from all.

### Two smaller things

**Vendored code is compiled quietly, and that is not reducing a check's
output.** quirc built with this tree's flags emitted 43 warnings about code
fuzznet does not own and will not change, burying the single line `make
qrcheck` exists to print. Its four translation units compile with `-w`; ours
keep every flag, and seven warnings remain, all of them ours.

**Two of those seven are real and predate this.** `qr/qr.c` has been emitting
`-Wvla` on `interleaved` and `stream` since sec 160 -- genuine variable
length arrays in a library whose whole discipline is that it allocates
nothing and bounds everything. They are stack allocations the compiler cannot
size. Nothing gates on warnings, which is why two years of `make check`
output could carry them unread. Not fixed here; it is not this change's
business and it wants its own.

## 170. The variable length arrays in qr.c, 2026-09-07

sec 169 noticed them and left them, being another change's business. They are
these two, in `fzn_qr_encode`:

    uint8_t stream[TOTAL_CODEWORDS[FZN_QR_VERSION_MAX]];
    uint8_t interleaved[TOTAL_CODEWORDS[FZN_QR_VERSION_MAX]];

`TOTAL_CODEWORDS` is a `static const uint16_t[]`, and **a `const` array is not
a constant expression in C.** So both are VLAs: stack allocations whose size
the compiler cannot check, in a library whose whole discipline is that it
allocates nothing and bounds everything. They have been there since sec 160
and `-Wvla` has printed on every build since.

### Why a warning survived four months of green gates

**Nothing in this tree gates on warnings.** `make check` runs 161 suites, a
style gate, a sabotage harness, an enum gate, a status gate and an
installcheck, and not one of them reads a compiler diagnostic. So the two
lines printed on every build, inside output nobody greps for the word
"warning", and a suite that passes says nothing about them.

That is `evidence.md`'s vacuous pass from an angle it does not list: not a
check that inspected nothing, but a **fact with no check pointed at it at
all.** The gates were all working.

### The fix, and why the constant is not trusted

`QR_CODEWORDS_MAX` is 655, which is version 15's entry and the largest in the
table. That is **a typed constant which has to equal a table entry**, and
`evidence.md` is explicit that such a value has no remedy in re-measurement:
every later reading of it agrees with itself, because the loop is closed.

So it is checked at the point of use rather than trusted:

    if (TOTAL_CODEWORDS[version] > QR_CODEWORDS_MAX)
            return FZN_QR_ERR_MALFORMED;

One comparison. Extending the table past version 15 without moving the
constant now refuses instead of overflowing two stack buffers -- which is
precisely the failure the VLA was concealing, by silently growing the frame
to fit whatever the table said.

The value itself was derived from the table by a script rather than read off
the line, which also confirmed two things worth knowing: the table has
exactly `FZN_QR_VERSION_MAX + 1` entries, and its last entry is its largest.
Neither was obvious and the bound depends on both.

### The suite had never made the largest code

The guard cannot fire while the table is right, so its only test is the
sabotage -- and the sabotage only bites if something encodes a version-15
code. **Nothing did.** Every successful case in `qr_test.c` was a small
version; the largest payload it used was one it expected to be REFUSED. So
the buffers this bound sizes had never been filled by the suite at all, and a
bound too small for them would have gone unnoticed exactly as the VLA did.

There is a case now, and it searches for the payload length that reaches
version 15 rather than writing one down -- a written length is another
constant that must agree with the capacity tables, with nothing to check that
it still does.

### What is left, and a measurement that was nearly wrong

After the fix the library builds with **zero warnings at `-Os`** -- 64
objects, GUI and CLI on. This section said exactly that and stopped, and it
would have been a true sentence answering the wrong question.

`make check` also builds a **sanitized** tree at `-Og`, and there `qr/qr.c`
still emits two: `-Wsign-conversion` in `place_data` and `draw_format`, on
expressions the `-Os` build folds away before the check runs. **The warning
set is a property of the optimisation level, not only of the source** --
`evidence.md`'s "a gate's verdict can be a property of the toolchain" arriving
in a place it does not list. A clean `-Os` build is not evidence about the
tree; it is evidence about one arrangement of it, and this file has now made
that mistake in the same section that was written to describe an unread
diagnostic.

So eleven remain, not nine, and none are the VLAs:

    tool/consumer_check.c        4   a shadowed local named `store`
    qr/test/qr_quirc_check.c     5   sign conversion, via `make qrcheck` only
    qr/qr.c                      2   sign conversion, at -Og and not at -Os

Eleven is small enough that a warnings gate is now possible, which it was not
while the VLAs were in the list. **Whether to add one is not this change's
call** -- it would make every future warning a build failure, which is a
convention change rather than a fix, and `working-practice.md` says those are
not adjusted in passing. It would also have to say which arrangement it
gates, because the two `qr.c` lines above show that answer differs.

### The eleven were fourteen, because the count came from an incremental build

Re-measured 2026-09-08 with `rm -rf` and a clean build of each arrangement,
because acting on the paragraph above meant re-deriving its number first. It
is a scope number, and `evidence.md` says nothing downstream re-derives one.

	-Os, GUI and CLI on          0
	sanitized -Og               14

The enumeration above lists eleven and names three files. The sanitized
arrangement holds **fourteen** across eight files, and six of them are in
SHIPPED LIBRARY SOURCES that the list does not mention at all -- the `bit_get`
family in `spool/plan.c`, `spool/spool.c`, `spool/scrub.c` and
`chunk/reassembly.c`, plus `qr/qr.c`'s two.

**The cause is that a warning is only emitted by a file that gets
recompiled.** Every count taken from `make check` is a count over whatever
that run happened to rebuild, and an incremental build is the normal way
anybody measures. The gate log this was checked against showed ten sites; a
clean build of the same tree shows fourteen. Neither run was wrong and only
one of them answers "how many warnings does this tree have".

So the method belongs beside the number: **`rm -rf` the build directory,
build each arrangement separately, and sort the warning lines unique.** A
figure taken any other way is a figure about a build, not about a tree.

### All fourteen are fixed, and six of them shipped

The six library ones are one idiom: a `uint8_t` or `uint16_t` promotes to
`int`, and `& 1u` then converts that signed value to unsigned. Benign in every
case -- the operand cannot be negative and the mask yields 0 or 1 -- so the
fix makes the promotion explicit rather than changing any value.

Of the eight in tests, six were the same shape or a shadowed local. Two were
worth more than the warning:

- **`chunk/test/reassembly_fuzz.c`** cast both arms of a conditional to
  `uint16_t` and the conditional promoted them straight back to `int`, so the
  assignment converted anyway. The casts were saying the right thing in a
  place where C does not listen; casting the whole expression is what they
  meant.
- **`spool/test/spool_file_test.c`** built a path with `snprintf` and did not
  read the result. `snprintf` cannot overflow, so this was never a memory
  fault -- what it could do is TRUNCATE, at which point the case opens a
  different file and passes having exercised a spool it did not mean. That is
  `evidence.md`'s vacuous pass wearing a formatting warning's clothes, and it
  is a check now rather than a cast.

**The gate question the paragraph above leaves open is unchanged and is still
the holder's.** What has changed is that the answer no longer has to be
"eleven, in some arrangement": both arrangements are at zero, measured the way
the method above says, so a gate would start from a clean tree rather than
from a waiver list. `evidence.md`'s note that a gate carrying a long ignore
list has been switched off by instalments is the reason that distinction
matters.

## 171. The pairing screen, and a design claim nothing was checking, 2026-09-07

sec 160 encodes QR modules, sec 161 paints them in a widget, sec 163 prints
them to a terminal -- and **nothing in the tree produced anything to put in
one.** `gui/provision_view.{h,cpp}` closes that: a provisioning card as the
code to photograph, beside who it says you are pairing with.

`provision/provision.h` is the payload those three were built for, and says
so: its card is uppercase base32 "because QR alphanumeric mode covers 0-9,
A-Z and a handful of symbols including `:`".

### The claim, measured

That sentence reads like an optimisation and is not. A card's text is **682
characters**, and:

    uppercase, level L    version 15        fits
    uppercase, M / Q / H  no version        does not fit at all
    lowercased, level L   no version        does not fit at all

Level L is the only level a card fits at, and the uppercase decision is what
makes it fit at all -- 682 bytes is past version 15's 523 data codewords, so
byte mode cannot hold a card at any level. **Both facts were load-bearing and
neither was checked**; the suite pins them now, so a later card layout that
grows past what a code can carry fails in a test rather than in somebody's
camera.

### The fingerprint waits for the verdict

This is the security decision the widget exists to get right.

A card names a root, a hop and a prekey, and the envelope signature is the
only thing saying those three came from one hand -- provision.h: "The parts
may each be genuine and not belong together." So an attacker can put a
**genuine root** beside their **own prekey** and sign the envelope
themselves. The root field then reads correctly.

A user pairing by comparing a fingerprint out of band compares exactly that
field, finds it right, and accepts. **Showing the fingerprint before the
signature has been checked hands the user the attacker's own evidence.** So
no fingerprint is offered for any card that has not verified -- refused,
expired, or simply never checked.

The code itself is still drawn, because a card is public by construction and
the offering side has nothing to check its own card against. It is the
fingerprint that waits, not the code.

The suite asserts this as `root_text() != fingerprint_of(genuine.root)` for
every unverified case, rather than by matching a refusal message. **A
security property tested by recognising a string is one a reworded string
switches off**, which is also why the widget has no `shows_fingerprint()`
predicate: it would have had to recognise its own wording.

### Four states short of usable, and they are four

    NOTHING     no card
    REFUSED     not a card, or the signature does not verify
    UNCHECKED   shape is fine, nobody was asked to check it
    UNDATED     verified, but no clock -- the expiry was never looked at
    EXPIRED     verified, and past its date
    USABLE      verified, and in date

UNCHECKED and UNDATED are the pair worth defending. `fzn_provision_verify`
takes `now` and treats zero as "skip the expiry check", which provision.h
justifies -- a device being provisioned may not have talked to anything yet.
A widget that passed zero and then said "usable" would be **reporting a check
it did not make**, and the expiry is what stops an old card being replayed at
a device. EXPIRED is separate on provision.h's own argument: a card that was
valid and is not any more is an ordinary thing to say to a user, where a
malformed one is a fault somewhere.

### The bug hunt that was my own instrument

Establishing the fit above, `fzn_qr_version_for` said a 682-character card
fits version 15 at level L and `fzn_qr_encode` refused the same input --
two functions of one module disagreeing, with a 91-character band between
them, and a card sitting inside it. That looked like a serious defect and it
was not one.

**The object I linked was not built from the committed source.** The sec 170
sabotage run had built `qr/qr.o` from its own mutation -- `QR_CODEWORDS_MAX`
at 654 rather than 655, which makes the new guard fire for version 15 -- and
the harness restores the SOURCE and leaves the object. I then linked that
object directly with `gcc` instead of going through make. Rebuilt, the two
functions agree exactly at 758 and there is no band.

`build-and-commit.md` says this in as many words: never conclude that a test
passes or fails from a binary the build step did not rebuild. The rule was in
front of me and the failure still took four measurements to find, because the
disagreement was plausible, specific, and pointed at code I had edited an
hour earlier.

**The suspicion that saved it was the right one and was aimed wrongly.**
Suspecting my own recent change was correct practice -- and the change was
innocent; what was guilty was the artifact. `make` itself was never fooled:
the restored source is newer than the object, so a build rebuilds it. Only a
direct link sees the stale one, and a direct link is exactly what a
throwaway probe reaches for.

## 172. From fuzzypickles: the holder has released the consolidation, and the generic half is still growing, 2026-09-07

Written 2026-09-07 from `fuzzypickles`. Everything measured here is measured
in that tree, in its voice; nothing in this tree was changed but this section.

### The fact that changes something

fuzzypickles' own sec 17 has carried, since it was written, the line **"the
consolidation itself waits on the holder saying so here."** The holder has now
said it, and attached a policy:

> a large chunk of fuzzypickles should go there, and functionality side by
> side, until it is proven that all of it and the knowledge has been
> transferred

**And their correction of my first reading of it, which matters more than the
sentence above.** I had taken "proven transferred" as a checkpoint -- a proof
that code and reasoning had moved, passed once. It is not. The holder's
clarification:

> they stay until we are sure that the new part is working, is the best
> solution and fully integrates. That takes time sometimes.

So the condition is a test of the REPLACEMENT, not of the transfer, and it is
a period rather than an event. Three criteria -- it works in use, it is the
BEST solution rather than an equivalent one, and it integrates fully at its
consumers -- with no date attached to any of them.

**The practical consequence for you is that nothing here is a deadline.** A
file arriving in fuzznet retires nothing in fuzzypickles on arrival, and the
duplicate existing is not a debt anybody is being asked to clear quickly. The
second criterion is the one I would expect a later reader to drop -- "it
works, retire the old one" is the natural reading and it is wrong, because the
local copy is what makes "is this better?" answerable at all.

### What is still here, measured today rather than recalled

fuzzypickles' sec 17 drew the line at whether the code knows a **contact**
exists, and listed the generic side. Re-measured against `core/src` today,
every file on that list is still local:

    blob.c            1988    sched.c           251
    capability.c      1061    link.c            214
    manifest.c         792    rendezvous.c      187
    append_log.c       475    addr_observe.c    151
    group_ratchet.c    389    recv_seen.c       133
    log_relay.c        312
    crypto_msg.c       212    generic total    6523 lines
    pairing_crypto.c   138
    peer_wire.c        118
    prekey_channel.c   102

### The part I would not have found by reading the list

**The generic half is not merely un-migrated, it is still accreting.** The ten
files the inventory named measured 5321 lines when it was written and measure
5587 now -- **+266 lines**, concentrated in four:

    group_ratchet.c   280 -> 389   (+109)
    blob.c           1893 -> 1988   (+95)
    manifest.c        753 ->  792   (+39)
    prekey_channel.c   79 ->  102   (+23)

Every line added to a file already agreed to be generic is a line that gets
written once here and moved once later, or diverges. That is not an argument
for hurrying -- the side-by-side policy above says explicitly that nothing is
retired early -- but it is an argument for **taking the growing files before
the static ones**, which is the opposite of the order size alone would
suggest. `blob.c` is the biggest and `group_ratchet.c` is the fastest-moving.

### Where a clean split is a lie, in fuzzypickles' own words

Three files carry both halves and the inventory says so: `identity.c` holds
the TOFU pinning discipline, which is generic, and the contact record, which
is not; `config_sync.c` and `peer_sync.c` are a generic signed-record sync
mechanism carrying chat-shaped payloads; `peer_pair.c`, `delegate.c` and
`sibling.c` implement realms, which are generic, against a trust model that is
fuzzypickles'. These are the ones where "move it" is a design question rather
than a transfer.

### One duplication that is already live

`qr/qr.c` arrived here today at 726 lines. fuzzypickles has carried
`client/qr.c` since 2026-07-30, at 455. Both implement the same standard --
version selection, Reed-Solomon, masking -- and **they are not
interchangeable**, which is the part worth knowing before either is deleted:

    fuzznet      fzn_qr_encode(const char *text, ...)    alphanumeric, base32 + FZN1: prefix
    fuzzypickles fzp_qr_encode(const uint8_t *data, ...) byte mode, deliberately

fuzzypickles' header argues the byte-mode choice explicitly: the contact card
is binary, alphanumeric packs 5.5 bits per character, and base58-ing the card
to reach that mode spends about 5.9 bits of text per 8 bits of payload, so raw
bytes are strictly smaller. Consolidating onto an alphanumeric-only encoder
would lose that. Whether your encoder grows a binary entry point is yours; I
am reporting that the choice exists and is argued, not asking for it.

**And fuzzypickles did not fail to move this.** Your own `qr/qr.h` records
that sec 71 deliberately stopped short of an encoder and that the holder
approved the scoping and has since reversed it. There was nothing to move into
until today.

### What I am asking for

Nothing yet, beyond knowing this is coming. The order, the pace, and what
"proven transferred" means are all yours and the holder's. I have not filed
the cross-project question either -- that two trees pinning one dependency
pin the same commit is checked by nobody, and you said it belongs on
`claude-guidelines`' signal list rather than between us.

## 173. The QR gate stops being opt-in, 2026-09-07

`make qrcheck` is part of `make check` now. It was excluded, and the comment
saying why was still sitting above the target:

> NOT PART OF `make check` ... it needs a sibling checkout, and a gate that
> breaks for another tree's reasons is one people switch off.

**That reason expired when sec 169 vendored quirc, in the same session, and
nobody noticed.** An exclusion outliving its own justification is the shape
`evidence.md` calls a claim that outlived its subject -- and it cost the
tree's only independent decode running on demand rather than every time.

### What it buys, and why neither tree had it

Measured in fuzzypickles rather than assumed: they proved their encoder
against zbar and libqrencode once, over 20 payloads from 1 to 1800 bytes, and
recorded it. Their STANDING check then had to use their own recogniser,
because -- their words -- "a committed test cannot depend on a package that
happens to be installed", and they state plainly what that costs: it no
longer proves the symbol is readable by the rest of the world.

That is a better-reasoned position than the one this tree held, and it
identifies exactly the constraint vendoring removes. An independent decoder
that needs nothing installed can run every time. So:

    theirs   independent witness, once, recorded    own decoder, standing
    ours     independent witness, on demand         -- nothing standing
    now      independent witness, standing

### A skip that reported both halves

Written first as separate recipe lines with `exit 0` in the skip. Make gives
each recipe line its own shell, so the skip printed its notice and the next
line then failed for the reason the skip had just excused -- **SKIPPED and
non-zero in one run**, both true and the pair meaningless. It is one shell
now, and the three cases are the ones `MONOCYPHER_DIR` keeps apart: an empty
variable is off, a missing vendored copy is an unfinished clone and skips
naming the command, an override pointing at nothing is an error.

## 174. recv_seen, and the two paths it sits between, 2026-09-07

Working with fuzzypickles directly rather than through the holder, on their
instruction that the relay was losing information. It was: this entry is
three corrections in a row, each one dissolving the answer before it, and
none of them would have survived a round trip.

### Eviction: the same word, two consequences

fuzzypickles asked for this to be written down here, and it is theirs as much
as ours. **fuzznet refuses when a window is full and fuzzypickles evicts, and
both are right, because the structures differ.**

`record/journal.h` refuses: "dropping an issuer to make room forgets what was
seen from it, and the next record from that issuer is then accepted at any
sequence -- which readmits everything it ever sent." `frame/freshness.h`
cites the same reasoning, and records that refusing caused a real outage that
"never ended".

Their `recv_seen.c` evicts, and argues it well: dropping the oldest
commitment costs at most one duplicated inbox line for a message old enough
that 256 others have arrived since, and a sender only retransmits while
unacknowledged.

**Evicting a per-issuer SEQUENCE high-water mark readmits everything that
issuer ever sent, which is a security property. Evicting one unordered
COMMITMENT costs a duplicated inbox line, which is a UX one.** A port that
landed `recv_seen.c` beside `journal.h` would have put two headers arguing
opposite positions in one tree with neither mentioning the other.

### Three answers, each one wrong until the next measurement

**First: "fuzznet already covers this."** freshness.h bounds its replay
window by command expiry rather than by a ring, so a restart is safe for free
-- if a retransmission carries the original expiry.

**Second, measured by them: neither branch.** A retransmission carries the
original CIPHERTEXT, not a re-seal, so the commitment inside is unchanged --
stronger than the hypothesis needed. Their timestamp is authenticated, inside
the MAC, which is the property expiry-bounding requires and it already holds.
**And nothing checks it.** There is no age comparison anywhere in their
receive path: the timestamp is a display and ordering field. So the
ingredients are present and unused, and adopting expiry-bounding there is a
behaviour change rather than a swap -- a message delayed past the window
becomes undeliverable rather than late, and a host that was off for a week
loses traffic that today merely arrives slowly.

**Third, and this is where it rests: they priced the wrong half.**
freshness.h distinguishes itself from their case in its own words -- "sec
4.4a raises the stakes above a chat program's ... a replayed command is not a
duplicated message; it is a router being reconfigured a second time by
somebody who recorded the first." It is the COMMAND path, where late means
unwanted and refusing is the right outcome.

Chat is record traffic, and this tree has a second path for that:
`record/journal.h` deduplicates by per-issuer sequence with no expiry at all,
and `persist/persist.h` holds the journal among the recoverable state, so the
high-water mark survives a restart. That is recv_seen's requirement met by a
different structure -- durable, unexpiring, and one number per stream rather
than N commitments.

**Open, and theirs to answer: do their messages carry a per-sender sequence?**
journal.h rests on a sender numbering its own stream from 1 upwards. If they
have one, recv_seen is a fourth spelling of journal.h. If the 16-byte
commitment is a message's only identity, the record path needs a wire change
first -- a real cost, but a different and more honest one than the delivery
trade.

### What the exchange is worth on its own

Nothing has been ported. Three sessions of measurement have so far produced
**no code**, and the alternative was porting a 133-line file in an afternoon
and discovering none of this. The consolidation's stated bar is that a
replacement must be BETTER rather than equivalent, and that bar cannot be
cleared by a tree that does not know what it already has -- which this tree
demonstrably did not, having built 1004 lines of QR beside a working
implementation it never opened.

## 176. The reconciliation, both halves, 2026-09-07

sec 175 said the first act was reconciling fuzzypickles' inventory against
what this tree already has, each side answering for its own tree. Done. Their
lines describe what each file DOES; mine describe what is here. Where they
meet, the file comes off the list.

**The headline is that the list was wrong in both directions**: it named
things already here, and it missed things already here.

### Already here, and the state matters more than the fact

"Already here" is not one status. Under the holder's criteria -- works in
use, is the best solution, integrates fully -- an absorbed module that its
originating consumer has never called clears none of them.

They measured it. **Of the twenty-two generic files, exactly ONE includes
anything from this library.**

    sched/      included by sched.c                the only one of the 22
    ratchet/    included by peer_seal_internal.h -- NOT by group_ratchet.c
    blob/       not included; their blob.c is 1988 lines and takes nothing
    link/       not included; their link.c untouched since 2026-07-28
    log/        not included

**AND THE PATTERN IS STRUCTURAL RATHER THAN A LAPSE.** Fifteen headers from
here are in use over there -- chain, record, session, wire/seal, tree,
constant_time and the rest -- and the files using them are `core.c`,
`peer_seal.c`, `sched.c`, and the whole of notes and library. Those are the
NEW subsystems, written after this library was in their build. **The old
generic files were not converted; they were bypassed.**

So adoption is real and substantial and it is happening at the MARGIN. A
module here gets new callers; it does not get the old file's callers. Which
means the holder's second criterion -- better rather than equivalent -- **has
never been tested on any of the five**, because no replacement has yet been
asked to serve the original's callers. There is no comparison to win yet, and
that is true of all five rather than of `link/` alone.

`ratchet/` shows what that costs. It is included by their peer sealing and
not by `group_ratchet.c` -- and `group_ratchet.c` is where the `advance_to`
defect lived, in a path this library's replacement was not serving. Extracted
is not substituted, and the gap between the two had a security consequence
sitting in it.

**Two reasons for "not proven", and the record should say which.** `link/` is
KNOWN unswappable -- diverged past a swap, demonstrable. `blob/` and `log/`
may be perfectly swappable and nobody has tried. Policy treats both as
unproven; they are not the same thing, and calling all three "already here"
loses the distinction that decides what to do about them.

**`link/` is the one that is known rather than untested.** They still ship
`core/src/link.c` and include no header from here; mine "runs in this
project's unit tests and nowhere else". Theirs is addresses, transports and
byte budgets, mine is ids and metrics feeding `fzn_sched_candidate_t`, and
**neither is a superset**. So the holder's second criterion cannot be
applied: "better than what it replaces" presumes the two are comparable, and
these are no longer two spellings of one thing. That is a decision to be
taken rather than a measurement either tree can make.

### Three false friends, all three mine

Every one was a row where I matched a fuzznet module to a filename. Their
lines killed all three.

    manifest.c   THEIR routing record -- where this user's hosts are, signed
                 and propagated. `chain/manifest.h` is what a peer HOLDS and
                 LACKS. Same word, unrelated jobs.
    delegate.c   outbound sending through the host a contact knows. Routing,
                 not authorisation; I had matched it to revocation.
    sibling.c    local registry of the same user's other hosts. I matched it
                 to `wire/bytes.h` on a word. They quoted my own prediction
                 that this was the failure mode back at me, correctly.

### Two files already here that the inventory never listed

**`delivery.c`, the twenty-third.** `record/ledger.h` names it as the source;
they had missed it because sec 17's inventory was drawn by asking which files
know a contact exists, and `delivery.c` had been extracted late. **A list
written once and quoted later misses exactly this**, which is sec 175's
co-development lesson arriving on its own schedule and against its own
authors.

**`signed_tag.h`, and it is further along than anything else.** Not a file to
port: `wire/bytes.h` already carries a SHARED REGISTRY. Tags 1..12 are
allocated to their `core/src/signed_tag.h` with their twelve names quoted
from their header, 13..31 are held for their growth during the transition,
128+ is this library's, and their rule that a retired tag is never reused is
adopted whole. Two trees reading one registry, with the reason stated: during
a transition both encodings exist and they must not be able to verify as each
other.

### Where the destination may already be past the source

`crypto_msg.c` is, in their header's own words, a documented **stepping stone
ahead of real sessions** -- per-message 2-DH with a key-committing AEAD. This
tree has `session/session.h`, `session/agree.h`, `session/commitment.h` and
`ratchet/ratchet.h`, which is the thing a stepping stone steps toward.

If that holds, `crypto_msg.c` is not a port and never was: it is the case
where the replacement is better rather than equivalent, which is the only
case the holder's policy actually asks for. Stated as a candidate, not a
finding -- I have read their one line and my four headers, and nobody has
compared the constructions.

`pairing_crypto.c` is its deliberate opposite: DH-only confidentiality with
NO sender authentication, because at pairing time there is no pinned key yet.
That pairs with `provision/provision.h` here, and the absence of
authentication is the design rather than a gap in it.

### Still genuinely absent

    recv_seen.c      the direct-message half needs a wire sequence; holder's
    addr_observe.c   reflexive address discovery
    rendezvous.c     NAT hole-punch coordination
    log_relay.c      a remote READ of another host's log retention

The log subsystem is three files -- `append_log.c`, `log_show.c`,
`log_relay.c` -- and this tree has the first, minus its line format, which
their own measurement had already classified as specific rather than general.
`log/log.h`'s range and read-since look like `log_show.c`'s job and that is
untested; `log_relay.c` is a cross-host query and has nothing here.

`addr_observe` and `rendezvous` are two of three volunteer relay services.
`wire/relay.h` here is relay POLICY -- which subsystem may spend what -- and
is adjacent to them rather than the same thing.

## 177. A leak I attributed to a shape that was a property of my model, 2026-09-07

I put a security question to fuzzypickles: their key-committing construction
is the one `session/commitment.h` names as theirs, and this tree had found
that a commitment derived from the transcript alone is a stable per-pair
identifier in the cleartext head. If they shipped it unchanged, a passive
observer or any relay reads their social graph without decrypting anything.

**The answer was no, twice over, and the first reason is the one worth
keeping.**

### The flaw was the long-lived transcript, not the commitment in the clear

Their `crypto_msg.c` transcript is 240 bytes and **includes a fresh ephemeral
public key**, generated per call and never reused -- their header requires it,
because their nonce is all-zero and that is safe only while the derived key is
used exactly once ever. So their commitment changes every message. Same
derivation, same in-the-clear placement, and **nothing linkable across
frames.**

Which means this file had the finding filed under the wrong half. It read as a
finding about a derivation shape; it is a finding about a SESSION MODEL. An
ephemeral-static construction gets unlinkability free from the ephemeral. A
session construction -- long-lived transcript, per-peer key -- has to buy it,
and the two-step split is what buying it costs.

**The shape was theirs and sound. The long-lived transcript is this library's,
and so is the leak.** A property inherited from a neighbour is still yours
once you change what you feed it, and the header says that now.

### And the sentence naming them was half stale

`peer_seal_internal.h` in their tree includes THIS header and derives the
pair's AEAD and commitment keys from it. Their own record says why: "their
head carries one at offset 0x41 that does that job and does it better". What
remains of theirs on the text path is a message identifier that never travels.
Their pre-split form is still live for acks and the pairing frame, where it is
unlinkable for the reason above.

### The pattern I claimed was wrong, and this is its counter-example

I had told the holder that a defect and its proven fix being on opposite sides
of the split was a PATTERN -- `advance_to`, then this -- both times with the
fix in the tree not running the code.

**Here the fix is in this tree and fuzzypickles is running it**, on the path
that carries conversations, already landed. That is what substituted rather
than merely extracted looks like, and it is the one place either of us can
point at where the holder's second criterion was actually met: the replacement
was better, they adopted it, and their header names which of the two won and
why.

Two instances and a generalisation, and the third case inverted it. **The
frame was three hours old and had just been right twice**, which is
`evidence.md`'s own warning about a frame that has just been right, arriving
against the session that keeps quoting it.

It also decides one row of the `crypto_msg` comparison before we started
running it -- in this library's favour, by evidence neither of us went looking
for, and reported by the tree it went against.

## 178. Four reasons, and which of them this tree can hold, 2026-09-07

The `crypto_msg` comparison is closed before it was run. fuzzypickles
verified rather than read: `fzp_msg_encrypt` and `fzp_msg_decrypt` have **zero
production callers** -- every caller is their own test -- and `messaging.c`
calls their peer sealing, which includes `session/commitment.h` from here. So
there was no comparison for that tree to offer on any axis, and they said so
having offered one: "I offered you a comparison I could not have run."

What the file is instead is an **executable record of four reasons** their
sec 17 says must survive "as reason, not as code". Mapped against this tree,
one line each:

    1  the all-zero nonce is safe ONLY because the derived key is used once
       ever -- a property of the EPHEMERAL, not of the AEAD
                                        NOTHING HERE. At risk.

    2  the prekey is not on the wire and neither is a signature, because
       trust in it is pinned at peer-add
                                        OPPOSITE CHOICE HERE, recorded.
                                        `prekey/prekey.h` is a signed,
                                        published record, and its header
                                        already engages their model: this
                                        library asked which row blocked, and
                                        their answer was that in their tree
                                        the contact record is MADE FROM the
                                        prekey record at add time.

    3  the transcript is ordered BY ROLE, because a directed message must key
       differently in each direction
                                        FULLY HERE, both kinds, and the rule
                                        that selects between them.

    4  two acknowledgement tags from one AEAD key under separate domain
       labels, so holding one says nothing about the other
                                        HERE, in `chain/service.h` and
                                        `session/commitment.h`.

### Reason 3 was already answered, by a rule they caused

`session/session.h` carries it: "THE QUALIFIER MATTERS AND THE FIRST DRAFT
LEFT IT OUT, which fuzzypickles caught by contrasting their two transcripts."
Canonically when the relationship is symmetric and has no roles at derivation
time; BY ROLE when the roles are real, asymmetric and covered by what is
signed. Their `prekey_channel.c` is named as the first kind, their
`crypto_msg.c` as the second.

And the question they said a merged design would still have to answer -- can
one design carry both -- **is answered by this file already carrying both**:
`fzn_session_transcript` sorts, `fzn_session_chains` orders by role, in one
header, "which is why the distinction is stated here rather than left as a
preference."

### Reason 1 is the one that can actually be lost

An all-zero nonce is safe there only while the derived key is used exactly
once ever, and that safety lives in the EPHEMERAL rather than in the AEAD. So
**no test of an AEAD would notice it breaking** -- their observation, and the
reason it is the dangerous one to drop.

This tree has no instance of it. Every frame here carries a nonce, so there
is nothing to hang the reason on: it cannot be adopted as code and it cannot
be demonstrated by anything running. If their file is ever retired, this is
the entry that has nowhere to go, and recording it here is the whole of what
"survive as reason" can mean for it.

### The symmetry worth keeping

They corrected me that a property inherited from a neighbour is still yours
once you change what you feed it -- the derivation shape was theirs, the
long-lived transcript mine, the leak mine. Their role-ordering row is the same
statement from the other side: role-ordering is right for a directed message
and wrong for a session, and **a merge that took the shape without the
question would get one of the two silently wrong.**

Both halves of that sentence were found by the tree it went against.

## 179. The transfer view, and a field name Qt will not let a consumer read

`gui/transfer_view.{h,cpp}` shows one blob being assembled: how much is held,
what is outstanding, and whether anything is still happening. Beyond sec 139's
named list, which is complete -- this is the state every consuming software
has to put in front of a person and had no object for.

### Looking at a transfer must not change it

`fzn_transfer_expire` reclaims assignments whose deadline has passed and
returns how many it took. **It mutates.** A view that refreshed itself by
calling it would take a peer's outstanding ranges back as a side effect of
somebody having a window open, and the transfer would behave differently
depending on who was watching.

So everything here is read-only, and the suite proves it the way that cannot
pass vacuously: render an overdue transfer twice, require the outstanding
count to be unchanged, **and then require the library to still be able to
reclaim it.** Without that last assertion the case passes for a view that
reclaimed nothing because there was nothing to reclaim.

### Three conditions that all read `in_flight == 0`

    IDLE      nothing held, nothing asked for -- it has not started
    STALLED   incomplete, nothing outstanding -- peers quiet or all reclaimed
    COMPLETE  the library says so

A screen showing the count alone puts "not started", "stuck" and "finished"
in one word, and those are exactly the three a person looking at a stopped
transfer needs to separate. Same shape as sec 165's unspelled-versus-denying
and sec 166's expired-versus-revoked, which is now the third time this
distinction has been the whole of a widget's design.

**A passed deadline is not a failure.** The range returns to the want-list;
the bytes are not lost. The screen says reclaimable, because reporting a
routine consequence of a lossy transport as an error is how a person learns
to ignore the field.

### `fzn_transfer_t::slots` cannot be read by a Qt consumer

Qt defines `slots`, `signals` and `emit` as bare macros. `fzn_transfer_t` has
a FIELD called `slots`, so `transfer->slots[i]` does not compile in any
translation unit that has seen a Qt header:

    error: expected unqualified-id before '[' token

**This is not a widget bug and the widget is not the victim.** It is a
collision between this library's public struct and a macro every Qt consumer
has, and it blocks any consumer reading that field -- which is the field
holding what each peer was asked for.

The build now passes `-DQT_NO_KEYWORDS`, and that is worth having on its own
terms rather than as a workaround: **sec 140 already forbids what those
keywords are for.** No widget here has a `Q_OBJECT`, declares a slot or emits
anything, and the gate proves it. So the flag turns a convention into
something the compiler keeps, and a widget that later wants a signal gets a
clear error instead of a silent moc dependency.

**It does not fix the collision for a consumer that uses Qt keywords
normally**, which is most of them. That wants the field renamed, which is a
public API change and the holder's. Recorded rather than done.

### The fixture lets the library count

`fzn_spool_open` "recompute[s] `have` from the bits rather than trusting a
caller", so the test sets bits and opens the spool rather than assigning
`have` directly. The position the widget reports is then the LIBRARY's count
of what the fixture laid down, which is what makes comparing `held()` against
it worth anything.

Its store ops refuse every call. The view causes no read and no write, so the
vtable exists to satisfy the constructor -- and refusing is the honest stub:
if this widget ever grows a path that touches a leaf, it fails loudly rather
than appearing to work.

## 180. Renaming `slots`, and a proof that held while the change was wrong

The holder's instruction, after sec 179 recorded the collision. Qt defines
`slots` as a bare macro, so a public field of that name cannot be read by any
Qt consumer.

**There were two such fields, not one**: `fzn_transfer_t::slots` and
`fzn_reasm_t::slots`, each with a matching parameter on its init function.
Renaming the one sec 179 happened to name would have left the identical defect
beside it, which is the fix-the-copy-in-front-of-you error
`working-practice.md` warns about. Both moved: `assigns` for the transfer,
whose element type is `fzn_transfer_assign_t`, and `partials` for reassembly,
whose element type is `fzn_partial_t` -- `code-style.md`'s one-word-per-concept
rule choosing the names rather than taste.

`FZN_TRANSFER_MAX_SLOTS` went to `FZN_TRANSFER_MAX_ASSIGNS` with it. An
uppercase macro does not collide, so that half is vocabulary rather than
necessity.

### The proof passed and the change was still wrong

The rename carried the proof `evidence.md` asks for: every changed line must
reduce to the original by substituting the identifier back. 172 lines, and all
172 satisfied it.

**And `sim/test/network_test.c` had THREE unrelated arrays called `slots`** --
`fzn_partial_t` for reassembly, `fzn_replay_entry_t` for the replay window,
and `fzn_transfer_assign_t` for a transfer. One regex renamed all three to
`assigns`. The result compiled, and the proof held, because an
identifier-for-identifier swap is exactly what it was.

    fzn_partial_t assigns[SIM_SLOTS];        <- a reassembly array
    static fzn_replay_entry_t assigns[8];    <- a replay window
    fzn_transfer_assign_t assigns[FS_SLOTS]; <- the only correct one

So the invariant was true and was the wrong invariant. It asserted the change
was mechanical; it could not assert the change was RIGHT, because the thing
that made it wrong -- three meanings sharing one spelling in one file -- is
invisible to a check that only compares spellings. **A proof covers the
property you named, and naming the property is the part that is not
mechanical.**

Nothing caught it but reading the diff. The suite passes either way, because
a test's local variable name is not a behaviour.

### The check that proves the fix, as against the workaround

sec 179 added `-DQT_NO_KEYWORDS`, which made the widget build and did nothing
for anybody else. The rename is checked the other way round:

    g++ -fsyntax-only ... gui/transfer_view.cpp     # keywords ON

That compiles now. A consumer using Qt normally can read the field, which is
what the flag never did and what the instruction was for. The flag stays, on
sec 140's argument alone -- no widget here has a `Q_OBJECT`, declares a slot
or emits anything, and it turns that convention into something the compiler
keeps.

## 181. The planned-deletion view, whose design the library had already written

`gui/sweep_view.{h,cpp}` shows what is about to be taken off this host, how
far it has got, and -- when nothing is going -- why nothing is going.

The whole design is a sentence already in `catalog/sweep.h`:

> THEY ARE KEPT APART RATHER THAN SUMMED because a consumer that swept nothing
> needs to say WHY ... Collapsed into one number, a sweep held back by the
> last-copy guard would be indistinguishable from a catalogue with nothing to
> sweep -- and those want opposite responses.

The library went to trouble to keep seven counters apart, and a screen showing
"0 planned" undoes that in one line. **This is the first widget whose central
guard was specified by the module it displays rather than found while building
it**, and the suite's main case is that sentence turned into an assertion.

### Four reasons, four actions

    retained   this host's own policy working -- change the policy for space
    shared     a guard refusing: a retained node needs the same bytes
    last_copy  a guard refusing: too few other hosts hold it -- the answer is
               MORE REPLICAS, not more sweeping
    absent     nothing to do

A person looking at a full disk needs to know which they are in, and three of
those four are not "try again".

`truncated` is said loudly whatever else is true, on sweep.h's own argument:
the rows ran out, so "a sweep that silently held some of them would leave a
consumer believing it had reclaimed what it had not". It is the one counter
that means every other number on the screen is short.

### Drawing must not delete

sec 179's read-only rule arriving at a more dangerous module.
`fzn_catalog_sweep_advance` is called **after** the bytes are gone -- the
header is explicit, because a crash between the two must repeat a removal
rather than skip one. So a widget that advanced a cursor while drawing would
record a removal that never happened, and the record is the only thing that
says the bytes are gone. The suite renders a part-done job three times and
requires the cursor not to have moved.

Progress comes from `fzn_catalog_sweep_progress` rather than from `done` and
`used`, because that function's own comment says it is "what to draw" and that
it answers while a sweep holds the catalogue. Using the accessor the library
provides for a view is cheaper than being right by accident.

### What made this one quick

Every widget before it needed the distinction that must not collapse to be
found: unspelled against denying, expired against revoked, not-started against
stalled. Here it was written down, with the reason, in the header of the thing
being displayed. **A module that records why its counters are separate hands
its view the specification**, and that is worth more than any amount of
guessing from the outside -- which is the same lesson the fuzzypickles
exchange produced, arriving from inside one tree.

## 182. The revocation view, and a soundness predicate the library lacks

`gui/revocation_view.{h,cpp}` shows what this host believes has been
withdrawn -- and what it believes has been GIVEN BACK, which is the same table
and not the same thing. `gui/capability_view` answers "is this one capability
usable"; this answers "what does this host know", which is what somebody asks
when a peer says they were cut off and nobody here can see why.

### Presence is not revocation

`chain.h` is explicit and the reason is not tidiness:

> A withdrawal REPLACES the revocation at this key rather than removing it, so
> PRESENCE IS NOT THE ANSWER to "is this revoked" -- every reader must ask
> this field.

The entry stays because removing it would let a re-relayed copy of the
withdrawn revocation be re-admitted on every propagation round from every peer
that had not yet heard the withdrawal -- "not a one-time resurrection but a
loop".

So a screen listing the store's rows as revocations reports every capability
that was ever revoked and has since been RESTORED as still cut off, which is
what `revocation.c` calls "the outage the whole withdrawal design exists to
end". The two are counted apart here, there is deliberately no accessor for
the sum, and the summary says *those capabilities work again* -- because that
sentence is the thing somebody is actually looking for.

### The walk is bounded by `capacity`, and that is a library gap

A corrupt store is one whose `used` exceeds its array; that is the definition
`fzn_revocation_covers` and `fzn_revocation_known` use internally, and both
fail closed on it -- `covers` answers "revoked", `known` answers "fetch it".

**Neither is a soundness predicate a consumer can ask.** There is no public
way to separate "this store is corrupt" from "this triple is revoked", so a
widget cannot delegate the question. It bounds its own walk and says the store
is unreadable rather than drawing a number from it -- and the unreadable state
is kept apart from "nothing revoked", because collapsing them is the
fail-OPEN answer.

sec 166 found the identical gap on `fzn_chain_store_t` and recorded it there.
That is twice now, on two stores, and it is the same missing function both
times. **Adding it is a library change and the holder's**; recording it is
what a widget can do, and this is the second widget to have to.

### What the suite requires that a single case would not

Three entries, one in force and two withdrawn, proves the counts partition.
It does not prove the widget is reading the field -- a widget that always
reported one in force would pass it. So there is a second store of nothing but
withdrawals, requiring zero in force, and the pair is the assertion.

## 184. The state view, which looks past an accessor on purpose

`gui/state_view.{h,cpp}` shows what this host currently believes about one
subject -- and, when it believes nothing, whether that is because nobody ever
said or because somebody took it back.

### The one widget here that does not just render the library's answer

`fzn_state_get` returns NULL for a tombstone and for a subject nothing ever
set, and state.h says why: "a caller asking what a subject says must not have
to know that this file remembers who unset it."

**That is right for the caller it was written for and wrong for a person.**
Code taking a decision cannot act differently on the two, and inviting it to
would be inviting a bug. But "nobody configured this" and "somebody revoked
it, and here is who" are the two things somebody staring at a host that will
not do what they expect most needs told apart -- and the tombstone is sitting
in the table with the issuer still on it.

So sec 165's rule is followed for the VALUE and knowingly stepped past for the
ABSENCE. The library is not wrong and neither is this; **they have different
callers**, and that is the whole of the argument. It is written at length in
the header because "the widget reads a field the accessor hides" is otherwise
indistinguishable from a widget whose author had not read the header.

The suite's central case makes the library prove the setup: it asserts
`fzn_state_get` really does answer NULL for the cleared cell before checking
that the widget separates them. Without that, the case would pass for a
library that had never collapsed the two.

### The third soundness gap, closed on the same instruction

Walking is what the tombstone answer costs, so this needed the predicate sec
183 added to the other two stores -- and `state/state.c` had the same private
rule, `usable()`, as a third copy.

The holder's instruction named two stores because two had been reported. This
is the same gap in a third module, found while building the consumer, and it
is applied on the same decision rather than left for a fourth widget to
open-code. **Flagged as a judgement rather than an instruction**, and
reversible.

**It answers a narrower question than its two siblings, and that is real.**
`fzn_chain_store_sound` and `fzn_revocation_store_sound` ask "may I WALK
this", so an empty store with no array is sound to them. `fzn_state_sound` is
the condition the mutating paths here already use, so it must also be true for
a WRITE -- and a write needs somewhere to put a cell. An array is required
even at zero entries.

They are **not** silently reconciled. Changing which states `fzn_state_apply`
accepts is a behaviour change wearing a predicate's clothes, and whether the
three should agree is the holder's. Three modules, three subtly different
spellings of one rule, and each difference turns out to have a reason -- which
is the argument for making them public rather than for making them identical.

## 185. The sync view, and a fail-open the library spent a module removing

`gui/sync_view.{h,cpp}` answers the question a person actually asks of a peer:
am I up to date with it. And, before that, whether this host is in a position
to say.

### Two states, one number

**"Up to date" and "cannot say" both report a deficit of zero.**
`chain/manifest.h` built `fzn_manifest_overflowed` to separate them and states
the stakes plainly: it answers 1 for a dropped pair "and ALSO for a NULL
state, a state whose own fields disagree, and an issuer that is not followed
-- all of which are the same fact in different clothes: this host cannot say
what it is missing from that key."

And why it answers the opposite way round from `fzn_revocation_covers`'s NULL:
"an absent state means the deficit is entirely unmeasured, and **reporting an
unmeasured deficit as sound is the fail-open this module exists to remove**."

A screen drawing the number without asking would put that fail-open back at
the last possible moment, after a whole module had been written to remove it.
So the suite's central case asserts both report zero missing AND that they do
not read alike: the number is the same and the screen must not be.

### The sticky flag is the sharp end

An issuer whose report once overflowed stays overflowed, and the widget
reports UNMEASURED for it **even when a deficit is present and listable**. A
host that knows it lost pairs cannot say what it is missing, however many it
can name -- and a count shown beside that knowledge is worse than no count,
because it looks like the answer.

### Two smaller things the header argued for

**A short report is said.** `fzn_manifest_deficit`'s `dropped` is required
rather than optional, because "a deficit report that quietly does not fit is a
range nobody asks for again". A view showing the pairs it got and not the ones
that would not fit is the same silence one layer up.

**A fresh joiner is complete by vacuity, and that is the truth rather than a
caveat.** manifest.h: "no manifest is an empty union is a zero deficit ... A
number's absence is distinguishable from zero; a set's is not." A followed
peer that has said nothing is up to date, and the widget says so without
hedging.

### The pattern, now eleven widgets in

Every one of these has turned on a distinction that must not collapse, and
they divide cleanly into two kinds. Most had to be FOUND -- unspelled against
denying, expired against revoked, not-started against stalled, cleared against
never-set. Three were SPECIFIED by the module being displayed: sweep's seven
counters, state's deliberate NULL, and this one.

The specified ones are quicker to build and better guarded, because the
argument is already written and the suite can quote it. **A module that
records why its states are separate hands its view a specification**, and that
is the strongest case yet for the habit this tree already has of writing the
reason next to the rule.

## 187. Ten widgets that had never been drawn, 2026-09-07

Thirteen of these objects exist. **Three had ever been rendered on a
character grid.** The other ten carried sec 140's claim -- no Q_OBJECT, it
displays -- and passed a static gate saying they use no pixel geometry qtty
cannot honour, and neither of those is the same as having been drawn.

sec 159 found a real defect by rendering one: a `QPlainTextEdit` frame that
came out as a left edge and nothing else. So ten unrendered widgets were ten
unasked questions, and the instrument for asking has been vendored since
sec 169.

### What is asserted, and the number worth having

Two things per widget: that the words it says are ON the grid at 80x24, and
**the narrowest width at which they still are.** The second is the useful one
-- a consumer sizing a pane needs it, and sec 158 measured 41 columns for the
fingerprint the same way.

Measured, six widgets, rows held at 24:

    authz_view         23 columns    "unguarded"
    capability_view    20            "expired"
    sweep_view         26            "held it back"
    revocation_view    20            "work again"
    journal_view       39            "nothing received"
    sync_view          20            "cannot say"

All six fit an eighty-column terminal with room to spare, and the widest need
is 39 -- close to trust_view's 41, which remains the floor for this family.
**Nothing was broken**, which is a result rather than a non-result: the static
gate and sec 140's rule have been holding, and now that is measured rather
than asserted.

Each widget is put into the state a person most needs to read -- the one
saying something is wrong or being held back -- because that is the text most
likely to be long, and a floor measured on the short state would be the wrong
floor.

Containment rather than arithmetic, on sec 158's reason: counting characters
and subtracting a second render compares two different strings.

### Four are still undrawn, and which four is the point

`transfer_view` needs a spool with store ops, `state_view` and
`provision_view` each need a signing fixture, and `config_view` exists only
under FZN_CLI. Those are fixture costs rather than reasons, and saying so is
the difference between a gap and an unstated one -- **this entry would
otherwise read as "all the widgets are checked", which is exactly the claim
sec 140 was making before any of them had been drawn.**

## 189. Two sections numbered 130, 2026-09-07

Reported by `claude-guidelines`, who found it after hitting the same collision
three times in one afternoon writing into fmake -- 173, 180 and 186 all taken
between their read and their write -- and went looking for whether it had
already happened silently. It had, here and in two other trees.

**The mechanism is the obvious one and it is not carelessness.** A session
picks the next number by reading the file; between the read and the write,
another session takes it. Both of these were written on 2026-09-06.

### The repeated-heading check structurally cannot see it

This tree's docs gate has always refused a repeated heading. Two sections
carrying 130 with DIFFERENT TITLES are different headings, so it passed them
both, every run, for a day. The new check is on the NUMBER among siblings, and
it is keyed by level and parent because this tree is why: there are bare
`### 1.` sections restarting under several `##` parents, which are correct,
and a rule keyed on the number alone would have made the trees that number
most into the noisiest.

### Which one moved was a measurement, not a coin toss

Their advice, and it was right: which 130 should move depends on what cites
it. Five references in this file, and **all five mean the same one** -- sec
131's own title is "and sec 130 was wrong", and its body quotes `sec 130 said
"one node per host"`. Nothing outside this tree cites either.

So the cited one keeps 130 and the uncited one -- "hydra will want `state/`"
-- becomes 188. No citation moved, because the one with citations did not.

**Renumbering by position would have got it backwards.** The file is not in
numeric order: the uncited 130 sits between 97 and 141, and the cited one sits
inside a descending run of 131, 130, 129. Whichever looks more out of place is
not the question; whichever is pointed at is.

### The gate is taken, and it has been seen to fail

`tool/style_gate.py` synced after the renumber rather than before, on
`harmonization.md`'s corollary that a tool change is not spread into a tree it
will turn red -- twelve trees took it immediately and three of us were held
back with our own lists. Then, because a check nobody has watched fail is not
yet a check: 187 was renumbered to 186 by hand, the gate named both lines and
refused, and the file was restored.

## 190. Paying the fixture costs, and what the tenth widget showed

sec 187 drew six widgets and named four it had not, calling them "fixture
costs rather than reasons". That is only worth saying if the cost is then
paid, so it was: all ten now render.

    authz_view         23 columns    "unguarded"
    capability_view    20            "expired"
    sweep_view         26            "held it back"
    revocation_view    20            "work again"
    journal_view       39            "nothing received"
    sync_view          20            "cannot say"
    transfer_view      20            "stalled"
    state_view         22            "took it back"
    config_view        32            "/var/lib/fuzznet"

### The tenth rendered nothing, and that is the finding

`config_view` in its unspelled state showed **nothing at any width up to 120
columns.** Not a widget defect: an unspelled config has no values, by design,
so it is all label -- and **a `QFormLayout` row label does not reach the qtty
grid.** Measured on `authz_view`, where a value and a label sit in one row:

    snapshot contains "unguarded"  (the value, a QLabel I made)   -> yes
    snapshot contains "Requires"   (the row label, made by Qt)    -> NO

**Nine widgets passed and the finding was in all of them.** Every assertion
sec 187 wrote happened to match a VALUE, so nine looked fine while showing
their answers with nothing saying what each answer is about. The only widget
where the absence is visible is the one with no values to hide behind, and it
was the one I nearly dropped as too expensive to fixture.

That is the sharpest instance yet of this session's recurring shape: **the
case that is awkward to set up is the case that discriminates.** Six easy
widgets rendered, all green, and the property they shared was invisible until
the tenth had nothing else to show.

### Pinned as it is, not as it should be

The render test now asserts that the value IS on the grid and the row label is
NOT. Written that way round deliberately: when qtty fixes it, this goes RED
and says so, which is the notice this tree wants rather than a silent
improvement it never notices. Nothing here is worked around.

Reported into qtty's own `project.md` under their sec 12, "From fuzznet",
left uncommitted -- their tree has work in flight and it is not mine to
commit into. The report states the reproduction and says the cause is unknown
from here, because I have not read their cell walk and the difference I can
see -- caller-made label against `addRow`-made label -- is an observation
rather than a mechanism.

## 191. A sync line for a daemon, on two channels

`cli/sync_print.{h,c}` answers "are we synced with this peer" for a host with
no display. `gui/sync_view` is the same two facts for a screen.

**And the CLI is currently the better of the two for a terminal**, which sec
190 is why: a `QFormLayout` row label does not reach the qtty grid, so the
widget shows its answer unlabelled while a printer composes its own words and
loses nothing.

### The state goes out of band, and that is the design

A health check must not read the sentence to find out what happened. sec 168
settled that a consumer parsing another component's output becomes "a parser
of a format, which is a new thing to get wrong rather than one thing fewer" --
and a status line is exactly the format somebody would parse.

So `state_out` carries the answer for a program and the line carries it for a
person, and neither reads the other's. It is REQUIRED rather than optional, on
`fzn_manifest_deficit`'s own argument for its `dropped`: "an optional
out-parameter is one every caller ignores", and this is the one a health check
must not.

### `FZN_SYNC_UNMEASURED` is zero, deliberately

A caller that never reads `state_out`, or reads it after a refusal, sees the
conservative answer rather than the reassuring one. The refusal path sets it
before it can fail, which is `fzn_chain_store_lookup`'s reason for clearing
its out-parameters first.

The suite poisons the variable with `FZN_SYNC_UP_TO_DATE` before every call
that should report otherwise, so a passing case proves the call WROTE the
answer rather than that the stack happened to hold it.

### The same guard as the widget, and it matters more here

"Up to date" and "cannot say" both have a deficit of zero. On a screen that is
a person misreading a number. In a monitoring script it is a host that cannot
measure its own deficit reporting green -- **the fail-open `chain/manifest.h`
was written to remove, arriving in somebody's alerting**. A caller switching
on the enum cannot make that mistake by accident; one grepping the line for a
number can, which is the whole reason the enum exists.

The suite checks both channels separately: the words differ for a person, and
the enum differs for a program. Either alone would pass a version that got the
other wrong.

## 192. A journal line, and the state the caller did not ask for

`cli/journal_print.{h,c}` reports one stream's position and the condition of
the table it lives in. `gui/journal_view` is the same facts for a screen.

### The second state is the point

sec 186 established it: a full journal refuses every issuer it has not met,
**the peer being turned away has no row at all**, and every row that does
exist still looks healthy. So the condition is invisible to anybody who asked
the obvious question -- which stream am I on -- and this reports it whether or
not they thought to ask.

That makes the table's out-parameter the interesting one. Making it optional
would be making it absent, because the caller who needs it is by definition
the caller who did not ask: they are looking at Bob's stream and the problem
is Dave, who has no row. So both states are required, on
`fzn_manifest_deficit`'s argument for its own `dropped` -- an optional
out-parameter is one every caller ignores.

The suite proves the warning is not decorative by anchoring a third issuer and
requiring `FZN_JOURNAL_ERR_FULL`. Without that it would pass for a printer
that says FULL whenever it feels like it.

### Zero is the answer that asks for attention

`FZN_JOURNAL_STREAM_UNTRACKED` and `FZN_JOURNAL_TABLE_FULL` are the zero
values of their enums, and both are set before anything can fail. A caller
that ignores an out-parameter, or reads one after a refusal, gets the state
that wants looking at rather than the one that grants absolution. sec 191 made
the same choice; this is the second instance, so it is now a habit of these
printers rather than a decision taken twice.

The suite checks it by poisoning both variables with reassuring values before
a call that must refuse, and requiring them gone.

### Where the CLI has overtaken the GUI

Three printers now against eleven widgets, and for a terminal the printers are
the better half -- sec 190: a `QFormLayout` row label does not reach the qtty
grid, so a widget shows its answers unlabelled while a printer composes its
own words.

There is a second advantage that has nothing to do with that bug, and it is
the one worth keeping. **A widget has one channel and a printer has two.** The
screen carries the sentence and the enum carries the verdict, so a monitoring
script never parses prose -- and every one of these views turned on a
distinction that a number alone destroys. The GUI has no equivalent: a caller
wanting `fzn_sync_view`'s verdict reads `shown_state()`, which is the same
idea, but the widget must still have drawn something first.

## 193. The duplication I re-created twice knowing better, 2026-09-07

sec 168 removed a duplication between `gui/log_view` and `cli/log_print`: the
same summary wording in two files, matched by hand, with nothing checking they
still agreed. The fix was that the widget asks the printer.

**Then sec 191 and sec 192 made the same mistake twice.** `cli/sync_print` and
`cli/journal_print` were each written for a widget that already existed, and
each decided the state from the library itself:

    gui/sync_view      fzn_manifest_overflowed, fzn_manifest_deficit, its words
    cli/sync_print     fzn_manifest_overflowed, fzn_manifest_deficit, its words

    gui/journal_view   walk, classify next, compute full, its words
    cli/journal_print  walk, classify next, compute full, its words

Two implementations of one screen, twice, written days after the section that
removed exactly that.

### Why it kept happening, which is the part worth keeping

**A CLI counterpart written for an existing widget always re-creates the
duplication unless the widget is revisited.** At the moment of writing the
printer, the natural act is to write the logic; the widget is somewhere else
and passes its own tests either way. Nothing fails. sec 168 was retrofitted to
`log_view` precisely because the printer came second there too -- and the
lesson recorded was about the outcome rather than about the ORDER that
produces it.

So the rule, stated as a trigger rather than a principle: **when a printer is
added for a fact a widget already shows, the widget changes in the same
commit.** That is the only moment at which anybody is looking at both.

### The fix, and what the widgets gave up

Both widgets call their printer, show its line, and take their state from its
enum. `sync_view` loses `detail_text`, `missing` and `dropped`; `journal_view`
loses `pending_text` and `capacity_text`. A consumer wanting numbers asks the
library -- `fzn_manifest_deficit` and `fzn_journal_pending` -- which is where
they live rather than a widget's reading of them.

Both move under FZN_CLI, as `log_view` and `config_view` already are.

Each suite gains the assertion that keeps it: `state_text()` must EQUAL what
the printer produces. A relationship, so it survives the words changing and
goes red the moment somebody composes a sentence in a widget again.

Six sabotage entries retired -- they guarded logic that no longer exists in
the widget -- and two added in their place. The harness refused to verify
until they were, which is the third time this session its stale-entry check
has been the thing that noticed a structural change.

### What the widgets lost on a terminal, and what they did not

`sync_view` was three rows and is now one; `journal_view` was three and is
now one. On qtty that costs nothing at all, because sec 190 measured that a
`QFormLayout` row label never reaches the grid -- the rows were carrying
labels nobody could see. On a desktop it is a real simplification and one
fewer place for the two halves to disagree.

## 194. A sweep line, with the rule applied from the start

`cli/sweep_print.{h,c}` reports what is about to be taken off this host, how
far it has got, and why nothing is going when nothing is.

**sec 193's rule was applied rather than discovered this time**: the printer
and `gui/sweep_view` changed in one commit, so the duplication never existed.
That is the first of these five printers not to have created one first and
removed it afterwards.

### Why this one matters most on a headless host

A host reclaiming disk unattended is exactly where somebody has written a
monitoring rule, and `catalog/sweep.h`'s central requirement becomes an
alerting question: "a sweep held back by the last-copy guard would be
indistinguishable from a catalogue with nothing to sweep -- and those want
opposite responses."

On a screen that is a person misreading a zero. **In a rule it is a host whose
disk cannot be reclaimed reporting the same as one with nothing to reclaim**,
and only the first needs anybody to do anything -- specifically, to add
replicas rather than to sweep harder, which the line says in as many words.

### Truncation is its own out-parameter, and that is not tidiness

A plan can be READY and SHORT at the same time, so folding truncation into the
state would make the two mutually exclusive and lose one. It is a separate
required parameter for the same reason the table's condition is in sec 192:
orthogonal facts do not share a channel.

### What the widget kept

`sweep_view` shows the printer's line and takes its state from the enum, but
keeps its own progress BAR -- drawn from `fzn_catalog_sweep_progress`'s
numbers rather than from the printer's sentence. **A bar is a thing a screen
has and a line does not**, so that is not a second implementation of anything:
the sentence and the bar say the same thing in the two ways their media allow,
and only the sentence is duplicated-if-copied.

That is the line worth drawing for the rest of these: a widget may add what
its medium affords, and may not restate what the printer already said.

Four guards moved from the widget to the printer, one relationship guard added
in their place, and the harness refused to verify until the stale four were
gone -- the fourth time this session.

### And one of the five mutations was aimed wrongly

`sweep-print-held-back-is-not-empty` SURVIVED. The condition it guards is
three lines and the mutation replaced only the first:

    said = (plan->retained > 0u || plan->shared > 0u ||     <- replaced by (0 ||
            plan->last_copy > 0u)                           <- left intact

which leaves `(0 || last_copy > 0)` -- still true for the very case the test
uses. The guard was written for the last-copy case and mutated everything
except it.

Same class as sec 166's, and worth counting rather than re-explaining: this is
the third mutation this session that reported CAUGHT-or-SURVIVED for a reason
other than the one it was written for. **A mutation is code, it is not
reviewed, and it is the one piece of code in the tree whose only test is that
it fails.** The check that finds them is reading which line caught which --
free, and it has now paid three times.

## 195. A transfer line, and a Makefile mistake made twice

`cli/transfer_print.{h,c}` reports whether a blob is still arriving, how far
it has got, and which of three stopped states it is in. Printer and widget in
one commit, on sec 193's rule -- the second time it has been applied rather
than discovered.

### Three conditions, and what a count alone costs a rule

sec 179 established that not started, stalled and complete all read
`in_flight == 0`. On a screen that is a person confused. **In an alerting rule
it is a script that pages somebody about a finished download and ignores a
stuck one**, which is the worst possible pairing of the two errors.

So all three differ on both channels, and the suite requires it: three
distinct lines and three distinct enum values, each compared against the
others rather than merely asserted.

A passed deadline is reclaimable rather than failed, on sec 179's argument --
the range returns to the want-list, and reporting a routine consequence of a
lossy transport as an error is how a field stops being read.

Nothing here mutates. The suite renders an overdue transfer twice and then
requires the LIBRARY to still be able to reclaim it, which is what separates
"the printer left it alone" from "there was nothing to reclaim".

### The widget kept the bar and the window

sec 194's line, applied again: a widget may add what its medium affords and
may not restate what the printer said. The bar is filled from the library's
numbers; the congestion window stays a widget row because it is a property of
the SCHEDULER rather than of the transfer's progress, and a status line
carrying it would imply otherwise.

### A Makefile mistake made twice in two sections

Both times, moving a widget under `FZN_CLI` meant deleting a line from a
backslash-continued list, and both times the deletion left the newline:

    gui/authz_view.cpp gui/capability_view.cpp gui/provision_view.cpp \
                                        <- a blank line, and make stops
                gui/revocation_view.cpp gui/state_view.cpp

`make` reports it as "missing separator (did you mean TAB instead of 8
spaces?)", which is true of the NEXT line and says nothing about the
continuation that orphaned it. sec 193 hit it, this section hit it again, and
the second time it took as long to find as the first because the error names
the wrong line.

**The fix is the pattern rather than the instance**: delete the newline WITH
the line. `s.replace("            gui/x.cpp \\\n", "")` and not
`s.replace("            gui/x.cpp \\", "")`. Written down because a mechanical
edit that leaves a dangling continuation is invisible in a diff -- the removed
line is gone and the blank one looks like spacing.

## 196. A capability line, and a wait loop that watched somebody else's build

`cli/capability_print.{h,c}` reports whether one capability is usable and, if
not, which of the two reasons. Printer and widget in one commit, sec 193's
rule, third application.

### Expired and revoked call for opposite actions

sec 166 separated them for a screen, where it saves a person a wrong guess.
Here it decides what an automated response does: **an expiry wants renewing
and a revocation is somebody's decision about this key, where renewing would
be exactly wrong.** So they are separate enum values and separate words, and
revocation wins when both are true.

Revoked is `fzn_revocation_covers` and never `..._known` -- they differ on
exactly one state, an entry whose revocation has been WITHDRAWN, so the
fixture builds one and the suite asserts the two predicates really do
disagree before checking the printer. Expiry is `fzn_chain_expired_at`'s
answer, because FZN_NO_EXPIRY is 0 and the obvious comparison inverts.

### The wait loop was reading another session's build

Three suites into this section the gate reported **151 suites** where the
previous run reported 183, which looked like thirty-two silently lost.
Nothing was lost. The count was taken from a log still being written.

The cause is a pattern match, and it is `running-code.md`'s own warning
arriving in a shape that document does not list. The loop was:

    PID=$(ps -o pid=,cmd= -u "$USER" | awk '$2=="timeout" && /make check/ ...')
    while [ -d /proc/$PID ]; do sleep 10; done

Other sessions run `timeout ... make check` in their own trees -- hydra and
netcfgd both were -- so the match can select **somebody else's process**, and
the loop then returns when THEIR build finishes. It is not the self-matching
pgrep that document describes; it is the neighbour-matching variant, and it
fails the other way round: instead of never returning, it returns too early
and hands back a partial measurement that looks complete.

Two things made it survive being wrong. `grep -c` on a partial log gives a
plausible number rather than an error, and a smaller number after a change
that moved files reads as a consequence of the change. **A wrong measurement
that agrees with the story you already have is the one that gets believed.**

The fix is to wait on a pid this session created rather than one it
recognised. Recorded here rather than as a rule, because the tree does not
own the loop -- it is in the harness's shell invocations -- but the next
session to write one should not have to find this twice.

## 197. A state line, and the accessor both halves look past

`cli/state_print.{h,c}` reports what this host believes about one subject
and, when it believes nothing, which of the two nothings it is. Printer and
widget in one commit, sec 193's rule, fourth application.

### The argument moved rather than being repeated

sec 184 made the case for the widget: `fzn_state_get` answers NULL for a
tombstone and for a subject nothing ever set, because "a caller asking what a
subject says must not have to know that this file remembers who unset it" --
right for code taking a DECISION, wrong for a REPORT.

That argument is the printer's now and the widget inherits it by asking. **The
interesting part is that this is the one place where the two halves agreeing
was never in doubt and consolidating still helped**: both were going to look
past the accessor, and having one of them do it means the reasoning exists
once, next to the code that acts on it, rather than in two headers that would
drift into disagreeing about how far past to look.

For a daemon the two nothings are the two answers to "why will this host not
do what I asked" -- set it, or find out who unset it and why. Opposite next
steps from an identical NULL.

### `FZN_STATE_CELL_UNREADABLE` is zero and that choice has teeth here

Every printer in this family makes its conservative value zero. This one is
the case where the reason is concrete rather than principled: **"unset"
invites writing and "unreadable" does not.** A caller that ignored the state
after a refusal and saw NEVER_SET would be told, in effect, to go ahead and
configure something it has not managed to read.

### The gate runner now waits on its own child

sec 196 recorded a wait loop that matched `timeout ... make check` in `ps` and
could select another session's build. It is a two-line script now: the runner
backgrounds the gate, records `$!`, and waits on that. It cannot match a
neighbour because it never matches anything.

Written down because the fix is smaller than the finding and the finding is
easy to forget: **wait on a process you started, not on one you recognised.**

## 198. A revocation line, and an assertion sec 183 had superseded

`cli/revocation_print.{h,c}` reports what a store holds, in force and
withdrawn counted apart. Printer and widget in one commit, fifth application
of sec 193's rule.

### What consolidating found

The widget's suite failed on a case it had passed since sec 182: **"an empty
store is not an absent one", asserted as different WORDS.**

sec 183 had already made that wrong and nobody noticed. That section settled
that a NULL store is SOUND, on `chain/manifest.c`'s long-standing contract:
"no store means no revocations known, which is an answer". If NULL and empty
are the same answer about revocations, a screen spelling them differently is
inventing a distinction the library had deliberately removed.

So the words are the same now and the STATE still separates them, for a
consumer that cares whether it holds a store at all -- which is a fact about
its own plumbing rather than about what has been withdrawn.

**Nothing in the tree compared those two sections until a printer forced
both through one implementation.** That is the second thing consolidation has
turned up that no test was looking for, after sec 193's duplication: putting
two readings of one fact in one place is a way of DISCOVERING that they had
diverged, not only of preventing it.

### The Makefile hazard, four times, and the actual fix

Deleting one entry from a backslash-continued list by string replacement has
now broken this file four times, in three shapes:

    a blank line left behind      -> "missing separator", pointing at the next line
    a trailing backslash left     -> the list swallows the following `ifdef`
    the LAST entry removed        -> GUI_SRCS swallowed GUI_HDRS and GUI_TSRC

The third is the worst because it fails silently in `make`: the lists still
parse, they are simply wrong, and what failed was a style gate three targets
later reporting four headers "in the tree and not in HDRS".

The fix is not more care with the pattern. **It is to rewrite the whole list
rather than patch a line out of it**, which is now written above those lists
so the next edit meets the rule before it meets the hazard. A list is small;
a dangling continuation is invisible in a diff.

## 199. An authz line, and an exemption that moved rather than died

`cli/authz_print.{h,c}` reports what a kind of request requires and which
origins can reach it. Printer and widget in one commit, sixth application of
sec 193's rule.

On a host refusing requests, the question is which refusal this is. An
unspelled policy and one written to refuse everything both DENY, and only one
is a configuration fault somebody has to find -- `chain/authz.h` calls
`spelled` "the field the whole design rests on" for exactly that. Guarded and
unguarded get different words for the reason `fzn_authz_verdict_t` keeps
GRANTED_BY_CHAIN and GRANTED_UNGUARDED apart.

### The exemption moved with the code, and that is the finding

sec 165 recorded `authz-view-asks-the-library` as an EXPECTED SURVIVOR:
`fzn_authz_origin_permitted` is `origin != FZN_ORIGIN_NONE && (origins &
BIT(origin))`, only the three real origins are ever asked about, so the call
and an open-coded bitmask agree on every reachable input. A test comparing
output against the library compares a copy of the rule against the rule.

Consolidating raised the obvious question -- does moving the logic into the
printer make it catchable? **No, and the reason is worth keeping.** The
uncatchability was never about WHERE the code lived. It is about two
expressions being equal over the reachable inputs, and that does not change
with the file. So the entry moved to `authz-print-asks-the-library` and the
exemption moved with it.

**Consolidation fixes duplication; it does not turn a structural guard into a
behavioural one.** Worth stating because the opposite is tempting: five of
these moves have made things testable that were not, and it would have been
easy to assume this one did too and quietly drop the exemption -- leaving the
harness claiming to hold something it does not.

### Three assertions broken by a blind rename

Replacing `origins_text()` with `state_text()` across the widget's suite
compiled and failed three cases, all of the same shape: they compared the
whole accessor against an exact string -- `== "nothing"`, `contains
"unguarded"` -- which was true of a field and is not true of a combined line.

They are relationships now: no origin is shown as reaching an unspelled
policy, asked through `shows_origin_permitted`, which reads the screen rather
than a field that no longer exists. **A test that names a field survives the
field being renamed and not the field being merged**, which is the same
distinction sec 168 drew between asserting a value and asserting a
relationship, arriving from the maintenance side.

## 200. A provisioning line, and a threshold that meant the wrong thing

`cli/provision_print.{h,c}` reports whether a card verifies, who it says you
are pairing with, and the text a code would carry. Seventh application of
sec 193's rule.

### A logged fingerprint is worse than a displayed one

sec 171 established the rule: no fingerprint for a card that has not
verified, because an attacker can put a GENUINE root beside their own prekey
and sign the envelope themselves, and the root field then reads correctly.

**On this side the reason is sharper.** A fingerprint on a screen is gone when
the window closes. A fingerprint in a LOG outlives the moment, is read later
by somebody who was not there, and carries none of the doubt the operator had.
So the suite asserts its ABSENCE for every state short of verified, by
comparing against `fzn_trust_fingerprint`'s output rather than by matching a
refusal message.

### The enum order was wrong and the pairing caught it

The first draft ordered the states by how bad they sound -- UNDATED then
EXPIRED -- and wrote the fingerprint test as `state >= UNDATED`. That prints a
root for an EXPIRED card, which `gui/provision_view` does not do.

**Two implementations disagreeing, caught before either shipped, because they
were written in one commit.** sec 193's rule has been retiring duplications
that already existed; this is the first time it prevented one. The order is
now "the signature verified, and the expiry did not stop it", so the threshold
means what the test needs it to.

An expired card's signature IS good and its parts DO belong together -- the
recombination attack is a signature failure, not an expiry. Withholding the
root there is sec 171's conservative choice, and the suite says so rather than
letting it look like a consequence of the ordering.

### And a regression the widget's own suite caught

Rewriting the widget to ask the printer, I dropped the condition that a code
is only drawn once `fzn_provision_open` has succeeded. `fzn_provision_text`
will happily base32 any bytes of the right length, so rubbish was being drawn
as a scannable code.

The widget asks the library the shape question again rather than parsing the
code back out of the printer's line. **Two callers asking one library is not
duplication; two callers DECIDING would be** -- which is the line sec 193 is
about, and it is worth having stated in the one case where re-asking is
correct.

## 201. The eleventh view, which did not consolidate

`cli/trust_print` finishes the set of printers, and `gui/trust_view` is the
one view of the eleven that stayed as it was. That is the finding, so it is
worth writing down more carefully than the ten that did move.

**The printer was needed and is real.** A CLI had no way to say what this
host's anchor is, and the first draft of its enum got the important case
wrong: it named `PINNED`, `ADOPTED` and `NONE`, and mapped everything else
through a `default:`. `FZN_TRUST_SELF` fell down that hole and printed *no
anchor -- this host trusts nothing yet*, which inverts what `trust.h` says
the two states are. A self-anchored node "is a complete estate of one ... a
working state rather than a placeholder"; an unanchored one "adopts the next
root offered, so whoever reaches it first owns it". The line would have
invited an operator to fix a correct node into the dangerous one. The enum
names all four sources now with no `default:`, so a fifth that nobody handled
is warned about -- by `-Wswitch`, which `-Wall` carries, and not by
`-Wswitch-enum`, which this build does not pass; the mechanism was misnamed
here until sec 264 measured it, and it warns rather than refusing because
`-Werror` is out by decision. `trust_print_test` asserts that a self anchor
and an absent one do not print the same line.

**Then sec 193 asked for the widget in the same commit, and the widget was
changed, and the change was wrong.** It was given `fzn_trust_print`'s state
as the decider for whether to show a fingerprint, which read as exactly the
consolidation the other ten got. A sabotage entry was written for it -- drop
the `said == FZN_TRUST_LINE_NONE` half of the guard -- and **it survived**.

The reason is in `trust/trust.c`:

	const uint8_t *fzn_trust_root(const fzn_trust_t *trust)
	{
		if (!trust || trust->source == FZN_TRUST_NONE)
			return NULL;

		return trust->root;
	}

`fzn_trust_root` returns NULL **exactly when** the source is `FZN_TRUST_NONE`.
So the widget's `!root` and the printer's `said == NONE` are one library fact
read twice, and they cannot disagree unless the library contradicts itself.
`fzn_trust_source_str` likewise already separates all four sources, SELF
included, in the library's own words. There was nothing for the printer to
decide on the widget's behalf, and the dependency was symmetry with the other
ten rather than merit.

**A surviving sabotage is the only thing that could have said so.** Every
assertion in `trust_view_test` passed with the dependency in and passed with
it out, because the widget's behaviour never depended on it. Reading the code
would not have found it either -- the call was there, its result was used, and
the use looked load-bearing. This is `evidence.md`'s *a consumer that is right
by coincidence looks exactly like a wired one*, arriving from the direction
that flatters: the coincidence was making a **new** dependency look justified,
not an old one look safe.

**What was kept is the cross-check, and it belongs to the test.** The widget
links no printer; `trust_view_test` links both surfaces and asserts, over all
four constructions, that a fingerprint is on screen exactly when the printer
reports an anchor and that the source the widget names is the one the library
gives. That assertion fires: mutating the printer's `SELF` back to `NONE`
reddens `trust_print_test` with three failures and `trust_view_test` with two,
one of them the relationship. So the two independent readings are pinned to
each other without either importing the other.

**The line this adds to sec 200.** That section settled that two callers
asking one library is not duplication. This one settles the converse cost: a
call added for symmetry is not free, because it still has to be kept working,
still appears in a link rule, and -- worst -- **reads to the next person as
evidence that the question was thought about**. A dependency nobody can
sabotage is a comment claiming a relationship the code does not have.

**The consolidation therefore stands at ten of eleven**, and the eleventh is
recorded as measured-and-declined rather than left out. The holder's
instruction that a solution must win on technical merit rather than on effort
cuts both ways: it refuses the cheap duplicate, and it refuses the tidy
dependency that buys nothing.

## 202. Which numbers are measurements

`cli/link_print` and `gui/link_view` are the twelfth pair, and the first
written for a module that had no consumer surface at all rather than for one a
widget already showed. So sec 193's rule arrives from the other side: the
printer and the widget were designed together, and the question sec 201 forced
-- does the widget need the printer, or is this symmetry -- was asked before
either was written rather than after.

**The fact they exist for is one `link.h` states about itself.** A link is
registered with the far end's declared metric and the estimate STARTS there,
because the alternative

> "has to answer 'what latency does an unmeasured link have?' -- and the
> honest answer, zero, makes a link nobody has ever used look infinitely fast
> and win every selection in `sched/`"

That defends **selection**, and it leaves **reporting** wide open. Nothing in
`fzn_link_entry_t` distinguishes a number that was measured from one that was
asserted: a link registered a second ago and a link measured a thousand times
both render as milliseconds, and only `observations` tells them apart. An
operator reading "40 ms" off a link nobody has ever sent a packet on is
reading a stranger's assertion in the typeface of evidence.

**The test that pays for the whole pair** is the one where the LOWEST estimate
belongs to the unmeasured link. A table with one measured link at 200 ms and
one asserted at 40 ms is `FZN_LINK_LINE_MEASURED` -- there IS evidence -- and
the number a person reads is the 40. So the marker goes on the number it
qualifies rather than in a trailing note about the table. That branch was
untested when first written, and it is exactly the hazard the header describes
arriving by the door the header left open.

**Two distinctions the states keep apart.** No link registered is a host
nobody has configured; every link marked unusable is a host whose interfaces
are down. Both have no usable path and they send an operator to opposite
halves of the system, so `FZN_LINK_LINE_NONE` and `FZN_LINK_LINE_ALL_DOWN` are
separate and their lines differ. And evidence on a link nothing can choose is
not evidence: switching off the only observed link drops the state to
UNMEASURED rather than leaving MEASURED standing on a path no selection will
return.

**The unmeasured count is a second out-parameter because the state hides it.**
A table is MEASURED as soon as ONE usable link has an observation, while three
others sit at their priors and `sched/` will choose one of them the moment its
declared metric wins. A caller watching only the state cannot see that. The
count excludes unusable links deliberately -- counting them would make the
number RISE when an operator switched a bad path off, which is the sabotage
`link-print-unusable-links-are-not-counted` pins.

**And this time the widget earns its dependency, which is the point of
recording it beside sec 201.** The printer's line can say *N usable links are
still on a declared metric* and it names only the lowest. It cannot say WHICH,
because it is one line. The widget's rows can, and that is the whole of what
it adds: a column-aligned row per link with `declared` where the samples go
and a dash where the loss rate would be, so an operator deciding which path to
take out of service can see it. Sabotaging that branch reddens the widget's
suite and leaves the printer's green, which is what a real division of labour
looks like -- where sec 201's inert call reddened nothing at all.

The alignment is in the string rather than in a layout, on sec 158's argument
for the fingerprint: a table whose columns move with the window cannot be
compared against a second reading of itself or against a CLI.

**One asymmetry in the cross-check worth knowing.** Mutating the printer's
classification reddens the printer's suite and NOT the widget's, because the
widget takes its state from the printer and the two still agree. That is
correct rather than a gap: the cross-check asserts agreement, and correctness
is the printer's own suite's job. A cross-check that could catch a wrong
classification would have to hold a second implementation of it, which is the
duplication all of this exists to remove.

**And the claim about fuzzypickles was re-taken rather than quoted.** `link.h`
carried their 2026-09-03 report that they ship their own `core/src/link.c` and
include no header from here. Their tree has since grown a
`core/test/fuzznet_link_test.c`, which reads like a counter-example and is not
-- it proves the library COMPILES AND LINKS there, the verb rather than this
module. `fzn_link_` still appears nowhere in their sources, so this pair
duplicates nothing of theirs.

**The other half of that measurement was wrong, and it is the more useful
half.** I also wrote that no front end of theirs displays link health. They
corrected it within the hour: `daemon/ipc_server.c`'s `link_describe` prints
one, and it read

	rtt 0ms, 0/3 answered, cost 10

for a link nothing had ever been heard from -- this section's hazard, already
live in their tree, in the one directory I did not search. I had grepped
`gui/src`, `tui`, `cli` and `client`, which is a scope chosen from what "front
end" usually means rather than from where the answer could be, and four empty
directories read exactly like an absence. `evidence.md` states it: the scope
of a search is chosen before you know who owns the answer. A daemon that
answers an IPC query is a front end for this purpose and I did not think of it
as one.

Worth keeping because of the direction of the error. The claim made this
project's work look more original than it was -- they had the same display and
the same bug -- and a claim that flatters is the one nobody re-checks. It was
caught only because it was sent to the tree it was about, in a message that
invited the correction by naming where I had looked.

## 204. Two kinds of no, and a tick that cannot say either

`cli/peer_print` and `gui/peer_view` report a local socket's admission
decision: who connected, what they asked for, and the answer. Writing them
turned up a gap in `local/` and a hazard that belongs to screens specifically.

**The library gap.** `fzn_vocabulary_admit` returns `FZN_PEER_NOT_MEMBER` for
two situations:

- no rule names the verb at all, so the policy does not cover it -- a typo, a
  verb nobody added, a client asking for something this daemon does not do;
- rules DO name it, and this peer holds none of those groups.

The first is a configuration finding and the second is an access decision about
a person, and they want opposite responses. A daemon logging both as "denied"
sends an operator to the wrong half of the system -- which is `peer.h`'s own
"empty is not unknown", one layer up.

The printer had to say which and could not. It could have walked the table
itself, and that is exactly the duplication sec 200 draws the line against: a
second implementation of "does a rule name this verb" would disagree the first
time one forgot that a rule longer than `FZN_VERB_MAX` is one the module
ignores. So `local/vocabulary.c` gained `fzn_vocabulary_names`, and the
matching predicate both functions ask moved into one static `rule_names` --
`admit` calls it too, so there is one implementation rather than two agreeing.
A sabotage entry pins that they cannot diverge: making `names` count rules that
`admit` ignores reddens the vocabulary suite.

**The screen hazard, which is this pair's real content.** Every affordance a
toolkit offers for membership is two-valued: a checkbox, a tick, a coloured
dot. The answer is three-valued, and `peer.h` spent a module on why -- "the enum
has no boolean reading", because flattening "could not tell" into "no" is safe
only while both deny, and flattening it the other way "turns a read that failed
into an allow". Use any of those affordances and UNKNOWN has to become one of
the other two at the last inch, after the library has defended it all the way
there. So the verdict is three words, and the suite asserts they are pairwise
distinct AND that none is a prefix of another, since a narrow column truncates.

The same thing again, in the place a screen makes easiest: an unreadable group
list and a genuinely empty one both draw as an empty widget unless something is
put there deliberately. peer.h states that pair as the reason
`fzn_peer_groups_parse` exists at all. Both cases now say what they are in
words, and `group_count` is not read when the list is unknown, because peer.h
documents it as meaningless then -- a stale count is exactly what a caller is
most likely to be holding.

**A verb is bytes a stranger chose.** `vocabulary.h` is explicit that this
library "cannot tell `status` from `destroy` and must not learn", so a verb
reaches the printer unexamined. Written into a line as it came, a newline in one
lets a peer forge a log entry underneath its own denial: a peer that cannot run
a command writing the record that says somebody did. Everything outside
printable ASCII becomes `\xNN`, and so do the quote and the backslash, or the
escaping itself would be forgeable.

**And the fixture was right for the wrong reason until a sabotage said so.**
The check that the two denials do not read alike used two different verbs. A
sabotage collapsing both reason clauses into a bare "denied" SURVIVED it -- the
lines still differed, on the verb. Holding the verb fixed and varying the TABLE
is what leaves the reason as the only thing that can differ. The widget's copy
of the check had the same flaw and the same fix. `evidence.md`'s consumer that
is right by coincidence, in a test rather than in code, and nothing but the
surviving mutant would have found it.

## 205. The render sweep had stopped running, and nobody could have known

`make qtty` renders every widget through a character grid and measures the
narrowest terminal each one still says its own words on. It is opt-in, and it
had been broken for some time. Three faults, none of which reported itself.

**It did not link.** `cli/provision_print.o` was added to the target in
`7908846` without `provision/provision.o` beside it, so the link failed on
three undefined symbols. Every later change to a widget compiled fine and was
never rendered.

**Four expectations had gone stale while it could not run.** The sweep asserts
that each widget says a chosen word on an 80x24 terminal. Sec 193's
consolidation moved nine widgets onto printers and changed their wording:
`unguarded` became `UNGUARDED`, `held it back` became the sweep's per-reason
text, `stalled` became `STALLED`, `took it back` became `taken back`. Four
widgets were therefore asserted to say things nothing in the tree says any
more.

**And it found a real defect the moment it ran.** `capability_view` showed the
capability and `expires at 1000` on an 80-column terminal and nowhere said
`expired`. `fzn_capability_print` put the capability first, a capability spells
to 64 hex characters, and a terminal clips a line from the RIGHT -- so the
answer was the part that fell off and the opaque identifier was the part kept.

The fix is the general rule rather than a width tweak: **the answer goes left
of the evidence.** What a narrow terminal then loses is 32 bytes nobody
compares by eye, and losing those is visibly a truncation rather than silently
a different meaning. **The sentence that stood here said only
`capability_print` had that shape. It was wrong, and sec 207 has the
measurement** -- three printers had it, and the claim was made by reading one
file rather than by asking the other thirteen.

**Two things about the instruments, which cost more than the faults.**

A grep for what those printers say used the pattern `"[a-z][^"]{4,60}"`, which
cannot match a string beginning with a capital. It reported that
`transfer_print` no longer says anything like `stalled`; it says `STALLED`. An
absence manufactured by the pattern, and it read exactly like a finding --
`evidence.md`'s first way, met head-on.

And the failure message named neither the widget nor the string, so two
failures at once said only that something among a dozen widgets was wrong. It
names both now, and prints the rendered screen on a failure. That is what
turned `capability_view` from a guess into a reading: the screen showed the
hex, then `expires at 1000`, and no verdict -- which is a different diagnosis
from every mechanism theorised before looking.

**The cause was the opt-in arrangement, so that is what changed.** A new
`qttycheck` runs the same sweep from `make check`, with the preconditions as
SKIPS rather than errors -- and each skip says out loud that no widget was
rendered, because a silent one is a green line claiming coverage it never had.
`make qtty` stays strict for whoever asks for it directly. `evidence.md` states
the class: a check that runs only elsewhere is a check you have stopped
running. Here "elsewhere" was "when somebody remembers", which is worse than
CI, because CI at least goes red.

The floors it measures now, for all twelve widgets:

	authz_view 20, capability_view 20, sweep_view 28, revocation_view 26,
	journal_view 34, sync_view 20, transfer_view 20, state_view 22,
	config_view 32, link_view 46, peer_view 20, provision_view 20

`provision_view` is in that list for the first time: its header was included by
the render test and no such widget was ever built, so it had been compiled into
the sweep and never rendered by it.

**And moving it into `check` had a cost this section could not see, paid the
same day.** The scratch path named above was a fixed `$(BUILD_DIR)/.qtty` and
is `$(BUILD_DIR)/.qtty-<pid>` in the tree now: a fixed name made two concurrent
runs delete each other, which was harmless while the target was opt-in and
became reachable the moment it joined `make check`. Sec 208.

## 206. The sweep run in full again, at 321 entries

Sec 52 ran every sabotage entry and found one that had silently stopped
testing. That sweep was on 2026-09-03, over **42** entries. The table holds
**321** today, and until now no full run had happened in between.

	CAUGHT      317   including both controls
	SURVIVED      4   all four on the declared expected list
	PATTERN-MISS  0
	exit          0

**The result is that nothing was wrong, and the value is in knowing rather
than assuming.** No entry had quietly stopped testing anything, both controls
failed the way they are meant to, and the four survivors are exactly the set
`EXPECTED_SURVIVORS` declares with reasons -- `manifest-sig-zero-sign`,
`relay-hop-header-min`, `peer-linux-trim-call` and
`authz-print-asks-the-library`.

**What was actually at risk, stated precisely, because the obvious reading
overstates it.** `make style` has run `--verify` on every gate since sec 52,
so the specific failure sec 52 found -- an entry whose pattern stops matching
-- has been caught continuously ever since. That is a real defence and it is
not the same question. **Matching proves the substitution still applies;
catching proves something still notices.** An entry that still names one site
but whose mutation is now absorbed by a different guard, or whose assertion
has been weakened, reads healthy to `--verify` for ever. Only a sweep asks.
Between 42 entries and 321, nothing had asked.

**The barrier was a cost nobody re-measured.** The `sabotage` target's comment
said a full sweep is "builds plus one `make test` each, and nothing budgets a
timeout" -- true about the shape, and read as a reason not to run one.
Measured: **321 entries in 40.6 minutes**, about 7.6 seconds each, because the
builds are incremental. An assumption had been doing a measurement's work.

The comment carries the number now, and the instruction to run one after
landing a batch of entries.

**And the estimate made on the way to the measurement was wrong in the
comfortable direction.** One entry timed at 17.5 seconds including both
controls, from which this project priced the table at "about six seconds each,
roughly half an hour". It is 7.6 and 40.6 -- a third more than the figure that
had already been sent to a sibling project as a reason the sweep was cheap.
Extrapolating from a warm single run understates, because the single run pays
no cost for the builds the other 320 entries each trigger. The estimate is
recorded beside the measurement rather than replaced by it, since the gap is
the finding.

**What this does not establish.** A caught mutation says some assertion
noticed; it does not say the RIGHT one did. Sec 152's rule -- read which line
caught which entry -- is still the check that separates a guard being defended
from a guard being shadowed by an unrelated assertion, and a sweep of 321
entries produces 321 such lines that nobody reads. This run was read for
verdicts, not for attribution. That is a smaller claim than "every guard is
held to account by something", which is what the tool prints.

### The trade is coverage against attribution, not coverage against effort

Reported by fuzzypickles 2026-09-08, in answer to the numbers above, and it
corrects the reading this section would otherwise have invited -- that a table
is the grown-up version of sabotaging by hand.

They sabotage by hand, one edit at a time. That method **gets attribution for
free**, because there is one line to read and the person who wrote the
mutation is standing over it. Their three from that day: reverting a link
predicate failed `link_test.c:240` and `:246` and nothing else; deleting an
address check failed `addr_observe_test.c:179` six times, once per control
character, with the accepted control and the high-byte case staying green; a
safe-area sabotage failed exactly the two menu-bar assertions with the
zero-inset control still passing. In each, WHICH assertion fired was the
finding -- the address one would have been a different bug if the control had
gone red.

	table   coverage, and no attribution unless somebody reads 321 lines
	hand    attribution by construction, and coverage only of what
	        somebody thought of

**Neither is the other's superset.** A table cannot have their blind spots and
cannot, at this size, have their attribution. Hand sabotage cannot have this
table's stopped-testing failure and cannot have its breadth.

**The option that would have both, which is theirs and is not taken.** A sweep
that printed only the entries whose CATCHING LINE HAD CHANGED since the last
run turns 321 unread lines into a short diff -- and it is a diff over output
the tool already produces rather than a new harness.

Its cost is a design choice nobody has made: keying on `file:line` would go
off on every unrelated edit above an assertion, since line numbers move
constantly, so it would have to key on the assertion TEXT and then a reworded
message reads as a moved guard. That is the sort of noise that gets a check
switched off by instalments. Whether the baseline is worth carrying, and what
it keys on, is the holder's -- recorded here rather than started, because a
tool that cries wolf about attribution is worse than one that stays silent
about it, and this section's own subject is a check nobody ran.

## 207. The same clipping in two more printers, and a claim made by reading

Sec 205 fixed `capability_print`, whose verdict fell off an 80-column terminal
because 64 hex characters came first, and closed with: *Only
`capability_print` had that shape.*

That sentence was written from having read one file. Asked properly -- grep
the printers for `fzn_trust_fingerprint`, then render each and measure where
its answer begins -- the answer is **five printers emit a 64-character
fingerprint and three put it before the answer.**

	trust_print        source at column 82   PAST an 80-column terminal
	authz_print        answer at column 93   PAST an 80-column terminal
	capability_print   fixed in sec 205
	state_print        verdict first, safe
	provision_print    verdict first, safe

**`trust_print` is the one that matters.** Its line read

	a5a5 a5a5 ... a5a5 (configured out of band)

so an operator on a standard terminal saw the key and never learned whether it
was pinned, adopted or this node's own. That is the TOFU distinction --
`trust.h` calls an adopted anchor "authenticated by nothing" -- and it was the
half that fell off. The source comes first now and the fingerprint follows
after a dash.

**`authz_print` is worse in degree.** Its answer -- which origins may reach a
kind at all -- began at column 93, so a guarded policy showed its capability
and nothing about who may use it. Reachability leads now.

`state_print` and `provision_print` were already verdict-first and are
recorded as measured rather than assumed.

### Why the sweep did not catch the authz one

`make qttycheck` renders `authz_view` and asserts its words reach an 80x24
terminal, and it passed throughout. Its fixture is `fzn_authz_unguarded`,
whose line starts `no capability -- UNGUARDED` and is short. **The case with a
64-character capability ahead of the answer was never drawn.** A second widget
in the guarded state is in the sweep now, and reverting the printer turns it
red -- checked rather than assumed.

`evidence.md` states the class: a test can name the hazard exactly and cover
only the safe path. The sweep's own name for that entry is the fixture, and
the fixture was the unguarded case because that is the case somebody reached
for when writing it.

### The guard, and the shape of the error worth keeping

Each of the three printers now asserts in its own suite that the answer begins
before column 72 -- the bound is 72 rather than 80 to leave room for whatever
prefixes a line in a log. Reverting `trust_print`'s order fails
`trust_print_test.c:145` by name, so the guard has been seen to fire rather
than merely added.

**What produced the wrong claim is worth more than the two fixes.** Sec 205
was written at the end of repairing a target, having found and fixed one
instance, and the closing sentence generalised from that instance without a
second look. `evidence.md` names it: a frame that has just been right is the
hardest one to drop, and the tell is that the answer arrives faster than the
evidence. It cost one grep to check -- the same grep that produced the table
above -- and the sentence was published instead.

It is also the second instrument fault in the same section's lineage. Sec 205
records a grep whose pattern could not match a capitalised string and reported
an absence; this is a claim of exhaustiveness made without any grep at all.
Both were about *which printers do X*, and both were answered from the one
printer already in hand.

## 208. Putting the sweep in `check` made a latent collision reachable

Sec 205 moved the qtty render sweep into `make check`, on the argument that an
opt-in check is one that has stopped running. That argument holds. What it did
not account for is that the target was written for a reader who types it, and
`make check` is typed by everybody -- including two sessions at once, which
`CLAUDE.md` says is the ordinary case in these trees rather than an exotic one.

**The mechanism, read out of the recipe rather than inferred from the
symptom.** The scratch was a fixed `$(BUILD_DIR)/.qtty`, and every invocation
does `rm -rf "$scratch"` at the start AND again from `trap ... EXIT`. So a
second run's startup delete removes the first's unpacked tree mid-build, and
the first's exit trap removes the second's. **Deterministic rather than racy**,
which is why it reproduced first time.

It surfaces as

	qtty: their library would not build; the log goes with the scratch

-- a message blaming the vendored project for a collision in this file. Anyone
meeting it would go and look at qtty.

**Measured both ways, two concurrent runs each:**

	fixed scratch    A RC=2  B RC=2   both "their library would not build"
	per-run scratch  A RC=0  B RC=0   both 112 checks, 0 failures, nothing left

The control is stronger than the prediction was. The expectation was that one
run would lose; in fact **both** do, because each deletes the other.

**The fix keeps the prefix on purpose.** The scratch is `.qtty-$$` now, and the
`.qtty-` prefix is load-bearing rather than cosmetic: sec 205's style-gate
prune keys on that name, so a scratch abandoned by a KILLED run -- where the
trap never fires, which is exactly how sec 205's leftover happened -- is still
pruned. A `mktemp` name would have looked cleaner and silently defeated the
guard added hours earlier.

### How it was found, which is the part worth keeping

Not by the gate, and not by looking for it. A sabotage run that should have
turned the sweep red came back with **no FAIL line and no test output at
all**, and the working tree restored cleanly afterwards -- which reads exactly
like a completed sequence. The tidy story was available and wrong: the target
had aborted before the test ran, because that sabotage run overlapped a
still-running background invocation of the same target.

Had the run been judged by its exit path and the restored file, sec 207 would
have recorded "the sweep was seen to fail, checked rather than assumed" on the
strength of a run that never executed the check. That is `evidence.md`'s
failing check that could not have succeeded, arriving inside the act of
verifying something else -- and the thing that caught it was reading the log
rather than the outcome.

**The defect being hunted was in `authz_print`. The defect found was in the
gate, and it was mine, introduced the same day.** A sweep that runs everywhere
is worth more than one nobody types; it is also a thing every session now
depends on, and it had a collision in it from the hour it was promoted.

## 210. Thirty dependency files, written every build, read by nothing

Found by adding a field to a struct.

`fzn_link_table_t` gained a `log` pointer in sec 209. The next sanitized run
died in `gui/test/link_view_test` -- a suite with nothing to do with logging:

	ERROR: AddressSanitizer: stack-buffer-overflow
	    #0 fzn_link_table_init link/link.c:81
	    #1 main gui/test/link_view_test.cpp:63

`fzn_link_table_init` writing eight bytes past the end of a caller's struct is
one layout in the library and another in the binary linked against it, which
is the symptom `build-and-commit.md` names in its first dependency rule.

**The cause is one substitution.**

	TEST_OBJS = $(TEST_SRCS:%.c=$(BUILD_DIR)/%.o)

`%.c` cannot match a `.cpp`, so **no C++ object has ever reached `TEST_OBJS`**,
and `GUI_OBJS` was never added to `OBJS` either. `DEPS` is derived from those
two lists, and `-include $(DEPS)` is what reads dependency files back. So the
compiler was writing 30 `.d` files under `gui/` on every build and make was
reading none of them: **no GUI source or test has ever rebuilt because a
header changed.**

Every one of those 30 files was correct. `link_view_test.d` names `link.h`
four times. They were written, they were accurate, and nothing opened them.

### Why it survived, and why it surfaced now

Nothing about a stale object announces itself. A widget compiled against last
week's header links, runs and passes -- the tests assert on behaviour, and the
behaviour was unchanged, because until now no header this side includes had
altered a STRUCT LAYOUT. Sec 202's `link_view` and sec 204's `peer_view` both
added widgets and printers; neither changed a struct anyone else declares.

A `log` pointer on a caller-owned table did, and the failure was immediate,
loud and in the right place. **The sanitizer turned a silent staleness into a
stack-buffer-overflow with a two-line stack**, which is the best outcome
available: the alternative the rule predicts is "a pile of nonsense assertion
failures" that reads as a broken change rather than a broken build.

### The fix, and the proof

`GUI_TOBJ` is named beside `GUI_OBJS`, and `DEPS` gains both halves. Both
expand to nothing when the GUI is off, so a build without it pays nothing.

Proved the way the defect was found rather than by reading the variable:
`touch link/link.h`, rebuild, and count whether `link_view_test.cpp` is
recompiled. It is. Before the fix the same command recompiled nothing, which
is what let a struct change reach a binary that had not seen it.

**The general shape, which is not about C++.** A list whose pattern encodes a
file extension silently excludes every member with a different one, and
excluding them from a DEPENDENCY list is invisible by construction -- the
build still works, the tests still pass, and the only symptom is staleness
nobody attributes. Two lists here derive from `TEST_SRCS` and one derived
list was wrong; the tell was that `TEST_SRCS` itself carries `.cpp` entries
while everything computed from it quietly does not.

### Signalled, and the scope claim did not survive being measured

Filed to `claude-guidelines` as **"A dependency list whose pattern names a
file extension silently drops every source with a different one"**, commit
`1ea383f`. On the copyright holder's instruction, whose reason was that other
trees had likely copied this Makefile.

**They have not, and measuring it changed what the signal says.**

	%.c= substitutions in a Makefile     fuzznet 11, every other tree 0
	trees with C++ and hand-rolled deps  beerssh, hembygd, fuzznet

`beerssh` is not affected: its hand-written Makefile `-include`s exactly what
it compiles by hand -- vendored libvterm -- and its Qt objects belong to
qmake, which does its own dependency tracking. A first count of its `.d`
files says 1193, which looks alarming and is OpenSSL's own build under
`build-deps-android/`.

**`hembygd` already has the spelling that cannot have this defect**, which is
what makes it worth a signal rather than a fix here:

	-include $(shell find $(BUILD_DIR) -name '*.d' 2>/dev/null)

A derived list can be incomplete; a `find` cannot be, in this direction. That
is a cross-project convention question and so is not this project's to settle
-- fuzznet has taken the narrow fix, naming the C++ halves explicitly, and
proposes neither form as the rule.

**The reason to record the negative.** The prompt was a reasonable guess and
it was wrong, and a signal filed on it unmeasured would have sent a pass
looking for a defect in sixteen trees that have never had it. `evidence.md`'s
rule is that a scope number is the claim in a finding nobody re-derives; this
one was re-derived because it was somebody else's guess rather than this
project's, which is the easier case. The hard case is the same guess made
here.

## 212. Two stores that refuse rather than evict, and now say so

`record/journal` and `state/cell`, on the same rule as sec 211: the reader
filters, so the source does not have to omit.

Both modules share a design decision and it is the reason each has a CRIT.
Neither evicts. `journal.h`: forgetting an issuer readmits everything it ever
sent. `state.h`: dropping a setting reverts it to a default nobody can trace.
So a full journal cannot track a NEW issuer and a full state cannot record a
setting, **and neither condition recovers on its own** -- which is what
separates them from every other refusal in this library and is exactly what
`FZN_JOURNAL_ERR_FULL` and `FZN_STATE_ERR_FULL` cannot say.

	record/journal  CRIT  full: no new issuer can be tracked, nothing evictable
	record/journal  WARN  a gap, and HOW MANY records it is
	state/cell      CRIT  full: this setting is not recorded, nothing evictable
	state/cell      WARN  a second issuer writing a cell the first one owns

**The gap one is the clearest case for text over a code.** One missed datagram
and an hour of unreachability are the same `FZN_JOURNAL_ERR_GAP`. The caller
holds `seq` and could subtract, and does not, because nothing told it to. The
line says "7 record(s) were missed" and the difference between the two
situations stops being an inference.

**And the conflict one is not about the call at all.** `FZN_STATE_ERR_CONFLICT`
says this write was refused. What somebody needs to see is that a SECOND
ISSUER is writing a cell a first one owns, which is a fact about the
deployment: two authorities competing for one setting, and only one of them
knows it.

### The gate refused before the tests were written, which is the gate working

`tool/log_gate.py` named both new subsystems as unasserted the moment the emit
sites landed. That is the case it exists for and the one a spelling check
cannot see -- not a typo, but an emit site nobody tested. It goes 3 subsystems
over 4 sites to 5 over 8, and `journal_test` gains 12 checks while `state_test`
goes 230 to 241.

### Two instrument slips inside one batch, both caught by the compiler

A nested function declaration inside a block, and a reference to a fixture
helper that does not exist -- `BODY_A1` where this suite has `BODY_A`, and a
`CHECK` macro where it spells the same thing `expect`. Each was a guess at a
neighbouring file's vocabulary rather than a reading of it, and each cost one
compile. Cheap here because the compiler holds the whole vocabulary; the same
guess about a RUNTIME convention is what sec 210 was.

## 213. The catalogue, and a severity that is the whole content

`catalog/edge` joins sec 211 and sec 212, and it is the first module where one
of the two events is deliberately NOT a problem.

	catalog/edge  CRIT  full: no slot is ever freed, so no further link
	catalog/edge  INFO  an offered link lost to the one already held

**FULL is permanent here too, and this time it was measured rather than
inherited.** The three stores before it say so in their own headers; the
catalogue does not, so the claim needed checking: `catalog->used` is set to
zero by `init` and otherwise only ever compared. Nothing decrements it. So
`FZN_CATALOG_ERR_FULL` is not one refused link, it is every link from now on
-- and the neighbouring `hold_used--` is a different array, which is exactly
the kind of thing that makes a grep an unsafe answer to this question.

**STALE is convergence working, and INFO is the whole point of it.** A link
losing to the one already held is ordinary. Logging it at WARN would be how
the warnings that matter get drowned -- so the severity is not decoration on
this event, it IS the event's content. Its sabotage entry is a severity flip
and nothing else, and it reddens the suite.

It is worth saying at all because **a peer whose links ALWAYS lose has a clock
or an ordering problem, and that is invisible one refusal at a time.** Nothing
in `FZN_CATALOG_ERR_STALE` accumulates; a log does.

### Three more anchors retired by one change, which is now a measured rate

Adding two log calls to `catalog.c` retired `catalog-tombstone-is-stored`,
`catalog-full-refuses-not-evicts` and `catalog-resolver-is-consulted` -- all
three anchored on multi-line spans that a wrapped `if` broke. Re-pointed at
the condition or the return alone, and each re-verified by mutation: 5, 2 and
8 assertions respectively.

That is **eight anchor re-points in one day**, across four modules, every one
caused by adding a line inside a block an entry had spelled out. The rule from
sec 211 held each time and is worth restating as a number rather than an
instinct: an anchor's length is its exposure, and the part of a line that
names the thing being tested is almost always shorter than the block it sits
in.

### A test asserted its own text and got it wrong

The catalogue's FULL line says "no slot is ever freed"; the assertion written
beside it looked for "never freed". Both were written in the same minute by
the same hand, and the suite caught it immediately -- which is the one case
where asserting on wording is cheap, because the wording and the assertion are
in the same change and disagree at once.

It is worth noting against the temptation it creates: the fix is to assert a
substring that carries the MEANING (`ever freed`, the permanence) rather than
to relax the assertion until it passes. A test that stops checking the words
would still have passed, and the line could then say anything at all.

## 214. Pressure that recovers, and a refusal that is not ours

`chunk/reasm` and `spool/store`, and both are the exceptions to what sec 211
to 213 established.

	chunk/reasm   WARN  saturated: all slots live, this message will not complete
	spool/store   ERR   the backend refused a VERIFIED leaf

**The reassembly table is the first store here that RECLAIMS.** The journal,
the state, the revocation store and the catalogue all refuse permanently
because nothing in them is ever freed; a reassembly slot comes back when its
partial expires. So `FZN_REASM_ERR_FULL` is pressure rather than a state, and
it is a warning rather than critical for that reason -- the severity is
carrying a real distinction between "this will clear" and "this is now how
things are".

What the return value still cannot say is that the table is saturated AT ALL.
One refused chunk and a table full for a minute are the same value, and this
module's own header argues that a table refusing when full is a table one
sender can fill.

**The spool's is the one refusal in this library that is not about the
protocol.** Every other event here is fuzznet judging something. `spool/store`
reports the CONSUMER'S OWN STORAGE saying no -- a full disk, a revoked
permission, a device that went away -- and the leaf had already VERIFIED when
it happened. So the spool's bookkeeping and the storage disagree from that
moment, the bit is correctly not set, and the leaf will be asked for again for
ever. `FZN_SPOOL_ERR_BACKEND` names the layer and nothing else: not which
leaf, not where, not how much.

That is why it is ERR rather than WARN or CRIT. It is not fuzznet's fault and
not permanent in fuzznet's sense -- a disk can be emptied -- but nothing in
the protocol will resolve it either.

### What the gate cannot see, found by satisfying it wrongly

`tool/log_gate.py` reported all twelve emit sites asserted while
`spool_test.c` DID NOT COMPILE. It greps for the subsystem literal in test
sources; a literal in a file the compiler rejects satisfies it exactly as well
as one in a file that runs.

That is a real limit and it is the shape this project keeps meeting: **the
gate checks the artifact it was pointed at, and "a test mentions this string"
is not "a test asserts this string".** It is not worth fixing by parsing C --
`make check` builds every suite, so a non-compiling test cannot reach a commit
-- but it is worth knowing that the gate's pass is conditional on a build the
gate does not perform.

### The same mistake twice, one module apart

`REQUIRE` in these suites expands to a bare `return;`, which is fine in a void
test function and wrong inside `main`. Written into `main` for the catalogue,
fixed, and then written into `main` again for the spool twenty minutes later.

Both were caught by the compiler in seconds, so the cost was nothing -- but
the repeat is the interesting part: the first fix was to MOVE the block, and
the lesson recorded was about `return` types rather than about the shape.
**A fix that relocates code teaches less than one that changes it**, because
nothing about the new location says why it is the right one. The suites put
test cases in functions and call them from `main`; following that would have
avoided both.

## 215. The replay window, where a log earns its place most plainly

	frame/replay  WARN  a nonce already in the window
	frame/replay  CRIT  window full, so every FRESH frame is now refused

**A replay is the event this library exists to refuse**, and
`FZN_FRESH_ERR_REPLAY` reaches a caller that may do nothing with it. One
replay is a retransmission. A stream of them is somebody trying, and
**nothing in a return value accumulates** -- a caller sees each refusal
separately and would have to be counting to see the second thing at all. This
is the clearest case in the library for a log over a code, and it took until
the twelfth module to reach it.

**The full window is worse than it looks and its cause is not in the value.**
It refuses FRESH frames, not replays -- so a host in this state is dropping
legitimate traffic. And nothing here prunes on its own: `fzn_replay_expire` is
public and is the CONSUMER'S to call. So a full window means either that
nobody is expiring or that the capacity is below the arrival rate the horizon
implies, and those want opposite fixes. The line names `fzn_replay_expire`
for that reason, and the test asserts that it does.

Refused rather than evicted, deliberately, and the module's own comment says
why: dropping the oldest live entry would reopen it to replay, so an attacker
able to generate traffic could flush the window and then replay anything
recorded. That is what makes CRIT right -- the safe behaviour under pressure
is the one that stops accepting.

### A test function placed before the fixtures it uses, three times

Written above `nonce_of`, `AHEAD` and the `<string.h>` this suite includes,
so it failed on three implicit declarations at once. Moved to sit immediately
before `main`, which is where the catalogue's and the spool's ended up after
the same correction.

Three modules, three placements, one shape: **a test case goes immediately
before `main`, because that is the only point in one of these files where
every fixture, macro and include is already in scope.** Recorded as a
position rather than as a rule about declarations, since the first two
corrections were filed as `return`-type problems and taught nothing that
prevented the third.

## 216. Two more, and two the shape refuses

`record/store` and `claim/hold` join the diagnostics. `ratchet` and `blob`
were examined and DECLINED, and the reason is structural rather than a
judgement about whether they have anything to say.

	record/store  ERR  the backend returned a record that is not the one asked for
	claim/hold    ERR  a release the backend refused, with `held` already cleared

**MISPLACED is the sharpest event in this batch**, and the module's own
comment says why: a record handed back under the wrong key "may be perfectly
well signed, which is why a signature check further up would not have caught
this". So no layer above can see it and no layer below is looking. The return
value names the fault; the line names the DISCREPANCY -- wanted stream and
sequence against what arrived -- which is what says whether a backend is
confusing sequences or confusing issuers, and those are different bugs in
somebody else's code.

**The claim one is about a window nobody watches.** `held` is cleared BEFORE
the release is attempted, deliberately -- a process that believes it still
owns state the kernel may have handed on is how this design desynchronises a
ratchet. The consequence is that when the backend then refuses, this object
believes the claim is gone and the world may disagree, nothing later in the
process retries, and `FZN_CLAIM_ERR_BACKEND` reaches a caller unwinding a
failure path that is unlikely to look.

### Two modules where a log field would be wrong

**`ratchet` has no context to hold one.** `fzn_ratchet_chain_t` is a key and a
sequence -- a VALUE, copied by assignment, and one fuzzypickles declares. A
log pointer in it would be copied with every chain, would bloat every message
that carries one, and would mean a value type owning a borrowed pointer with a
lifetime nothing checks. Logging from `ratchet` would have to pass the log as
a parameter, which is signature churn on a hot path for one event.

And the event is weaker than it looks. `FZN_RATCHET_ERR_BEHIND` is the
frequent one, and this module already says what to do about it: "ordinary
weather on a datagram transport, and a caller that treats it as an intrusion
will alarm on it hourly". **The source told me the severity, and the severity
is low enough that the parameter is not worth it.** `TOO_FAR` is the
interesting one and is rare.

**`blob` has no context either.** `fzn_blob_tree_t` is a working accumulator
-- a stack, a depth, a leaf count -- and `FZN_BLOB_ERR_FULL` there means a
caller asked for a tree larger than the format allows, which is a programming
error at build time rather than a field condition. Nothing about it is
surprising at three in the morning.

**This is sec 201's rule applied to logging.** Every part of the library
should log; not every part has a place to put a log or something worth
saying, and adding a field to a value type to keep the pattern uniform would
be exactly the symmetry that section refused.

### Four instrument slips in one batch, all cheap and all the same shape

An invented sequence number (zero, where this store's records start at one); a
"fix" that broke a working fixture by making the requested sequence match the
slot being answered with, which is the opposite of what the case needs; a test
function inserted at a `printf` anchor that sits INSIDE `main`; and a suite
that does not include `<string.h>`.

Every one was a guess about a neighbouring file's vocabulary rather than a
reading of it, and every one cost a single compile or a single run. **The
compiler and the suite hold that whole vocabulary, which is why guessing there
is cheap** -- and why the same habit applied to a runtime convention, where
nothing holds it, is what sec 210 cost.

Three sabotage anchors retired again, all spelled over the multi-line
conditions the new log calls wrapped in braces. Eleven re-points today.

### The gate could not run whole, and what ran is recorded rather than implied

Three `make check` runs were killed by the harness for machine memory
pressure, on a box reporting 30 GB available throughout -- so these are
allocation spikes during sanitized compiles and instrumented test processes,
not exhaustion. Several other sessions were building at the time.

Splitting the gate into its stages is what made the result reportable at all:
a kill then costs one stage rather than erasing the evidence that the rest
passed.

	style        RC=0  338 sabotage anchors, log-gate coverage
	test         RC=0  100 clean suites
	installcheck RC=0  73 public headers as C++, all four arrangements
	ctcheck      RC=0
	qrcheck      RC=0
	sancheck     KILLED at 56 clean suites, no failure before it
	qttycheck    KILLED building qtty's own Qt library

**What was done instead of claiming the two missing stages.** The five suites
this change touches were built and run individually under AddressSanitizer --
store, claim, freshness, reassembly, spool -- all clean. That is the check
that matters here, because this batch adds a POINTER TO A PUBLIC STRUCT, which
is the exact class that produced sec 210's stack-buffer-overflow.

And `qttycheck` is unaffected by this change rather than merely unrun: no
widget declares `fzn_record_store_t` or `fzn_claim_t`, and none includes
either header. Checked rather than assumed, because "probably unaffected" is
how a skipped stage becomes a habit.

**The environment fact is worth keeping separately from the result.** A
commit that said "gate passed" would have been true of five stages and silent
about two, and a reader six months from now cannot tell a stage that passed
from one that never ran -- which is sec 205's whole subject, arriving from the
machine rather than from the Makefile.

## 217. The module I said was done, and a gate that missed a site

sec 216 closed the logging pass with twelve modules and two declined. It was
wrong: `log/` was neither, and it is the module whose own header argues for a
log line most explicitly.

	log/stream  INFO  evicting stream N seq M kind K, T dropped in total

**`log/` is the only store here that EVICTS**, which is why it was not on the
never-evicts list and why it fell out of the sweep of refusals -- it does not
refuse. `log.h` says why: "losing its oldest entries is its normal condition
rather than a failure. A log that refused to accept anything once full would
stop recording exactly when something interesting started happening."

That same paragraph makes the case for the line without meaning to. `dropped`
is exposed and a caller can read it -- and the header calls it what it is:

> `dropped` could not have rescued it either: it is one count for the whole
> log, it does not say which sequences went ... **It is a health number, not
> an answer.**

So the line names the stream, the sequence and the kind that went. At INFO,
because eviction is the design working; reporting it as a problem would be
wrong about the module rather than merely noisy, which is what its sabotage
entry pins.

### The gate reported success while missing an emit site

This is the finding worth more than the module.

`log.c` already has a type named `fzn_log_t` and a parameter named `log`, so
the wrapper macro was called `LOG_DIAG` rather than `STREAM_LOG` to avoid
shadowing. `tool/log_gate.py` scans for `\b[A-Z][A-Z_]*_LOG\s*\(` -- a name
ENDING in `_LOG` -- so `LOG_DIAG` was invisible to it.

**It printed "11 subsystem(s) over 16 emit site(s), each asserted by a test"
and was missing one** -- against 12 over 17 once the name was one it could
see, re-derived here rather than recalled. The empty-sweep guard could not
fire either: sixteen other sites still matched, so the detector was neither
silent nor complete.
sec 214 recorded that this gate cannot see whether a test compiles; this is
worse, because it cannot see an emit site at all and says nothing about it.

**The pattern encoded a naming convention and nothing checked the
convention.** That is the whole defect, and renaming the macro would have
dodged it rather than fixed it -- the next module with a name collision would
meet the same trap.

So the gate now finds every macro that WRAPS `flog_printf` and refuses one
whose name it could not have scanned for, with its own exit code:

	log-gate: log/log.c wraps flog_printf and is named LOG_DIAG, which
	          this gate cannot see

Shown by renaming the macro back and watching it fire. The macro is
`STREAM_LOG` now, which is both a better name and no longer the thing keeping
the gate honest.

### And the pass was declared complete one module early

Worth recording as a habit rather than an incident. sec 216 listed the modules
with a caller-owned context and worked through them; `log/` has one and was
missed because the SWEEP was for refusals -- every other module announced
itself by returning an error, and this one announces itself by silently
succeeding. **A survey keyed on how a thing fails cannot see the thing that
does not fail.**

## 218. The ledger, where the readers have no error channel

sec 217 ended by naming the reason `log/` was missed: the sweep was keyed on
REFUSALS, and a module that announces itself by succeeding cannot be found
that way. So this pass replaced the query with an enumeration -- every library
source with an `_init` that takes caller-owned storage, checked one at a time
against whether it is wired:

	wired          twelve of sec 211-216, plus log/ in sec 217
	declined       ratchet, blob -- value types, no context (sec 216)
	left           chain/manifest, persist/persist_file, prekey,
	               record/ledger, trust

`record/ledger` is the strongest of the five and is done here.

	record/ledger  ERR   a table that cannot be scanned, said in corrupt()
	record/ledger  ERR   full, and no row is ever reclaimed
	record/ledger  INFO  a confirmation that arrived behind, and by how much

### The case is different from every module before it

Every other line in this pass says something a return value could not carry.
**This module has readers with NO RETURN VALUE TO CARRY ANYTHING.**
`fzn_ledger_confirmed` returns a version and `fzn_ledger_count` returns a
count, so an unscannable table answers ZERO -- and zero is exactly what an
honest "never heard of this peer" answers. The two are indistinguishable to
every caller, permanently, by construction.

So this is not an unreported condition. It is an **unreportable** one, and
until sec 209 there was no channel in the library that could express it at
all. What follows from it is a host resending every subject to every peer for
as long as it lasts -- the safe direction by design, which is why nothing
else complains.

Said inside the static `corrupt()` rather than at its three callers, because
that is the one place all three reach, and two of them are the ones with
nowhere to put it.

### Two severities decided against a sibling rather than by it

**FULL is at ERR where `chain/revocation.c` takes CRIT for the same
structure.** Both tables refuse rather than evict and neither ever reclaims a
row, so the shape argues for the same severity and the shape is wrong. The
POLARITY decides it: a full revocation store can fail to WITHHOLD an
authority, and a full ledger can only fail to notice a delivery. That is the
asymmetry `fzn_ledger_behind` is already built on -- under-claiming costs a
retransmission, over-claiming skips something a peer needs -- so the severity
follows the module's own reasoning instead of its sibling's.

**STALE is at INFO because the header had already made the argument.** The
table "is identical either way", and a caller that wants to know its
acknowledgements are arriving out of order can read the return value. What
the return value cannot carry is HOW FAR back the late one was: one reordered
datagram and a peer whose view has fallen a long way behind are the same
`FZN_LEDGER_ERR_STALE` and are different problems.

### A sabotage that survived, and why it was the wrong sabotage

The first entry written for the corrupt line **SURVIVED**, and it deserves
recording because the mistake is not the one sec 52 catches.

It was not stale and it named exactly one site. It substituted one wording of
the message for another:

	"ledger cannot be scanned: %zu row(s) claimed in %zu slot(s)%s, so "
	"ledger cannot be scanned -- %zu row(s) in %zu slot(s)%s, so "

The test asserts on `resent`, which is in the NEXT string literal, so nothing
it checks could move. **The sabotage was aimed at the line and the test is
aimed at a claim, and those are not the same target.** An anchor check cannot
see this: the entry applied, the tree changed, the suite was right to pass.

Replaced by two that bite -- one inserting a `return 1` above the emit so the
line is never reached, one flipping ERR to INFO -- and both were watched
failing before they were recorded. The rule that comes out of it:
**a sabotage has to break the SENTENCE THE TEST ASSERTS, not the code the
sentence lives in**, and the way to know is to name the assertion it should
fail before running it.

## 219. A hundred red CI runs, found by a peer, in three defects of one shape

fuzzypickles looked across the workspace after their own CI went red for an
account-level reason, checked whether ours was the same thing, and reported
that it is not: both jobs execute, steps run, no billing annotation. **100 of
100 runs failed**, and the last success is off the end of a hundred-run
window.

Their sentence for why they sent it is the one worth keeping: *20 of 20 is
the state that stops being read.* Nothing here was going to find it. `make
check` is green and has been green all day, and neither failing step is in
it.

### Two defects, one per job, and both were already written down here

**`core (no crypto binding)`: `make style` refuses a real source.** That job
checks out deliberately WITHOUT submodules, so FLOG_ON is unset -- and sec
209 defined `FLOG_TSRC := link/test/link_log_test.c` INSIDE `ifdef FLOG_ON`.
The gate that checks every `.c` in the tree is in some list compares an
unconditional filesystem walk against a conditional list, so a source that
exists reads as unlisted, in the one arrangement nobody builds by hand.

The Makefile carries the rule sixty lines below the mistake, about
`MONO_SRCS`:

> Named OUTSIDE the conditional, because these files exist in the tree
> whether or not this build compiles them, and `make style` compares the
> source lists against what is actually there. Inside the `ifdef MONO_ON`
> they would be empty in a build that skipped the binding, and the check
> would report two real sources as unlisted -- a false finding, which is
> worse in a gate than no finding at all.

**`full`: the `clean` step, and this half predates the logging work.**
`./tool/ct_control.o` and `./tool/wipe_control.o` -- the two codegen controls
`ctcheck` compiles from a `sed` of a real source -- were in no list `clean`
reads, which is why the oldest run in the window already fails on the `full`
job and passes `core`. The flog objects joined them, and because CI cleans
the sanitizer tree first, `./san/flog.o` and its siblings were still there
for the in-place clean to find. **A third set fell out at the same time:
every `gui/` object, `GUI_OBJS` being defined inside `ifdef GUI_ON` exactly
as `FLOG_OBJS` was.**

	clean: build artifacts survived:
	  ./flog.o ./san/flog.o ./tool/ct_control.o ... 31 gui/ objects

Three variables named outside their conditionals -- `FLOG_TSRC`,
`FLOG_CLEAN`, `GUI_CLEAN` -- plus the two controls named literally. The
Makefile's own comment on `MONO_CLEAN` says where the rule came from: "found
in a consumer's tree while moving their submodule pin", which is
fuzzypickles. **The same tree reported the class and then reported the
instance, four days apart, and in between it was rewritten twice by somebody
who had read the comment.**

### And a probe writing into the source tree

Not a CI failure, and found only because `clean` refuses what it has no list
for. Under `make coverage` the build sets `CFLAGS="-Og -g --coverage"`, the
four feature probes compile stdin against `-o /dev/null`, and gcc derives the
coverage note file's name from the input -- so each probe wrote **`a--.gcno`
into the source tree**. Reproduced in a scratch directory both ways:

	cc -Og -g --coverage -x c - -o /dev/null   ->  a--.gcno
	cc -Og -g            -x c - -o /dev/null   ->  nothing

`FZN_PROBE_CFLAGS` filters the coverage flags now, beside the filter that
already keeps `-MMD` out of a probe for the same reason -- and that earlier
one was paid for in exactly the same way, a flag that belonged to the build
reaching a compile whose output is `/dev/null`.

### A fourth instance, found by the clean the fixes made possible

Running the gates on a freshly cleaned tree for the first time -- which is
what the two `clean` fixes above made a thing that happens -- `qttycheck`
failed in the linker:

	/usr/bin/ld: cannot find ./trust/trust.o: No such file or directory
	... twelve more, ending with ./constant_time/constant_time.o

**The `qtty` target had NO PREREQUISITES AT ALL.** It names twenty-eight
objects on its link line and asked make for none of them, so it worked only
because `check` runs `test` first and nobody had ever run it alone after a
`clean`. That is the same sentence as the three defects above with the words
changed: a rule that is correct only because of what happened before it.

`build-and-commit.md` warns about the opposite half of this -- a header added
to a `$^` rule's prerequisites reaching the command line -- and the two are
one problem. `QTTY_RENDER_OBJS` is now the prerequisite list AND the link
line, so they cannot be two lists, and it is attached with
`$(if $(and $(GUI_ON),$(CLI_ON)),...)` so a build without the widgets still
prints its refusal rather than compiling twenty-eight objects first.

### What actually kept this hidden, which is not "CI was red"

Two silences composed, and neither is the other's fault.

**The `clean` step exists BECAUSE nobody runs `clean`.** That is its own
comment's argument: it was added after a consumer found the fault, on the
grounds that a consumer's tree is "the one place `clean` gets run by somebody
who did not write it". So the step was correctly placed and there is no local
gate that duplicates it -- `evidence.md`'s *a check that runs only in CI is a
check you have stopped running*, arrived at from the other direction, since
here the check was deliberately put where the situation occurs.

**And a job that fails for one reason cannot report the second.** `core` went
red today on the style gate; `full` had been red since before that on
`clean`. A red history reads as one fault, and this one is two faults of
different ages -- which is the reason the useful figure in the peer's report
was 100 of 100 rather than any particular log.

The lasting item is neither of the fixes. It is that **`make check` does not
run `make clean`, on purpose, and nothing says so out loud.** A gate that is
green while a target of the same Makefile refuses is a gate whose scope
nobody has written down. Signalled to `claude-guidelines` as *Eight trees have
a `clean` that verifies its own work and not one of them runs it from
`check`*, with the measurement -- and with the adjacent shape recorded there
as NOT a signal, since two independent detectors over all sixteen Makefiles
put "a source list defined inside a build conditional" at fuzznet 37 and every
other tree 0.

**Closed: run 34286170335 is green, both jobs, every step.** Named rather
than asserted, because the fix was verified locally first and a local mirror
is still a claim about somebody else's runner.

## 220. The seam where sixteen failures share one bit

`persist/persist_file.c` is the POSIX backend behind `persist.h`, and it is
the widest gap in this library between what a function knows and what it
returns. `load` and `save` are `int`. Eleven distinct failures in the save
path and five in the load path all leave as `0`, and `errno` -- which is where
the operating system says whether the disk is full, the directory read-only,
or the path on a filesystem with no `fsync` -- is discarded at the boundary.

	persist/file  INFO  nothing stored for slot N yet
	persist/file  WARN  a file at one of our names that we did not write
	persist/file  ERR   which step of an atomic save failed, and why

### The pair that matters is not an error in one direction

**A slot with no file and a slot holding a file too large for the caller's
buffer both return `0`.** The first is a host's first run. The second is a
file in this store's directory, under this store's naming, that this library
did not write -- and the refusal's own comment already said so: "a caller
sizing at FZN_PERSIST_MAX should never see this unless the file is not ours".

So the module had the distinction, wrote it down, and had no way to say it.
ENOENT goes at INFO, because alarming on every first run would be wrong about
the design; anything else on the open goes at ERR; and a foreign file goes at
WARN, which is what separates the pair. The tests hold the RETURN VALUE FIXED
at 0 across both cases and require the LINES to differ, since that is the
whole claim.

### One helper, because the verb is the content

The eleven save failures differ by a verb and agree on everything else, so
`say_failed` takes it: `create at mode 0600`, `write`, `flush`,
`sync to disk`, `close`, `rename over the target`. A person reads those
differently -- a refused create is permissions or a path, a short write is
usually space, and a refused rename is **the one failure where the bytes were
good**, so the target still holds the previous state and `0` cannot say that.

`errno` is captured before any other call at every site, because `fclose` and
`unlink` set it too and reading it after the cleanup reports the cleanup's
luck. This is the second POSIX-only translation unit to read errno --
`session/random_linux.c` is the other -- and flog's own stdio backend spells
it `strerror(errno)`, which is what this follows.

### Two limits, both stated rather than worked around

**An init failure is not reported.** `fzn_persist_file_init` returns NULL for
an absent `dir` or one too deep for a bounded path, and at that moment there
is nowhere to put a line: the caller cannot have set a log on a struct whose
fields are still whatever its memory held. The NULL means only those two
things, so it costs nothing.

**And the helper needs four explicit discards.** With flog absent
`PERSIST_LOG` expands to nothing, so all four of `say_failed`'s parameters
become unused -- a warning, in an arrangement this library ships. The other
emit sites need no such line because they name struct fields the surrounding
code uses anyway; this is the first helper whose whole body is a log, and it
is worth knowing before the next one is written.

## 221. A coverage census that could not see eight of its own sources

Wiring the backend meant writing sabotage entries for it, which is when
`tool/sabotage.py` turned out to be reporting coverage over a population
narrower than the tree.

The census reads `make manifest` and required an entry for every `source `
line. The manifest names the four crypto bindings `binding ` and the four
file backends `backend `, each with the macro that gates it. **So eight files
were outside the check, and seven of them had never been sabotaged at all** --
while the tool printed `342 entries over 48 of 49 library sources` and read as
a complete sweep.

	before   49 sources, 48 covered, 1 deliberately guard-free
	after    57 sources, 56 covered, 1 deliberately guard-free

**`record/store_file.c` had entries anyway, which is what says the exclusion
was an artifact of a word rather than a decision.** One backend of four was
swept because somebody wrote entries for it without the census asking; the
other three and all four bindings were not, and nothing anywhere said so.

### What was in the unswept seven

The four bindings are fifty lines each and are the last place a defect can
hide, because everything above them trusts what they return:

	sign-verify-checks-the-signature   a verifier that accepts everything
	aead-open-checks-the-tag           an open that ignores the tag
	hash-covers-the-whole-input        a digest over none of its input
	agree-refuses-an-all-zero-shared-secret   an X25519 output an attacker
	                                          chose

`chain/sign_monocypher.c` exists ONLY to invert monocypher's polarity --
"Monocypher returns 0 for a good signature and -1 otherwise; the seam is the
other way round" -- so the whole file is one expression, and nothing above it
can catch that expression being wrong. It had no entry.

The backends took the properties their own headers argue for: the mode set at
creation rather than chmod'ed afterwards, so a prekey secret is never briefly
world-readable; contention distinguished from a broken store, since a caller
reading EACCES as "somebody else owns it" waits for ever for an owner that
does not exist; and a spool sidecar checked against the blob it belongs to,
so a reused path cannot report leaves nobody has as present.

### The census now names them, shown by removing entries rather than by trust

	with the four binding entries removed, the census would name:
	  chain/sign_monocypher.c session/hash_monocypher.c
	  session/aead_monocypher.c session/agree_monocypher.c

Before the change it would have named none of them, which is the control this
kind of check needs and the reason the widening is not taken on faith. The
same shape as sec 219 in a different file: **a list whose completeness check
has a narrower population than the thing it describes**, and in both cases the
narrowing was a word.

### And the finding is narrower than it first sounded: all ten were CAUGHT

Run against the suites as they stood, **every one of the ten was caught by an
assertion that already existed**:

	sign-verify-checks-the-signature   a tampered signature verified
	aead-open-checks-the-tag           the ciphertext did not open to the draft
	hash-covers-the-whole-input        BLAKE2b-512("abc") does not match RFC 7693
	agree-...-all-zero-shared-secret   a low-order peer key produced a usable key
	persist-secret-mode-0600           a stored secret is not owner-only
	claim-file-contention-...          a second description took a claim held
	spool-file-sidecar-belongs-...     a sidecar for another blob was restored

So **nothing was unguarded.** The bindings had KATs, the low-order point had
its own case, the mode had an assertion, and the reused spool path had one.
What was missing was not coverage but the census's ability to SAY so: it
printed a figure over 49 files while the tree had 57, and the eight it could
not see were the eight nobody would have thought to check by hand.

That is worth separating carefully, because the two findings license different
things. **A gap in a suite is work to do. A gap in a census is a claim to
stop making** -- and the second is the one that was here. The entries are
worth keeping anyway, on sec 52's argument that a guard nothing sabotages is a
guard nobody has watched fail; but this pass added no protection the tree
lacked, and saying otherwise would be the flattering version.

## 222. Two modules where the line IS the security surface

`trust/trust.c` and `prekey/prekey.c` join the diagnostics, and they are the
first two where the log is not a better way to report a failure -- it is the
only place the event can be reported at all.

	trust/anchor  NOTE  an anchor taken, how it arrived, its fingerprint
	trust/anchor  WARN  a re-anchor refused, naming the transition attempted
	trust/anchor  WARN  an all-zero root refused
	prekey/pin    NOTE  a rotation, which FZN_PREKEY_OK cannot distinguish
	prekey/pin    WARN  a rollback refused, and how far back it was

### `trust.h` asked for the line before there was anywhere to put one

> A library cannot make first contact safe; it can refuse to hide when it
> happened.

That sentence was written to justify `adopted_at` and `fzn_trust_source`, and
it is an argument for a log line that had no channel to be one. Adoption
returns FZN_TRUST_OK: **nothing anywhere reports that this host has just begun
trusting a key nothing authenticated.**

**And FZN_TRUST_ERR_ANCHORED is one code for two stories.** `self -> adopted`
is an attempt on the single window this design closes -- whoever answers first
becoming the root -- and `pinned -> pinned` with a different key is usually a
misconfiguration. The header sets out the whole table and the code returns one
value for every row of it. The test holds the RETURN VALUE FIXED across both
and requires the two sentences to differ, which is the only assertion that can
distinguish a line that carries the transition from one that merely fires.

**The line borrows the module's own words.** Both source names come from
`fzn_trust_source_str`, the same function `cli/trust_print.c` uses, so a
reader of a log and a reader of a screen are told the same thing in the same
vocabulary -- sec 200's rule, met from a third direction.

**And the fingerprint goes last**, which is sec 207 arriving in a place it was
not written for: a terminal clips from the right, so 79 characters of hex must
not sit in front of the verdict. The test asserts the fingerprint's position,
not merely its presence, and the sabotage for it puts the hex first.

### The pair in `prekey` is two successes, not a success and a failure

Every earlier module in this pass logs where a return value is too coarse
about a FAILURE. This one is sharper: `fzn_prekey_pin` returns
**FZN_PREKEY_OK** both for a re-delivery that moves nothing and for a rotation
that replaces this peer's key material. Same code, and one of them changed a
key.

The header already called the re-delivery "ordinary and not an event", so the
rotation gets the line and the echo does not -- at NOTE, because it is normal
and it is key material. The rollback gets a WARN carrying the DISTANCE: a
record one second older than the one held and one a year older are the same
FZN_PREKEY_ERR_ROLLBACK, and the second says somebody kept a copy.

### Three lines deliberately not written, and each one asserted

A decline nobody asserts the absence of is a line somebody adds back for
symmetry, so each has a test that fails if it appears and a sabotage that puts
it back:

	FZN_TRUST_ERR_UNCHANGED   the return value says exactly this; a join
	                          repeated is not a fault
	FZN_PREKEY_ERR_WRONG_HOST the caller chose both the peer and the record,
	                          so it holds everything a line could name
	a prekey FIRST USE        `trust/anchor` has already said an anchor was
	                          taken, with provenance and fingerprint

The third is sec 194's boundary -- a widget may add what its medium affords
and may not restate what the printer said -- arriving between two LAYERS
instead of between a printer and a widget. `fzn_prekey_peer_set_log` sets the
embedded anchor's log too, because the peer owns it, so a first use produces
one line from each layer on two subsystems and neither repeats the other.

### Two mechanical things worth carrying forward

**The macro's own test comes too late when an argument is expensive.**
`TRUST_LOG` checks `(t)->log` inside itself, but the fingerprint is built
before the call -- so the success path is wrapped in `if (trust->log)` and
79 characters of hex are not formatted on every anchor for nobody.

**A value computed only to be logged needs an explicit discard.** With flog
absent the macro expands to nothing, its arguments vanish with it, and
`replacing` is set-but-unused -- a warning, in an arrangement this library
ships. `persist/persist_file.c`'s helper needed four of these for the same
reason. The rule that separates them from every other emit site: a site that
names struct fields the surrounding code uses anyway needs none.

### Two sabotages that were CAUGHT and tested nothing they claimed

The entries defending the two silences inserted a log call before a `return`.
Both of those returns sit inside a **braceless `if`**, so the inserted
statement became the whole body and the return became unconditional. Both were
reported CAUGHT.

	prekey-wrong-host-is-silent  FAIL prekey_test.c:441: a re-delivery of
	                                  the record already held was refused
	trust-echo-is-silent         FAIL trust_test.c:264: a second, different
	                                  root -- got "already anchored"

Neither of those is the case the entry is about. They are cases about
something else failing because an unconditional return broke the module, so
what the run demonstrated is that breaking control flow breaks a suite --
which nobody doubted.

**CAUGHT is what hid it.** The verdict was correct and the reason was not, and
nothing distinguishes the two except reading WHICH check failed. That is
`evidence.md`'s instruction in as many words -- *sabotage the thing, then read
which check failed, never that something did* -- and it is the second time in
one day that a sabotage looked fine and was aimed at the wrong claim, after
the ledger entry in sec 218 that reworded a string no assertion read.

The two failures are worth putting side by side, because the pair is the whole
lesson: **a sabotage can fail to test its claim by changing too little (a
reworded string nothing asserts on) or by changing too much (a statement that
re-binds an `if`), and both come back looking like a working guard.** Braces
in the replacement fix this one, and both are now caught by the assertion that
is actually about them.

### The 13 failures that were a stale object

Worth recording because it read exactly like the feature not working. The new
test came back with thirteen failures, every one of them
`a refused re-anchor said nothing` and its neighbours -- a perfect symptom of
diagnostics that do not emit.

Nothing was wrong. Checking that the module still compiles without flog is one
command, `make trust/trust.o FLOG_DIR=`, and it leaves behind
`trust/trust.o` **built without FZN_FLOG_ON**. The next `make` saw an object
newer than its source and linked it. **Make tracks timestamps and cannot see a
flag change**, so a deliberate check of the other arrangement poisons the
default one and says nothing.

`build-and-commit.md` warns about concluding a test's result from a binary the
build did not rebuild. This is a step past that: the object WAS rebuilt, under
different flags, which is a state neither make nor the timestamp can express.
The remedy is the one this tree already uses for sanitizers -- give the other
arrangement its own build directory, so the two never share a file.

**And the remedy as first written here did not work, which is the part worth
keeping.** It said `BUILD_DIR=noflog`, and one section later that was tried on
`chain/manifest.c`:

	make chain/manifest.o BUILD_DIR=noflog FLOG_DIR=

That compiled `chain/manifest.o` -- the DEFAULT one -- without flog, and the
next `make` found it newer than its source and did nothing. **`BUILD_DIR` only
redirects targets whose NAMES contain it**, so naming the object at its
default path opts out of the variable entirely; make then matched its own
built-in `%.o: %.c` rule, whose command line has no `-DFZN_FLOG_ON` in it. The
diagnostics were poisoned by the very command written to avoid poisoning them,
and ten assertions failed reading exactly like a feature that does not work.

`nm -u` is what settled it in one line, the same instrument that measured
flog's allocations in sec 209:

	before   (nothing)
	after    U _flog_printf

So the working form names the target under the other tree --
`make noflog/chain/manifest.o FLOG_DIR=` -- or builds the whole thing there.
The general shape is worth more than the flag: **a variable that composes a
path cannot protect a target you name yourself**, and a `%.o` request that
misses every explicit rule does not fail, it finds a built-in one.

## 223. The one refusal that fails open, and the pass closed

`chain/manifest.c` is the last module with a caller-owned context, and it holds
the one refusal in this library that fails **open**.

	chain/manifest  WARN  N of M pairs dropped, deficit table full at K
	chain/manifest  CRIT  no room to follow another issuer, and none evicts
	chain/manifest  WARN  a manifest smaller than one already seen

### The count existed nowhere at all

`FZN_MANIFEST_ERR_DEFICIT_FULL`'s own comment says what it means:

> A dropped pair does not make this host report a fault; it makes it report a
> SMALLER deficit than it has, which is to say it looks MORE complete than it
> is.

So this is not a refusal that costs a caller an operation. It is a host quietly
understating what it is missing -- and `dropped` in `fzn_manifest_admit` was an
**`int` used as a boolean**. One pair short of complete and forty produced the
same return value, the same overflow flag, and no number anywhere. It counts
now, and the line carries all three figures: how many went, out of how many the
manifest named, against the table's capacity.

**The overflow flag is not a substitute, for the reason `log/log.h` gave about
`dropped`.** It is durable, a consumer can read it, and it is one bit: it says
the deficit is understated and never which authority is missing from it. A
consumer that fetches to close a deficit cannot fetch what it was never told
about. That is the same sentence sec 217 wrote about a different count, which
is why the two modules were the hardest ones in the pass to see.

### Severities taken from the module's own citations

**FULL is at CRIT because this module cites `record/journal.h` for its
behaviour** -- "Refused rather than evicted, for the reason `record/journal.h`
refuses a full journal: dropping an issuer forgets its deficit, and a forgotten
deficit is a host that looks complete" -- and that module takes CRIT for the
same structure. The severity follows the citation rather than the shape, which
is the same method sec 218 used to reach the OPPOSITE answer for the ledger: a
full ledger can only fail to notice a delivery, so it is ERR, while a full
issuer table means every revocation those issuers publish is invisible for
ever.

**The replay gets a WARN and the refusal stays silent.** The high-water mark
refuses a smaller manifest without complaint, and refusing silently is right --
but a replay aimed at clearing an overflow flag is somebody trying to make this
host look complete, and the header already says a carrier needs no key to
arrange it.

**And SHAPE and UNKNOWN_ISSUER are declined, on the header's own warning.** It
says a receiver that logged malformed bytes "as its own defect would be looking
in the wrong place": ordinary hostile input, arriving at whatever rate a
stranger chooses. A line per rejected datagram is a log a viewer cannot use
and, above informational, a lie about whose fault it is. Both declines are
asserted by the test and defended by a sabotage that puts a line back.

### The pass, closed

Seventeen modules carry a log, which is every one with a caller-owned context:

	link/snapshot  chain/store  chain/revocation  chain/manifest
	record/journal  record/store  record/ledger  state/cell
	catalog/edge  chunk/reasm  spool/store  frame/replay
	claim/hold  log/stream  persist/file  trust/anchor  prekey/pin

Declined, each for a reason rather than for quiet: `ratchet` and `blob`, whose
types are values copied by assignment with nowhere to put a borrowed pointer
(sec 216); and every module that takes its state as parameters rather than
holding it, where a log would be signature churn on a hot path for one event.

**What made the pass hard was never deciding what to say.** It was finding the
modules -- sec 217's sweep was keyed on refusals and could not see a module
that announces itself by succeeding -- and, twice, discovering that the return
value a module already had was coarser than its own comments knew: the ledger's
readers with no error channel, and this one's boolean where a count belonged.
Both were written down years' worth of comments ago and nobody had read them as
a gap.

## 224. The deficit on a screen, and the ambiguity that put it there

The pairs stopped at fourteen printers and fifteen widgets. Enumerating what
the library can say against what a consumer can show leaves one fact that
matters more than any of them and had no surface at all: **how much of the
revocation picture this host is missing, and whether that number can be
believed.**

	cli/manifest_print   NONE  UNFOLLOWED  COMPLETE  PENDING  UNDERSTATED

sec 223 wired the log for it. A log is for whoever is looking at a log; this is
for the person asking whether their host is safe to trust, and `manifest.h`
already says they cannot tell from the number alone -- a dropped pair "makes it
report a SMALLER deficit than it has, which is to say it looks MORE complete
than it is".

### The library could not tell two opposite states apart

Writing the printer found a real ambiguity rather than a missing convenience.

	fzn_manifest_pending     0 for an issuer that is not followed, and says
	                         so: "the absence of a question", not an answer
	fzn_manifest_overflowed  1 for a dropped pair AND for an issuer nobody
	                         named -- "the same fact in different clothes"

Each is right for the caller it was written for. Together they mean the pair
**(0, 1) has two readings**:

- this host does not follow that key, and tracks nothing from it;
- it does follow it, its count is a floor, and the pairs it did record have
  since been satisfied.

The second is reachable -- `fzn_manifest_satisfy` drains the deficit table
while the flag clears only on an admission that drops nothing -- and the test
asserts the fixture reproduces the (0, 1) pair before asserting anything about
the line, so the case cannot quietly stop being the case it claims to be.

**To a caller deciding whether to refuse, the conflation is correct**: both are
"cannot say" and `overflowed`'s comment argues for exactly that. **To a person
reading a screen they are opposite sentences.** So `fzn_manifest_follows` was
added, and it answers the OPPOSITE conservative direction from `overflowed` on
purpose: an unreadable state is "not following" here and "cannot say" there,
because claiming to follow a key whose entry cannot be read hides the same gap
from the other side. Both refuse to flatter the host.

This is the fourth time a printer has found a library gap rather than a
formatting question -- after `fzn_chain_expired_at`, the two soundness
predicates and `fzn_vocabulary_names`. **A display asks a question no decision
ever asks: not "may I proceed" but "what is true", and the second is
strictly harder.**

### One state, two wordings, and the zero that must not read as good news

`FZN_MANIFEST_LINE_UNDERSTATED` covers a floor of three and a floor of zero.
They read differently to a person -- "AT LEAST 3 revocations outstanding"
against "none this host can name is outstanding, and it knows there are more it
cannot" -- and they are the same thing to a caller, which is that the number
cannot be trusted downwards. So the line differs and the state does not, on sec
201's rule.

The zero case is worded separately rather than falling into the counted one
because "AT LEAST 0" is not a sentence, and the wrong repair would have been to
let it print "up to date". Three of the five lines exist to stop a zero reading
as good news: NONE says *cannot say*, UNFOLLOWED says *nothing is tracked*, and
this one says *more than none*. **The whole file is one distinction spelled
three ways, which is what it takes when the underlying accessor answers zero
for four different reasons.**

## 225. The manifest line nothing reads back

sec 221 widened the sabotage census to the bindings and the backends and left
the front ends outside it. Closing that turned up why they were outside: **the
list they would have been read from was wrong.**

	before   subsystem cli/cli.c FZN_CLI_ON
	         subsystem gui/ FZN_GUI_ON against Qt6Widgets
	after    one line per source, 16 of cli and 15 of gui

`CLI_SRCS` holds sixteen files. The manifest named one, as a hand-written
literal, and had done since the CLI was one file -- so **a consumer following
`make manifest` to build the CLI subsystem got the argument parser and none of
the fifteen printers.** The GUI line was a bare directory where every other
line in the target names a file.

### Why it survived: it is the only output here nothing reads back

`installcheck` compiles a consumer from the `source` lines and refuses if a
core object so much as defines a primitive's name. `sabotage --verify` reads
`source`, and now `binding` and `backend`. **Nothing anywhere consumes
`subsystem`.** It is generated output that no gate re-derives, which is the
condition `evidence.md` names for a number nobody re-checks -- and unlike a
document, a generated list is read by tools that were told what to expect by
the thing that wrote it.

So the fix is two changes that only work together. The manifest names each
source, and the census reads `subsystem` lines. Widening the census to the old
lines would have been widening it to a wrong list, which is worse than not
widening it: a coverage check over `cli/cli.c` alone would have reported the
front ends swept.

### What the widened census found, which is what the hand count found

	population   57 -> 88     covered 87, one deliberately guard-free
	named        gui/qr_view.cpp, gui/trust_view.cpp

Those are the FIRST pair, written before this table covered widgets at all,
and the only two of fifteen with no entry -- measured by hand before the
census was widened, then named independently by the census afterwards. **Two
counts by different methods agreeing is worth more here than either alone**,
and it is the check `evidence.md` asks for before a scope number is used: not
the same query twice, a different one that would fail differently.

Both have an entry now, and neither is decoration. The QR widget's refusal
uses `fzn_qr_err_str`'s words so a dialog and a log spell one fault one way;
the trust widget shows `(none)` rather than an empty field, because a blank
where a fingerprint belongs reads as a fingerprint OF SOMETHING and somebody
comparing it out of band would conclude the peer is wrong.

## 226. The aggregate a single line cannot make

`gui/manifest_view` completes sec 224's pair. Each row is
`cli/manifest_print`'s line for one issuer, verbatim; what the widget adds is
that there are several of them and **which is worst**.

	nothing is being tracked
	all 3 issuers are up to date
	2 of 5 issuers have revocations outstanding
	1 of 5 issuers report less than they are missing

### The worst row decides, not the majority

This is the whole of the widget's judgement and it is the one thing a consumer
would plausibly get wrong writing the loop itself. `manifest.h` calls a dropped
pair the one refusal in the library that fails OPEN, so **four sound issuers
and one understated is not "mostly fine"**: the understated row is the only one
that can be hiding an authority this host still honours. A summary counting
good rows would be right four times out of five and wrong about the row that
matters.

Its sabotage is a majority rule -- `understated > asked / 2` -- which is
exactly the reasonable-looking thing somebody writes when the aggregate is a
proportion rather than a floor.

### The summary describes what was asked, the rows what fitted

Past `FZN_MANIFEST_VIEW_ROWS_MAX` the list stops drawing and says so, on
`gui/link_view`'s rule that a list which silently stops is one somebody reads
as complete. But the WALK does not stop: an understated issuer past the row
limit still reaches the summary and still reaches `understated()`.

The test puts the understated issuer at the very end of thirty-four and
requires both, and the sabotage for it is one word -- `continue` to `break` --
which is the natural way to write the truncation and quietly makes the summary
describe only what fitted.

### The render sweep caught it, and it is the only thing that could

`qttycheck` refused the first version:

	undefined reference to `fzn_manifest_print'

The widget was added to the qtty render target's SOURCE list and the printer's
object was not added to its LINK line. Nothing else in the tree links every
widget together -- `make test` builds each view's own test binary with its own
short object list -- so no other gate can see a widget that compiles, tests
and does not link beside its siblings.

**And it was going to be linked into the sweep without being rendered by it.**
The sweep's case table names each widget and the string a terminal must carry;
a widget absent from that table is built and never drawn. So the fixture is an
issuer whose count is a FLOOR rather than a sound one, and the sweep requires
`less than they are missing` to survive an 80x24 terminal -- which is sec 207's
hazard met head on, since that sweep exists because `capability_view`'s verdict
was falling off the right edge behind a 64-character identifier.

	manifest_view   needs 59 columns to say "less than they are missing"

Fifty-nine is the widest floor in the sweep -- the others run 20 to 46 -- which
is what a summary that names two numbers and a verdict costs. It fits an
eighty-column terminal with room, and the number is recorded here so the next
person widening that sentence knows what it was.

### No key is drawn, and no enumerator was added to draw one

A row is a label and a verdict. Thirty-two bytes of issuer spell to 64
characters, and a truncation of one is the prefix comparison `trust/trust.h`
refuses to invite; the label is the consumer's word for the key and is what a
person recognises.

**And the consumer supplies both, which is why no `fzn_manifest_issuers` was
added.** The temptation was there -- a widget listing issuers wants to
enumerate them -- and `manifest.h` already answers it: the recipient set "is
policy, and policy is not this library's". A consumer that called
`fzn_manifest_follow` necessarily holds the keys it passed, so an enumerator
would be this library keeping a second copy of a list its caller owns. That is
the opposite conclusion from sec 224, where `fzn_manifest_follows` WAS added --
and the difference is not taste: `follows` answers a question about state the
caller cannot see, while an enumerator would return the caller its own input.

## 227. Two zeroes that meant opposite things

`cli/ledger_print` is `cli/manifest_print`'s mirror: that one says what THIS
host is missing, this one says what somebody ELSE has confirmed receiving.
Building it found the same shape one module over, and worse.

	NONE  UNREADABLE  UNKNOWN  BEHIND  CURRENT

`fzn_ledger_confirmed` returns a version and answers **0** for a peer that has
never acknowledged a subject and for a table nobody can walk.
`fzn_ledger_count` answers 0 for both. `fzn_ledger_behind` answers "behind"
for both. Every one of those is right for the caller it was written for -- the
header argues it, and the direction chosen costs a retransmission rather than
a delivery -- and between them a person cannot tell:

- one peer is out of date, on a ledger that works;
- the ledger cannot be read, so EVERY peer answers that way and nothing on the
  screen is evidence.

**`chain/manifest.h` at least had `fzn_manifest_overflowed` to say "cannot
say". This module had nothing at all**, which is why `fzn_ledger_sound` was
added and is asked first. It is the fourth of its family, after
`fzn_revocation_store_sound`, `fzn_chain_store_sound` and `fzn_state_sound`,
and it answers the same way they do: a NULL ledger is SOUND, because no ledger
means no confirmations recorded, which is an answer.

### The predicate had to be split from the line that reports it

`corrupt()` carries sec 218's ERR -- the one that exists because
`fzn_ledger_confirmed` and `fzn_ledger_count` have no error channel. A
soundness predicate IS an error channel: it returns the answer. So a
`fzn_ledger_sound` implemented as `!corrupt(ledger)` would contradict the
argument the line rests on, and **a consumer refreshing a screen would emit the
same ERR every frame.**

So the file has `unscannable()`, which is the question and says nothing, and
`corrupt()`, which is `unscannable()` plus the line. One implementation, two
behaviours around it -- sec 200's rule, met in a new place: two callers asking
one library is not duplication, and here the two callers want different
consequences from one answer.

Its sabotage restores the one-line version, and the suite catches it: **asking
whether a ledger can be read must not log that it cannot.**

### A test that clobbered the evidence it was asserting on

Worth recording because the first version passed nothing and looked like a
module fault. The silence check was written into the middle of the block that
asserts on the captured line:

	FAIL ledger_print_test.c:507: the line does not say what follows

`memset(&diag_seen, 0, ...)` before calling `fzn_ledger_sound` wiped the very
line the following assertions read. **An assertion that resets shared capture
state has to come last in its block**, and the test now says so where the next
person will meet it rather than only here.

### And a citation to a function that does not exist

The header first argued its required out-parameter "on `fzn_ledger_deficit`'s
argument for its own". There is no `fzn_ledger_deficit`; the function meant is
`fzn_manifest_deficit`, which in turn credits `record/sync.h`'s
`fzn_sync_digest`, and that is what the header cites now.

Nothing would have caught it. `make style` holds every PATH in this document
against the tree and no gate reads a function name out of a comment -- which
is the shape `evidence.md` calls an invented identifier: well-formed, plausible
and matching nothing that has ever existed. Caught here only because the
sentence was checked against the tree before it was believed.

## 228. One unreadable table voids a screen of green rows

`gui/ledger_view` completes sec 227's pair, and it is `gui/manifest_view`
pointed the other way: that one is what this host is missing, this one is what
everybody else has received. One subject, many peers, which is the shape the
question has -- a consumer asking "has this gone out" holds one document and a
list of hosts.

	nothing is being tracked
	all 4 peers have confirmed this version
	3 of 4 peers have not confirmed this version
	this ledger cannot be read, so nothing here is evidence

### The aggregate rule is different from sec 226's, and it has to be

`manifest_view` reports the worst row because one understated issuer can hide
an authority. This one reports UNREADABLE because **an unscannable ledger makes
every row a fiction, not a bad one.** Each accessor answers such a table in the
voice of a readable one -- a version of zero, a count of zero, "behind" -- so a
screen of peers all reading CURRENT can be drawn from a table nobody can walk.

That is not a majority to be outvoted. It is the whole display being void, and
the test gives the widget three peers who would all be CURRENT on a sound
ledger and requires the summary to say the opposite.

**And `outstanding()` stays zero there, which is a refusal rather than a
claim.** Nobody measured how many peers are behind, so no number is offered;
`shown_state` is what says whether a number means anything.

### Two sabotages that SURVIVED, and the third way to aim one wrong

The first version counted UNREADABLE rows and compared the count, and two
entries were written against it. Both survived:

	ledger-view-unreadable-voids-the-screen           SURVIVED
	ledger-view-reports-no-number-it-did-not-measure  SURVIVED

Neither was stale and both applied. **They varied a distinction the code cannot
express.** Unreadability belongs to the TABLE, not to a peer -- every row is
unreadable or none is -- so `unreadable` is only ever `0` or `asked`. A
majority rule fires on exactly the same inputs as `if (unreadable)`, and the
`outstanding` count in that branch is already zero, so assigning it changes
nothing.

sec 218 recorded a sabotage that changed too LITTLE and sec 222 two that
changed too MUCH. This is the third way: **a substitution that changes the
code and cannot change the behaviour, because the condition it varies has only
one reachable shape.** All three come back looking like a working guard, and
only the survivors announce themselves -- which is the one mercy here, since
these two did.

The fix is not a better sabotage. The code was wrong in the same way the
sabotage was: it asked a whole-table question once per row. `fzn_ledger_sound`
is asked once now, before any row, and no rows are drawn at all -- a list of
identical "cannot say" lines is a screen pretending to have per-peer answers.
The single entry that replaces the two removes that check, and the summary then
reports delivery over a table nobody can walk.

### Collapsed in the summary, kept apart in the rows

A peer that acknowledged version three and one that has never spoken are
counted together -- **the action is identical, send it** -- so an aggregate
that split them would offer a distinction nobody acts on. The row still says
which, because they are different things to look into, and the test asserts
both halves: one summary number, two different sentences beneath it.

That is sec 194's boundary used as a design rule rather than a caution: the
widget adds what its medium affords, and what the row already says it does not
repeat in the summary.

### The render sweep, added at the same time this once

sec 226 linked a widget into the qtty sweep without drawing it, and the case
table is what decides which. This one is in the table from the start, in the
state that voids the screen -- so the string a terminal has to carry is
`nothing here is evidence` rather than a row of green.

	manifest_view   needs 59 columns to say "less than they are missing"
	ledger_view     needs 33 columns to say "nothing here is evidence"

**Sixty-three was written here first, and this section falsified it two
commits later.** The restructure above -- asking the table once and drawing no
rows at all when it cannot be read -- made the widget narrower, because in that
state the summary is the only thing on it. A countable present-tense claim
about the tree's own shape, stale within an hour of being written, by the hand
that wrote it.

So the observation it was offered for does not survive either: fifty-nine is
the widest floor in the sweep, and it belongs to a line that reports a
QUANTITY. The honest version is the smaller one -- these two numbers are what
the sweep measured today, and both clear eighty columns.

## 229. The counter that could not be taken without spending it

`cli/replay_print` shows how full this host's replay window is and, when it is
full, which of two opposite fixes it needs. `frame/freshness.h` asked for the
line and could not have produced it.

	NONE  EMPTY  HOLDING  FULL_UNPRUNED  FULL_LIVE

### A full window is an emergency that does not look like one

The window REFUSES rather than evicting, and its header argues why: evicting
the oldest live entry "silently reopens replay", so an attacker able to
generate traffic could flush the window and replay anything recorded. The
consequence is that a full window is **a host refusing fresh frames**. It is
not corrupt, it is not crashing, and the only thing that says so is a return
value handed to a caller that may do nothing with it.

So both FULL lines open with `REFUSING FRESH FRAMES`. Its sabotage removes
those three words and leaves `full at 2`, which is true and does not say what
is happening.

### The distinction the header named and nothing could make

> a full window means either that nobody is expiring or that the capacity is
> below the arrival rate the horizon implies. **Those want different fixes and
> the value says neither.**

Nothing else could say either. `used` and `capacity` say the window is full;
the only thing that knew WHY was `fzn_replay_expire`, and **it had to consume
the answer in order to give it** -- a caller asking "how many are reclaimable"
by calling it has reclaimed them, and a report that changes what it describes
is worse than no report.

`fzn_replay_expirable` is the same walk with no write. A full window with
entries to reclaim is a consumer that has stopped calling expire, and the fix
is a caller; a full window of live entries is a capacity below what the
horizon implies, and the fix is the sizing formula. **Two states rather than
one with two wordings**, which is the opposite call from sec 224 and for a
stated reason: there a floor of three and a floor of zero want the same action,
here they want different ones.

The test holds `used`, `capacity` and every other accessor's answer fixed
across the pair and requires the states and the lines to differ -- and asserts
separately that rendering reclaimed nothing, because a printer that expired
what it counted would be the defect this function exists to avoid.

### A fourth way to aim a sabotage wrong: at something `const` already holds

The entry written for "expirable does not expire" mutated `due++` into
`window->used--`, and the harness reported **NOT-BUILT**:

	error: decrement of member `used` in read-only object

`fzn_replay_expirable` takes a `const fzn_replay_window_t *`. **No mutation of
that function can reclaim anything**, because the signature forbids it -- so
there is no sabotage to write, and the entry was removed rather than repaired.

That is the fourth aiming error in one day, and unlike the other three it is
not a mistake about the code:

	sec 218  changed too LITTLE          a string no assertion read
	sec 222  changed too MUCH            a statement into a braceless `if`
	sec 228  changed nothing REACHABLE   a condition with one shape
	sec 229  changed nothing LEGAL       a property the compiler enforces

**The harness caught this one for free**, because sec 45 had already made
NOT-BUILT its own verdict rather than letting a failed build read as CAUGHT --
"a build that fails exits non-zero exactly as a failing test does". A distinct
verdict for "the mutation did not compile" is what turned a category error
into a one-line report.

The test's assertion that rendering reclaimed nothing stays, and now says why:
it cannot fail while both signatures are const, and it is a tripwire for the
plausible edit that widens either. **A check the compiler holds today is worth
keeping for the day the compiler stops holding it**, provided it says so --
otherwise it reads as a check that passes, which is what a check that cannot
fail looks like from outside.

### And no widget, which is the first printer here to get none

sec 226 and sec 228 earned their widgets on an AGGREGATE: several issuers,
several peers, and a summary no single call to the printer can make. **A host
has one replay window.** There is no list, so a widget would be a `QLabel`
holding this file's line, which is what a consumer gets by calling the printer
and putting the string in one.

sec 201 settled the general question when `gui/trust_view` was found taking a
dependency that could not fail: a surface added so that every printer has one
is symmetry rather than merit. The pairing rule in sec 193 says the narrower
thing -- that a printer written for a fact a widget ALREADY SHOWS must change
that widget in the same commit -- and nothing shows this.

Recorded rather than left as an absence -- and stated as a RULE rather than a
count, which took three attempts:

> **A widget exists where a screen adds an aggregate the printer cannot
> make.** A printer for a single object gets none, because the widget would be
> a `QLabel` holding its line.

sec 226 and sec 228 pass that test -- several issuers, several peers, a
summary no single call can produce. This one does not, and neither does sec
230: a host has one replay window and one reassembly table.

**The count in this paragraph has now been wrong twice.** It said "sixteen
against seventeen", carried from memory when `ls cli/*_print.h | wc -l`
answers it; corrected to seventeen against seventeen, which the very next
printer falsified. A total is the wrong thing to write down here: it changes
whenever either side does and it says nothing a reader needs, since **neither
list is a subset of the other and the interesting facts are the exceptions.**
`gui/config_view` is the other one, and it EDITS an `fzn_cli_t` through
`fzn_cli_arg` rather than displaying a fact -- so its CLI counterpart is the
command line itself, and a printer for it would be the second opinion about a
legal service number that widget's header exists to refuse.

`gui/config_view` is the other one: it EDITS an `fzn_cli_t` through
`fzn_cli_arg` rather than displaying a fact, so its CLI counterpart is the
command line itself. A printer for it would be a second opinion about what a
legal service number is -- which is the duplication that widget's header was
written to refuse.

### An anchor that stopped naming one site, with nobody touching it

	sabotage: freshness-sweep-entries matches 2 sites in frame/freshness.c

`fzn_replay_expirable` opens with the same two lines as `fzn_replay_expire` --
the null check and the disagreeing-fields refusal, deliberately, because
drawing a different boundary from the operation it describes would be worse.
So an entry written months ago, untouched, stopped naming one site.

`evidence.md` states it and this is the first instance of it here:
**uniqueness is a property of the file at the moment of the edit, not of the
string.** Nothing but the census could have caught it -- the suite passes
either way, and a sabotage matching two sites tests neither reliably. The entry
is re-pointed with enough context to name the compaction, and it now carries
why it moved.

## 230. Three fixes behind one FULL, and an ordering the header did not state

`cli/reasm_print` says how full the reassembly table is and, when it is full,
which of THREE actions will help. `chunk/reassembly.h` names the problem on
the error code itself, and names it as a misreading somebody has already had:

> IT NO LONGER MEANS "live, unexpired" ... A slot may be HANDED -- completed
> and waiting on the caller to release it, which the sweep must not take ...
> Both are live and neither is reclaimable by waiting, so a consumer reading
> the old wording would conclude that **TIME ALONE FIXES A FULL TABLE.
> Releasing what it holds is the other half.**

	slots past their deadline       call `fzn_reasm_expire`
	slots handed and not released   the CONSUMER is leaking them
	slots live, held and unexpired  the bounds are too small

**The middle one never self-corrects**, and the module chose exhaustion as its
honest symptom: "A caller that never releases now exhausts the table and sees
FULL. That is the honest failure and it is the smaller harm." A line that
cannot tell it from a sizing problem sends somebody to enlarge a table that
will fill again, which is the one outcome that makes the leak harder to find.

So the most actionable wins: handed before unswept, unswept before live. A
leak is a bug, a missed sweep is one call, and a size is a restart.

### No accessor was needed this time, and that is worth saying

sec 224, sec 227 and sec 229 each closed a library gap, and the habit that
forms from three in a row is to look for a fourth. `fzn_partial_t` is a public
type with `live`, `handed` and `expires_at` on it, so a consumer COULD write
this walk. What it would get wrong is the CLASSIFICATION -- which is precisely
what the header says a consumer gets wrong -- so the printer does it once, in
the module's own terms, and adds nothing to the library.

**A printer earns its place by knowing something, not by needing something.**

### And no widget, on sec 229's rule

One host, one reassembly table, so a screen has no aggregate to add and the
widget would be a `QLabel` holding this file's line. The same call sec 229
made and for the same reason, stated there as the rule this follows rather
than re-argued here.

### sec 218's error again, made after sec 218 was written

`reasm-print-handed-is-not-sweepable` SURVIVED. The sabotage removes the
`continue` after a handed slot is counted, so a handed slot past its deadline
is also counted as sweepable -- a count that offers back a slot
`fzn_reasm_expire` will never take.

The case written for it used a FULL table and asserted the STATE. A
miscounted `sweepable` leaves the state at FULL_HANDED either way, so nothing
it checked could move. **The sabotage changes a COUNT and the assertion read a
STATE**, which is sec 218's finding exactly -- a substitution aimed at a claim
the test does not make -- committed here after that section was written and
after two more instances had been recorded in sec 222 and sec 228.

Worth keeping as a recurrence rather than a new class. Three ways to aim one
wrong are a taxonomy; the same one twice in a day is a working habit that has
not changed, and the fix is procedural: **name the assertion that should fail
before running the sabotage**, and if it is not there, write it first.

The case now uses a table with ROOM, because only the HOLDING line prints the
sweepable count -- and carries a control beside it, the same slot unhanded,
without which the new assertion would pass for a census that counts nothing.

### The ordering the header did not state

The test's fixture called `fzn_reasm_init` and then `fzn_reasm_slot_init`, and
every case failed with `the fixture does not build`.

`fzn_reasm_init` walks the array and refuses a slot with no buffer, so slots
must be initialised FIRST. The header said only that `slot_init` is "separate
from the above because the buffers are usually one block the caller carves
up" -- which reads as though either order works, and the code has always
enforced one.

**A precondition that is true and unwritten is indistinguishable from one
nobody thought of**, which `evidence.md` states and this is an instance of: the
rule was real, the enforcement was real, and the only thing missing was the
sentence. It says it now, and says how it was found -- by a caller doing it
the other way and getting FZN_REASM_ERR_MALFORMED from a table whose arguments
were all fine.

## 231. The third list with a population narrower than its subject

sec 221 found the sabotage census reading only `source ` lines while the tree
had bindings and backends too. sec 225 found `make manifest` naming one CLI
source where there are eighteen. Both were the same shape, so it is a lens
rather than two incidents: **a completeness check whose population is narrower
than the thing it describes.** Pointed at the remaining gates deliberately, it
found a third.

	over CORE_SRCS   39 error renderers, all walked (40 rows)
	over SRCS        40 error renderers, all walked (40 rows)

`fzn_cli_err_str` is a real renderer with real arms, and `cli/cli.c` is a
SUBSYSTEM rather than a core source -- so it sat outside the set this gate
walks while having a row in `err_str_test`. **Deleting that row, or adding an
arm to that renderer with no row for it, was invisible here**, because "all
walked" stayed true over a set the renderer was never in. The gate exists to
stop an arm rendering text no test has ever read, and it could not see the one
renderer a consumer meets first.

### Three of the five gates could not have this, and the reason is structural

The sweep was not a guess. `status_gate.py` and `enum_gate.py` derive their
population from `.gitmodules` -- everything in the tree except vendored trees
-- and `log_gate.py` walks the tree with a named skip list. **None of them can
be narrower than the tree, because none of them enumerates.**

The two that had the defect both read a list somebody wrote: `make manifest`'s
output keyed on a WORD, and this one keyed on a VARIABLE. So the rule that
comes out is not about care:

> **Derive the population from the filesystem or the build, and the check
> cannot be narrower than its subject. Enumerate it, and it is narrower the
> moment anything is added anywhere the enumeration did not anticipate.**

### And the guard it needed already existed, which I got wrong first

The probe runs `nm ... 2>/dev/null`, so an unbuilt object is skipped in
silence. That was measured on 2026-09-04 -- adding `disclose/` and running
`make style` before anything compiled reported "27 error renderers, all
walked", **a true statement about the objects that happened to be present** --
and a loop refusing a missing object was added then.

**I added a second one, because I read that guard's comment as a description
of the present.** It opens `EVERY OBJECT MUST BE THERE, WHICH THIS DID NOT
CHECK` and narrates the defect in the past tense before fixing it, which is
how a reader skimming for whether a check exists concludes that it does not.
It exists. It was pointed at `CORE_SRCS`, the same narrower list this section
is about.

So the right change was one line, not a new loop: **widen the guard with the
sweep it guards.** Two checks doing one job with different populations is
worse than one, because the narrower fires first with its own wording and the
next reader has to work out which is authoritative.

The finding is worth more than the fix. **A comment written as the narrative
of its own repair reads as a statement of the defect**, and the reader most
likely to misread it is the one checking whether the repair happened. The
first sentence describes code that no longer exists; nothing marks where the
past tense stops.

Shown failing by moving `cli/cli.o` aside before the duplicate was removed,
and again on a clean tree afterwards with only the widened guard in place:

	style: ./constant_time/constant_time.o is missing, so the renderer sweep
	style: below would skip it silently and report a pass over less than
	style: what the build made. Build the objects first.

sec 52's rule, and it is what surfaced the duplication: the message that came
back was not the one I had written.

### And that guard has been breaking `make check` from a clone since it landed

Running it on a fresh checkout to prove the refusal, rather than trusting the
one in this tree, showed something older:

	$ git clone . freshclone && cd freshclone && make check
	style: ./constant_time/constant_time.o is missing ...
	make: *** [style] Error 1

`check: style test ...` runs style FIRST, the renderer sweep needs the
objects, and the guard refuses -- so **the documented entry point has stopped
before compiling anything since 2026-09-04**, the day the guard was added.
Checked against the pre-sec-231 Makefile on the same clone: identical failure,
same file. Widening the guard did not cause it and the fix is not to narrow
it.

`style: $(OBJS)` -- **the check builds what it inspects.** It costs nothing on
a warm tree and nothing at all inside `check`, since `test` builds the same
objects a moment later; what it removes is a first impression that reads as a
broken makefile. The clone runs through style and into the suites now.

**Nothing in this tree could have found that.** Every gate here runs against a
tree somebody has already built, which is the one state where the defect is
invisible -- and it survived five days of `make check` passing, because
passing is what it does on the second run.

**And CI could not have found it either, because CI never runs `make check`.**
It runs the stages, in a fixed order with job-specific arguments -- `make test
MONOCYPHER_DIR=` then `make style MONOCYPHER_DIR=`, and `make SANITIZE=1
BUILD_DIR=san test` rather than `sancheck`. Every stage passes from a clean
checkout because the FIRST of them builds. The composed target the README puts
front and centre is run by nobody but a developer, on a tree that is already
warm.

### The obvious signal, measured and dropped

That looked like a workspace-wide gap worth sending to `claude-guidelines`, so
it was counted before it was written. Of the ten private trees with both a
`check` target and a workflow, **eight run `make check` in CI** -- situ,
fuzzypickles, beerssh, bbq-predictor, netcfgd, fmake, apt-emerge, openmlx4 --
and two do not: hydra and this one.

So it is not a pattern, it is fuzznet's own arrangement, and the arrangement
has a reason: the two jobs exist to build with and without the crypto binding,
which needs per-job arguments that `check` does not take. What follows is a
LIMIT rather than a defect -- `make check` is a developer convenience nothing
automated exercises -- and the honest response is to write that down rather
than to add a second full run to CI for a failure mode that has occurred once
in five days.

Counting first is what stopped a signal going out about eight trees that
already do the thing.

## 232. A parser nothing fuzzed, and eight bytes it never read

sec 231's lens -- a completeness check whose population is narrower than its
subject -- was pointed at one more hand-kept list: `FUZZ_BINS`. Every module in
this tree with a byte parser has a harness. One did not.

	parsers with a *_open over bytes   chain manifest revocation persist
	                                   prekey provision record
	harnesses named after one          all of those except persist

`persist/persist.c` decodes four blobs from a file, and `persist/persist_file.c`
goes to some length over that file: mode 0600 at creation so a prekey secret is
never briefly world-readable, an atomic rename so a torn trust anchor cannot be
read as a whole one. **A format defended that carefully is one somebody can
reach**, and its four decoders had hand-written negative cases and nothing else.

### The property is sharper than an invariant, because the thing is a pair

The other harnesses assert that nothing is written out of bounds, or keep a
shadow model of a table. A pure serialisation pair admits a better question:

> **No single-byte mutation may be accepted and still re-pack to the original
> bytes.**

A mutation that survives both is a byte the format WRITES AND DOES NOT READ.
`head_check` refuses a trailing byte for exactly that reason, in its own
words -- *"a trailing byte is a second encoding of one blob ... 'ignore what
you do not understand' is how one format becomes several"* -- and a dropped
field is the same fault one position further in, where no length check can see
it.

### It found one immediately

`fzn_trust_pin` and `fzn_trust_self` take no timestamp, and `anchor()` in
`trust/trust.c` stores `adopted_at` only for an ADOPTED source. So `pack`
writes eight zero bytes for a pin and for a self-root, and `open` passed them
to nobody:

	persist_fuzz: kind 0 byte 39 can be changed and the blob still
	persist_fuzz: opens to the same value and re-packs to the original
	persist_fuzz: bytes -- a byte this format writes and does not read

Byte 39 is inside the timestamp -- body starts at 2, the key is 32, the source
is 1. **Eight bytes of every stored pin and every stored self-root could hold
anything at all**, in the trust blob and again inside every peer blob, which
embeds one.

Harmless in effect: the value is meaningless for a pin. Not harmless as a
format, by this module's own standard, and not harmless as storage -- it is
eight attacker-writable bytes in a file whose integrity nothing else checks,
in a state directory holding a trust anchor. `open` refuses a non-zero
timestamp on a non-adopted source now, which is one condition and makes the
encoding canonical.

**Shown by reverting the fix and watching the harness name the byte**, then
restored and watched pass. sec 52's rule, and the reason the harness exists at
all rather than the test suite gaining another case: a hand-written case tests
the byte its author thought of.

### The known-answer test had frozen a state no API can produce

The refusal broke `persist_kat_test`, and what it broke is the finding's other
half.

	FAIL persist_kat_test.c:173: the literal peer blob opens

That case built its fixture by writing struct fields directly -- `memset`,
then `peer.trust.adopted_at = ADOPTED_AT` beside
`peer.trust.source = FZN_TRUST_PINNED` -- which is a `fzn_trust_t` **no API in
this library can produce**, since `anchor()` stores a timestamp only for an
ADOPTED source. `pack` faithfully wrote the field, and the bytes were frozen as
the format's known answer.

So the KAT was pinning a byte-string this library cannot write, and had been
since it was written. **A known-answer test is only as good as the provenance
of its answer**, and a fixture assembled field by field has no provenance at
all -- it is the writer's idea of a value rather than a value. `evidence.md`
makes the point about vectors generated by running the code under test; this is
the same fault a step earlier, where the input never came from the code either.

Corrected to an ADOPTED source, which keeps what the case was actually for --
`prekey` begins at 43 and `created_at` at 75, and exchanging them preserves the
length, so a NON-ZERO timestamp is what makes the offsets distinguishable. A
zero there could not tell a field read from its own offset apart from one
dropped entirely.

### And the second property, which is the cheap half

Every prefix shorter than the whole must be refused, since `head_check` is
exact rather than "at least". 2000 truncations refused in 2000 cases -- a
decoder reading one byte past a short buffer would be found here rather than
by a consumer whose file was cut short by a full disk.

**`fzn_persist_secret_open` is deliberately not covered**, and saying so
matters more than covering it: it takes an `fzn_agree_ops_t` to re-derive a
public key, `persist_test.c` has a binding to hand and exercises it, and a
harness that quietly covered three of four would report a pass over a subset --
which is the shape sec 221, sec 225 and sec 231 each found in a different list.

## 233. The one field outside the tag, fuzzed at last

sec 232 closed the last module with an `_open` and no harness. Re-deriving the
population with a WIDER pattern -- every function taking
`(const uint8_t *, size_t)` rather than only those named `_open` -- found two
more, and one of them matters more than anything else on the list.

	fzn_relay_budget   wire/relay.c   harness: NO

**`wire/relay.h` says what this field is, and it is the worst case in the
protocol:**

> IT IS OUTSIDE THE AUTHENTICATED REGION, NECESSARILY. The tag covers `head`
> and the sealed region; `hop` is before both ... So the budget is **mutable
> in flight by anyone** ... A stranger can write 255 into the budget of a
> frame it did not create. Trusting that number turns one datagram into as
> many forwards as the network has paths, which is **an amplifier built out of
> a helpful default.**

Every byte this module reads is a byte anybody on the path may choose, and no
harness in the tree reached it. `frame/test/receive_fuzz.c` does not mention
relay; nothing did.

**THE PROPERTIES WERE NOT UNGUARDED**, which the sabotage run showed and this
paragraph then got wrong twice. Both entries came back naming
`relay_test.c:80` and `log_test.c:800` -- assertions that predate this
session -- so what these harnesses add is not first coverage but INPUT
coverage: the clamp was asserted on a frame somebody wrote, and is now
asserted on ten thousand nobody did.

**But "caught by the unit test, not the harness" is also wrong, and that was
the second version of this sentence.** `make test` RUNS the harnesses -- 42
fuzz lines in a run, 20000 cases each -- so they are inside the sabotage loop,
and `sabotage.py` prints ONE failure line. `relay_test` is line 179 of the run
and `relay_fuzz` is line 207, so the unit test simply fails first. The
harnesses catch these mutations too, which their own controls showed directly:
the clamp removed gives `budget answered 247 with a ceiling of 237`.

Three passes on one paragraph -- flattering, over-corrected, measured -- and
the thing that settled it was reading the run rather than reasoning about it.
**A single failure line names the first check to fail and says nothing about
the second**, which is the same shape as a status word standing in for a
result.

### The narrow query is what hid it

sec 232's search was `_open(const uint8_t` -- the naming convention six
parsers happen to share. `fzn_relay_budget` parses bytes and is not called
`_open`, so a population derived from the NAME missed the module whose input is
the least trustworthy in the library.

That is sec 231's rule turned on the query rather than the list: **a population
derived from a naming convention is an enumeration wearing a derivation's
clothes.** Running it a second way, with a pattern that would fail differently,
is what `evidence.md` asks for before a scope number is used, and it is the
third time today that the second query disagreed with the first.

### It contradicted the header on its first run

	relay_fuzz: an empty policy answered -4/0 where the plain call answered 0/0

`relay.h` says an empty policy table "means every frame takes `fallback`, which
is **exactly** `fzn_relay_budget`". With a fallback of zero it does not: the
policy form answers `FZN_RELAY_ERR_REFUSED` where the plain form answers OK
with a budget of zero.

**The code is right and the sentence was unqualified.** `FZN_RELAY_ERR_REFUSED`
exists for precisely this, and its own comment argues it: a zero ceiling is a
policy decision "somebody made and may want to see counted, logged or
reconsidered", and collapsing it into EXHAUSTED "would make a misconfigured
policy indistinguishable from normal traffic reaching the end of its budget".
So the harness's property was wrong, the header gained the clause it was
missing, and the case now asserts BOTH halves -- equivalence above zero, and
REFUSED at zero.

### What it asserts, and it is the header's own sentences

	the clamp                    never larger than `allowed`, for any bytes
	clamp THEN decrement         a spend must lower what the next reader sees
	a refusal leaves the frame   memcmp over the whole buffer, not the field
	an empty policy is the plain call, above zero
	a spend does not rewrite the hint

**Nothing in it knows an offset.** Frames are built through the generated
accessors and read back through the public API, so it asserts the contract
rather than the encoding -- and `relay.h` records what raw-offset knowledge in
a consumer cost when a caller had to write `frame[1]` by hand.

Shown failing by removing the clamp:

	relay_fuzz: budget answered 247 with a ceiling of 237 -- the clamp is
	relay_fuzz: the whole of what this module does

### The second one it found, which I dismissed before checking

The same widened query returned `fzn_log_body_text`, and I said in passing
that it "reads a body out of a record this host already holds, not bytes off
the wire". **That was wrong, and saying it before reading the header is the
error rather than the conclusion.** `log.h`:

> NEWLINES ARE ESCAPED, AND THAT IS THE POINT RATHER THAN TIDINESS. A viewer
> showing one entry per line, handed a body containing a newline and a
> plausible sequence number, would display a **SECOND ENTRY THAT NO ISSUER
> EVER SIGNED**. Escaping is what stops a body forging a neighbour. Every byte
> outside printable ASCII goes to `\xNN`, so the same argument covers a
> terminal escape sequence.

A body is opaque bytes an ISSUER chose. The record is signed, which
authenticates the author and says nothing about the content -- so this
function stands between an attacker's bytes and a terminal, and it is the
only thing standing there. `cli/log_print` and `gui/log_view` both render
through it.

	log_fuzz: 2000 cases, 2000 rendered (1295 escaped, 705 unchanged),
	          157 carried a newline

**The identity case is the control and the harness is worthless without it.**
A renderer that escaped everything, or emitted nothing at all, satisfies "the
output is printable" perfectly -- so a body already printable and free of
backslashes must come back byte-identical, or the property is being met by
destroying the input. Shown failing by widening the printable range to admit
a newline:

	log_fuzz: byte 13 of the rendered line is 0x18, which is not printable
	log_fuzz: ASCII -- a body reached a terminal unescaped

### And the floors were cleared by luck until the fixture was biased

The first run reported 10 exhausted spends and 0 policy fallbacks against
floors of 40 and 40. Drawing `allowed` and `hops` uniformly from 0..255
reaches a zero about eight times in two thousand, and a table that always
named the frame's own subsystem never took the fallback arm at all.

Half the draws are now 0..3 and half the tables deliberately name a different
subsystem: 212 exhausted, 465 fallbacks, 446 inflated budgets clamped. **A
coverage floor that a uniform draw cannot reach is a floor that would have
been met by luck or not at all**, and either way it would have said nothing
about the boundary it was written for.

## 234. Asking a signed format the question mutation cannot

sec 232 found a byte a format wrote and nobody read, by mutating a blob and
requiring every accepted mutation to re-pack differently. That instrument does
not work on a SIGNED record, and `evidence.md` says why: a field inside a
signed range cannot be tested by mutating it on the wire, because the mutation
breaks the signature too and the rejection comes from the signature either way.

**The same question has another form, and `spool/test/message_fuzz.c` had it
all along**, better stated than sec 232 put it:

> Anything the decoder ACCEPTS, re-encoded from what it handed back, must
> reproduce the input byte for byte. That is the strongest property this
> format has ... two encodings of one message is how a receiver that
> de-duplicates by bytes sees two questions where a peer asked one.

Surveyed across the harnesses: four build records with an encoder and never
compare bytes afterwards -- `manifest_fuzz`, `revocation_fuzz`, `prekey_fuzz`
and `sync_fuzz`. The richest of those is the manifest, whose entries carry a
capability, a grantee, a revocation id and a state byte, so this adds the
property there.

**Two of those four were named wrongly, and reading the source is what said
so.** `sync_fuzz` calls `fzn_journal_init`, `fzn_journal_admit` and
`fzn_journal_anchor` and nothing else -- there is no encoder in it and no
decoder either, because a digest is a claim rather than a format. It was in
the list because a survey written from the design put it there. And
`prekey_fuzz` is the case below.

### Why nothing else in that harness could see it

`manifest_fuzz` is model-based and strong: it keeps an independent shadow of
what the deficit table should hold and compares after every admission. But
**the model reaches the module through the same accessors a dropped field
would break**, so a decoder that ignored the state byte would produce a shadow
that agreed with a store that was equally wrong. Only the bytes are outside
that loop.

Shown by making `fzn_manifest_is_withdrawn` return 0 and watching the property
fire on the first case, where the whole model stayed silent.

**A unit test catches that particular mutation too**, and the sabotage run says
so -- `manifest_test.c:977`, "a withdrawn entry did not open", which runs
before the harness and fails first. So the entry's first rationale, that only
re-encoding can say it, was too strong and is corrected. What the property
actually buys is catching a dropped field WITHOUT somebody having written a
case for that field: the state byte has one, and a fourth field added tomorrow
would not.

### Two mistakes of mine, both in the comparison rather than the code

**The first version compared the whole blob** and failed on every input.
`fzn_manifest_encode` leaves the signature region zero -- signing is the
caller's -- so `again_len` bytes includes 64 bytes the encoder cannot fill. It
reported a format defect that was mine, and the debug print settled it in one
line: `first diff at 133`, which is the start of the signature in a one-pair
manifest rather than anything in the body.

**And the counter was not reported**, so the property could have stopped
running and the harness would still have printed a pass. It is in the summary
and under a floor now -- 16000 re-encodes in 2000 cases -- on the same rule
that a check nothing counts is a check that can go quiet.

### The second application, and I made the same omission again

`revocation_fuzz` has it now too: 23551 re-encodes in 2000 cases, every field
`fzn_revocation_encode` takes having an accessor on the decoded record, and the
comparison stopping at `FZN_REVOCATION_BODY_LEN` because the encoder lays a
record out UNSIGNED.

**The counter went unreported there as well, in the same sitting, minutes after
correcting it in the manifest.** Knowing a mistake is not the same as not
making it, and the thing that caught it both times was reading the harness's
own summary line and noticing a number missing from it.

Its control makes `fzn_revocation_supersedes` read the issuer's bytes instead
of its own field -- a decoder wired to the wrong offset rather than one
dropping a field -- and **the failure was read rather than counted**. Run
against the harness alone it prints

	MODEL: a revocation re-encoded from what the decoder handed back is not
	the body it was decoded from

which is this property and not the shadow model that surrounds it. sec 222's
rule, applied to a control rather than to a sabotage: a run that goes red
tells you something failed and nothing about which.

**And run through `make test`, which is what the sabotage entry does, it is
caught one binary earlier** -- `revocation_test.c:406`, *re-encoding what
the accessors read did not reproduce the signed bytes*, a check that has
been there since `75865bc` and that I had not read before claiming the
property was new here. So what the harness adds to this module is not the
property. It is **the population the property holds over**: one fixture
becomes 23551 decoded shapes, and the fixture is the one arrangement whose
fields somebody chose.

That is the second time in three entries that reading the run rather than
the design changed what could honestly be claimed for it, and both times
the correction made the claim smaller and the reason to keep the work
unchanged.

### The third application, which was written and then thrown away

`prekey_fuzz` got the same treatment: a `reencoded` counter, a floor, the
body-only comparison, 16000 re-encodes in 2000 cases, green. Then the
control -- `fzn_prekey_open` pointing `out->prekey` at the host field --
and the property fired on case 0, exactly as predicted.

**And so did everything else.** With the comparison compiled out, the
harness's own shadow caught the same sabotage one check later:

	INVARIANT: the stored prekey is not the model's

and `prekey_test` caught it in eight assertions without the harness at
all. So the property found nothing here that this module was not already
covered for, and the change was reverted rather than kept.

**The criterion, which is what the survey should have been asking**, and
it took two more controls to state correctly. The first attempt said the
property earns its place where a format carries a field the module does
not ACT on. That is a claim about the format, and it is the wrong half:

> **the property earns its place where the harness's model reaches a
> field ONLY through the module's own accessor.**

Which is a claim about the harness. `manifest_fuzz` reaches an entry's
state that way and nothing else -- so a decoder that dropped the state
byte produced a shadow that agreed with a store that was equally wrong,
and only the bytes were outside that loop. `prekey_fuzz` GENERATES its
host, prekey and `created_at`, keeps them, and compares the module's
behaviour against its own copies: the accessor is not the only route to
the field, so a wrong offset is caught without any byte comparison. The
format is the same shape in both cases; what differs is where the
harness's expected value came from.

sec 201's rule, arriving at a harness instead of a screen: **a property
added to a third harness because two others have it is symmetry, not
merit.** What made the first two worth it was a field their models could
not reach, and asking that question first would have saved the
implementation -- though not the control, which is the part that
answered it.

### And the survey missed the harness that had already said all of this

`record_fuzz` carries the property, and has since it was written. Its
PROPERTY 2 is *an OPENED record re-encodes, from its accessors alone, to
the identical bytes*, and the comment above the function makes the
argument this section spent three commits arriving at:

> The re-encode is the part `record_test.c` does once and this does over
> every drawn combination. It is what makes "a record is a view over its
> own bytes" a checkable statement rather than a description: if any
> accessor read the wrong offset, the bytes it produces differ.

Which is the unit-test-versus-population distinction, in the tree, in the
richest format the library has, before sec 232 was written.

So the honest account of this section is not that it found a property.
`message_fuzz` had it, `record_fuzz` had it and had stated why, and what
these commits did was carry it to the two formats that lacked it and
throw away a third attempt that was not needed. **The survey named four
harnesses and got two of the four wrong, in both directions** -- it
included `sync_fuzz`, which has no format at all, and it never looked at
`record_fuzz`, which is where the argument already lived. A survey that
enumerates from memory finds what it remembered.

**And `record_fuzz` is the criterion's own example.** It draws every
field, holds them in a `struct fields`, and asserts each accessor against
the value it signed -- so its re-encode is the belt on those braces
rather than the only strap. Which raised a better question than the one
this section started with: **that property has never been seen to fail.**
`tool/sabotage.py` held 388 entries over 92 sources and not one of them
touched `record/record.h`, the file holding every accessor of the richest
format the library has, whose own comment says a wrong offset shows in
the bytes.

There is one now -- `fzn_record_kind` reading the `stream` offset, which
is the exact swap `fzn_record_sign`'s comment warns a call site can make
in silence. It is caught, and NOT where the entry was aimed:

	FAIL record_test.c:586: kind did not survive the round trip

A unit test, one binary before either harness. That is the third control
in this section to land somewhere other than where it was pointed, and
all three landed the same way: **on the cheapest check that could see
it.** Which is the sabotage tool working as designed -- it reports the
FIRST thing to fail, and the first thing to fail is the thing worth
having -- but it means a control cannot, on its own, tell you a property
is alive. Only a sabotage nothing cheaper can see does that, and for
`record_fuzz`'s re-encode I do not have one: every field it reads back,
it also generated.

### Some headers are code, and the census could not see them

**The census read `make manifest` for its population, and that target
named no header.** So the figure it printed -- 92 of 93 -- was true about
the sources and silent about eleven accessor bodies in `record/record.h`,
eight in `chain/manifest.h`, ten in `chain/revocation.h`, and two in
`chain/authz.h` that decide whether a capability is guarded.

This is sec 217's lens again, and the fourth time: **a completeness check
whose population is narrower than its subject.** The narrowing is
specifically that "source" was read as "the thing the compiler is invoked
on", and a `static inline` body is compiled into every consumer's
translation unit rather than once here -- **more exposed than a `.c`,
not less.**

`manifest` emits `header <path>` per `$(HDRS)` now, and the census keeps
the ones whose contents hold a body. The contents decide, not the name:
sec 217's own remedy says a population derived from a naming convention
is an enumeration wearing a derivation's clothes, and "headers are the
files ending in .h" would have swept in the three generated ones, which
are `situ`'s to write and not this tree's to sabotage.

It named two the hand count had also found -- `chain/authz.h` and
`wire/bytes.h` -- and both now have entries:

	authz-requires-is-guarded  FAIL authz_test.c:223: a required
	                           capability with no chain was granted
	get-be16-is-big-endian     FAIL manifest_test.c:514: open

The first landed where it was aimed. The second did not: the assertion
that spells big-endian out byte by byte lives in `record_test`, and what
actually fired was a manifest failing to open two binaries earlier. Four
for four now, on the cheapest check.

**And the report line had to be widened with the population**, which is
the third time in this session that a count went unreported after the
thing it counts was added -- twice as a harness counter, once here. The
line said "92 of 93 sources" while reading a population that now includes
six headers. A figure describing a narrower population than the check
behind it is how this gap survived in the first place.

## 235. The bound that binds is not the one the line reports

`cli/reasm_print` answers "how full is this table", in six states, and a
consumer reading it is told `holding 4 of 16` on a host that is dropping a
peer's messages.

`chunk/reassembly.h` says why in its own words, about the field the printer
never mentions:

> WITHOUT THIS THE OTHER BOUNDS DO NOT HELP. A table that refuses when full
> is a table one sender can fill, and then nobody else is served -- the
> denial of service moves rather than going away.

`per_sender_max` is doing its job exactly when the capacity is nowhere near
binding. So the printer's whole vocabulary is about the bound that is NOT
refusing anybody, and it is silent for as long as the other one is working.
`fzn_reasm_accept` returns `FZN_REASM_ERR_QUOTA` with half the table free;
the line calls that "holding, with room".

That is sec 229's shape one module over -- *a full window is an emergency
and does not look like one* -- except worse, because here the host is not
even full. There is no number in the line that is wrong. The reader draws
the right conclusion from every count in it and the wrong conclusion about
the host.

### The distinction the API could not make

Counting a sender's slots looks like three lines a consumer writes:
`partials`, `live` and `sender` are all public. **The three lines a reader
writes are the wrong ones.**

`fzn_reasm_accept` refuses at `held_by(table, sender) >= per_sender_max`,
and `held_by` counts every LIVE slot -- **including the ones already HANDED
to the caller**. A count of "messages this sender is still assembling",
which is what the natural reading means, excludes handed slots and is
therefore SMALLER than the one the module enforces. A consumer using it
sees room where the next chunk gets QUOTA.

The header already warns about this confusion in the other direction, on
`FZN_REASM_ERR_FULL`: *a slot may be HANDED -- completed and waiting on the
caller to release it*. Same distinction, other bound, and until now the API
could not express it. `fzn_reasm_held_by` is the fourth accessor added for
this reason, after `fzn_manifest_follows`, `fzn_ledger_sound` and
`fzn_replay_expirable`, and the rule they share is worth stating plainly:
**where a header names a distinction and the API cannot make it, a consumer
will make a different one.**

It is one function with the quota's own, not a second walk beside it. Two
definitions of "held" is the drift the accessor exists to prevent.

### FZN_REASM_LINE_QUOTA, and why it outranks HOLDING

Appended as 6 rather than inserted, so a value already in somebody's log
keeps meaning what it meant. Asked only where the table has ROOM -- a full
table refuses everybody and the per-sender bound is moot in it.

	REFUSING -- 2 senders hold their quota of 2 while 11 of 16 slots
	stand free, so per_sender_max is the bound that binds

Both numbers, because naming only one is how a reader ends up raising the
capacity. sec 207's rule puts the verdict left of the evidence, and here
the free slots ARE the evidence rather than the reassurance.

### The fixture had two slots, and the question needs three

Every slot in `reasm_print_test`'s fixture carries the same all-zero
sender, and the fixture's `per_sender_max` was 1 -- so **one live slot was
already a capped sender**, and three assertions asking for HOLDING were
asking for a state this printer no longer produces. They were right to
fail: a table holding one of two, refusing that sender's next chunk with a
free slot beside it, is not "holding, with room" in any sense a reader can
act on.

The bound is a fixture parameter now, defaulting to one that cannot bind
before the table is full, so the cases that are about FULLNESS say only
that.

**And the third slot is what makes the sender-grouping askable at all.**
One sender holding two slots is ONE peer being refused; a census counting
slots says two. With a two-slot table a sender holding both fills it, the
FULL arms answer first, and no input distinguishes the two censuses -- sec
228's lesson, that a condition with one reachable shape is a condition no
sabotage can test, met before the sabotage rather than after it.

### And the accessor is under the harness, not only the unit test

`reassembly_fuzz` already recomputed the quota per live slot -- *the quota,
recomputed rather than trusted* -- which is a second implementation of
exactly what `fzn_reasm_held_by` exports, written before the accessor
existed. So the two are compared per case now, which is the relationship
rather than either value: both can be plausible and wrong, and they cannot
drift together without somebody editing both.

The same sabotage that the unit test catches -- `held_by` skipping handed
slots -- fails there too, with a reduction attached:

	INVARIANT: fzn_reasm_held_by disagrees with a count of the live
	slots this sender holds
	  at offset 14: index=0 chunks=1 len=6
	reassembly_fuzz: FAILED on case 25 (seed 26)

### The three controls, and the one that justifies the third slot

	held-by-counts-handed-slots
	  FAIL reassembly_test.c:528: a handed slot was not counted as
	  held, so a consumer reading this would see room where the next
	  chunk is refused

	reasm-quota-is-asked
	  FAIL reasm_print_test.c:140: a sender at its quota with a slot
	  free was reported as merely holding

	reasm-quota-counts-senders-once
	  FAIL reasm_print_test.c:159: one sender holding two slots was
	  counted twice, so the line inflates how many peers this bound
	  is refusing

Each landed where it was aimed, which is the first time in three sections
that has happened -- and the third is the one worth keeping. It fires on
**exactly one assertion**, the case that could not be written while the
fixture had two slots, so it is the evidence that widening the fixture was
load-bearing rather than tidying. A sabotage that fires on one check is
also the sharpest kind: nothing cheaper intercepted it, so that check is
the only thing standing between this line and a wrong count.

**Run by hand rather than through `tool/sabotage.py`**, which is worth
saying because the tool is the thing that normally provides this evidence.
It refuses a dirty tree -- correctly, since it rewrites files in place and
restores from memory -- so the sequence had to be commit, then control,
then this paragraph. And two attempts to run it were killed for memory
while another user's full sweep held 30 of this machine's 47 GB. Its trap
worked: `sabotage: signal 15 -- files restored`, and `git status` clean
after both. Patching one file and rebuilding one test binary is what the
loaded machine could actually run, and it answers the same question sec 52
asks.

### The widget this did not need

**No widget.** A screen would add per-sender rows a line cannot carry, and
that is sec 229's criterion for one -- but the fact that matters is an
aggregate a line CAN carry, and the printer carries it now. A widget on top
of this is worth building when there is a consumer holding the labels; sec
201's rule is that adding it because the other printers have one is
symmetry rather than merit.

## 236. A sweep that says how much it threw away

`fzn_reasm_expire` returns a count. A slot reclaimed from a sender that sent
one chunk and stopped, and a slot reclaimed from a message two chunks from
done, are the same integer in it -- and the second is bytes this host
accepted and then discarded.

**The failure that makes this matter is invisible from every other
surface.** A `max_hold` shorter than a transfer takes expires every message
just before it completes. The table stays roomy, so `fzn_reasm_accept`
refuses nothing and `cli/reasm_print` reports `holding 2 of 16`; the sweep
returns a number that looks like healthy housekeeping; and the consumer
receives nothing at all, with no error anywhere. It is sec 235's shape
again -- every number correct, the conclusion wrong -- except that here
there is no state a printer could add, because what has gone wrong is a
RATE and a printer describes a snapshot.

So the log is the surface, which is what a log is for.

### The line is a description, not a diagnosis

Two emit sites, split on `arrived > 1`:

	FLOG_WARN   expiring a message that was arriving: 2 of 3 chunks and
	            16 bytes are dropped, so if this repeats max_hold is
	            shorter than a transfer takes
	FLOG_DEBUG  expiring a message that never progressed: 1 of 3 chunks,
	            held until 50

One chunk is a sender that spoke once, which is ordinary loss and belongs
below the default filter. Two or more means chunks were arriving over time
and this host gave up while they were still coming.

**The threshold is available rather than arbitrary, and that is why it is
this one.** A proportion -- three quarters arrived, one chunk short -- would
have been a number nobody could defend, and sec 228's lesson is that a
condition whose shape cannot vary is a condition no sabotage can test.
"More than one chunk landed" is a fact about the slot, not a judgement about
how nearly done it was.

**And the warning does not claim `max_hold` is the cause**, because a sender
that genuinely died mid-transfer produces the identical slot. It says what
was observed and names the field to look at. `evidence.md` keeps the rule as
a reduction and a mechanism being separate claims: this line is the
reduction.

### The control, and the entry it broke

	expire-separates-loss-from-abandonment
	  FAIL reassembly_test.c:1655: a sender that spoke once and stopped
	  was reported above debug, which makes ordinary loss look like a
	  fault

Fired where aimed, on the threshold rather than on the severity, because
those are separate edits and only one of them is the one a tidy-up makes.

**And adding the second FLOG_WARN to this file broke an existing entry**,
which is the verify gate earning its keep in a way no test could:

	sabotage: reasm-saturation-is-said matches 2 sites in
	chunk/reassembly.c, wanted 1

The entry named `"chunk/reasm", FLOG_WARN,` and that was unique until this
commit. **Uniqueness is a property of the file at the moment of the edit,
not of the string** -- `evidence.md` says exactly that about anchors, and
here the tree grew the ambiguity by itself, with nobody touching the entry.
It carries the first line of the saturation message now, which is the part
that cannot become ambiguous without the message itself changing.

## 237. The deletion path was the silent one

Counting emit sites per module: seventeen modules carry a log, and the three
that take bytes off this host -- `catalog/sweep.c`, `spool/scrub.c`,
`catalog/copy.c` -- carried none at all.

`catalog/sweep.h` opens *planned deletion: taking bytes off this host,
deliberately*, and its own argument for being planned rather than immediate
lists two ways to lose data -- a blob several nodes share, and being the last
host that has it. The module with the most carefully reasoned hazards in the
tree had nothing to say while it worked.

### Not an error, which is why it was silent

Both moments this commit gives a voice are ones where nothing is wrong, and
that is exactly what kept them out of the return values.

**`min_others == 0` switches off the last-copy guard**, and it is the
caller's to give: the header says so at length -- right for a cache, wrong
for the only copy of a photograph, and a default here would be *a number
nobody chose applied to data nobody can get back*. What no surface said is
that **the plan it returns is indistinguishable from one that passed the
guard**: `last_copy` is zero whether the seam refused nothing or was never
asked.

	NOTE  planning to remove 2 blobs with the last-copy guard off:
	      min_others is 0, so no witness was asked whether anybody else
	      holds them

`FLOG_NOTE` and not a warning, because nothing has gone wrong -- something
irreversible is about to happen with a check disabled, which is what a note
is for. Silent when the capture planned nothing, since a plan that removes
nothing has disabled nothing that mattered.

**And truncation was already called loud by the header** -- *a sweep that
silently held some of them would leave a consumer believing it had reclaimed
what it had not* -- while its only voice was a counter beside six others.
That is a claim a document made and the code did not keep.

	WARN  2 removable blobs did not fit in this job's 1 rows, so running
	      it to the end reclaims less than the catalogue offered

### Through the catalogue's log, not the job's

A sweep is something that happens TO a catalogue, and a consumer that has
already said where that catalogue talks should not say it again per job. It
also means the sublog name the consumer chose puts these lines under the
same heading as everything else that catalogue said -- which is the whole
argument for flog's tree, arriving at a module that had no log at all.

No new field, no new setter, no change to any struct: `SWEEP_LOG` reads
`catalog->log` exactly as `CAT_LOG` does.

### The controls

	sweep-says-the-guard-is-off   NOTE -> DEBUG
	  FAIL sweep_test.c:817: a disabled guard was reported as a fault or
	  filtered as chatter, and it is neither

	sweep-truncation-is-said      WARN -> INFO
	  FAIL sweep_test.c:841: a consumer about to believe it reclaimed
	  what it did not was not warned

Both are severity edits rather than logic edits, deliberately: the plausible
change to a line like this is somebody quieting it, not somebody deleting
it. Each fires on exactly one assertion.

**And the case that the guard being ON is silent is the control the block
needs**, not decoration. Without it every assertion above passes for a
module that says the same thing on every capture -- which is the shape
`evidence.md` calls a control that cannot fail the way the thing it controls
for fails.

### What is still silent, and one of them correctly

`spool/scrub.c` and `catalog/copy.c` remain at zero, and `blob/`, `tree/`,
`spool/plan.c` have no log at all. Whether each of those has an event no
return value carries is a question per module rather than a sweep to run --
sec 201's rule, and the reason this section covers one module rather than
six.

**Asked of `catalog/copy.c`, the answer is no, and the discriminator is one
line of its own source.** Its most consequential count is `unknown`: a peer
asking for a root this catalogue does not reference, which its header calls
the difference between copying a catalogue and *a capability for a catalogue
silently becoming a capability for the blob store*. That is a security event
and it sounds exactly like something that wants a line.

It does not, because `fzn_catalog_copy_offer` REQUIRES its plan --
`if (!plan) return FZN_CATALOG_ERR_MALFORMED` -- so `unknown` reaches every
caller there has ever been. A log line would restate what the return already
carries, which is sec 194's boundary applied to a log instead of a widget.

**That is the whole difference between it and `spool/scrub`**, where the
identical-looking count sits behind an out-parameter the header says may be
NULL. The lens found three silent removal paths; two had a fact with nowhere
to go and one had a caller that is made to receive it. **A module being
quiet is not the finding -- a fact with no channel is** -- and the check is
whether the API lets the caller decline to hear it.

## 238. A finding a caller may throw away

`spool/scrub` exists to detect silent corruption: bytes that were verified
once, re-read later, no longer what they claimed. It reports what it found
through `out_checked` and `out_dropped`, and `scrub.h` says of both -- **both
may be NULL.**

So a consumer scrubbing on a timer, which is the way anybody would run it,
calls `fzn_scrub_step(scrub, hash, 64, NULL, NULL)` and a cell that failed
its reference is repaired in complete silence. This host's storage handed
back bytes it was never given, the module noticed, and nothing anywhere
records it.

That is sec 237's shape with the volume turned up: there the fact had a
counter nobody had to read, here it has one the caller may decline to
receive.

### The index, not the count again

	WARN  cell 1 no longer matches its reference: 64 leaves from 64 go
	      back on the want-list, so these bytes were not the bytes that
	      were verified

**`out_dropped` says how many; only this says which**, and that is the whole
of what it adds. Clustered failures are a region of a disk going and
scattered ones are something else entirely -- a distinction with nowhere
else to be made, and the reason this is a line rather than a duplicate of a
number the caller already has.

The assertion is on the cell number for the same reason, and its control is
the sabotage that logs `first` instead of `cell`: the leaf index rather than
the cell, a line that still says something true and answers a different
question.

	scrub-says-which-cell-rotted
	  FAIL scrub_test.c:781: the line does not say WHICH cell failed

**WARN and not ERR**, because the module's answer to this is repair -- the
leaves go back on the want-list and a peer re-supplies them proved. Whether
anybody still has them is `spool/transfer`'s question. Reserving ERR for
what the library cannot fix is what keeps the level meaning something.

### Two clean passes, because one is not a control

The block asserts silence twice: once before the spool has a log at all, and
once after, over an intact blob. The second is the one that matters. Without
it every assertion below passes for a module that emits on every cell it
checks -- and a scrub over a large blob is thousands of cells, so a line per
cell would bury the one line that is the point.

## 239. What is verified now, which a running total gets wrong

`catalog/sweep` has `fzn_catalog_sweep_progress` -- *what to draw*, in its
own words, *the one thing the holder asked stay possible of a job that holds
the catalogue*. `spool/scrub` is the same kind of long-running job over the
same kind of grid and had no equal to it.

A consumer could keep its own figure, and the way that figure is wrong is
the reason this is a call:

	fzn_scrub_seal  reports what THIS call sealed        only rises
	fzn_scrub_step  clears the seal on every cell it repairs

**So a running total and the truth agree until a cell fails**, which is to
say until the module does the thing it exists for -- and from then on the
consumer's version says a rotted blob is fully verified. Subtracting
`out_dropped` as it arrives does not rescue it either: a cell sealed,
dropped and sealed again is counted twice in one and once in the other, and
no arithmetic over deltas recovers the size of a set.

`fzn_scrub_progress` counts the bitmap. Not a counter on the struct -- that
would be a second record of what the bitmap already says, parting company at
the first `bit_clear` somebody forgets to pair with it.

### Asserted as the disagreement, not as either number

The test seals, checks that the two figures AGREE on an intact blob, corrupts
one cell, and then requires them to differ by exactly one in the direction
repair moves them. A test pinning the count would pass for an accessor
returning a stale total; this one cannot.

Its control makes the accessor count cells instead of reading their seals --
which is precisely the consumer's running total, reimplemented inside the
library -- and the failure says so in its own words:

	FAIL scrub_test.c:767: a repaired cell is still counted as verified:
	4 sealed against a running total of 4

**Both out-parameters are required**, unlike `fzn_scrub_step`'s. sec 238 is
what a count nobody has to receive costs, and a caller asking how far along
it is has no use for half a fraction.

**This is the fifth accessor added because a header named a distinction its
API could not make** -- after `fzn_manifest_follows`, `fzn_ledger_sound`,
`fzn_replay_expirable` and `fzn_reasm_held_by`. Four of the five were found
the same way: by asking what a consumer would have to compute for itself,
and then checking whether the obvious computation agrees with the module's.
It usually does, right up to the case the module exists for.

## 241. A gate that checked names and claimed sites

`tool/log_gate.py` ended every run with

	log-gate: 17 subsystem(s) over 33 emit site(s), each asserted by a test

and the check behind it was: does the quoted subsystem string appear
anywhere in the test sources. **That is a claim about SITES made by a check
over NAMES.** `chunk/reasm` had three sites under one name and one assertion
satisfied all three; the two this session added to it were covered before
they were written.

Same shape as the sabotage census's own line an hour earlier -- a figure
describing a wider population than the check behind it -- and this one had
been quoted in five commit messages as evidence that the diagnostics work
was held to account.

### The severity is what a test actually compares

A test asserts `seen.type == FLOG_WARN` beside the subsystem, so the pair is
the strongest thing available without matching message text. The gate now
requires **one test FILE** to name both.

**Per file, because concatenating them first is vacuous** -- `FLOG_WARN`
appears somewhere in a suite of 111 binaries whatever any one module
asserts. Measured before adopting: 32 pairs over 38 sites, all covered
today, so this is a floor being written under work already done rather than
a bar nobody clears.

**And a site whose severity is not a plain `FLOG_` constant would take its
pair with it silently**, so the gate counts sites twice -- once by
subsystem, once by subsystem-and-severity -- and refuses when the two
disagree. That is the same paranoia the wrapper-name check already
encodes, and sec 217's incident is why it is there: a hole in a pattern is
silent unless something compares two counts.

### What it still does not catch, pinned rather than left implied

Two sites at the SAME subsystem and severity, one asserted and one not.
Catching that needs message text, and a test asserts fragments rather than
whole lines, so there is nothing mechanical to compare. Written into the
gate beside the pattern, because a gate whose limits are unwritten gets
quoted for guarantees it never made.

### Both new arms were made to fail

	site at a severity nothing asserts    no test names chunk/reasm and
	                                      FLOG_CRIT together      rc 1
	severity not a plain constant         4 emit sites and 3 readable
	                                      severities              rc 2

The exit codes are the file's existing division: 1 for a gap in coverage, 2
for an instrument that cannot see.

**And the first control found a second fault in the same run.** The failure
printed the trailer written for the SUBSYSTEM case -- *a typo files a
normal-looking line where nobody greps for it* -- which does not describe a
severity nothing asserts. It names both now. A new arm reaching an old
explanation is not something the arm's own test would show, and only
watching the failure print did.

## 242. A detector measured on one instance of what it detects

`spool/scrub` exists to notice that stored bytes are no longer the bytes
that were verified, and until now the only thing asking whether it works was
`scrub_test.c`, which flips one bit in one leaf of one arrangement. sec 102
calls scrub the piece with no equivalent anywhere; it also had no harness.

`spool/test/scrub_fuzz.c` asks two properties over arbitrary corruptions of
arbitrary partial blobs.

	1. DETECTION IS COMPLETE   every sealed cell whose stored bytes
	                           differ loses its leaves
	2. AND NOTHING ELSE MOVES  a cell whose bytes did not change keeps
	                           them

**The second is what makes the first able to fail.** A scrub that dropped
everything satisfies property 1 perfectly, and a false positive is not a
harmless extra check -- it discards sound bytes and asks a peer to send them
again. So the two are one assertion of SET EQUALITY: the cells that lost
their leaves must be exactly the sealed cells whose slot bytes changed.

	scrub_fuzz: 20000 cases, 13965 with a drop, 6035 untouched, 2006
	tail drops, 4989 partial blobs, 15011 fully sealed, 9963 multi-cell
	drops, detection exact throughout

### Two decisions that keep the model independent

**It observes through `fzn_spool_has`, not the seal bitmap.** Whether a cell
is still sealed could be read straight out of the caller-owned bits, and a
model that did would be agreeing with the implementation about the very
thing it checks. What a consumer sees is which leaves are back on the
want-list, so that is what this compares.

**The cell decomposition is this file's own**, derived from what `scrub.h`
describes -- full cells of `FZN_SCRUB_CELL`, then a tail of one cell per set
bit below it -- rather than copied from `scrub.c`. It is checked against
`fzn_scrub_cells` every case, so two implementations meeting is one of the
assertions rather than an assumption.

### The first failure was mine

	MODEL: the step reports 0 cells dropped and 2 cells lost their leaves
	scrub_fuzz: FAILED on case 91 (seed 92)

`fzn_scrub_step` sets `out_checked` and `out_dropped` to what THAT CALL did.
The harness steps in random bites until the pass wraps and had been reading
the last call's numbers as the pass total. The module was right and the new
model was wrong, which is the ordinary case for a new model and the reason
`evidence.md` says to suspect it -- and it took ninety-one cases to find,
where the fixture in `scrub_test` steps once and could never have shown it.

### Controls

	detection inverted (`!= 0` to `== 0`)   cell at leaf 0 was sealed, its
	                                        stored bytes changed, and it
	                                        still holds leaves
	the forget removed                      the same line
	cell_is_whole always true               sealing refused: backend

The first two land where they were aimed and have entries. **The third does
not, and so does not get one**: sealing a holed cell reads a leaf that was
never placed, so the spool refuses and the module's own error path answers
before any property does. An entry aimed at a model, caught by a backend
error, records a guard that was never exercised -- which is sec 234's
finding about controls landing on the cheapest check, met once more and
acted on this time by not writing the entry.

## 243. A non-property, made executable

`catalog.h` argues at length about a property its merge rule does NOT have:

> a proper OR-Set lets a remove cancel exactly the adds it has SEEN, so a
> concurrent add survives a remove that never knew about it -- and that needs
> causal metadata on every edge. This rule is the honest first pass.

The suite tested the property it DOES have -- two hosts adding a member agree
whatever order the assertions arrive in -- with two assertions in opposite
orders. Nothing tested the limit.

Measured with three: alice links, bob links, alice unlinks with a later
sequence.

	order alice, bob, alice-unlink   linked = 0
	order bob, alice, alice-unlink   linked = 1

Whether alice's unlink applies depends on whether her own link is what the
table holds when it arrives, and that depends on which link came first. Both
halves of the rule are working exactly as `catalog.h` describes: a later
statement supersedes its own issuer's, and across issuers presence wins.

### Why a non-property is worth a test

**A reader who meets that divergence without this case will read it as a
defect**, and the two available "fixes" are both worse than the behaviour.
Checking presence before issuer is the one `catalog.h` records having tried:
it makes a catalogue nothing can be removed from. Adding causal metadata to
every edge is an OR-Set, which is a design decision with a memory cost, and
not one to arrive at by way of a bug report.

So the test asserts the disagreement, and says in its own comment that **it
is expected to fail the day somebody implements an OR-Set** -- at which point
the change has to come here and say so, rather than being discovered by a
consumer whose hosts stopped agreeing.

This is the shape `working-practice.md` describes for a deliberate
non-decision: it *decays like an entry recording a fix, and more quietly*. A
prose paragraph about a property the code lacks is invisible to every gate; a
test is not.

### The control found the suite already had it covered

Sabotaging the rule to skip the issuer check fires five assertions, and mine
is the third of them:

	FAIL catalog_test.c:266: a stale link was accepted over a removal
	FAIL catalog_test.c:372: alice's unlink did not supersede her own
	                         earlier link

So no sabotage entry: `catalog-issuer-supersedes-first` already names that
site, and the assertion that answers first is one that predates this. By sec
242's own rule an entry aimed at a check something cheaper answers records a
guard nothing exercised -- and here the honest reading is that the new test
adds a claim about the LIMIT rather than coverage of the rule.

**And the sabotage would not apply as first spelled.** The
issuer-supersedes-first line appears three times in `catalog.c` -- the edge
rule, the content rule and the name rule are the same shape -- so the anchor
had to carry the comment above it. `evidence.md` again: uniqueness is a
property of the file, not of the string, and here the file had three of them
from the start.

### The content table diverges the same way, and its comment says otherwise

The same shape one table over. `fzn_catalog_content_held_wins` keeps what is
held across issuers, and both the header and the source defend it in the same
words:

> KEEPING THE HELD ONE IS NOT A PREFERENCE FOR THE FIRST WRITER, it is the
> only answer available that does not depend on arrival order

Measured, alice's and bob's assertions given to two hosts in opposite orders:

	host a, alice first    root 0xaa
	host b, bob first      root 0xbb

**Whichever arrived first stands, so the outcome depends on arrival order and
the surviving writer is the first one to arrive.** Both clauses of that
sentence read as denials of exactly that.

There is a reading under which it is right, and it is probably the intended
one: the RULE consults no order, because across issuers there is no "later"
to appeal to, and any rule that claimed to order them would be inventing an
authority. That is a true and load-bearing point. But it is not what the
sentence says, and the sentence is what a consumer reads before deciding
whether its hosts converge.

**Flagged and not rewritten.** `working-practice.md` is explicit that a
document contradicting the code is not to be silently resolved in either
direction, and this is a design rationale rather than a comment about
mechanism -- the same argument appears in `catalog.h` and in `catalog.c`, and
whoever wrote it was answering a real question about what a rule without
causal metadata can promise. **Whose decision it is: the copyright holder's.**

What is here instead is a test pinning the measured behaviour, taking no view
on the wording, so that reconciling the two is a deliberate act by somebody
who owns the argument rather than a discovery by somebody whose hosts stopped
agreeing. Its control -- keeping the offered entry instead -- fires both of
its assertions and one that predates it, which is also why it gets no
sabotage entry.

**The edge case has a paragraph saying what it is not; the content case has a
sentence that reads as a convergence claim.** Same limit, same module, and
only one of them was written to be un-mistakable. That is the more useful
finding than either divergence: a non-property is only as safe as the
sentence describing it.

**And there are three sites, not two.** `fzn_catalog_name_held_wins` says
only *the same rule and the same reasoning as content's*, so it inherits the
sentence by reference. No third test -- that would be symmetry rather than
merit, since the behaviour and the argument are content's -- but whoever
reconciles the wording is reconciling three places, and a fix that reached
two of them would leave the name table's comment pointing at a paragraph that
had changed under it.

## 244. One of the encoder's two modes had never been decoded

`qr_test.c` opens by saying what it cannot do: *every assertion here is about
shape ... and a QR code can satisfy all of it and decode as nothing.* The half
that says it is a QR code at all is `make qrcheck`, which builds quirc from
source and reads back what this tree encodes. That division is right and it is
recorded.

**What nobody had counted is the population qrcheck reads back.** One payload
per (level, version) cell, and every one of them `AAAA...`. The print fixture
beside them is `PROVISIONING CARD 1234567890`. Capitals, digits and a space.

`qr.h` says the mode is chosen and not asked for:

> Text that is entirely in QR's alphanumeric set -- digits, capitals, and
> ` $%*+-./:` -- is packed at 5.5 bits a character; anything else goes as
> bytes at 8.

So **the encoder has two modes and an independent decoder had seen one of
them.** Byte mode is what any lowercase or punctuation-bearing payload takes,
and its bit packing and character-count indicator are different code.

It is the fixture question fuzzypickles asked this tree on 2026-09-05 --
*what value is every fixture in this suite on the same side of?* -- answered
here as: every payload was inside the alphanumeric set.

### It works, and now something says so

44 more round trips, four levels by eleven lengths, payloads built from
lowercase and `_~` so the mode chooser cannot take the narrow path.

	qrcheck: 104 of 104 checks round-tripped through quirc

**Lengths rather than one payload per version**, because byte mode's bug
surface is the packing and the length indicator, and both move with length
rather than with content.

### The control is quirc naming the mode

A sweep of payloads *intended* to be byte mode proves nothing if the encoder
quietly packed them as alphanumeric, so `roundtrip_typed` asks quirc which
mode it read and the sweep requires `QUIRC_DATA_TYPE_BYTE`. Pointed at
capitals instead, it refuses:

	FAIL qr_quirc_check.c: byte mode L (1 chars): decoded as data type 2,
	wanted 4

Which is the control this section needed rather than a nicety: without it the
44 new checks could have been a second helping of the 60 old ones, and the
output would have looked exactly the same.

**An empty result, recorded with its method.** No defect was found. What
changed is that a whole mode of a generator the holder asked for is now read
back by somebody else's decoder on every `make check`, and the sentence in
`qr.h` describing the two paths has a witness for both.

## 245. A property whose refusals all happened too early

`ratchet_test.c` asks whether a fast-forward lands where stepping lands. It
asks it once: a chain initialised at sequence 0, jumped to 5, with room for 8
skipped keys. **Every fixture in that file starts at zero** -- which is
fuzzypickles' question again, and the answer here is the starting position. A
receiver's chain is at zero exactly once and spends the rest of its life
somewhere else.

`ratchet/test/ratchet_fuzz.c` asks it from anywhere, over any distance, with
any cap, against the same oracle: a table of every position's message key and
chain key built by stepping `fzn_ratchet_derive` in a loop written in the
harness.

	ratchet_fuzz: 20000 cases, 19770 from a moved chain, 12829 jumps,
	7171 adjacent, 3938 capped, 4345 exactly at the cap, 20000 behind,
	12829 split paths, 12829 abandoned part-way, every jump landed where
	stepping lands

**The property no fixture starting at zero can ask** is that the path does not
matter: reaching a target directly and reaching it through an intermediate
leave identical chains. That is the one a receiver leans on, because frames
arrive in whatever order the network chose.

### The floors caught the generator, twice

First run: 90 adjacent cases against a floor of 100, and 136 capped against
250. The targets were drawn uniformly, so the adjacent case -- `target ==
from + 1`, which is **in-order delivery, the common case on the wire** --
happened 4.5% of the time, and a cap drawn uniformly in 1..96 was almost
never smaller than the jump it had to cut.

Both were fixed in the GENERATOR rather than in the floors. A floor lowered to
whatever the run happened to reach is a floor that has stopped saying
anything, which is the whole reason these harnesses carry them.

### And a sabotage survived, which is what made the harness honest

Property 4 was *a refusal writes nothing*, asked with a behind target and a
jump past the bound. Moving `*to = work` to before the derivations survived
2000 cases.

**Both of those refusals return before the module touches anything.** They
are checked at the top of `fzn_ratchet_advance`, above `work = *from`, so a
module that wrote its destination early could not fail either of them. The
property had one reachable shape -- sec 228's finding, in a new module.

The refusal that lands mid-jump is a failing hash, and the harness now carries
a budgeted seam that runs out after starting: `hash_budget = jump - 1`. With
it, the same sabotage fails on case 0.

	MODEL: an advance abandoned part-way wrote its destination, so a
	caller holds a position that is neither the old one nor a usable new
	one

`ratchet_test.c` has `test_a_refused_hash_leaves_the_chain_alone`, so the
tree was never unguarded here. What was wrong was the harness's own claim: it
said *a refusal writes nothing* and could only produce refusals that write
nothing by construction.

### The first failure, again, was the harness's

	INVARIANT: an advance from 72 to 86 with cap 0 was refused: 1

`fzn_ratchet_advance` refuses when `!skipped_count != !skipped_out` -- both or
neither -- and a cap of zero with a count pointer is neither. The module was
right. **And the first version of that line did not print the code**, only
that something was refused, which is sec 222's rule met from the harness side:
a run that goes red tells you something failed and nothing about which. The
caller-wants-none path is now asked deliberately, with all three absent, as a
property of its own: whether the skipped keys are wanted must not change where
the chain lands.

## 246. Eleven selections, every one over a pair

`sched_test.c` calls `fzn_sched_select` eleven times and **every candidate set
is two links.** With two, "the cheapest that qualifies" is the comparison the
code makes, so the test and the code agree by construction: a tie among three,
or a minimum that is neither first nor last, is not expressible.

The same question as sec 245, one module over, and the answer is the size of
the set rather than the starting position.

	sched_fuzz: 20000 cases, 12811 chose, 7189 none qualified, 3508 ties,
	5672 from the middle, 2499 singletons, 8619 saturated costs, 8379
	partly filtered, the choice was a cheapest qualifying link throughout

### The model is an independent argmin, and the arithmetic earns two of them

The harness computes each candidate's cost with its own saturating sum,
written from what `sched.h` describes, and takes the minimum over the
candidates that pass the hard constraints. A model that asked
`fzn_sched_cost` what the cost should be would agree with the module always.

**That arithmetic is worth two implementations because it is where this
module's only recorded defect lived.** `sched.c` carries the measurement: with
a weight of 4294967295 on the metric, a link declaring metric and latency both
at 4294967295 cost **zero** -- the cheapest value representable -- and was
chosen over a link costing 1 ms. Widening the multiplies was not enough,
because the sum was a bare `+=`. So weights and metrics here are drawn to
include their extremes rather than plausible values, and the wrapping sabotage
fails on case 6 with the two costs printed side by side.

### The tie floor caught the generator again

22 ties in 2000 cases against a floor of 100. Independent u32 draws almost
never produce two equal costs, so the rule that makes this scheduler
reproducible was barely exercised -- by a harness written specifically because
the suite could not express it.

A third of candidates after the first are now **copies of an earlier one**,
keeping their own id. That reaches 366 ties, and it is what a real table looks
like when two links are idle and measure identically.

### Five properties, three controls

	the sum wraps           MODEL: link 5 costs 18446744073709551615 here
	                        and 5175078128174287867 there
	a tie takes the later   MODEL: index 2 was chosen where 0 is the first
	                        qualifying link at that cost
	the filter scores       MODEL: nothing qualified and select answered ok

The third is `sched.c`'s own words made falsifiable -- *a link that fails a
hard constraint is skipped entirely rather than scored badly: scoring it would
let a large enough weight elsewhere bring it back.* The harness also asks it
from the other side, by redrawing only the weights and requiring every
`fzn_sched_admits` verdict to be unchanged: a hard constraint that moved when
a weight did would be a penalty wearing a filter's name.

**And two modules in two sections now, found by one question.** Every fixture
in a suite sits on one side of something; the cheap way to find it is to read
the fixtures rather than the assertions, and both times the answer was a
dimension the author had no reason to vary.

## 247. The line a consumer needs before it drops somebody's traffic

`sched.h` states the consequence and stops there:

> When nothing survives, `FZN_SCHED_ERR_NONE` is the answer and the caller
> drops. Falling back to the least-bad survivor would be the wrong kind of
> helpful.

So a consumer holding that error is about to discard traffic, and the only
thing it has to explain that with is **one code shared by every reason.** The
header already knows: it says `fzn_sched_admits` and `fzn_sched_cost` are
exposed *because a consumer often wants to say WHY nothing qualified.*

`cli/sched_print` is that line. Seven states, and the reasons want different
actions:

	every link down          the consumer's own links, not this class
	all too slow             raise max_latency_ms, or accept the delay
	all too lossy            raise max_loss_permille
	all too small            lower min_mtu, or fragment
	excluded differently     NO single change admits anything

**The last is the one worth building the printer for.** Every other state
points at a field; that one exists to say that pointing at any of them would
be wrong, and it is the case where every obvious remedy sends a reader to
change something that cannot help. It is `cli/reasm_print`'s shape -- several
causes, several actions, a line that says which -- and sec 201's test for
merit is met because the states are not variants of one wording.

### A sixth accessor, for the same reason as the other five

`fzn_sched_admits` answers with a bool, so it says that something excluded a
link and not what. The printer needs the difference, and the two ways to get
it were to re-derive the three comparisons in `cli/` -- a second definition of
a hard constraint, drifting from what `fzn_sched_select` actually skips -- or
to ask the module.

`fzn_sched_excluded_by` names the first failure in the module's own check
order, and **`fzn_sched_admits` is now a reading of it**, so there is one
definition rather than two. That is the sixth accessor added in this session
because a header named a distinction its API could not make, after
`fzn_manifest_follows`, `fzn_ledger_sound`, `fzn_replay_expirable`,
`fzn_reasm_held_by` and `fzn_scrub_progress`.

### The caller passes the answer in

`fzn_sched_print` takes the `err` and `chosen` that `fzn_sched_select`
returned rather than selecting again. A printer that selected for itself would
be a second selection that could differ -- on a table another thread had
touched, or simply under a different class -- and **a report about a choice
nobody made is worse than no report.**

Its own guard follows from that: an `err` of OK naming a link the class
excludes is reported as NONE rather than as a choice, because it is either a
caller pairing an answer with the wrong table or a selection this module would
not have made, and calling it a choice would put the printer's name behind it.

### The refactor broke an existing sabotage entry, and the gate said so

Moving the usable check into `fzn_sched_excluded_by` left
`sched-usable-veto` naming `if (!link->usable) return 0;`, which no longer
exists.

	sabotage: sched-usable-veto matches nothing in sched/sched.c

**Nothing about the build or the suite would have noticed.** The entry would
have sat in a table that reads as coverage, reporting a guard as defended
while matching nothing -- which is exactly what `verify` was written for, and
the second time this session that a refactor of mine has invalidated an anchor
somebody else wrote. It names the new site now, and its control fires through
`sched_fuzz`'s independent `admits` model rather than only a unit test.

**And two of the three new entries were wrong in the same breath** -- a tab
too many on a `return`, so they matched nothing either. The gate found all
three together, before any of it was committed, which is the whole argument
for a check that runs without building anything.

## 248. The rows the line refuses to draw

`cli/sched_print`'s NO_SINGLE_FIX line names no bound to change, on purpose:
naming one would send a reader to alter the thing that cannot help. What that
leaves is a reader told there is no single fix and nothing about where the
several are.

`gui/sched_view` is where that can be said. It shows the printer's line as the
verdict, per sec 193, and adds a row per link -- id, cost under this class, and
either that it is carrying the traffic or which constraint excluded it. sec
194's boundary exactly: the printer counts, and a screen has room to say which.

	link 7    cost 500              too slow
	link 8    cost 10               too lossy
	link 9    cost 10               MTU too small

**It is not `gui/link_view`.** That widget's subject is which of a link's
numbers are MEASUREMENTS and which are the far end's word, and its header says
that is the whole reason it exists. This one's subject is one CLASS against the
same table. Two questions over one set of rows, and a widget answering both
would be a screen whose columns disagree about what they are for.

**The chosen link says CARRYING rather than `qualifies`**, because on a table
where three qualify a reader should not have to compare costs by eye to find
the one moving traffic. Its control is that sabotage: with the branch removed,
every row reads `qualifies` and the choice has to be inferred from the summary
and the arithmetic.

### installcheck caught the header nothing included

	installcheck: installed but not included by the consumer:
	cli/sched_print.h
	installcheck: the check would pass whatever those headers did.

The gate parses every public header as C++ through `tool/consumer_check.c`,
and a header absent from that file is a header the parse cannot fail on. **The
check would have gone green over a public header with a C++ error in it** --
and the gate says so in exactly those words rather than reporting a pass over
77 of 78. That is the vacuous-pass rule built into a gate instead of left to
whoever reads its output.

Both spellings needed it: the angle-bracket include for the installed tree and
the quoted one for the source tree, which are the two arrangements
`installcheck` builds.

### Three gates, three different omissions of one change

`style` passed the widget. Then `installcheck` found the header missing from
`tool/consumer_check.c`, and `qttycheck` found the object missing from the
renderer sweep's link line:

	undefined reference to `fzn_sched_print'

A widget added to that sweep needs its PRINTER's object there too, and
`sched/sched.o` was already present so only the printer was missing. Nothing
in `make test` could have seen it: the widget's own test rule names its
objects explicitly and links fine.

**Each gate caught a different half of the same omission**, which is the
argument for having three rather than a bigger one. And none of them is the
gate a reader would predict: the C++ parse found a documentation-shaped
problem, and the terminal renderer found a link.

**Verified by symbol rather than by re-running the gate**, because the
machine could not fit another Qt build -- `nm -u gui/sched_view.o` names three
undefined `fzn_` symbols and `nm --defined-only` on the two objects now on the
line provides all three. That is the exact failure answered, rather than a
green run over everything else as well. `qttycheck` had not completed at the
time of the commit, and saying so is the point of the distinction.

### The widget in the render sweep, and the assertion that waited to be run

`gui/test/qtty_render_test.cpp` includes its widget headers **by hand**, and
`gui/sched_view.h` was the only one of the eighteen absent. Nothing requires
the list to be complete, so a widget added to the tree is silently unmeasured
against a terminal -- the population lens once more, and the population is
derivable from `GUI_SRCS`.

**The case was written, reverted, and then landed with a measurement.** The
sweep asserts each widget shows its sentence on an 80x24 terminal, and this
printer's longest line is 79 characters through a word-wrapping label:

	DROPPING -- no single change helps: 1 too slow, 1 too lossy,
	1 too small, 0 down

Whether "no single change helps" survives that wrap is a measurement, and
`qttycheck` was killed for memory four times before it could be taken -- three
while another user held the machine at load 20, once with it idle, always
inside qtty's own library build and so before this code was reached. A
syntax-only compile passed, which says the C++ is right and nothing about the
columns.

**So it was reverted rather than committed**, because a gate carrying an
assertion nobody has watched pass is the thing sec 52 is about. It went in on
the next quiet machine, with the substring shortened to "no single change" for
exactly the wrap the earlier caution named:

	sched_view         needs 34 columns to say "no single change"

118 checks where there were 116. The caution was worth the round trip: 34
columns is a fact, and the version that guessed would have been a guess in a
gate.

### A hardcoded -j4 is a decision taken for every machine

`qttycheck` built qtty with `$(MAKE) -j4`, which is four Qt C++ compiles at
once. `QTTY_JOBS ?= 4` keeps that default and lets a loaded machine turn it
down; the run that verified the link fix used `QTTY_JOBS=1`. `running-code.md`
is about parallelism nobody chose, and a fixed number in a recipe is the same
fault with the value visible.

### Six sections, one question

sec 243 through sec 248 came out of reading fixtures rather than assertions.
The dimension every fixture sat on one side of was, in order: one bit in one
arrangement, a chain at sequence zero, a candidate set of two, and a payload
inside the alphanumeric set. **None of them was a dimension the author had any
reason to vary** -- which is why the question works, and why it is worth asking
of a suite that looks complete.

## 249. The gate that would have said so

sec 248 added `gui/sched_view` to the render sweep by hand, having found it
absent by hand. That closes the instance and not the class: the next widget
joins the build, the suite and the style gate without joining the one check
that puts it in front of a terminal, and the sweep goes on reporting a clean
run over the subjects it happens to know about.

`make style` now derives the widget list from the directory and requires each
one to be included by `gui/test/qtty_render_test.cpp` AND referenced there.

	style: 18 widgets, each one used by qtty_render_test

It is the same shape as the error-renderer check beside it, which exists for
the same reason and was itself widened in sec 231 after its population turned
out to be narrower than its subject.

### The message said more than the check did, for the third time today

The first version grepped for the `#include` and reported

	style: 18 widgets, all rendered by qtty_render_test

**A header can be included and the widget never constructed**, so "rendered"
was a claim about something the check did not look at -- the same fault as sec
241's *each asserted by a test* over a check that only read names, written by
the same hand a few hours later.

It requires a reference to the TYPE as well now, which is what shows a widget
is built rather than merely compiled against, and the message says *used*
rather than *rendered* because that is what a type reference proves.

**And it deliberately does NOT require a row in the sweep's `cases[]`
table.** Measured before deciding: 18 headers are included and 15 have a row.
The other three are exercised on purpose somewhere else in that file --
`trust_view` and `log_view` in their own blocks, `qr_view` through a decoder
rather than a string match -- so demanding a row would be demanding the wrong
shape of test for a sixth of them. What the check does not prove is written
beside it rather than left for somebody to quote it for.

### Two versions, and the first one had this section's own fault in it

The first version read `$(GUI_SRCS)` and carried a branch for the GUI being
off. **That branch is unreachable**: `GUI_SRCS :=` seeds two widgets before the
`FZN_GUI` decision is taken and never empties, so `FZN_GUI=0` leaves it
holding `trust_view` and `qr_view` rather than nothing.

Worse than unreachable, it would have been WRONG where it did run. On a
machine with no Qt the check would have reported

	style: 2 widgets, all rendered

-- a true sentence about a narrower population, which is precisely the fault
the gate was written to catch. sec 228 says a branch with one reachable shape
is a branch no sabotage can test; this one had that and a misleading pass
besides.

**Asking the filesystem removes both.** `ls gui/*.cpp` is the same population
on every machine, needs no `_view` pattern to filter it -- sec 217's rule that
a population derived from a naming convention is an enumeration in disguise --
and a future non-widget source there will fail this and have to be exempted
out loud.

### Both branches were made to fail

	a widget nothing includes  style: widgets qtty_render_test does not
	                           use: sched_view                       rc 2
	included but never built   style: ... does not use:
	                           sched_view(unused)                    rc 2
	no widget sources at all   style: no widget sources were found, so
	                           this checked nothing                  rc 1

The second came free: the scratch directory the probe ran in could not be
created, so the snippet ran somewhere with no `gui/` at all and refused
exactly as written. An empty-population guard that has been seen to fire is
the difference between a gate and a gate-shaped thing, and this one is now
the third in this tree -- after the sabotage census and the log gate -- to
say so in its own words rather than pass quietly over nothing.

## 250. Small enough to visit whole

`trust/` is four sources and three operations, and `trust.h` writes the
transition table out in prose:

	self -> pinned     permitted; an operator said so, out of band
	self -> adopted    REFUSED; nothing authenticated that
	self -> self       refused, like any other re-anchoring
	pinned or adopted -> anything else    refused, as before

`trust_test.c` walks that with hand-chosen sequences. **The state space is
6561 sequences of four**, which runs in less time than drawing random ones
would -- so `trust/test/trust_walk_test.c` visits all of them.

	trust_walk_test: 97257 checks, 0 failure(s); every sequence of 4
	operations over 3 keys agreed with the header's table (7719 ok, 11964
	anchored, 6561 unchanged, 1158 self-to-pin)

**A fuzz harness reports what it happened to reach; this reports that there is
nothing else to reach.** Where a module is this small, that is the stronger
claim and it is cheaper to make.

The model was written from the header rather than from `trust.c`, and it
agreed on the first run -- which is the outcome worth having and not the one
to assume: sec 245's model was wrong on case 91, and being wrong is the
ordinary fate of a new model.

### The property that needs no model

Every step asserts that a call not returning OK left the anchor
**byte-identical**, `memcmp` over the whole struct. An anchor is what every
other decision in this library is measured against, so a refusal that moved
one is the worst failure the module could have.

That is sec 245's property, and this is where it is asked properly: there,
both refusals the harness could produce returned before the module touched
anything, and the sabotage survived until a mid-flight failure was added.
Here **every refusal is reached from every reachable state**, because the walk
is exhaustive -- there is no arrangement left for a refusal to hide in.

### No CHECK macro, because a line number is not enough

Every assertion here has a SEQUENCE to report. The controls:

	trust-only-a-pin-replaces-a-self-root
	  after [self(1) adopt(0)] the model says already anchored and the
	  module says ok
	trust-the-same-key-is-an-echo
	  after [pin(0) pin(0)] the model says already anchored to this root
	  and the module says already anchored to a different root

A failure naming `trust_walk_test.c:172` would leave a reader to work out
which of 6561 walks it was. The style gate's rule is that a failure line names
its suite; here the suite is not enough to find the case, so the line names
the path that produced it.

**The first sabotage is the one that matters.** Widening the join from *a
self-root may be replaced by a pin* to *a self-root may be replaced* re-opens
the window a self-root exists to close: a node trusting itself for want of
anybody else could then be taken by whoever answers first. The header calls
that asymmetry the whole design, and until this file nothing walked
`self -> adopt` at all.

## 251. The answer that must not read as a fault

`claim.h` says it about `FZN_CLAIM_ERR_HELD` in its own words:

> AN ANSWER RATHER THAN A FAULT -- it is the expected result for every
> process but one, and a caller that logs it as an error will fill a log on a
> working host.

A consumer showing a person *could not start: error -2* has alarmed them about
a host that is fine, and this is the line most consumers will show most often:
every window but the first gets it.

`cli/claim_print` is the surface for that, and for the three answers beside
it. The distinctions are all in `claim.h` and none of them survives into an
integer a person reads:

	this process owns it       nothing; go on
	this process let go        nothing; another may take it now
	another process owns it    nothing; this is the design
	the backend cannot say     an operator -- the store is unusable
	                           rather than busy
	the caller lost track      a bug in the consumer, not the host

### Two judgements, going opposite ways

**MALFORMED and STATE share a line.** A null argument and a release without a
take are both the consumer having lost track of which process it is in, the
person reading cannot act on either, and splitting them would draw a
distinction for the code's benefit on a surface the code does not read. sec
201.

**But OK does not.** The first draft read `fzn_claim_held` and reported an
unheld OK as ELSEWHERE -- which is a sentence about another process nobody had
asked about, after this one deliberately let go. A release returns OK and
leaves the claim unheld; a take returns OK and leaves it held; the code alone
does not say which way round the caller is. `FZN_CLAIM_LINE_RELEASED` is the
fifth state, and it was found by reading the arm back rather than by any test.

### The seam's convention, read rather than assumed

The first fixture set the seam to succeed with `held_out` clear, expecting
contention. The module said otherwise: the seam's return means *did we get
it*, and `held_out` disambiguates only a FAILURE -- zero with held set is
contention, zero with it clear is a backend that could not answer.

The test was wrong and the module was right, which is the ordinary case and
worth the sentence because the fixture LOOKED like the contended one. Reading
`fzn_claim_take` settled it in a minute.

### The three controls, and the one the fifth state exists for

	the working case alarms       the expected result for every process
	                              but one was reported as a problem
	broken and busy collapse      a host that cannot arbitrate at all was
	                              not reported as such
	a release reads as contention a release was reported as somebody else
	                              holding the claim

The third is the one the fifth state exists for, and it fails on the
assertion that was written before the state was.

### Three lenses swept, and empty

Recorded so the next reader does not re-run them. **No parser without a
harness remains** -- `session/aead.h` is the only decode-shaped function
outside the ones already fuzzed, and it is a crypto seam. **`state`'s
permutation property is already exhaustive**: `state_test.c` carries a
`next_permutation` and walks its record set whole, so sec 250's technique is
not new to this tree and that suite pioneered it. **The link-to-sched seam is
exercised end to end** by `link_test.c` and `sim/test/provision_test.c`, both
of which call `fzn_link_snapshot` and `fzn_sched_select` in one test.

An empty result is a measurement only with its method attached, and these
three say where not to look next.

## 252. The code that exists for a reader, with nothing to read it

`prekey.h` says it outright:

> THE ROLLBACK CASE, and it has its own code because it is the one an
> operator has to see. A stranger who replays a host's older, real,
> correctly-signed record is offering a key the host has moved on from -- and
> if that key has since leaked, accepting it is the whole attack. Nothing
> about the bytes is wrong, which is why the signature cannot catch it.

**A code that exists for a reader, and nothing showed it to one.** Seven codes
reach a consumer and every distinction among them dies in the integer a person
sees -- including that one, and including the one the header calls not an
event at all.

`cli/prekey_print` has nine states because each has a different reader.

### One code, three events

A first pin, a rotation and a re-delivery all answer `FZN_PREKEY_OK`, and
`prekey.h` says of the third that it is *"ordinary and is not an event"*. A
consumer showing a key change every time a record is redelivered teaches a
person to ignore the one that is real -- the same failure as `claim.h`'s HELD
and `trust.h`'s UNCHANGED, met a third time.

**So the printer takes the peer BEFORE and AFTER.** Both OK cases leave the
record stored and the difference is whether anything moved, which no return
value carries and no single snapshot shows. A caller copies a small value with
no allocation behind it; the alternative was collapsing a distinction the
header spends a paragraph keeping.

### The direction that gets confused

`FZN_PREKEY_ERR_SIGNER` is THIS host having no verifier. A consumer rendering
it as *this peer could not be verified* **has accused somebody of something
the host did** -- and it is the easy mistake, because a forged record and a
missing verifier both stop a peer being pinned.

That is why `SIGNER` and `MALFORMED` share a line and `SIGNATURE` does not:
the first two are this side's fault and the reader cannot act on them
differently, while the third is a statement about the record.

`SHAPE` gets its own line for the same reason pointed the other way. Bytes
that are not this protocol's shape are usually a version difference, and a
line that does not say so leaves a reader suspecting a peer over a version
number.

### A conditional assertion is one that may never run

The first test drove the SIGNER case with a verifier that returns zero, and
asserted the mapping behind an `if`. Measured: a verifier that RETURNS no
yields `FZN_PREKEY_ERR_SIGNATURE` -- correctly, since a verifier saying no is
the signature not verifying -- and only an ABSENT one yields `SIGNER`.

So the interesting branch never executed, behind an `if` that read like
caution. It uses a NULL verifier now and asserts unconditionally, plus that
the two lines differ, which is the confusion the state exists to prevent.

### The three controls, and the one built for the header's own sentence

	a rollback does not announce itself   the case prekey.h says an
	                                      operator has to see does not
	                                      announce itself
	the missing verifier blames the peer  the line accuses the peer of
	                                      something this host did
	a re-delivery reads as a rotation     reported as a change

## 253. One code, and the day somebody's identity disappeared

`persist.h` names the distinction and hands it to a caller:

> Nothing stored under that slot. An ordinary state on first run, and its own
> code so a caller can tell it from a backend failure -- which is the
> distinction that decides whether to mint a fresh prekey or to stop and
> shout.

There is a second distinction inside that one, and no code carries it at all.
**`FZN_PERSIST_ERR_ABSENT` on a first run is routine; on a host that has
stored before it is data loss** -- and the store answers identically either
way. Nothing but the caller's own context tells them apart, and nothing else
in the system will report it.

`cli/persist_print` takes that context as `had_stored` and says so plainly in
its header: **a caller passing it wrong turns data loss into a routine line.**
It is the one argument here the library cannot check, and it decides whether a
person is told anything at all.

### And a corrupt file is not an attack

`persist.h` rules it out in as many words -- *a peer cannot reach these bytes,
so this is a corrupt or foreign file rather than an attack* -- and a person
told their identity is corrupt will assume the worst thing it could mean
unless the line says otherwise. The line also carries that the file is **left
alone rather than repaired**, because it is still there and somebody may want
it.

That is the same shape as sec 252's SHAPE arm, one layer down: the reading a
person will take is worse than the truth, and the surface is where the truth
gets said.

### Every slot names itself

Losing a trust anchor and losing one peer's ratchet chain are not the same
event. The test requires all five slots to produce five different sentences,
which is the assertion that catches a printer naming the state generically.

The slot words are **not** a public `fzn_persist_slot_str`. The strings here
are written to sit inside a sentence a person reads, and a consumer wanting
the name alone wants a different string -- adding a public renderer is a
decision about that module's surface rather than something a printer takes on
its way past.

### What `had_stored` must not touch

Asserted directly: a corrupt file reads the same whether or not the host had
stored before. A parameter read on more paths than its contract names is a
dependency nobody documented, and here it would mean a corrupt anchor
described two ways for no reason.

### The two controls

	data loss reads as a first run    a host that has stored before,
	                                  finding nothing, was told it was a
	                                  first run
	the attack is not ruled out       the line lets a person assume the
	                                  worst thing a corrupt identity
	                                  could mean

The second entry was first written with a contrived replacement -- an `if (0)`
around a fragment of the original string -- and rewritten to be exactly the
substitution that was run by hand, then applied through the table to confirm
it compiles and fails. **A sabotage entry that has never been applied is a
claim about a file, not a test of it**, and the difference is one command.

## 254. The question a per-slot line cannot answer

`cli/persist_print` says what happened to ONE slot, because that is what a
caller asks one call at a time. A person starting a program wants the other
question -- **did my identity come back** -- and that is a fact about the set:
four slots read and the anchor missing is a different morning from four slots
read and one peer's chain missing.

`gui/persist_view` shows the printer's line per slot and adds the aggregate,
with the worst row deciding the summary as `gui/manifest_view` and
`gui/ledger_view` do. A person scanning five lines reads the first sentence
and stops, so one loss among four recoveries has to be what that sentence is
about.

	trust anchor    ATTENTION -- this host's trust anchor is gone, and
	                this host has stored it before ...
	own prekey      read back: this host's own prekey secret
	...

	persist_view    needs 35 columns to say "did not come back"

### A first run is not a partial recovery

Nothing stored anywhere is the most common startup there is. A screen
counting those slots as state that did not come back would alarm every new
install about a loss that never happened -- so FRESH and INCOMPLETE are
separate states rather than degrees of one, and the sabotage that merges them
fails on the assertion written for it.

### The rows stay in slot order

Not sorted by badness. Two readings of one host line up, and a person learns
where to look; sorting would move the rows under them the moment something
went wrong. Asserted directly -- the first row is the first slot and the last
is the last -- because it is the kind of thing a later edit improves away.

### Two gates caught it before any test did

Adding `gui/persist_view.cpp` failed `make style` twice in a row, each time
for a different omission, and neither is something the suite could see:

	sabotage: gui/persist_view.cpp has no entry and is not listed as
	guard-free

	style: widgets qtty_render_test does not use: persist_view
	persist_view(unused)

**The second is sec 249's gate catching a widget added four sections after it
was written.** That is the case it exists for -- a widget joining the build,
the suite and the style gate without joining the one check that puts it in
front of a terminal -- and it fired on its author within the hour. The
population being derived rather than listed is what made that automatic: both
gates learned about the file from the build, not from somebody remembering to
add it.

## 255. The paragraph a consuming build reads

`README.md` refuses to repeat inventories, and sec 63 records what it cost
when it did. What it does carry is the FORMAT of `make manifest`, because a
consuming build reads that paragraph to learn what the lines mean.

It named five kinds. The target emits eight.

	emitted   backend binding generated header include source subsystem
	          version
	named     source generated include binding backend

**`subsystem` is how the front ends are found at all** -- sec 225 added it
after the CLI and GUI were named by one literal line -- and a consumer
following this paragraph would not know those lines exist. `header` is
today's, and `version` had never been mentioned.

That is `evidence.md`'s countable present-tense claim about the tree's own
shape, in the file most likely to be read and least likely to be re-derived.
It is the same fault as sec 241's and sec 249's summary lines, one layer out:
a description narrower than the thing it describes.

### A gate over the kinds, not the prose

`make style` now asks that each key the manifest emits appear somewhere in
`README.md` as a backticked word.

	style: 8 manifest kinds, each named in README.md

**Only the kinds.** The paragraph can be rewritten freely and only a kind
going unmentioned fails -- a gate over wording is a gate somebody deletes the
first time it argues with a rewrite. Both arms were made to fail: dropping
`header` from the sentence, and a probe whose manifest emits nothing, which
refuses rather than passing over an empty set.

**This is the fourth population this session that turned out narrower than
its subject** -- the sabotage census over headers, the log gate over
severities, the render sweep over widgets, and now a README over the format
it documents. In every case the fix was the same shape: ask the build what
exists rather than keeping a second list, and make the check say what it
checked.

## 256. Is my own policy doing this?

`wire/relay.h` argues the distinction at length and says what collapsing it
costs:

> EXHAUSTED says the frame has travelled as far as it was sent to travel,
> which is every frame's ordinary end and says nothing about this host;
> REFUSED says this host declined a subsystem it could have carried ...
> Collapsing them would make a misconfigured policy indistinguishable from
> normal traffic reaching the end of its budget.

Two negative integers, and an operator watching traffic stop cannot tell
which is happening. **Is my own policy doing this** is the question a person
asks first, and `cli/relay_print` is where it gets answered.

That is the fifth module this session whose header names a distinction that
dies in the integer a person reads, after `sched`, `claim`, `prekey` and
`persist`. Every one of them was found the same way: read the header for the
sentence that says *this code exists because somebody has to see it*.

### The row an operator would change

A refusal names the subsystem AND says whether the table has a row for it.
A ceiling written down as zero and a subsystem with no entry at all are
**different edits** -- the first is a line to change, the second is a line to
add -- and sending somebody to find a row that does not exist is worse than
not naming one.

The zero is where relay.h's own subtlety lives: `fzn_relay_budget` with an
`allowed` of zero answers OK with a budget of zero, while a policy `fallback`
of zero answers REFUSED. Same ceiling, deliberately different status, and sec
233 records `relay_fuzz` asserting the equivalence flatly and failing on its
first run against code that was right.

### Written outside the tree until the commit

This section was held in a scratch file and appended in the same command as
`git add`, because two earlier sections -- sec 253 and sec 255 -- were swept
into another session's commits while they sat in `project.md` waiting for a
suite to finish. Nothing was lost either time and both are in history under
somebody else's message, which is a record problem rather than a code one.

**The window is the whole of it.** `CLAUDE.md`'s rule is to stage by path,
and staging by path does not help when the file is written minutes before the
commit and another writer commits in between. Writing the prose somewhere
else and appending it at commit time closes the window to a second, and costs
nothing.

## 257. A printer built on an absence I manufactured

`local/vocabulary.h` says `fzn_vocabulary_names` exists because `admit`
returns one verdict for two situations that want opposite responses, and that
a daemon logging both as "denied" **sends an operator to the wrong half of
the system**. It also records that this was found by writing `cli/peer_print`,
which had to report the reason and could not.

I checked who calls that accessor:

	grep -rn "fzn_vocabulary_names" --include=*.c . \
	  | grep -v "^./local/vocabulary.c" | head -5

Five lines came back, all from the module's own source and test. I read that
as *an accessor built for a surface that was never written*, and wrote
`cli/vocabulary_print` -- header, source, four states, an escaped verb.

**`cli/peer_print.c:168` calls it.** The hit was below the `head -5` cut.

### The rule I already had, pointed at a search

`evidence.md` lists four ways to manufacture an absence and names this one
exactly -- *the view*: `grep ... | head` over a hit below the cut, where the
command exits 0 and prints nothing. It also says, of checks, **never reduce
the output before you know it passed**, and the same sentence is true of a
search whose answer you are about to act on.

What made it survive is the asymmetry that entry warns about: *a loose
pattern makes you work; a short one makes you comfortable.* Five tidy lines
from one module read exactly like a complete answer.

### What the duplicate would have cost

`fzn_peer_print` takes the verb and the rules and returns both
`verdict_out` and `named_out`, and renders the same four answers. Its escape
is also stricter than the one I wrote: it escapes `"` and `\` as well as the
non-printables, so a verb cannot close the quoted region the line puts it in.
Mine let a quote through.

So the duplicate would have been a second surface for one question, with a
weaker escape, drifting from the first. It is deleted rather than committed.

**The cheap check I skipped costs one command.** `grep -c` before `head`, or
no `head` at all on a search that decides whether to write a file. Reading
the header's own last sentence would also have done it: it says the accessor
was found by writing `cli/peer_print`, which is a fair hint about who calls
it.

## 258. Not held, and the store that stopped answering

`record/store.h` keeps five codes apart and names what collapsing two of them
costs, in a sentence that is an operational harm rather than a tidiness
argument:

> Kept apart from ABSENT because "not held" is normal and "the store is
> broken" is not, and a caller that treated a broken store as an empty one
> would REFETCH THE WORLD.

And of the first: *what a reader gets for everything the owner has not
fetched yet, which on a busy host is most of what it asks for.* **The
collapse hides inside ordinary traffic** -- a host whose store has stopped
answering looks exactly like a host that simply does not have much yet, and
what it does about it is ask the network for everything it already has.

`cli/store_print` is the surface. Nothing rendered these: the search for one
was run over `cli/` and `gui/` with no `head` on it, after sec 257.

### The one nobody expects

`FZN_RECORD_STORE_ERR_MISPLACED` is *what came back IS a record and is not
the one that was asked for*. That is not a failure to find; it is a **wrong
find**, and `record/store.h` checks it before any signature for that reason.

Folded into "damaged" it would describe a filing problem as a corruption one
and send somebody to inspect a file when the fault is the index. It is the
only line here that opens with ATTENTION, and the assertion for it is that
the two sentences differ.

### Where the lens ends

sec 257 said this family was exhausted and it was not: `record/store` and
`tree` had no surface, and I had read their grep lines without checking. That
correction is this section.

`tree/tree.h`'s hit is *"A consumer shows both at top level, so the
distinction would be"* -- an argument about how a consumer displays a tree
rather than a code that needs explaining, and `tree/` returns no error enum
at all. So it does not want one, and the family is now genuinely closed: every
module whose header names a human reader either has a surface or has been
read and found not to need one.

## 259. For ever, pinned

`link.h` describes a permanent starvation and does not apologise for it:

> this table never reorders: entries are appended and never removed, so the
> links past the bound are the same links every call ... A consumer can be
> told the network is down while a healthy link sits one index past the end,
> FOR EVER, and it never gathers evidence on that link either because nothing
> is ever sent on it.

`link_test.c` checks the bound with two links and a cap of one. It does not
check the FOR EVER -- that the same links are dropped on every call, and that
nothing a consumer can do to a starved link brings it into view.

	link_fuzz: 20000 cases, 9142 starved, 10858 fitted, 5321 observed a
	starved link, 1538 full tables, 1577 empty, every snapshot was the
	first N in registration order

### It pins the behaviour as the design, and will fail when that changes

This is sec 243's shape: a limit somebody could meet, read as a defect, and
"fix". Both obvious fixes are worse than the behaviour -- rotation makes
which links a consumer sees depend on when it asked, and reordering breaks
the cursor `link/` guarantees. **The harness is expected to fail the day
somebody adds rotation**, and that is its purpose: the change has to come
here and say so rather than being discovered by a consumer whose selection
started wandering.

Its sharpest property is the fourth, and it comes from the header's sharpest
sentence. A starved link "never gathers evidence ... because nothing is ever
sent on it" -- so the case worth driving is a consumer that gathers evidence
on one ANYWAY, by hand: an ack, a loss and a usability change, and the link
is still invisible. 5321 cases did exactly that.

### The first failure was the harness's, and it was padding

	MODEL: two identical snapshots differ, so which links a consumer sees
	depends on when it asked

Two snapshots of one table, compared with `memcmp`. `fzn_sched_candidate_t`
is 24 bytes holding 22 bytes of fields -- two of padding after
`loss_permille` -- and the arrays were separate stack buffers, so the
comparison was reading whatever had been there. The module was right and the
model was wrong, which is the ordinary case for a new model and the third
time this session.

`memset` before each call fixes it and tests more than the field-by-field
comparison would have: with the padding zeroed, `memcmp` now asserts that
every byte of the answer is identical rather than every field.

## 260. The wrong answer that was chosen

`claim/` is two operations over a seam that answers three ways for one of
them and two for the other, so every sequence of five is 3125 walks --
`trust`'s trade from sec 250, and `claim/test/claim_walk_test.c` takes it.

	claim_walk_test: 46875 checks, 0 failure(s); every sequence of 5 steps
	agreed (3125 ok, 6948 lost-track, 2427 held elsewhere, 3125 backend,
	698 failed releases)

**The seam is part of the state**, which is what makes this worth walking
rather than testing by hand: `fzn_claim_take` asks the backend and then reads
`held_out` to tell contention from breakage, so one operation has three
outcomes chosen by an answer the test supplies, and the sequences that matter
are where those interleave.

### A refusal moves nothing -- except the one that moves something on purpose

`fzn_claim_release` clears `held` BEFORE asking the backend, and leaves it
cleared when the backend refuses. `claim.c` says why:

> `held` IS ALREADY CLEARED, so this object now believes the claim is gone
> and the world may disagree ... Of the two wrong answers, refusing to act is
> the one that cannot desynchronise a ratchet.

**Both answers are wrong and one was chosen.** A reader meeting a failed
release that still cleared the flag would reasonably call it a bug, and the
fix -- clear it only on success -- puts the process back in the state that
comment rules out.

So the walk ASSERTS it rather than exempting it, and the sabotage is the fix
itself:

	claim-a-failed-release-still-lets-go
	  [take=got release=fails] failed to release and this object still
	  believes it holds the claim, which claim.c rules out as the answer
	  that can desynchronise a ratchet

That is sec 243's shape and sec 259's: a limit or a deliberate wrong answer,
pinned so the change has to come here and say so.

### The first control was broader than the property

It removed the `held = 0` line outright, so successful releases broke too and
the walk failed at `[take=got release=ok]` -- a real failure about the wrong
thing. The entry uses the precise edit instead, moving the clear onto the
success path, which is what somebody would actually write. **A sabotage that
breaks more than the property tests the suite, not the guard.**

## 262. Which reason, and four ways to get the question wrong

Sec 261's find had a shape worth reusing: a property whose only witness is
an INCIDENTAL caller. `fzn_ct_memeq`'s reach was held by `record_test`'s
64-byte signature -- 24 calls out of 30.5 million -- and by nothing that
was aimed at it. The mechanical form of that question is: **which public
functions does no test name?**

The population comes from `make manifest`, so it is the set `make install`
ships rather than a naming convention over the sources: **439 functions
declared across 83 headers**, against 165 test sources and 208 others.

### The instrument was wrong four times, in four directions

Each fault changed the finding list, and only two of the four announced
themselves.

	1  the USE pattern required a trailing paren, so it could not see a
	   function passed AS a callback. Invented three findings --
	   fzn_catalog_add_wins and its two siblings, which four test files
	   wire up as `{ fzn_catalog_add_wins, NULL }`.

	2  the parser took the FIRST fzn_*( in each ;-chunk, so a
	   declaration whose preceding comment names another function was
	   dropped. Lost fzn_copyright and fzn_peer_group_verdict.

	3  it skipped a ;-chunk beginning with `#`. An include guard carries
	   no semicolon, so `#ifndef ... #define ... int fzn_ct_memeq(` is
	   ONE chunk, and the first declaration of every header went with
	   it. 439 became 366.

	4  it rejected a name preceded by an operator, to exclude calls. `*`
	   is a pointer as well as a multiply, so `const char
	   *fzn_agree_err_str(` read as arithmetic. Dropped 73.

**Faults 1 and 2 are the expensive kind and 3 and 4 are not**, which is the
opposite of how they look. Three and four are huge and were caught within a
minute, because a count that moves by 73 is a count somebody reads twice.
One and two are small, plausible, and move the list in the direction that
makes a tree look tidier -- and a dropped declaration is not a finding you
argue with, it is a function nobody ever examines.

What caught 3 and 4 was a second count that does not share the parser: a
crude scan of the same stripped text for `fzn_*(`, with the residue printed
rather than assumed. What caught 1 and 2 was reading the findings.

### And the rule that replaced them does not discriminate here

A declaration is a name at BRACE DEPTH 0; a call in a header lives inside a
`static inline` body and a prototype never does. That is the right rule and
**its agreement with the crude scan is not evidence for it**: the residue is
zero because no header inline body in this tree calls an `fzn_` function at
all. The two counts agree, and there is currently no case where they could
disagree, which is `evidence.md`'s own test for a control failed honestly.

### The one that was a gap

Eight names survived the first list, four the second. Three of those four
are accessors held through a caller, and are waived by name with the reason.
The fourth was mine, from sec 247: **`fzn_sched_excluded_by`**.

`sched_test.c` already pinned the boolean either side of it --

	expect(!fzn_sched_admits(NULL, &VOICE), "a null link admits nothing");

-- and a boolean collapses five reasons into one answer. So the one thing
the accessor says over `fzn_sched_admits` was the one thing nothing asked.

Measured rather than argued. `FZN_SCHED_EXCLUDED_MALFORMED` was replaced
with `FZN_SCHED_EXCLUDED_UNUSABLE`, which preserves `fzn_sched_admits`
exactly and maps to a printer state `sched_print_test` already exercises:

	make test: rc=0. The whole suite green.

It is caught now, at `sched_test.c:212`, and held by
`sched-a-missing-operand-blames-the-link`. **A missing operand is not a
link the consumer called down**, and a report that says so blames the wrong
party for a bug in its own caller.

### The sweep ships hand-run, and its waivers expire

`tool/public_reach.py`, not wired into `make style`: three waived names is a
waiver list, and a gate carrying one has been switched off by instalments.
It refuses two ways -- an unwaived name, and a **waived name that has since
acquired a test**, because a list that can only grow is one nobody prunes.
Both were made to fail before this was written.

### A number recalled rather than read

The waiver for `fzn_state_sound` first cited sec 233 for its narrower
contract. There is no such discussion; it is **sec 184**. The identifier
was completed rather than read, which `evidence.md` names as the one fault
class that measuring again cannot catch -- every re-run agrees with itself.
It was caught by opening the file, which is the only thing that catches it.

**And then this section did it again, four paragraphs up.** The accessor's
origin was written as sec 250 and is sec 247, in the entry whose subject is
that fault. Two for two: every section number written from memory here was
wrong, and both were correct-looking. The habit that works is not care, it
is `awk '/^## /{s=$0} /<name>/{print s}'` before typing the digits.

### Where this landed, and what it took to put it right

`tool/public_reach.py`, the `sched_test.c` assertions and the sabotage
entry above went into **`02d3b3b`**, whose subject was the catalogue's merge
classes. They were staged by name and verified with `git diff --cached
--name-only`, and the fuzzypickles session ran `git commit` in this shared
clone before this one did. The index is shared; **staging by name protects
the commit you make and not the one somebody else makes.**

This session's answer was to leave it: both commits were pushed, and a peer
reporting the holder's instruction is not authority for this session to act
on. It was split anyway, on the holder's decision, and the split is right --
they are `313a98b`, *"tool: a public-reach sweep, split out of a commit that
swept it up"*, 169 insertions over exactly those three files, with the four
commits that followed cherry-picked on top.

**And this paragraph is what the split broke.** It was written as the
forward-only mitigation -- a pointer saying where the work really was -- and
a pointer to a sha is a pointer to something a rebase can rewrite. It named
`02d3b3b` twice, in the present tense, about a commit that is no longer an
ancestor of anything. **The mitigation for a rewritten history needed
rewriting when the history was rewritten**, and nothing but reading the log
would have said so: the sentences stayed grammatical and confident.

What it cost is nearly nothing, because it was caught the same day by
noticing that four commit shas in `git log` were not the ones this session
had pushed. What it would have cost is a reader following a sha into
nothing. The two mentions in sec 263's table below are a different thing and
they stay: those record a QUESTION somebody asked at the time, not a claim
about where anything is now.

**A rebase under a running session is invisible until you look at a sha**,
and this session did not look for 44 minutes. The timeline, from the commits
themselves rather than from memory:

	00:07:53   the rewrite finishes, four commits re-created
	00:31:46   this session commits sec 265 -- onto the new history,
	           without noticing
	00:51:17   commits sec 266, then reads `git log` for another reason
	           and sees four shas it did not push

Nothing surfaces it in between. `git status -sb` says in sync, because it is
-- against the rewritten origin. `git fetch` succeeds, the commit succeeds,
the push succeeds. This session reported at the time that it had "pushed
while the rewrite was in flight" and that this was luck; the timestamps say
the write missed the window by 24 minutes, so it was not luck and it was not
a near miss. **It was 44 minutes of working on a history that had changed,
with every routine check reporting normal.** The write-hold `.git/write-notice`
proposes is what makes the window visible at all, and it was held correctly
here by the session doing the rewrite.

**And an orphaned sha still resolves in the clone that orphaned it.**
fuzzypickles' point, and it is the reason a citation like this one is worth
checking from somewhere else: `git show 02d3b3b` works here, because the
object is still in this repository, and fails for anybody who clones. So the
author verifying their own reference sees it succeed and every reader sees it
fail -- the false negative pointed at the one person who cannot observe it.

## 265. A rule you keep by not writing something

Sec 264 asked why one rule went unswept for eight files. The answer is not
carelessness and it generalises, so it is worth stating apart from the
instance.

**Two rules of the same family, from the same pattern, measured the same
afternoon:**

	conservative state before any refusal   22 of 22 sites  held
	no `default:` in a state switch          16 of 24 sites  8 unswept

The first is kept by WRITING something -- `if (state_out) *state_out =
FZN_SYNC_UNMEASURED;` near the top of every printer, above every early
return. The second is kept by NOT writing something.

**A rule you keep by writing something is visible at every site that keeps
it, and its absence is visible at every site that does not.** So it can be
asserted where it lives: each printer's own test refuses a reassuring state
after a refused render. Demonstrated rather than assumed -- delete
`sync_print`'s early assignment and `sync_print_test.c:161` says *a refused
render left a reassuring state behind*.

**A rule you keep by not writing something is invisible at the sites that
break it.** Eight printers had a `default:` and there was nothing to read:
an absence at eight sites looks exactly like an absence at none, and no
test can assert the absence of a line. Only a sweep over the population can
see it, and sec 8's verification -- *adding a code to `fzn_split_err_t`
produces the warning* -- confirms the mechanism at ONE site, which is
exactly what a not-writing rule cannot generalise from.

So: **an entry stating a not-writing rule should name the sweep, not the
site.** Sec 264's does now, and that is the only kind of entry where the
distinction matters.

### The lens run over this document, and it closes

If not-writing rules are the ones that go unswept, the question is which
others this document states. Every tree-wide prohibition in it, checked:

	a host never writes bytes it has not verified   fuzzypickles' tree, and
	                                               their contract, not ours
	a record here never carries a chain            self-enforcing: there is
	                                               no field, and the layout
	                                               tests hold the length
	verify before storing, three instances         held by sabotage --
	                                               chain-store-verify-first,
	                                               disclose-verify-before-
	                                               handing-back, and the
	                                               commit-before-verifying
	                                               entry
	no `default:` in a state switch                the one that was unswept,
	                                               and sec 264 swept it

**One instance, and it had already been found**, so the class is closed
rather than open. Recorded because an empty sweep with no method recorded
licenses nothing: what was looked for was a prohibition asserted of the
whole tree, and what the others turn out to be is another tree's contract,
a property of a wire format, and three entries in the sabotage table.

## 266. The eight lines I moved, and the two nothing was reading

Sec 264 moved eight renderings out of a `default:` into a named case. The
suite passed, 118 suites and no failures, and every printer test ran at an
unchanged count. **That told me nothing about two of the eight.**

The question came from asking a different one. The `EXHAUSTED` state of sec
263 was witnessed only under Qt, so: is any printer LINE asserted only by a
widget test? The answer is none -- 0 of 187, and that hole does not exist
for lines. What the sweep found instead is that a large share of lines are
matched by no test's search term at all, and two of them were text I had
moved that afternoon.

	sweep_print       "removed "               nothing read it
	provision_print   "verified, and in date"  nothing read it

`sweep_print_test` reads five fragments off other lines -- *1 of 4*, *1
retained*, *3 the last known copy* -- and for the finished job it read only
the state. `provision_print_test` reads the root fingerprint and the text
prefix and never a verdict at all. So if the wording had gone with the move,
or a trailing space with it, the suite would have said 118 suites, no
failures. Both are pinned now and both were watched failing on a one-word
change: *removed* to *remove*, and *verified, and in date* to *verified, in
date*.

**This is `evidence.md`'s unproduced diagnostic, met from the other end.**
That rule is about a message no test produces; here the message is produced
on every run of two suites and nothing reads it. The loss is the same and it
is the wording rather than the refusal: the state channel is well tested, so
a wrong verdict word would keep every state assertion green while the line a
person reads said something else.

### The 85 is an upper bound and I am not reporting it as 85 gaps

The sweep says 85 of 187 lines match no search term. **The extractor
under-counts what the tests pin**: it reads `strstr`, `strcmp` and
`contains`, and it missed `revocation_print` and `capability_print` (four
assertions each) and `state_print`'s `"set by"`, which my own follow-up
grep then missed again by including a trailing space the test does not use.
Three artifacts in one measurement.

So the number is a ceiling on a question the instrument cannot settle, and
the same shape fuzzypickles reported for their 95 the day before: a
population where coverage is real and the sweep cannot see it. What is
settled is the two, because those were checked by hand against the two
tests and then made to fail.

**Pinning all 85 is not proposed.** Most are fragments -- `" over "`,
`"; root "`, `"holding "` -- that compose a line rather than carrying a
verdict, and a suite that asserted every one would break on any rewording
whether or not the meaning moved. The subset worth pinning is the sentence
that carries the verdict, and the test for it is sec 207's: **the part a
terminal would clip last is the part a person reads first.**

### What made it findable was changing it

Nothing here was introduced by sec 264 -- both lines were unpinned before I
touched them. What the change did was put me in front of the question, and
**a passing suite after an edit is the moment to ask what the suite read**,
not the moment to stop. The eight edits were verified by the compiler
refusing a new state; three of the renderings were verified by tests that
already read them; two were verified by nothing, and I had reported the
suite green over all eight.

### A sentence in five printers that no input can produce

The bracket is worth stating as a bracket. The strstr-only extractor says 85
of 187 lines are unread; using every string literal in every test as a
search term -- which over-counts coverage, since a word in a CHECK message
can be a substring by accident -- says 67. **So between 67 and 85, and the
instrument cannot narrow it further.** A third of the lines, either way.

Reading the residue rather than counting it turned up one family:

	"a capability this line could not format"    capability_print
	"an issuer this line could not format"       state_print
	"an anchor this line could not format"       trust_print
	"this line could not format"                 authz_print, provision_print

**No input produces any of them.** Each is the else of
`fzn_trust_fingerprint(key, print, sizeof(print)) == FZN_TRUST_OK`, and that
function fails on exactly three conditions: a null key, a null destination,
or `cap < FZN_TRUST_FINGERPRINT_LEN`. At all five sites the destination is a
local `char print[FZN_TRUST_FINGERPRINT_LEN]` and the capacity its own
`sizeof`, so two are impossible by construction. The key is
`policy->capability.b`, `trust->root`, `card->root`, `chain->capability.b`
and `row->issuer` -- **every one the address of an ARRAY member** of a
struct the function has already refused when null. So the third is
impossible too.

**They stay, and the reason is a gate.** `status_gate.py` refuses a library
source that discards a returned status, so the call must be checked; and a
check must have an else. What would be wrong is calling it and ignoring the
answer, which is the failure the gate exists for. The branch is also the
right thing to keep if the key ever stops being an array member, where the
alternative is a truncated fingerprint -- the one output `trust.c` says it
must never produce, because a prefix is indistinguishable from a whole one
at a glance.

So the code is right and the silence was not: **five human-facing sentences
that cannot be reached, in branches a gate requires and that are worth
keeping.** What that cost was a reader meeting one and taking it as evidence
the path is exercised.

`cli/sched_print.c` already says out loud that its MALFORMED case cannot
arrive, and these five said nothing -- one site with the idiom and five
without, which is this session's recurring shape and not a new one. All five
say it now, naming the three conditions and why each is impossible there.
Nine lines added to each file and nothing removed.

## 267. The same eight, on the other side of the seam

Sec 264 named the state each printer's `default:` was absorbing and added a
gate so one cannot come back. **The gate read `cli/*_print.c`, and the
widgets switch on the same enums.** Eight of them carried a `default:` over
`switch (said)`, and they are the same eight modules -- capability, journal,
provision, revocation, state, sweep, sync, transfer.

So sec 264's own finding, repeated within hours by the session that wrote
it: **a rule applied to the population that produced it rather than to its
subject**, and a gate is not exempt from that just because it is mechanical.
A gate's population is a choice somebody made, and mine was the file list I
happened to be editing.

### What is different here, and it is not nothing

Every widget default mapped to the **conservative** state:

	capability_view   HOLDS_NOTHING      journal_view    UNTRACKED
	provision_view    NOTHING            revocation_view UNREADABLE
	state_view        UNREADABLE/NOTHING sweep_view      NOTHING
	sync_view         UNMEASURED         transfer_view   NOTHING

That is the good kind of fall-through, the one `provision_print` keeps: a new
state arriving at a widget was drawn as *nothing known* rather than as
another state's sentence. Wrong and safe, which is the direction
`harmonization.md` settles for a surface that cannot say -- so unlike the
printers, **nothing here was one edit from telling somebody a comfortable
lie.**

**What it cost is the rule's enforcement rather than its answer.** Sec 193
asks that a printer's new state change the widget in the same commit, and
the only thing that can make that happen is the widget failing to compile.
With a `default:` it compiles, the widget says *nothing known*, and the
state exists on the screen's other side unmentioned.

### The compiler enumerated it, not a pattern of mine

Six instrument faults in one day is enough to stop writing the seventh. Each
widget's `default:` label was deleted and the file compiled: `-Wswitch` then
named exactly what the switch no longer handled, one enumerator per widget,
and every one of the eight was the printer's own ZERO state mapped to the
widget's conservative one. So naming it is behaviour-identical by
construction rather than by my reading.

	before   all eight compiled silently with a spare state added
	after    all eight REFUSED it

The gate covers 43 files now -- 24 printers and 19 widgets -- and matches on
the switch's subject, `state`, `stream_state` or `said`, so
`provision_print`'s correct error-to-refusal default still survives it. Put
a `default:` back in `sync_view` and it names the file.

### A first draft of the probe was invalid C++

Worth recording because it wasted a cycle and the shape recurs: the first
attempt replaced each `default:` with `case (fzn_probe_unreachable)0:`, a
cast to a type that does not exist, so all eight failed to compile and the
report read *compile failed* eight times. **A probe that cannot compile and a
probe that finds nothing are one line apart in the output**, and the only
reason it was not read as "no widget absorbs anything" is that the failure
was loud. The version that worked removes the label and lets the compiler
speak, which is also the version that needed no cleverness.

## 268. Two ways to verify with less than you think

`make style` was red from `ef9fe5a` to `3ca0eff` -- 22 commits, about a day --
on two specification headers not in `HDRS`. Both sessions working this tree
reported passing verification throughout, and both were right about a
narrower thing than they said.

**fuzzypickles ran the TOOL and not the TARGET.** Their report, in their
words: they ran `python3 tool/style_gate.py` after every edit and it passed
every time, and it "is a NARROWER INSTRUMENT that does not run the header
check at all. Every verification I reported was true and about the wrong
population."

**This session ran the target and read a TRUNCATED run.** `make style` stops
at the first failing check, and the header check is twelfth of nineteen. So
seven checks did not run for 22 commits:

	132 test sources, all reached by `make test`
	153 test sources, every failure line names its suite
	40 error renderers, all walked by err_str_test
	19 widgets, each one used by qtty_render_test
	8 manifest kinds, each named in README.md
	version/version.h and VERSION agree
	project.md says nothing twice and names no missing file

Four of those bear on work committed here in that window -- eight widgets
changed, five test files edited, assertions added to four suites.

**And the part that is mine rather than shared: I noticed the truncation and
repaired one seventh of it.** The words at the time were *"the gate aborted
at the HDRS check before reaching the project.md check -- so my section is
unverified"*, and `style_gate.py docs` was then run directly. That is the
population lens turned on a gate and then applied to exactly the one check I
had a reason to want. **The question I did not ask is what ELSE was after
it**, and it is the same question this section, sec 264 and sec 267 are all
about. Six checks, none of which I had a reason to think about, and that is
precisely why a gate runs them.

All seven pass, so nothing was broken. What was wrong for 22 commits is the
claim, in six commit messages and every report: "style passes except for the
other session's two headers" describes a run that stopped before half its
work.

### The two failures need different remedies

	the narrower instrument   run the TARGET, not the tool it calls
	the truncated run         when a gate stops early, enumerate what came
	                          AFTER the failure, not what you wanted from it

Neither remedy catches the other. Running `make style` would not have helped
me, because I did run it; running it to completion is what I could not do
while somebody else's check failed first, and the answer there is to read the
target and list the checks the failure hid.

**A gate that stops at the first failure is reporting on a prefix of itself**,
and the length of that prefix is a property of somebody else's work. That is
worth knowing before quoting a green half.

### Why the repair was one seventh, which is fuzzypickles' diagnosis

Offered in answer to this entry, and it is the part that makes it
transferable rather than an anecdote:

> You went looking for the check you had a reason to want. That is the same
> pull as a detector inheriting the shape of the query that produced it, and
> as a frame that has just been right. The repair you reached for was
> correct and its SCOPE was set by what you were already thinking about.

So this is not a new failure family but an old one arriving at a repair
instead of at a measurement. `evidence.md` has it twice already -- a count
inherits its detector, and a frame that has just been right is the hardest
to drop -- and neither entry is about fixing something. **The scope of a
remedy inherits the question that prompted it**, exactly as a count inherits
the query that produced it, and a remedy is where it is least visible:
nobody re-derives the scope of a fix that worked.

Both halves are signalled as `claude-guidelines` 7befe9d, in their voice for
theirs and mine in my own words, with the sentence that keeps them apart --
running `make style` would not have saved me, because I did run it.

## 269. A harness whose first draft caught nothing

`catalog/` had no fuzz harness. It has one now, and what it took to make it
worth having is the entry.

**The commit that added it said "the last module here with no harness" and
that was wrong.** Measured afterwards, by asking `make -n` what each harness
links rather than reading the rules -- `link_fuzz` names `$(LINK_OBJ)` and a
regex over the Makefile cannot see through a variable:

	26 harnesses link 33 of 53 library sources; 20 are linked by none

Three of the twenty are `catalog/copy.c`, `catalog/reach.c` and
`catalog/sweep.c`, so the directory has a harness and most of its code does
not. **And the twenty is not a gap list either**, which is the second half of
the correction: six are thin backends over vendored code
(`*_monocypher.c`, `*_linux.c`), `qr/qr.c` has `qrcheck` round-tripping 104
renders through quirc, and `claim/claim.c` and `state/state.c` are reached by
exhaustive walks rather than by anything named `_fuzz`. `*_fuzz.c` is a
FILENAME, and randomised coverage in this tree is not confined to it.

So the honest statement is neither "the last" nor "twenty gaps": it is that
this is one source of fifty-three, the population is legible now, and what
each of the twenty deserves is a separate question per source.

**The merit question first.** `catalog_test.c` runs 1221 checks; a harness
earns its place only by asking something those cannot. It can: `catalog.h`
claims the merge rule converges -- "two hosts adding a member agree whatever
order the assertions arrive in" -- and sec 243 tested that with TWO
assertions in opposite orders. **Two is where an order-dependence is least
likely to show.** A harness can ask it at ten assertions across three issuers
over a shuffled permutation, which is where a merge rule actually fails.

### The first draft asserted two things and neither was worth much

	1. links alone converge -- every permutation agrees on every edge
	2. the edge SET converges whatever the mix, even where membership
	   does not, because an assertion about an unknown edge adds it and
	   the resolver chooses between answers rather than removing a row

It passed 2000 cases. Then both guards sabotaged in `fzn_catalog_add_wins`
**survived it**, and reading why is the whole of what this entry is for:

**Property 1 is nearly vacuous.** With every assertion `present`, every
asserted edge is linked under almost any resolver -- a broken merge rule
still leaves it linked, because there is no assertion that would unlink it.
The property is true, it is what the header claims, and it discriminates
almost nothing.

**Property 2 is real and the sabotages do not violate it.** Dropping the
tombstone row removes unlink-only pairs IDENTICALLY in both orders, so the
edge set stays order-independent while being wrong.

### What made it catch anything is an oracle, and its shape was not obvious

The strengthening I reached for first was **wrong**, and checking it is the
only reason it is not in the tree: *compare the whole edge -- issuer, seq,
present -- between the two orders.* That is false. `fzn_catalog_add_wins`
ends with "two issuers agreeing: keep what is held, so the answer does not
depend on arrival order" -- and that comment is carefully scoped. The ANSWER
does not depend on order; **which issuer's row is stored does**, and
asserting otherwise would have made the harness wrong rather than weak.

What is predictable is narrower: an edge **one** issuer speaks about, with no
two statements sharing a sequence. There the rule gives that issuer's later
statement, so the outcome is its highest sequence -- computed from the SET
rather than read from the table. Ties are excluded because `offered->seq >
held->seq` keeps what is held on equality, so two statements at one sequence
resolve by arrival: that is the rule working and simply not something an
oracle can predict.

	7543 single-issuer edges checked against the oracle in 2000 cases

### Four sabotages, two caught, and the two that are not

	a later statement no longer supersedes its own issuer's   CAUGHT
	the tombstone row is not kept                             CAUGHT
	an equal sequence now supersedes (`>` becomes `>=`)       survives
	presence no longer wins across issuers                    survives

**Both survivors are invisible by construction and that is pinned here so
nobody quotes this harness for them.** The tie change is exactly the case the
oracle excludes; and with links only, a tie leaves `present` at 1 either way,
so no convergence check can see it. Cross-issuer presence only shows in sets
containing an unlink, which is where sec 243 already licenses divergence --
so the harness cannot distinguish that break from the documented behaviour.
`catalog_test.c` catches both, with 5 failures on the tombstone alone.

**And `catalog_test` is what the sabotage table reports for the two that ARE
caught, because it runs first.** The entries read

	catalog-a-later-statement-supersedes  CAUGHT  catalog_test.c:266
	catalog-a-tombstone-costs-a-row       CAUGHT  catalog_test.c:262

which is the table doing its job -- the question it asks is whether a guard
is held by anything -- and is NOT evidence about the harness. That the
harness catches both was established separately, by building it against each
sabotaged tree on its own and reading its own MODEL line. Worth separating,
because `evidence.md` asks for which check failed rather than that something
did, and a run where an earlier suite intercepts is exactly the case it
names.

**The number that matters is not 2000, it is 65**: cases where membership
differed by order while the edge set did not. That is sec 243's
non-property occurring on its own in random data, sixty-five times, with the
property that must hold holding throughout.

### And the harness had sec 86's own defect in it

The first run segfaulted on case 0. The resolve ops were passed as a compound
literal in the call, and `fzn_catalog_init` KEEPS that pointer -- so the
catalogue read its resolver off a frame that had returned. That is sec 86's
fault, a view into a stack buffer whose scope had ended, written by the
session that had spent the day reading about it. It was loud here only
because the frame was reused immediately; sec 86's took AddressSanitizer and
a dozen clean `make check` runs to find.

fuzzypickles' formulation, from the other end of the same question:
**a compound literal is not a lifetime.** Caller-owned state means the
caller's state must outlive the call, and a compound literal is the thing
that looks like it does.

## 270. An oracle, where sec 269 could only have properties

`catalog/reach.c` has a harness now, and it is worth putting beside sec 269's
because the two were written a day apart against the same module and one of
them is much stronger. The difference is not effort.

**`catalog_fuzz` could only assert properties.** Its subject is a merge rule
whose answer for a contested edge is order-dependent BY DESIGN -- sec 243 --
so there is no function from the assertion set to the expected answer. What
is left is convergence and invariants, and sec 269 records what that cost: a
first draft whose two properties were both TRUE and caught neither sabotage.

**`reach_fuzz` has an oracle.** "Which nodes do the roots reach" has one
right answer for a given set of edges, so a breadth-first search over an
adjacency matrix -- different code, different data structure, written from
`reach.h`'s sentences -- computes it independently. That is the shape
`evidence.md` calls a second witness, and the difference shows immediately:

	the walk follows a tombstone as if it were a link   CAUGHT
	a node is counted known through a tombstone         CAUGHT
	the walk stops after the roots' own children        CAUGHT

Three of three, each with a distinct message naming the disagreement, against
two of four for the property harness. **A property can only find that two
runs disagree; an oracle knows what the answer should be.**

### The model was wrong twice, and both times the library was right

Neither was a defect, and neither was predictable from the header.

**A root the catalogue has never heard of is REFUSED**, not walked from.
`reach.c` checks the roots before the frontier and says why: such a walk
reaches nothing and "would otherwise propose everything", which is a proposal
to delete the whole catalogue. The first draft treated that refusal as a
failure. The harness now asserts it -- 682 of 2000 cases -- so the guard is
part of the subject rather than something the fixture steers around.

**A node known only through a TOMBSTONE is not a known node.** `candidate()`
skips an edge that is not present, so a node mentioned only in an unlink is
not counted, not walked, and not proposed. That is right -- `unreachable`
proposes DELETIONS, and acting on a row that says "not a member" would be
acting on the wrong half of it -- and **`reach.h` does not say so**. The
implementation settled it, which is `evidence.md`'s unwritten precondition:
from outside, one that is true and unstated looks exactly like one nobody
thought of.

Both are recorded in the harness at the point they bite, because the next
person to write a model of this walk will get them wrong in the same order.

### What the fixture reaches

	2000 cases: 1103 with something unreachable, 215 with nothing,
	1057 carrying a tombstone, 609 multi-root, 487 with a cycle,
	682 refused for a root the catalogue does not know

The cycle floor is there because a breadth-first search that revisits is a
non-terminating one, and a walk whose visited set is also its queue -- which
is what `reach.c` uses -- is exactly where that goes wrong. The fixture is
not free of cycles; it is required to contain them.

## 271. Three harnesses, three instruments, one module

`catalog/sweep.c` has a harness now, and with sec 269 and sec 270 that makes
three written against one module in two days. They are not three of a kind,
and the differences were forced by the subjects rather than chosen:

	catalog_fuzz   a merge rule whose answer for a contested edge is
	               order-dependent BY DESIGN, so no function maps the
	               assertion set to an expected answer. Properties, plus an
	               oracle over the one shape the rule fixes.     2 of 4

	reach_fuzz     a graph walk: one question, one right answer for a given
	               set of edges. A breadth-first search written from the
	               header is a second implementation.            3 of 3

	sweep_fuzz     a six-call protocol with a lock, a cursor and a refusal.
	               No answer to check -- what a random call SEQUENCE finds
	               is an ordering fault.                         3 of 3

**The instrument is a property of the subject, and picking the wrong one is
how sec 269's first draft asserted two true things and caught nothing.** A
harness for a protocol that looked for a wrong answer would find none; a
harness for a graph that asserted only invariants would miss a walk that
stops early. The question to ask first is not "what should I assert" but
"what kind of thing is this".

### What sweep_fuzz asserts, and it is all `sweep.h`'s own text

	rows sorted by node id     "the order is the same on every machine and
	                           after every restart ... That is what lets
	                           the cursor be a count"
	begin is idempotent        "a restart calls it again on a job it has
	                           loaded from disk"
	end refuses while work     so a consumer cannot abandon a sweep and
	  remains                  leave the catalogue unlocked
	BUSY while held            nothing may change the catalogue, which is
	                           what stops the list moving under a count
	the list does not move     step k hands back the row capture wrote at
	                           k, or the decision was not taken once

The last is the one the header's argument actually rests on -- "THE DECISION
IS TAKEN AT CAPTURE AND NEVER AGAIN" -- and it is the one no single call can
check.

### And what it deliberately does not do

**It does not model which nodes the plan chooses.** `sweep_test.c` owns that,
and needs a model of retention, holdings and witnesses to say anything about
the last-copy guard or a shared blob. The protocol is sound or not
independently of what the plan contains, and a harness that mixed the two
would fail for two unrelated reasons and be read as one.

That is the same line sec 269 drew and could not hold: there the properties
were about the merge rule AND the walk over its result, and separating them
is what made the oracle findable.

	2000 cases: 951 planned something, 1049 planned nothing, 1168 end
	refusals while work remained, 2000 assertions refused as busy,
	47 truncated plans

The "planned nothing" count is not padding. A run where every case planned
nothing would exercise capture, begin, end and the lock while every assertion
about a step sat inside an empty loop -- so both sides carry a floor, and the
end-refusal floor is the one that can only be met from inside the loop.

## 272. A fourth instrument, and the assertion that was false

`catalog/copy.c` has a harness, which gives every source in `catalog/` one.
The four are four different instruments and none of them was a preference:

	catalog_fuzz   properties      no oracle exists -- the answer for a
	                               contested edge is order-dependent by
	                               design
	reach_fuzz     an oracle       one question, one right answer, and a
	                               breadth-first search is a second
	                               implementation of it
	sweep_fuzz     a protocol      no answer to check; a random call
	                               SEQUENCE is what finds an ordering fault
	copy_fuzz      metamorphic     an oracle EXISTS and is not worth having:
	                               it would be a model of retention, the
	                               holdings seam and inline content, which
	                               is copy.c rewritten in the test

**The fourth is the interesting addition.** The other three were decided by
what the subject makes possible; this one by what it makes AFFORDABLE. A want
list is a function of the catalogue, so sec 270's move is available in
principle -- and paying for it means writing the module twice and testing
that two copies of one reading agree, which is `evidence.md`'s one witness
wearing a lab coat. What `copy.h` offers instead is a set of things the
answer must NOT depend on, and those cost nothing to check:

	the filing has no part in it   compute the want list, then give the
	                               catalogue a filing root and file nodes
	                               under it, then compute again -- identical
	written + truncated sizes      a second walk into exactly that size does
	  an array big enough          not truncate
	BUSY while any job holds it    a want list computed mid-sweep asks for
	                               bytes that are being deleted

### The assertion that was false, and the floor that caught the vacuous one

**The first draft asserted `written + truncated >= the distinct blobs in the
catalogue`.** It failed on case 0 and it deserved to: a want list holds blobs
this host does NOT hold, so the content table is not its denominator. The
right denominator needs the model this harness exists to avoid. The sizing
claim is checked where `copy.h` actually makes it -- the second walk -- and
that needs no denominator at all.

**And the metamorphic property was vacuous for two runs before a floor said
so.** `fzn_catalog_file_under` refuses an edge that does not exist -- "a
filing is a subset of the membership" -- and the fixture asserted content
without ever asserting membership, so nothing could be filed and the check
compared two identical unfiled walks. The output was `filed 0` in 2000 cases,
and the floor is the only reason that was visible: every assertion passed.

That is twice now that a coverage floor has caught what assertions could not,
against once that a floor was merely satisfied. **A floor is not a
completeness gesture; it is the only instrument that can see a property
quietly stop being exercised.**

### A sabotage on a counter is invisible to anything that reads it

Three sabotages, three caught, and the middle one caught DIFFERENTLY:

	a blob already listed is emitted again    an assertion
	a truncation is not counted               THE FLOOR
	a want list computed while held           an assertion

Blinding `plan->truncated` blinds every property that reads it -- including
this harness's own sizing check, which computes `written + truncated` and
would have walked into an array of exactly `written` and found no truncation
reported, because none is reported anywhere. Only the distribution shows it:
`0 truncated` where 164 were expected.

**So a counter cannot be held by an assertion over itself.** What holds it is
a floor over how often it moves, and that is a different kind of check rather
than a weaker one.

### What the harness pins and does not require

`truncated` is documented as an upper bound rather than a count: two
references to one blob arriving after the array filled are two truncations
and not one duplicate, "there is nowhere to remember the first". So the
harness COUNTS the cases where the bound was loose -- 44 of 2000 -- and
requires none of them, for sec 243's reason. A suite that required looseness
would fail the day somebody made the sizing exact, which is a change that
should arrive at this file and argue rather than break it.

## 273. A harness that could not hold its own property

`spool/transfer.c` has a harness. The property it exists for is the one
`transfer.h` says needed holding:

> a cursor advancing past each assignment was the obvious optimisation and it
> is a SECOND mechanism producing disjoint ranges -- so the two-peer test
> passed with the pending record removed, the cursor accounting for the
> disjointness on its own. **A property with two mechanisms where only one is
> load-bearing is a property no test can hold.**

`from` belongs to the caller now, so the pending record is the only mechanism
left. A harness can drive `from` adversarially -- backwards, into the middle
of a live range, past the end -- where two hand-written peers walk forward,
which is what the cursor was doing.

### The first draft had the same fault the header describes

It stubbed the store's read and write seams, because nothing in the subject
looked like I/O. So no delivery ever succeeded. **The window opens only on a
delivery the store can support**, so it stayed at its floor of one; with a
window of one, at most one assignment is live; and with one live assignment,
"no two overlap" compares each new range against nothing.

	8586 assigned, none overlapped, every assertion green

That is the sec 269 failure in a new place and worse, because here the
property was not merely weak -- it was **structurally unreachable**, and the
harness reported success over 2000 cases without ever once having two live
assignments to compare.

**What flagged it was a coverage counter reading zero**, not an assertion:
`window_halved 0` against 6073 failures. Reading `transfer.c` then explained
it in one line -- `transfer->window = 1u` at open, and growth only in the
delivery path. Third time today a floor has pointed at a vacuous property and
the first where the property could not have been reached at all.

The fixture places real bytes now -- leaves, a Merkle tree, proofs, a disk
array -- built once because it is deterministic, so deliveries succeed and
the window opens:

	131145 assigned and none overlapped, 52840 delivered, 17586 halvings,
	9757 expiries of which 588 dropped more than one batch

The last number is the one AIMD's rule is about: "one decrease per loss
event, not per assignment", and 588 cases put more than one batch behind a
single expiry.

### And a comment of mine was stale within the hour

While the store was stubbed I wrote a header paragraph saying congestion
control was not on trial here and could not be reached from this fixture,
and a printed line saying zero halvings was expected. Both were true when
written. Both were false an hour later because I changed the fixture, and
nothing about them would have looked wrong to a reader -- they were careful,
specific, and about a version of the file that no longer existed. Corrected
before the commit, and worth recording as the shape rather than the slip: **a
limit is a claim about the instrument, and rebuilding the instrument dates
it.**

### What it does not catch, pinned

Making `overlaps` treat TOUCHING ranges as overlapping survives every case.
That is correct and not a gap: the change is conservative, so it never
produces an overlap -- it only refuses assignments it could have made.
Nothing here measures a missed opportunity and nothing could, because
`transfer.h` says the search covers "a bounded number of candidate ranges"
and may answer NONE with free leaves elsewhere. **A refusal that was wrong
and a refusal that was allowed are the same observation from outside.**

## 274. A backend that lies, and the fixture question asked first

`record/store.c` has a harness, and it is the first of the last four whose
first draft held its property. The difference was not care; it was asking
sec 273's question before writing a line: **can the fixture reach a state
where the assertion has anything to compare against?**

Here the answer was yes from the first call. The store's property is the one
`store.h` argues for at length -- a shared cache is not a shared trust domain
because `get` compares what came back against what was asked for, "so a
store that returns the wrong record answers MISPLACED rather than handing a
caller somebody else's bytes under the name it asked for". What that needs
is a backend that lies and a record of what was filed where. Both are cheap,
neither depends on a window opening or a membership existing, and the first
run exercised every state.

### The backend is hostile by construction

`store_test.c` has a table with knobs -- a nominated wrong slot, a
truncation, a hard failure -- and turns each once, pinning which error
results. This harness turns them at random on every read and asks one
question across all of them: **did a lie ever become a wrong success?** A
lying backend may cause any refusal; what it may never cause is an OK that
carries bytes not filed under that name. The oracle is the map of puts, and
which error a lie produced is deliberately not asserted here, because that
is `store_test.c`'s and asserting it twice would be one reading twice.

	20000 cases: 159599 lies refused, 605 lies that happened to be true,
	29153 honest hits, 20193 puts the backend declined, 25582 overwrites,
	and no caller ever received bytes under the wrong name

The 605 are wrong-slot answers that named the slot actually holding the
record, which the store rightly accepts. That counter has no floor: a floor
on it would be a floor on luck.

### Three sabotages, three caught, and one entry earned

	the issuer is not compared              CAUGHT   wrong-slot lie
	the sequence is not compared            CAUGHT   wrong-slot lie
	what came back is not opened first      CAUGHT   truncation lie

Each message names which lie got through, which is what makes a random
backend worth more than a knob turned once: the harness cannot know in
advance which lie a given break admits, so it tries all of them.

`store.c` already had four entries in the sabotage table -- both placement
halves, absent-versus-backend, and the log line -- so the first two rows
above are held from the other side already and earn nothing. **The third
had no entry.** Nothing in the table sabotaged the shape check that runs
BEFORE placement, and a backend that truncates is exactly what reaches it:
the bytes that come back are not a record, and without the check the
placement code reads fields off a view nothing opened. One entry,
`record-store-what-came-back-must-open`, and it is the harness's whole
addition to the table.

**The lesson is the one sec 273 ended on, from the side where it went
right.** A property's fixture cost is not a detail to settle after the
assertions are written; it decides whether the assertions will ever compare
anything. Three harnesses in a row reported green over nothing because that
question came second. This one asked it first and had nothing to correct.

## 275. A harness that earns no entries, and why that is the right answer

`record/ledger.c` has a harness. It passed on its first run with every state
reached, three sabotages were caught, and **it adds nothing to the sabotage
table.** Those three facts belong together.

The ledger's contract is small enough to state as a function, which is what
makes this an oracle in sec 270's sense rather than a property in sec 269's:
per (peer, subject, kind) the confirmed version is the highest ever
confirmed, `behind(current)` is `confirmed < current`, an unknown key answers
zero, and a version of zero is refused because zero is what an absent row
already says. A max over a map is a second implementation of all of it in a
dozen lines that share nothing with `ledger.c`.

	2000 cases: 11726 advanced, 5479 stale and reported, 6078 zero refused,
	12710 new keys refused on a full table, 1856 known keys updated on one,
	8802 unknown peers asked, and the max agreed after every step

### The sabotage worth having asked for both halves

	a late acknowledgement is absorbed (latest wins)   CAUGHT   error code
	a stale one is reported AND ALSO written           CAUGHT   the table
	an equal version counts as an advance              CAUGHT   error code

The middle row is the one `ledger.h` argues about -- "reported rather than
absorbed, because the table is the same either way" -- and it separates two
things a return value cannot: the right error with the wrong table. Only
re-checking every key against the max after every step sees it, which is why
the harness does that rather than trusting the code it just got.

### And all three are already held

`record/ledger.c` carries ten entries in the sabotage table:
`ledger-monotonic`, `ledger-stale-reported`, `ledger-unknown-is-behind`,
`ledger-version-zero`, and six more. Every sabotage above falls under one of
them. **So this harness earns no entry, and adding one would be sec 201's
symmetry -- a row so the file has a row.**

What it adds is a different question from whether each guard is held. The
ten entries prove that removing a guard turns `ledger_test` red. The harness
proves the max-invariant holds across thousands of random arrival ORDERS,
which is the case the header's whole argument is about -- "an
acknowledgement that arrives late is reordering rather than retraction" --
and which two hand-written confirmations in one order cannot produce.
Those are both worth having and neither is the other.

### Why it went right first time, stated so it can be repeated

Sec 273's question -- can the fixture reach a state where the assertion has
anything to compare against -- was asked before a line was written, and the
answer was that every state is reachable from a random confirm over a small
key space against a small table. No window to open, no membership to
establish, no seam to satisfy. The capacity is drawn small on purpose, so
FULL is reached in 12710 of 2000 cases' steps rather than never; and the
version is drawn from six values, so an out-of-order arrival is common
rather than a coincidence. A fixture too roomy to fill and versions too
sparse to collide would have passed just as green over a fraction of the
contract.

## 276. The chain store, and a pattern in three stores

`chain/chain_store.c` has a harness. It passed on its first run with every
state reached, three sabotages were caught, and it adds nothing to the
sabotage table -- sec 275's shape exactly, and the reasoning there is not
repeated here.

What is worth recording is the model, because `chain_store.h` states its
semantics as sentences and each one became a floor:

	a chain for a held triple REPLACES,     3832 of 13009 replacements were
	  even a shorter-lived one              by a shorter-lived chain
	a DEAD entry is spent before FULL       5033 dead entries spent
	still FULL when every entry is live     12907 refusals over live stores
	expiry alone deletes nothing            24729 lookups withheld an entry
	                                        the count still included

**Which dead slot is spent is not modelled, deliberately.** The header says
the first in array order and that a deterministic choice "can be tested" --
`chain_store_test` does. From outside, every dead entry is withheld and
every one is counted, so which of them a new chain replaced is not
observable through lookup and count. A model that tracked array order would
be a model of the implementation, which is the one thing an oracle must not
be.

### The chains are real, and that is where the fixture cost went

`fzn_chain_store_admit` verifies before it stores, so bytes that do not
verify would test the refusal path 20000 times. Every chain here is one hop
minted by the root with the same stub signer `chain_test.c` uses -- byte 0
of a key is its identity, because the verifier derives it from there -- and
admitted while live. What a chain that does not verify does is
`chain_test`'s subject and is not asserted twice.

	three sabotages: a dead entry not spent, lookup handing back an
	expired chain, a live entry evicted to make room -- CAUGHT, each
	naming the sentence of the header it broke

### Three stores in two days, and the shape they share

`record/store.c`, `record/ledger.c` and `chain/chain_store.c` are all keyed
tables with a small contract, and all three harnesses passed first time
after three that did not. The difference was sec 273's question asked
before writing: **can the fixture reach every state the contract names?**
For a keyed store the answer is nearly always yes -- a small key space, a
small table and a clock the harness owns reach full, stale, expired and
replaced without a window to open or a membership to establish. That is a
property of the subject, not of care, and it is why these three were cheap
where `transfer` and `copy` were not.

Two of the three earned no sabotage entries and one earned a single one.
That is the right outcome for a module the table already holds: the harness
answers whether the invariant survives random order, which the table cannot
ask, and the table answers whether each guard is held, which a harness
cannot see. Writing an entry so the file has one is sec 201's symmetry, and
it was declined twice.

## 277. The authorization decision, against a table that never asks

`chain/authz.c` has a harness. It is the highest-stakes subject harnessed so
far -- `fzn_authz_decide` is the answer to "may this request proceed" -- and
it has the cleanest oracle, because `authz.h` states the whole decision as
sentences and each one is a row:

	an unspelled policy                     DENIED
	an origin the policy does not name      DENIED, before any capability
	an unguarded policy                     GRANTED_UNGUARDED
	a guarded policy with no chain          DENIED -- "exactly the case that
	                                        must not be confusable with no
	                                        capability required"
	a null root or signer                   DENIED
	a chain verified FOR ITS CAPABILITY     GRANTED_BY_CHAIN
	a chain for another capability          DENIED
	an expired chain                        DENIED

**The oracle never asks the library whether a chain verifies.** The harness
mints every chain itself, so it knows which capability it grants and when
it expires, and the expected verdict comes from that knowledge and the policy
alone. A model that called `fzn_chain_verify` to predict what
`fzn_authz_decide` should say would be checking the decision layer against
the thing it wraps -- which is most of it -- and would agree with a decide
that passed the wrong capability through, because verify would too.

### The polarity is a second assertion, not a consequence of the first

`authz.h` records the argument: the verdict's contract is that zero denies
and every other value grants, "a consumer reading it as a truth value is
reading it correctly", and adding a non-zero denial enumerator "would turn a
refusal into a grant at every such site". So every verdict is checked twice
-- against the table, and against the set {0, 1, 2} with its truth value
matching the table's. A verdict of 3 is a grant nobody named, and the table
would call it merely wrong.

	five sabotages: an unspelled policy granting, the origin unchecked,
	no chain read as no-capability-required, any verified chain
	granting, a denial of 3 -- all CAUGHT, each naming the row

### Two entries, and which two

Three entries already held this file: unspelled, the origin gate and the
manifest. Two of the five above were not held, and they are the two the
header singles out. `authz-no-chain-is-not-no-capability-required` is the
case the header calls exactly the one that must not be confusable -- a
guarded kind met with no chain is a denial, not a kind that needed none. And
`authz-reads-what-verify-answered` covers the single comparison every
refusal `fzn_chain_verify` can give passes through: with it inverted, a
wrong capability, an expired chain and one that does not verify at all would
grant.

Run through the table both are CAUGHT by `authz_test.c` -- lines 223 and 354
-- which runs before the harness. So both guards were already HELD, and what
was missing was the entry recording it; sec 269 draws the same line. That
the harness catches them independently was established by building it
against each sabotaged tree on its own, and it is the harness's own MODEL
line quoted above, not the table's.

### What the floors caught before any sabotage ran

Drawn uniformly, an unspelled policy and an unnamed origin together denied
77 of 100 cases before a chain was looked at, so the rows that exercise one
were two or three per cent -- and every verdict matched, over a fixture that
mostly asked the two cheapest questions. Weighted, the eight rows come out
between five and seventeen per cent each. **A decision table is only tested
where its rows are reached**, and the cheap rows are the ones a uniform draw
reaches first.

## 278. The capability derivation, and a sabotage that was right to survive

`chain/service.c` has a harness. The subject is `fzn_service_capability`,
which hashes a (service, product, name) triple into a capability id, and
the property is the one `service.h` states in capitals: distinct triples,
distinct ids. The oracle is a map from derived id back to the triple that
produced it; every derivation is looked up, and a hit carrying a different
triple is two grants become one -- which in a system where the verifier
derives the capability it requires and compares is one grant standing for
another.

	20000 cases, 287736 derived (172144 with a zero byte in the name,
	41126 empty), 17823 same-triple repeats agreed, 215819 pairs
	derived, and no two distinct triples ever shared an id

### The sabotage the harness was written to catch survived, and correctly

The header names its hazard: "if a field is ever added, it goes BEFORE the
name or it brings a length prefix with it; appending one after a
variable-length field is how two different capabilities come to hash the
same." The harness was designed around that sentence -- names carrying zero
bytes and varying in length, so a name's tail could be mistaken for a fixed
field's bytes -- and its first comment said the fixture existed to catch the
product moved after the name.

Sabotaged, that SURVIVED. And the model was right to find no collision: with
the name the only variable-length field and the length hashed, `name ||
be32(product)` decodes uniquely from the right, so the encoding is still
injective. The mechanism the header gave was wider than the hazard. What
actually collides is a SECOND variable-length field, or a hash that cannot
see the length -- and the second is what the zero bytes reach:

	the input zero-padded to a fixed size, the length not hashed
	    CAUGHT  (3, ANY, 1-byte name) and (3, ANY, 0-byte name) derived
	            the same capability
	only the first four bytes of the name hashed
	    CAUGHT  two 6-byte names under (2, ANY)
	the service not part of the input          CAUGHT
	an unspelled service accepted              CAUGHT
	the product moved after the name           SURVIVED, and should

So the fixture was right and the reason written above it was wrong. Both the
harness's comment and the header's sentence now say which case collides;
the header keeps its rule stated wider than the hazard, on purpose, so that
nobody has to re-derive which case they are in. **A sabotage that survives
is a claim about the code, and here the claim was true: the encoding
tolerates the edit the header forbids.** Had the comment been believed
instead of the run, the harness would have shipped saying it caught a
failure it cannot cause.

### Two entries earned

Nine entries already held this file -- the service, the product and the name
each in the input, the wildcard refused as a subject, the product bounded,
and four on the stream derivation. Neither of the two new sabotages was
held: `service_test` derives "read", "write" and "", names that differ in
their first byte and carry no zeros, so a padded input and a name hashed in
part are both invisible to it. Built against each sabotaged tree, the suite
stayed green and the harness went red. `service-length-hashed` and
`service-name-hashed-whole` are in the table, and through it both are
CAUGHT with `service_fuzz` as the first failure -- the harness is the only
thing holding them, which is what sec 201 asks an entry to be for.

### What this one adds to the taxonomy of sec 273

An oracle harness whose failure mode was the AUTHOR's model, not the
fixture's reach. Sec 273's question -- can the fixture reach a state where
the assertion has anything to compare against -- was answered yes here, and
the assertion still could not fire, because the state it reached was not a
failure. The check that separates the two is the same as ever: sabotage,
and read what the survivor means before deciding the harness is blind.

## 279. The session root, and a KAT vector that had chosen the one fixture it could not see with

`session/session.c` has a harness. The property is `session.h`'s in three
sentences: the base root is a function of the UNORDERED pair of (identity,
prekey), the ephemeral root of the ORDERED pair plus the ephemeral, and the
two chain keys are directed. The oracle is a bijection held as a table --
every root filed under a descriptor built from those sentences, and checked
both ways: two descriptors with one root is two sessions become one, one
descriptor with two roots is a side that cannot talk to the other. Four
hosts rotate their prekeys, pair off from either side, mint ephemerals, swap
roles, and refuse -- with themselves, on the first agreement, on the second,
in the hash, in either chain -- with the caller's buffers checked untouched
or wiped as the header says.

	20000 cases, 62879 base sessions (31404 with identities agreeing on
	16+ bytes), 58920 ephemeral (14593 with roles swapped), 14949
	rotations, 11806 sessions revisited, 91191 chain pairs, and every
	root and chain was one-to-one with its session

### The identities share prefixes, and that is the harness

The canonical order is a `memcmp` over thirty-two bytes. `session_test`
sorts identities that differ in their first byte, and the KAT's `ID_LOW`
and `ID_HIGH` differ in theirs. So a sort that read a prefix and broke the
tie by which host was asking -- deriving two roots for one pair, a pair
that then cannot talk -- was met by nothing in the tree. Here the hosts in
a case agree on a random number of leading bytes, up to thirty-one:

	sort on the first byte only         fuzz CAUGHT   test survived   kat survived
	sort on sixteen bytes               fuzz CAUGHT   test survived   kat survived
	sort on thirty-one bytes            fuzz CAUGHT   test survived   kat survived

`session-order-reads-the-whole-identity` is in the table, held by the
harness alone. Sec 273's question was answered by construction: the state
the assertion needs is a tie, and the fixture was built to produce ties.

### The first sabotage run was wrong twice, and both were instruments

The first sort sabotage resolved the tie by pointer AFTER the `order == 0`
check had been replaced, so it also accepted a session with yourself and was
caught -- by the harness and by `session_test` -- for that, not for the
sort. Read as written it said the suite held the sort. It did not; a
sabotage that breaks two guards is caught by whichever is cheaper, and the
report names neither.

And the KAT column read CAUGHT for every row, because the KAT binary had not
linked (it needs monocypher and the two real bindings) and a missing binary
exits non-zero. Eleven confident verdicts from a file that did not exist.
The rerun built each binary with `||` on the compile so a build failure
prints itself rather than a verdict, and its first row is a pristine
control -- three survivals -- without which the other rows still could not
be read.

### A v2 that sorted was held by nothing, and the reason is the vector

With the KAT actually running, the sabotage that lays the v2 transcript
down in canonical order instead of role order survived all three
instruments. The harness cannot see it: the ephemeral is agreed with the
RESPONDER's prekey, so the role is bound through the ephemeral shared secret
whichever order the identities take, and the roots stay one-to-one -- the
same shape as sec 278, a redundancy rather than a collision. `session_test`
checks bytes reach the transcript, not where. And the KAT's v2 vector had A
initiating, where A is `ID_LOW`: **the one fixture in which role order and
canonical order coincide**, so a v2 that sorted produced the documented
bytes. The v1 case in the same file had been laid out "so the canonical sort
is exercised in both directions"; the v2 case beside it had not asked the
question.

The vector's roles are the other way round now -- B initiates, and B sorts
second -- and the sort sabotage fails at `session_kat_test.c:424`.
`session-v2-is-role-ordered` is in the table, held by the KAT. The
harness's contribution was the sabotage, not the catch; evidence.md's
"choose a fixture so that the plausible wrong answer and the right one
differ" is the rule, and a known-answer vector is exactly a fixture.

### What the bijection cannot see, pinned in the harness

A redundant field. Drop a host's prekey public from the base transcript and
every rotation still changes the root through the shared secret; drop the
ephemeral shared secret from v2 and the ephemeral public still separates
sessions. Both survived the harness and both are caught by `session_test`'s
byte-reach checks and the KAT. The harness says so in its header, because
"a field is hashed" and "a field is the only thing separating two sessions"
are different properties and a reader quoting the harness for the first
would be wrong.

## 280. The same lens on the catalogue: a sort that reads a prefix

The session finding of sec 279 -- a comparison that reads only a prefix of
an identifier, held by nothing because every fixture's identifiers differ in
their first byte -- is a lens, and it was pointed at the catalogue next. Two
sites order by node id so a resume cursor can be a count into that order:
`catalog/sweep.c`'s `insert_sorted` and `catalog/catalog.c`'s `id_before`
in the refile capture. Both had a sabotage entry already -- `sweep-sorted-cursor`
and `refile-moves-sorted` -- and both entries DISABLE THE SORT ENTIRELY
(`while (0)`, `&& 0`). Arrival order that is not sorted at all is caught.

A sort that RUNS but reads one byte is a different defect, and it survived
every catalogue binary. The reason is the fixtures: `sweep_fuzz`'s `id_of`
set `b[0] = which + 1`, and the refile test used `idp(0x22)`/`idp(0x33)`,
whose `id()` fills every byte with the seed. In both, the identifiers differ
in byte 0, so a one-byte sort still orders them totally and agrees with a
whole-id sort. **An entry proving a sort exists is not an entry proving it
reads the whole key**, and nothing here asked the second question.

### What made the fixtures reach it

Two properties, and the first alone is not enough. The identifiers have to
SHARE a leading byte, so the sort meets a tie -- and the tie has to be
resolved the WRONG way by arrival, or a prefix sort that keeps arrival order
still comes out sorted by accident. `sweep_fuzz` learned this the slow way:
ids sharing byte 0 with byte 1 ASCENDING with arrival still passed the
one-byte sabotage, because a prefix sort keeps arrival order and arrival
order was already id order. Byte 1 DESCENDING with arrival is what reverses
them, so a prefix sort's tie-kept order is the reverse of id order and the
whole-id check fires. The refile hand test already knew this -- "0x33 is
filed before 0x22, so the table order is the reverse of the id order" -- and
only needed its pair to share a byte, which `id()` could not give it, so the
test grew a two-byte `hi`/`lo` pair.

	sweep.c reads one byte      fuzz CAUGHT   (was SURVIVED before the fixture)
	catalog.c reads one byte    test CAUGHT   (was SURVIVED before the pair)

`sweep-sorted-by-whole-id` is held by `sweep_fuzz`, `refile-sorted-by-whole-id`
by `catalog_test`; sweep_test survives the sweep prefix sabotage, so the
harness is the holder there. Both are distinct from the coarse entries beside
them, which they do not replace: a sort can be present and wrong, or absent,
and those are two failures.

### The lens is not spent

`chain/chain_store.c`, `record/journal.c`, `trust/trust.c`, `log/log.c`,
`state/state.c`, `chain/manifest.c` and `local/vocabulary.c` all compare
identifiers with `fzn_ct_memeq`, which is a whole-buffer equality rather than
an ordering, so a prefix read there is a different mutation -- a shortened
length -- and whether each fixture reaches a collision on the untested tail
is the next question. Recorded rather than swept, so the next pass has the
list and not the conclusion.

## 281. The lens once more: a lookup key compared by a prefix

Sec 280 left a list: the `fzn_ct_memeq` sites, where the prefix lens becomes
a SHORTENED-LENGTH mutation rather than a shortened sort, and the question
is which fixtures reach a collision on the untested tail. The two
highest-stakes sites turned out already held. `chain/chain.c`'s capability
compare in the verify walk is guarded by `chain_fuzz`'s `copy_near`, which
flips the LAST byte "the pair a comparison's length decides"; `session/commitment.c`'s
`fzn_commitment_check` is guarded by `commitment_test`, which asserts a
difference in the last byte and in the first are both seen. Whoever wrote
those applied this lens already, which is why sec 280 said to read the
finds for a shape rather than assume a gap.

The gap was in the CACHE. `chain/chain_store.c`'s `find_entry` matches a
cached chain on (root, capability, grantee) with three whole-field compares,
and a prefix read there returns a chain cached for a triple it was not
verified for -- a wrong authorisation, from a cache. Sabotaged to one byte
per field, it survived `chain_store_fuzz` AND `chain_store_test`, because
both mint keys through an `expand`/`key` that puts the seed in byte 0: every
distinct root, capability or grantee differs in the first byte, so a one-byte
compare tells them apart and the collision is never built.

### Four chains differing in one last byte

`chain_store_fuzz` grew a `near_miss_keys_are_distinct` block: a base chain
and three more, each differing from the base in exactly one field and only in
that field's last byte, admitted into a store of four, asserting the count is
four. A compare shortened in any one field collapses the pair that differs
there, and the count drops to three -- caught, and the message names the
consequence. All three fields were sabotaged independently and each was
caught; `chain-store-root-whole`, `chain-store-capability-whole` and
`chain-store-grantee-whole` are in the table.

	root / capability / grantee compare shortened to one byte
	    each SURVIVED before the block, each CAUGHT after

The near-miss root works only because the stub verifier keys identity on byte
0, so a root differing only in its last byte is the same host to the signer
and the chain still verifies -- the same property that let the fuzz loop use
one signer for every triple, turned to a use it was not built for.

### The list is shorter and still open

Held now: chain.c, commitment.c, chain_store.c, and revocation_fuzz (which
already carried near-miss ids). Not yet examined against a shortened compare:
`record/ledger.c`, `log/log.c`, `chain/manifest.c`, `record/journal.c`,
`record/sync.c`, `trust/trust.c`, `state/state.c` and `prekey/prekey.c`.
Each is a lookup keyed on an issuer, subject or peer, and the same question
applies: does its fixture ever store two keys sharing a prefix. Recorded,
not swept -- and with two of the highest-stakes sites already held, the
remaining ones are lower-stakes lookups rather than authorisation compares,
which is the order to spend attention in, not against.

## 282. The prekey verification, and a ranking sec 281 got wrong

Sec 281 closed by calling the remaining `fzn_ct_memeq` sites "lower-stakes
lookups rather than authorisation compares." That lumped `prekey/prekey.c`
in with the bookkeeping, and it does not belong there. `fzn_prekey_pin`
decides "is this the host I am anchored to" with a whole-key compare against
the anchor, and "have I already got this exact prekey" with a whole-prekey
compare. The first is a VERIFICATION boundary in the permissive direction: a
compare that read a prefix accepts a record from a different host whose key
agrees that far, and pins a prekey for a peer nobody signed. That is the same
class as chain.c's capability compare, not the same class as a journal's
issuer lookup.

Sabotaged to one byte, both compares survived `prekey_fuzz`, because -- as
with chain_store -- the harness keys host and prekey identity on the seed and
`expand` writes the seed into byte 0, so every host and prekey it builds
differs in the first byte. The model itself is seed-indexed, so a near-miss
pair sharing byte 0 cannot be expressed through it; the fix is a self-contained
block, as chain_store's was.

	the host compare shortened to one byte      CAUGHT (was SURVIVED)
	the prekey compare shortened to one byte     CAUGHT (was SURVIVED)

`near_miss_keys_are_distinct` anchors a host, then offers a record whose host
is the anchor with only its last byte changed and expects WRONG_HOST, and a
record whose prekey is the held one with only its last byte changed at the
SAME timestamp and expects ROLLBACK rather than the re-delivery a prefix
compare would call it. The near-miss host verifies because the stub signer
keys on byte 0 -- the same property chain_store's block leaned on.
`prekey-host-whole` and `prekey-prekey-whole` are in the table.

### The lens is closed for the boundaries; the bookkeeping is left

Held against a shortened compare now: chain.c, commitment.c, chain_store.c,
prekey.c, and revocation_fuzz. Those are the sites where a prefix match
crosses a trust boundary. What remains -- `record/ledger.c`, `log/log.c`,
`chain/manifest.c`, `record/journal.c`, `record/sync.c`, `state/state.c`, and
`trust/trust.c`'s UNCHANGED compare -- are lookups and dedup checks whose
wrong answer is a bookkeeping error, not an accepted forgery, and where a
prefix collision on a real key is infeasible anyway. `trust.c`'s compare is
conservative even when shortened: it refuses an update rather than accepting
a wrong root. These are recorded as examined-and-declined, which is a
different record from unexamined: the lens was carried to each and the stakes
weighed, and the attention goes to the next lens rather than the tail of this
one.

## 283. The next lens: the equality edge of an ordering compare

The comparison-LENGTH lens of sec 279-282 had a shape underneath it: a
fixture whose values are maximally separated cannot test whether the code
reads the whole value. Turned from a compare to an ORDERING, the same shape
asks whether a fixture ever produces the EQUAL case -- because `<=` and `<`
differ only there, and a fixture whose clock never lands on a deadline
cannot tell them apart. Expiry is where this lives, and the convention this
tree draws is "dead AT the deadline": `expires_at <= now`.

Most of it was already held, which is the sec 280 lesson again -- read the
finds for a shape before assuming a gap. `frame/freshness.c` carries an
explicit boundary entry (`replay-expirable-draws-the-same-boundary`, `<=`
sabotaged to `<`). `chain/chain.c`'s verify-site expiry is held by
`chain_fuzz` and `chain_test`; its `fzn_chain_expired_at` predicate by
`chain_store_fuzz` and `chain_store_test`. `provision/provision.c` draws the
OPPOSITE boundary on purpose -- a card is valid THROUGH its expiry second,
`expires_at < now` -- and `provision_test` pins it in as many words ("refused
ON its expiry, which is inside its life"), with `provision_fuzz` reaching the
equal case through a fixed `now`. The chain/provision divergence is real and
deliberate on both sides.

### Where it was not held: chunk/reassembly.c

Both of reassembly's expiry boundaries survived a `<=`-to-`<` sabotage. The
reap (`slot->expires_at <= now`) and the accept-time freshness refusal
(`expires_at <= now`) each had every test sweeping WELL PAST the deadline --
50 against 60 -- so the edge was never touched, and `reassembly_fuzz` fixes
`now` at 100 and never advances it, so it drives no expiry at all. A slot
could outlive its own deadline by a tick, or a chunk already dead cost a
slot, and nothing would notice.

	reap boundary <= to <         SURVIVED test and fuzz -> CAUGHT
	accept boundary <= to <       SURVIVED test and fuzz -> CAUGHT

`test_a_slot_is_reaped_at_its_deadline` sweeps a slot with a deadline of 50
at 49 (reclaims nothing) and at 50 (reclaims it), and accepts a chunk whose
expiry equals the clock (refused) and one a tick before (accepted). The
deadline is exactly 50 because the chunk's own expiry is below `max_hold` and
so is honoured unclamped. `reassembly-reap-at-the-deadline` and
`reassembly-accept-at-the-deadline` are in the table.

### The equality edge, elsewhere

Other ordering edges are unexamined against their equal case: the catalog
retain deadline (`now >= held->until`, held by `catalog_test` but not the
fuzzers), `spool/transfer.c`'s `deadline > now`, and the `<` in weakest-link
and rollback comparisons. Each is the same question -- does a fixture ever
land exactly on the boundary -- and the same order of attention applies: the
expiry edges that decide whether a credential is live come before the ones
that decide a buffer's reclamation tick.

## 284. The equality edge again: a grant with no life at all

Sec 283's lens -- does a fixture ever land exactly on an ordering boundary --
was carried down its own list. `spool/transfer.c`'s assignment deadline
(`deadline > now`) is held by both `transfer_fuzz` and `transfer_test`, which
track deadlines exactly and sweep at them. The prekey rollback boundary
(`created_at <= peer->created_at`) is held by `prekey_fuzz`'s ties. The
weakest-link `<` has no observable edge -- two equal expiries give the same
minimum either way.

The gap was `chain/chain.c`'s "a grant that expires at or before it was
issued is invalid," checked on both the verify side and the mint side with
`expires_at <= issued_at`. `test_expiry_before_issue_is_malformed_not_expired`
already covered it -- with a GAP, issued 5000 and expiring 4000. A gap is
refused by `<` as readily as `<=`, so the ZERO-LIFETIME case, a grant
expiring the instant it was issued, was the one the check's boundary turns
on and the one no test built.

	verify expires<=issued to <     SURVIVED test and fuzz -> CAUGHT
	mint   expires<=issued to <     SURVIVED test and fuzz -> CAUGHT

Why the fuzzer could not reach it, though it mints `expires == issued == 100`
sometimes: the equal case is MASKED. A hop expiring at 100 is also expired
whenever `now >= 100`, so the verdict is "refused" whether the issued-at
check fires or the expiry check does, and flipping one to `<` changes
nothing the model can see. The boundary is observable only when the clock is
BELOW the shared value -- a hop with `expires == issued == 5000` verified at
now=1000 -- which is a combination random generation rarely isolates from
every other reason a chain is refused. The fix is a fixture that names it:
the existing test grew an equal-dates case at a low clock, verify side, and a
`fzn_chain_mint` with equal dates, mint side. `chain-verify-zero-lifetime`
and `chain-mint-zero-lifetime` are in the table.

### What this pass established about the lens

Five expiry sites carried the boundary already (freshness, chain verify,
chain expired_at, provision both ways, transfer, prekey rollback); two did
not (reassembly, sec 283) and two more were half-covered -- refused with a
gap but not at the edge (chain's zero-lifetime, both sides). The recurring
reason a boundary goes untested is not that a fixture cannot reach the equal
value but that reaching it changes no verdict, because a SECOND refusal
masks the first. So the question sharpened: not "does a fixture land on the
boundary" but "does landing on it change an answer nothing else already
changed" -- which is the same shape as sec 277's masked-denial draw and
sec 52's control-must-be-reached, arriving from the direction of time.

## 285. The lens in the record and state decoders, and a floor a fuzzer cannot reach

Carried the masked-guard and boundary lenses into `record.c` and `state.c` at
the copyright holder's direction. `state.c`'s `put` is well-defended: the
STALE boundary (`seq <= e->seq`, the same-sequence replay the comment calls
"one genuine record re-presented and the permission came back") is held by
`state_test` at its equal edge, and the CROSS_STREAM refusal that must be
checked before STALE is held too. Its issuer-ownership compare is the
prefix-length class sec 281 declined, and it stays declined.

`record.c`'s version, object, exact-length and sequence-zero checks are all
held by `record_test` and `record_fuzz`; `BODY_TOO_LARGE` by `record_fuzz`'s
explicit "one past it, not SHAPE" case.

### The floor that changes no verdict

`fzn_record_open` opens with `if (len < FZN_RECORD_MIN_LEN) return SHAPE`, and
removing it survived `record_test`, `record_fuzz` and `record_kat_test` -- and
survived them under `SANITIZE=1` too. Two things hide it. Its VERDICT is
masked: a sub-header buffer that gets past a floorless open still fails the
exact-length check below, so the answer is SHAPE either way, and sec 284's
question -- does landing on the boundary change a verdict a second refusal has
not already made -- answers no. What the floor actually prevents is the
`body_len` read at offset 54 running off a short buffer, and that is an
out-of-bounds READ, not a wrong answer.

The read is guarded twice over, which is why it is subtle: the version and
object byte checks at offsets 0 and 1 short-circuit a garbage buffer before
the deep read, so the overflow needs a buffer that carries a valid version and
object and is still shorter than the 56-byte header -- a two-byte `{version,
object}` datagram is enough. `record_fuzz` cannot reach it from the other
side: it sweeps truncated LENGTHS but backs each with the full record's buffer,
so a read past `len` lands in valid bytes and a sanitizer sees nothing. No
build mode held the floor.

`test_open_bounds_its_own_reads` mirrors the existing `is_open` bounds test,
pointed at the parser: it opens exactly-sized allocations of 1 to
`MIN_LEN - 1` bytes carrying a valid version and object, and expects SHAPE.
Under a plain build it is a functional assertion that passes with the floor
present or removed; under `SANITIZE=1` -- the build this project runs -- it
aborts on the overflow the instant the floor is gone (`record.c:49`, confirmed
by removing it). So the guard is held by the sanitizer build, and it carries
no sabotage entry on purpose: the sabotage tool runs a plain `make test`,
where the removal is green, so an entry would read SURVIVED and misreport a
guard that is in fact held. This is the same shape as the constant-time
`codegencheck`, whose guard only a specific build can see.

### What the lens established

The record and state decoders are otherwise thorough. The one gap was a
safety guard whose removal is invisible to every functional test and to the
fuzzer built to attack that parser -- reachable only by an exactly-sized
allocation under a sanitizer, which is now the thing that reaches it.

## 286. The lens in the sync and journal decoders

Carried the boundary and masked-guard lenses into `record/sync.c` and
`record/journal.c` at the holder's direction. Most edges are held. In
`journal.c` the GAP boundary (`seq > e->received + 1u`, where the accepted
value is exactly the next sequence and the minimal gap is two past it) is held
by `journal_test`, and so is the DUPLICATE edge in `fzn_journal_check`. In
`sync.c` the empty-range edge (`ahead <= behind`) is held by both `sync_test`
and `sync_fuzz`.

### Two survivors that were no edges, and one that was

`sync.c`'s digest clamp (`their_count <= FZN_SYNC_MAX_POSITIONS`) and its
per-request clamp (`want > max_per_request`) both survived a `<=`/`>` flip,
and both correctly: at `their_count == MAX` the clamp examines MAX and ignores
none whichever comparison is used, and at `want == max_per_request` the value
stays `max` either way. These are sec 284's no-observable-edge case -- the two
branches meet at the boundary -- and adding a test for them would assert a
distinction that does not exist.

The real one was `fzn_journal_anchor`'s DUPLICATE edge. `seq <= e->received`
refuses a re-anchor at or below the position held, and flipping it to `<`
survived `journal_test`. The existing anchor cases could not catch it: the
backwards case anchors at 50 against 100, strictly less, which `<` refuses as
readily as `<=`; and the re-anchor-at-zero case is refused by the explicit
`seq == 0` check that sits ABOVE this comparison, not by the comparison. A
re-anchor at the exact sequence already received -- 101 against 101 -- is the
only input the boundary decides, and reporting it OK rather than DUPLICATE
claims a new anchor where the mark did not move. `journal_test` now anchors at
101 against a held 101 and expects DUPLICATE; `journal-anchor-refuses-a-standstill`
is in the table.

### What separated it from record.c's floor

Both were guards a fixture reached without exercising -- but for opposite
reasons, and they take opposite fixes. record.c's floor (sec 285) changed no
VERDICT, so only a sanitizer over an exactly-sized buffer could see its
removal, and it carries no sabotage entry because a plain `make test` cannot.
journal.c's anchor edge changes the verdict exactly at the equal point, so a
plain functional assertion at that point holds it and the sabotage tool
catches it. The question that told them apart is sec 284's: does landing on
the boundary change an answer -- for the floor no, for the anchor yes.

## 287. The lens in the manifest and trust decoders, and a test that proved nothing

Carried the lens into `chain/manifest.c` and `trust/trust.c`. `trust.c` is
well-defended: the fingerprint's `cap < FZN_TRUST_FINGERPRINT_LEN` floor -- an
out-of-bounds WRITE guard, worse than record.c's read -- is held by
`trust_test`, and unlike record.c's floor it changes the VERDICT on removal
(OK-with-overflow versus MALFORMED), so a functional test catches it without a
sanitizer. The all-zero-root refusal, the UNCHANGED short-circuit and the
SELF->PINNED re-anchor exception are all held too.

`manifest.c`'s decoder mirrors record.c -- a `MIN_LEN` floor, version and
object bytes, a count read, an exact-length check, then a strictly-ascending
`pair_cmp(...) >= 0` canonicity check. The canonicity check (the equal-adjacent-pair
edge) is held by `manifest_test`. The floor was not, and the way it failed is
the point.

### A control that could not fire, wearing a proof

`manifest_test` already carried the exactly-this test -- a two-byte buffer, to
reach the count read at offset 34 past a short allocation with the floor
removed -- and a comment stating it had been "proved by deleting it and
running `make test SANITIZE=1`, where this case reports a stack-buffer-overflow."
The buffer was `{ 1u, 4u }`. `FZN_OBJECT_MANIFEST` is 131, not 4, so the object
check three lines into `fzn_manifest_open` refused the buffer BEFORE the count
read -- the deep read the floor guards was never reached, no overflow could
occur, and the comment described a run that cannot happen. Measured: with the
floor deleted and `{ 1u, 4u }`, `manifest_test` under `SANITIZE=1` reports 524
checks and zero failures.

This is `evidence.md`'s control-that-cannot-fire and its claim-that-outlived-its-subject
in one object: a positive control aimed one byte off the path it was meant to
exercise, carrying a written assertion that it had been seen to work. The
version and object bytes are the schema's own constants now
(`{ FZN_SIGNED_VERSION, FZN_OBJECT_MANIFEST }`), so the buffer passes the two
byte checks and the floor is the only thing left to refuse it; deleting the
floor under `SANITIZE=1` now reports the stack-buffer-overflow the comment
always claimed. Like record.c's floor (sec 285) it carries no sabotage entry,
because the removal is green on the plain `make test` the tool runs.

### The shape worth keeping

record.c's floor was unheld because no test reached its guarded read; this
one had a test that reached for it and missed by a byte, which is worse,
because the miss came dressed as a proof. A positive control's aim is itself
a thing to verify -- the version and object bytes here were the difference
between a control on the path and a control beside it, and only running the
sabotage it claimed to have run tells them apart.

## 289. The lens in the sched and link decoders: two edges a fixture drew past

Carried the lens into `sched/sched.c` and `link/link.c`. sched's admit filter
excludes a link over a latency, loss, or MTU limit; each is an equality edge,
a link exactly AT the limit is admitted. `sched_fuzz` reaches the latency and
MTU edges and catches a `>`-to-`>=` flip on each -- but the LOSS edge survived.

The cause was in the fuzzer's own draw. `draw_u32` returns clustered values
(0, 1, UINT32_MAX, small moduli), and latency and MTU take it on BOTH the link
side and the constraint side, so `latency == max_latency` and `mtu == min_mtu`
coincide often. Loss did not: the link's `loss_permille` and the constraint's
`max_loss_permille` were each a raw `next()` u16, full-range, and two of those
coincide about once in 65536 -- so `loss == max_loss` never happened and the
`>` was never asked whether it should be `>=`. Loss draws through `draw_u32`
now, like the other two, and the flip is caught. No sabotage entry: the
harness's model holds all three filter conditions by disagreeing with the
code, so an entry would duplicate what the model already accounts for.

### link's upper bound, refused only from above

`fzn_link_register` refuses `loss_permille > 1000` -- values a per-mille
cannot mean. `link_test` tests 1001, which `>` and `>=` refuse alike, so a
`>`-to-`>=` flip survived: it would refuse a link at exactly 1000, which is
100% loss and a real measurement. The 1000 case is registered now in its own
one-slot table, so it costs no slot in the capacity test that follows;
`link-loss-permille-tops-at-1000` is in the table, caught on a plain build
because refusing a valid register changes the verdict.

### The shape

Both were the same miss from opposite ends: a boundary between an accepted
value and a refused one, with every fixture landing on one side. sched drew
past its loss edge because two full-range draws never coincide; link tested
one past its edge because 1001 is the obvious illegal value and 1000 the easy
one to skip. The rest -- sched's latency and MTU edges, link's capacity bound
and duplicate id, and both modules' saturating arithmetic -- were held.

## 290. The lens in the spool and message decoders

Carried the lens into `spool/spool.c` and `spool/message.c`. Most bounds are
held: spool's span-read range check (`count > leaves - first`) by `spool_test`,
message's exact-length checks by both tests, and the ENCODE-side count
ceilings at their exact edge (`test_a_count_past_a_ceiling_is_refused` encodes
at MAX and MAX+1).

### A ceiling tested from the encoder, not the decoder

`fzn_msg_have_parse` refuses `range_count > FZN_MSG_MAX_RANGES`, so a have
carrying exactly the maximum is legal and one more is not. Every decode in the
suite carried a handful of ranges: the round-trips use the planner's output (a
contiguous half-blob, one range), and `message_fuzz` round-trips whatever it
encodes. So the DECODER's ceiling was exercised nowhere at its edge, and
tightening it from `>` to `>=` -- which refuses a peer's full 256-range
have-set, an interop break rather than a memory fault -- survived `message_test`
and `message_fuzz`. The encode side had the edge covered; the decode side, the
one that reads a stranger's bytes, did not.

`test_a_full_have_set_decodes` encodes a maximum set of identical `{0, 1}`
ranges -- legal because the decoder requires only a nonzero count within the
leaves, no ordering -- and decodes it, expecting OK and the full count back.
`message-have-ceiling-is-inclusive` is in the table, caught on a plain build
because refusing a legal have changes the verdict.

### Two edges left as they are, on purpose

The decoder's `range_count == 0` EMPTY refusal survived too, but a zero-range
have is an empty answer -- benign, no read past the buffer, no work bought --
and the exact-length check already bounds every read the loop makes; it is a
validation nicety rather than a guard, and left unpinned. And spool's
`fzn_spool_forget` shares the `first >= leaves` range bound with the read
path that is held; its own edge was not separately probed to a conclusion and
is recorded as open rather than claimed clean.

## 291. The lens in the reach and copy decoders

Carried the lens into `catalog/reach.c` and `catalog/copy.c`. copy's
truncation bound (`plan->written >= out_cap`) is held by both tests --
`copy_fuzz` catches a `>=`-to-`>` weakening as a crash, an out-of-bounds
write past `out`, held loudly. reach's truncation bound and its dedup are
held; the dedup's `seq > out[i].seq` survived a `>=` flip but is a
no-observable-edge, aggregating a per-issuer maximum where replacing the max
with an equal value changes nothing (sec 284's pattern).

### The frontier's freshness, tested behind but not at

reach's walk refuses INCOMPLETE when an issuer's frontier is behind the
sequence the catalogue has applied: `frontier[i].received < seq`. `reach_test`
tests it with `received == 0` against an applied `seq == 1`, which `<` and
`<=` both call behind, and its fresh cases use `received == 99`, which both
call fresh. `reach_fuzz` sets every frontier to `highest + 1`, always fresh,
and does not model the INCOMPLETE path at all -- by design, its comment cedes
the frontier to `reach_test`. So the one input the freshness bound decides --
`received == seq`, a caller caught up to exactly the applied record -- was
reached by nothing, and tightening `<` to `<=` (which reports a caught-up
caller as INCOMPLETE and refuses a walk that should run) survived.

`reach_test` now vouches ALICE at exactly her applied seq and expects the
walk to proceed; `reach-frontier-caught-up-is-complete` is in the table,
distinct from `reach-frontier-behind` which removes the check rather than
loosening it. The pattern is sec 286's journal anchor again: a boundary
tested strictly to one side, with the equal case -- the only place `<` and
`<=` disagree -- left for the fixture to skip.

## 292. The lens in the trust and disclose decoders

`trust.c` was carried in sec 287 -- its fingerprint cap floor, all-zero root,
UNCHANGED and SELF->PINNED guards are held. This pass took `disclose/disclose.c`.

Its floors are held: `committed_len < FZN_DISCLOSE_SALT_LEN` (a blob shorter
than the salt) at exactly SALT_LEN by both tests, and the commit output-cap
check. The two INCLUSIVE upper bounds were not. `fzn_disclose_commit` refuses
`field_len > FZN_DISCLOSE_MAX_FIELD` and `committed_shape` accepts
`committed_len <= FZN_DISCLOSE_MAX_LEN`, so a field of exactly the maximum is
legal and the blob it produces -- salt plus MAX_FIELD, exactly MAX_LEN -- is
too. Every case in the suite committed a short field, so tightening `>` to
`>=` (refusing a maximum field at commit) or `<=` to `<` (refusing its blob as
misshapen at verify) survived.

### The caller list checked before the claim

The survivor was confirmed against ALL THREE callers, not the obvious two:
`disclose_test`, `disclose_fuzz`, AND `sim/test/disclosure_test.c`, which the
first probe would have missed -- the incomplete-binary-list mistake that made
a false gap (cited here by a section number no section had, 288). All three survived, and no library wraps disclose, so
the bounds were genuinely unheld. `test_a_maximum_field_commits_and_opens`
commits a MAX_FIELD field and hashes the MAX_LEN blob, exercising both bounds
at once; `disclose-field-max-is-inclusive` and `disclose-committed-max-is-inclusive`
are in the table.

### The lens, tallied

The inclusive-upper-bound miss -- a maximum legal input rejected by a `>`
tightened to `>=` -- has now recurred in link (loss 1000), message (MAX_RANGES),
and disclose (MAX_FIELD, MAX_LEN). It is the mirror of the caught-up and
zero-lifetime edges: wherever a bound admits its endpoint, the fixture tends
to test one past it and skip the endpoint itself, because the illegal value is
the obvious one to write.

## 293. The lens in the persist and store FILE backends

The `store.c` and `persist.c` cores were carried in sec 285 and an earlier
pass; this took the on-disk backends, `record/store_file.c` and
`persist/persist_file.c`, which read lengths off the disk and write into
caller buffers -- attacker-adjacent, since a corrupt or hostile store file
controls those lengths.

### A length read off the disk, written into the caller's buffer

`store_file`'s read pulls a two-byte length prefix from the file and preads
that many bytes into `out`, guarded by `len > FZN_RECORD_MAX_LEN || len > cap`.
The `>= cap` and MAX_LEN edges are held; DROPPING the `len > cap` clause
survived. Every read in the suite offered a full-size `out`, so a record
longer than the caller's buffer -- the case `len > cap` exists for -- was
never presented, and without the clause the backend preads past the buffer:
an out-of-bounds write whose size a disk file chooses. It is verdict-catchable
as well as a memory fault: without the guard the read returns success rather
than refusing. `test_a_record_larger_than_the_buffer_is_refused` stores a full
record and reads it into a buffer one byte too small, expecting refusal;
`store-file-read-fits-the-buffer` is in the table.

### persist_file's floors were held or unreachable

`persist_file`'s path-assembly overflow guard is held (its removal crashes
the suite), and its name-buffer floor `cap < NAME_MAX_LEN` is exercised at its
exact call value -- the `<=` weakening is caught. Dropping the floor entirely
survived, but its only caller passes `cap == NAME_MAX_LEN` exactly, so the
sub-floor case cannot arise: a defensive guard against a caller that does not
exist, the same shape as state.c's seq-zero check, and left as it is.

The store finding is the file-backend cousin of record.c's open floor (sec
285): a length that decides a read or a write must be bounded before it is
used, and the fixture that never presents an over-length input never asks.

## 294. The lens in the sweep and catalog decoders

Carried the lens into `catalog/catalog.c` and `catalog/sweep.c`. `catalog.c`'s
decode is held: `apply_edge`'s `present > 1` flag (a two-valued byte, so 2 is
SHAPE), the retain deadline at `now == until`, and INLINE content, which flows
through `content_set`'s `len > INLINE_MAX` check rather than a second copy.
`sweep.c`'s sorted-cursor and truncation bounds are held, and its
`min_others > 0` guard survived a `>= 0` flip but is a no-edge -- min_others is
unsigned, so `< 0` never fires and a bar of zero behaves the same either way.

### The last-copy bar, tested off its threshold

`sweep.c` withholds a blob from deletion when `others_holding(...) < min_others`
-- fewer than the caller's bar of other hosts hold it. `sweep_test` set
`others` to 0 and 3 against bars of 1 and 4, all strictly below or above the
threshold, which `<` and `<=` order the same way. `sweep_fuzz` reaches
`others == min_others == 1` but is a protocol harness -- it checks the sweep's
call sequence, not which blobs the plan chose -- so it does not oracle the
decision. The one input the bar decides, a blob held by EXACTLY `min_others`
others, was reached by nothing, and tightening `<` to `<=` (withholding a blob
that meets the bar, retaining more than the caller asked) survived.

`sweep_test` now captures at a bar of three against a blob three others hold
and expects it swept; `sweep-last-copy-bar-is-inclusive` is in the table. It
is the inclusive-bound miss of sec 292 in the opposite direction: there a
maximum was rejected by a tightened upper bound, here a value that MEETS a
lower bar is withheld by a tightened one, and both are the endpoint a fixture
skips because the strictly-past cases look like enough.

## 295. The lens in the peer and vocabulary decoders

Carried the lens into `local/peer.c` and `local/vocabulary.c`. `peer.c`'s
groups parser is held: the `count == FZN_PEER_MAX_GROUPS` stop, the gid
overflow (`value > 0xffffffffu`), and the membership scan's group-count bound
are all caught. `vocabulary.c` was not.

### A verb of exactly the bound, matched against a rule of exactly the bound

`vocabulary.c` refuses a verb or a rule verb `> FZN_VERB_MAX` in three places
-- the shared `rule_names` predicate, `fzn_vocabulary_names`, and
`fzn_vocabulary_admit` -- and all three read `>`, so a verb of exactly the
maximum is legal and one more is not. The suite tested the bound thoroughly on
the wrong side: a MAX-length verb against SHORT rules (NOT_MEMBER whether the
check reads `>` or `>=`, because nothing matches either way) and a rule of
MAX+1 (refused by both). The one input that separates `>` from `>=` -- a
MAX-length verb meeting a MAX-length rule, which must match -- appeared
nowhere, and tightening any of the three to `>=` refused a verb the policy can
express, unseen.

`vocabulary_test` now builds a rule whose verb is exactly FZN_VERB_MAX bytes
and queries it with the same, expecting both `admit` to return MEMBER and
`names` to return 1 -- which holds the rule-side bound and both query-side
bounds at once. `vocabulary-verb-max-is-inclusive` is in the table; the two
query bounds are the same edge and the same test holds them, so they earn no
separate entry (sec 201).

### Note

This pass ran while the network was down (`git fetch` could not resolve the
host), so the commit is local until a push succeeds; the gates ran and passed
locally. It is the inclusive-bound miss of sec 292 and 294 a fourth time --
the endpoint a fixture skips because the strictly-past cases look like enough
-- now in the verb table that gates what a local peer may ask for.

## 296. The lens in the qr and provision decoders

`provision.c` was carried in sec 292 (its floors held, its two inclusive
maxima fixed). This took `qr/qr.c`, which is mostly an encoder -- text to a QR
matrix -- with the "decoder" being quirc, used by `qr_quirc_check` for a
round-trip. Its input validation is held: the EC level bound (`level > 3`, at
level 3), the matrix `x >= size` OOB guard, and the alphanumeric-char refusal.

### The version fit, off by an exact fill

`fzn_qr_version_for` takes the smallest version whose capacity is at least the
payload: `payload_bits(...) <= capacity`. Tightening `<=` to `<` survived
`qr_test` and `qr_print_test`. It is a REACHABLE edge, not a no-op: a sweep of
`version_for` across every length and level under `<` and `<=` found thirteen
(length, level) pairs that disagree -- 47 alphanumeric characters fill version
2 at level L to the bit, and `<` bumps them to version 3. The consequence is a
QR larger than the caller needs, and at FZN_QR_VERSION_MAX a refusal to encode
a message that fits.

`qr_quirc_check` probes "the longest payload this version holds," which is
exactly this boundary -- but it needs a quirc checkout, absent here, so it
runs only under the `qrcheck` target; and it RECOMPUTES the longest length from
`version_for` itself, so it adapts to `<` rather than catching it. Every case
in `qr_test` sits strictly inside a version, where `<` and `<=` agree.
`qr_test` now asserts a 47-char payload is version 2 and a 48-char one is
version 3; `qr-version-fit-is-inclusive` is in the table.

### The empirical check earned its place

Whether `<=` versus `<` was even observable turned on arithmetic: in byte mode
`payload_bits` is a header plus a multiple of 8 and the header is not a
multiple of 8, so it never equals a capacity (also a multiple of 8) -- a
no-edge. Only alphanumeric mode, whose bits advance 11 per two characters, can
land exactly on a capacity. Rather than reason it out per mode, a sweep under
both comparisons settled it: thirteen real disagreements, so the edge is
reachable and worth holding. It is the inclusive-bound miss (sec 292, 294, 295)
a fifth time, in the version chooser of the QR encoder.

## 318. Retirement migration: status, and the evolve-in-place recommendation

A handoff note, folded before a context clear. sec 317 mapped the retirement
of the old catalog/; this records how far it has gone and the one decision it
now turns on.

BUILT, additive, catalog/ untouched, all gates green:
- The DATA MODEL is superseded and hardened (secs 314-316): the ATTRIBUTE
  wire encoding, membership-as-attribute, partial-data safety, and the codec
  fuzzed (attribute_fuzz) with decode's body bound made symmetric.
- STEP 1, reachability: `fzn_catalogue_referenced` and `fzn_catalogue_sources`
  in catalogue.c -- the local curated-link check that replaces reach.c's
  transitive DAG walk. "Unreferenced" is not "deletable" (C7/C17).
- STEP 5 FOUNDATION, the holder set: `fzn_catalogue_holders` -- C8's "which
  hosts hold this," derived from the capability axis (a HOLDER-capability
  assertion can only come from a real holder, C5e/C8a). This is what copy's
  holdings/offer and sweep's last-copy guard asked catalog/ a callback for;
  now it falls out of the record set. out_count == 1 is a last copy.

THE PIVOT. reachability and the holder set are the two things the new model
genuinely CHANGES. Everything left -- the sweep planner, retention, copy,
filing -- is COMPOSITION of these plus logic that is UNCHANGED from catalog/
(the tri-state retention table, the sweep guard-chain and cursor, copy's
wrapping of holders). copy's holdings/offer is now just `holders`; want is
`holders` + retention + reachability; sweep's last-copy guard is
`holders` out_count == 1.

RECOMMENDATION (mine; the choice is the holder's because it edits tested
code): EVOLVE catalog/'s sweep and copy IN PLACE -- swap their data source to
consume `referenced`/`holders` instead of the edge-walk and the holdings
callback, keeping the tested guard-chain, cursor and removal_t. Pure-additive
work past this point would REWRITE unchanged catalog/ logic from scratch,
which is the duplication the guidelines warn against and risks reintroducing
bugs the tested code already fixed. Evolve-in-place preserves that logic.
"No one is using catalog yet" (the holder, this session) makes either safe.

OPEN, none of them mine to settle:
- The evolve-vs-rewrite choice above, to finish sweep/copy/retention.
- ~~The reclamation POLICY (C18)~~ SETTLED 2026-09-21: no automatic GC. C18
  stands, grace and granularity do not arise, and step 4 is a recorded
  decision rather than a build. sec 330.
- Confirm retention and filing stay per-host (C5a HOST), never shared records.
- ~~"install on phone"~~ SETTLED 2026-09-21: no Android fuzznetd build. The
  library already ships on Android inside fuzzypickles' APK, and a
  cross-compile gate now keeps that true from here. sec 333.

## 510. The sweep over stage 4, and two questions from fuzzypickles, 2026-10-07

### What the stage 4 sweep left

The sabotage sweep over the entries stages 4a to 4b-ii touched, plus the
four revoke-load guards sec 506 restored and the two purge entries: 74
entries, 73 caught. These include all four restored guards, the full-store
stop in `node/apply`, and both purge retries.

The one survivor was `node-roots-set-journal-repoints-the-store`.
`fzn_node_roots_set_journal` re-points a store attached before it, and
every test set the journal first (`roots_of`) and attached after. fuzznetd
does the reverse: it attaches at start and sets the journal when
`records/` opens. pair_test's revoked-member scenario now builds R's roots
in the daemon's order. With the re-point removed, the line falls: X,
added before it, is dropped (two failures).

### Open, from fuzzypickles' sec 196

fuzzypickles drafted dropping a removed contact's incoming shares, then
reverted it before commit because it reversed the holder's decision of
2026-10-06 (sec 478 above). Both trees keep what a removed contact shared
until `remove received`. Two things remain:

- **~~A removed contact is still pulled.~~ Settled in sec 576**: the
  holder decided 2026-10-09 that a removed contact's shares are pulled no
  further while it is removed, and again once it is added back. What it
  shared stays, as before.
- **A requirement for the sibling wire.** A delegated message whose
  contact the owning device has removed is never acked, so the delegating
  host retries for good. It needs a "cannot deliver" answer that host can
  act on. Answered in sec 607 by a not-delivered mark that travels, for a
  contact removed; the wire itself is still fuzzypickles'.

## 878. Where this stands, folded 2026-11-04

A session's fold, so the next one starts from the record rather than
from memory. Everything below is committed and pushed, the tree is level
with origin, and the inbox is empty.

**Built across secs 852 to 877, in the order the holder set** (sec 851,
and the holder's word of 2026-11-04 for 871 to 875):
- Local permissions, 852.
- `call` by name, here, across hosts and through a follower: 853, with
  the bound on its answer in 863.
- Lists and records under a prefix: 854, 855 and 861.
- The consumer services as build flags, with unreachable code dropped at
  link: 856 and 860.
- Huge pages refused before main, 862.
- Events since a cursor, 866.
- Group-scoped settings and `get setting here`, 868.
- The relay route, 871.
- Command propagation, 872.
- The staged commit, 873.
- Sealed group values and later members: 874 and 875.
- The in-process reader, 877.

**Open, none asked for:**
- **A staged clear** (`remove staged`). The machinery of sec 873 would
  carry it.
- ~~A sealed value reaching a later member once its sealer is gone.~~
  Built in sec 880.
- **A contact's key as a `message` event's NAME.** fuzzypickles says it
  does not need this.

**Notes for the next session:**
- `fzn_node_settings_here` and `fzn_daemon_setting_here` answer -1 for a
  value sealed to a key this host lacks. Test for `> 0`, not for nonzero.
- An older build refuses a group cell (sec 868) or a stage object (sec
  873) it is carried, and goes on with the rest of the stream.
- `live_ext` now runs about seven minutes. Its Makefile bound is 560 s.

**Waiting on the holder:** nothing.

## 892. Where this stands, folded 2026-11-05

Everything is committed and pushed, the tree is level with origin, and the
inbox is empty. Since sec 878: secs 879 to 891.

**Verified on the final code:** `make test`, `make style`, `make livecheck`
(235 phase lines, no failure, the new scripts among them) and `make
livecheck-faults`, which is where `live_estate` runs.

**`make livecheck-san`, its first run as a target: 0 reports, 18 scripts
passed, and `live_siblings` failed once**, at phase a: "after 6 rounds each, a
pairing taken at B False, at C False". Unexplained. Repeated at once, it passed
4 of 4 sanitized and 2 of 2 plain, which is what an intermittent fault does and
clears nothing. Neither host paired in any of twelve daemons, so it is no late
log line. **The candidate, not proved:** its ports were 28000 to 32000, across
fuzzypickles' fixed 29800 to 31000, and a suite of theirs was running. The run's
logs went with its scratch. Its ports are moved past theirs; if it fails again
there, this was not the cause.

**Leaks:** nothing reports through `live_ext`'s clean stops. A daemon stopped
by SIGTERM dies without LeakSanitizer running, since nothing here handles that
signal, so a live script over `fuzznetd` says nothing about leaks. Memory
reachable from a static is not a leak to it either.

**Two trailers are wrong and stand, the commits being pushed.** `4312c3a`'s
names no commit (sec 890). `aaf69c2`'s reads `09b200d0aa52`, its first seven
right, for `09b200d3379d`.

**Open, none asked for:**
- A staged clear (sec 873), for want of a consumer.
- `sec 880`'s limits: a holder away at a reseal may hand on the old value, and
  a sealed value is replaced, never withdrawn.

**Waiting on others:** fuzzypickles' pin and its step 3, told of every fix; fzpd
on `fzn_daemon_main` is its tree's work. netcfgd told of `any=x`, the follower's
read, and sec 879.

**Waiting on the holder:** nothing.

## 901. Where this stands, folded 2026-11-05

**Built since sec 892, all on the holder's word or a consumer's asking:** two
people may share a name (893), a host keeping and relaying nothing carries no
group's lines (894), what is decided apart is tracked (895), a device joins by one
code (896), SIGTERM stops cleanly and leaks are looked for (897), a contact's root
is asked first (898), a held event stream (899), a kept reply goes only where it
was asked from (900). `FZN_PRODUCT_NETCFGD` is 3.

**Gates at `03a3337`, nothing beside them:** `make test`, `installcheck`, `style`,
`livecheck` (252 lines), `livecheck-faults` pass. `livecheck-san`: 19 scripts
passed, 0 reports, leaks on, and two failed.

**`live_siblings`' failure is explained, and sec 892's candidate was wrong.** It came
back with its ports moved and no other suite up, so ports were not it. C takes its
pairing once, says so 15 ms past the reconcile line, and the script read the log
at that line and stopped the daemon: read after the stop now, 5 of 5 and more.

**`live_contacts` f0, explained 2026-11-06.** Bounds of 90 and 150 s at e2 and f2 are
180 and 300 now, a sanitized round being 66 s. f0 went on failing now and then, in
the plain suite too, so "under the sanitizer" was wrong, and so was reading a tail
of S's log as S offering nothing. With every log kept: S delivered the line, and
**R3 filed and settled it.** R3 has no address of its own, but says hello to R, and R
advertises where a host was seen (sec 697), so S may reach it, by timing. That is
right. The script looked only at R and R2, believing R3 unreachable. It now takes R3
as a filer, and such a run leaves sec 802 unasked.

**`make livecheck-san` at `4677d9d`, nothing beside it:** 21 scripts, no report,
leaks on: its first clean run.

**Open, unexplained, said as that:**
- **`live_names` b failed once** in `make livecheck`: after 180 s neither host had
  the other's name. It then passed 18 of 18 alone, and in every gate since. Logs
  went with the run. Orphaned daemons of this session's were up on those ports for
  part of the day, from runs killed by an outer `timeout`, which may or may not
  bear on it. Not concluded.
- **Why sec 897's stop raised `live_contacts`' f2 failures** (sec 898).
- **`live_faults` j** failed once at its 60 s bound, with other runs beside it, and
  passed alone.

**A lesson of this run:** `timeout` around a live script kills the script and not
its daemons, whose process groups are their own. Stop one with `-s INT`, or let it
reach its own deadline.

**Waiting on the holder:**
- A right to hold the application's events for `any` (netcfgd's asking): sec 883
  refused `any=r`. The 4 held slots this line once feared for are gone (sec 903), and
  the word with them (sec 899), so what is left to weigh is any local user hearing
  what the application publishes through `local/events`.

**Waiting on others:** fuzzypickles' `contacts-same-name` expectation, its pin and
step 3, and fzpd on `fzn_daemon_main`. A real second user for sec 899, on either
side. Open from before: a staged clear (sec 873), sec 880's limits.

## 1173. The library in binary: the fold before it landed (2026-11-15)

Written at the week's stop. The work it describes was built in a scratch
copy under the other account, which this account could not read the next
day, so it was built again from the design below and landed as
**section 1174** -- read that; this section is kept only for the design as
it was first worked out.
