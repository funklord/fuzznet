# fuzznet's journal: what was true once

Moved out of `project.md` under the holder's rule of 2026-11-20: dated
state-of-play sweeps, session narrative and closed findings, so that
`project.md` stays readable enough to be authoritative. Oldest first,
appended to and never rewritten. **A section here keeps its number**, so
a `sec N` citing it resolves here -- `make cites` reads both files'
headings (project.md sec 1403).

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

## 1173. The library in binary: the fold before it landed (2026-11-15)

Written at the week's stop. The work it describes was built in a scratch
copy under the other account, which this account could not read the next
day, so it was built again from the design below and landed as
**section 1174** -- read that; this section is kept only for the design as
it was first worked out.

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

