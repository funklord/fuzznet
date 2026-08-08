# project.md

**fuzznet** — the authenticated datagram protocol shared by `fuzzypickles`,
`netcfgd` and the planned `raidcfgd`.

This document is the source of truth and **wins over the code**. Where the
implementation learns something this does not say, this gains it.

Created 2026-08-08, on being asked to stop three projects writing the same
protocol three times.

---

## 1. What this is, in one paragraph

A C library that carries **authenticated, framed, chunked messages between a
client and a daemon-side bridge over UDP**, with a capability model in which a
stolen device is something you *revoke* rather than a password you change. It
does not know what the messages mean. Each consuming project keeps its own
command vocabulary, its own semantics and its own local socket; what they stop
duplicating is the envelope, the signing, the session, the chunking and the
reassembly.

---

## 2. The scope decision, which is the whole design

The request that produced this named two needs:

1. local, pre-authenticated, group-gated access to a daemon running locally
   or as root;
2. authenticated remote access over an efficient UDP protocol.

**Only the second is shared, and that is a finding rather than a
simplification.** It comes from netcfgd's `docs/shared-protocol-brief.md`,
written for this library before a line of it existed, and it is worth stating
in full because the obvious shape of a shared protocol library is the shape at
least one consumer cannot adopt.

### The local hop is not shared, and must not be

| | fuzzypickles | netcfgd | raidcfgd |
|---|---|---|---|
| local encoding | the core's canonical binary wire, one parser for local and remote | newline-delimited JSON | undecided; does not exist |
| local transport | `AF_UNIX` `SOCK_SEQPACKET` | `AF_UNIX` stream, line-delimited | undecided |
| local authentication | filesystem permissions, owner-only, same user | the kernel, before a byte is parsed | must be group-gated |
| already built | yes | yes, specified and pinned by a generated witness, implemented three times | no |

Two consumers already have a local hop, they disagree about its encoding, and
**both disagreements are load-bearing rather than accidental**:

- fuzzypickles deliberately uses **one encoding for both hops** so that there
  is exactly one parser for every consumer of core bytes, local or remote —
  the same reasoning as "different-privilege hosts parse the same manifest."
- netcfgd deliberately uses **JSON on the local hop** because not being a
  black box is the product: its runtime state is greppable JSON, a shell
  script with `jq` is a legitimate client, and the machine having the problem
  is usually a router being reconfigured over the network that is failing.
  Its full argument is `docs/socket-protocol.md` §3.1, and it is falsifiable —
  it names what would change the answer.

A library that imposed either choice on the other project would be asking a
maintainer to give up a stated product property to gain a dependency. So
**fuzznet does not define the local hop at all**, and the seam is drawn where
the trust boundary already is:

| | local control socket | fuzznet |
|---|---|---|
| carries | whatever the project already chose | a binary framed message |
| reaches | this machine only | across a trust boundary |
| authenticated by | the kernel, before a byte is parsed | a signed capability |
| chosen for | each project's own reasons | exactness, authentication, size |

### What about group gating, then?

The first need is real, and it is **not** met by anything today:
fuzzypickles' local link is same-user by construction and has no credential
check at all, because it has never needed one; netcfgd's daemon does its own.
A daemon running as root and serving a group needs `SO_PEERCRED` /
`SCM_CREDENTIALS` and a real gid check.

It ships as an **optional module** (`fuzznet_local`, §8) rather than as part
of the core, and the reason is the risk netcfgd's brief names precisely:
**raidcfgd does not exist.** Of the three consumers of a group-gated local
socket, one has declined it, one would have to migrate an existing working
socket to gain it, and the third is imagined. An imagined consumer's
requirements are exactly the kind that turn out wrong after an API is fixed.

So the local module is written, and it is written *last*, against a real
raidcfgd rather than a hypothetical one. Everything in §4 is needed by two
real consumers today.

**Rejected: one library, one encoding, both hops.** It is the shape somebody
will propose again, so the reason is recorded rather than left to be
rediscovered — it costs netcfgd a stated product property, and it buys
fuzzypickles nothing it does not already have.

---

## 3. Who links this, and who does not

**The privileged daemon never links fuzznet.** netcfgd fixes this in its
design §11.3 and repeats it as constraint 6: whatever speaks UDP is a separate
unprivileged process holding an ordinary local socket connection. The
consequence for this library is a permanent one and shapes its API:

- fuzznet is linked by an **unprivileged bridge** that terminates the remote
  protocol and then speaks the project's own local socket as an ordinary
  client;
- it never runs in the process holding `CAP_NET_ADMIN`, a RAID controller, or
  a user's private keys beyond its own session material;
- therefore **a fuzznet vulnerability is not a root vulnerability**, and the
  library must never acquire an API that would tempt somebody to link it into
  the daemon to avoid a hop.

fuzzypickles is the exception that proves it: its daemon *is* the thing that
speaks to peers, because for a chat program the network is the product. It
links fuzznet as a peer of its own core rather than behind a bridge, and it is
the only consumer that will.

---

## 4. What the core carries

Everything here is needed by fuzzypickles and netcfgd today. Nothing here is
speculative.

### 4.1 Framing and canonical encoding

Fixed-width, big-endian, no padding, **exactly one valid representation per
value**. Reader/writer primitives over caller-owned buffers, no I/O, so they
are fuzzable directly with no daemon or socket in the loop. This is
fuzzypickles' `core/src/wire.c` — 101 lines, already fuzzed — and it is the
least controversial thing in the library.

Canonical form is not aesthetic here: it is what lets a message be **hashed,
signed and byte-compared**, which is exactly the property netcfgd names as
absent from JSON and exactly why the remote hop cannot be JSON even in the
project that wants JSON locally.

### 4.2 Authentication, and the identity model

A **capability chain rooted at a user key**, verified against a pinned root
rather than adopted, with revocation carried on contact.

fuzzypickles' `identity.c` and `capability.c` are the working implementation
(~2200 lines together) and netcfgd's brief calls this the part it most wants,
as a requirement rather than a preference: *a stolen device is a capability to
revoke, not a password to change.*

**Capabilities are opaque to the library.** fuzzypickles has six
(`admin`, `host-manage`, `store`, `relay`, `send`, `peer-manage`); netcfgd has
three (`observe`, `wifi`, `admin`) which are **independent rather than a
ladder** — a machine may grant `admin` to a group somebody is in and `wifi` to
one they are not, so there is no maximum to report. A library that assumed a
total order would be wrong for netcfgd on its first day. So fuzznet carries an
opaque capability identifier and verifies the *chain*; what a capability
permits is the consumer's.

### 4.3 Freshness: commands expire, grants do not

This looks like a conflict between the two projects and is not, which is worth
writing down before somebody "resolves" it.

fuzzypickles' §3 is emphatic that **authority is not ended by a clock**: a
grant without a duration is the default precisely so that no expiry can
silently disconnect a host, and revocation is on contact. netcfgd asks for
**mandatory expiry on commands**, because a command that reconfigures a router
an hour after it was sent — because the router was off — is precisely the
failure commit-confirm exists to prevent, and because a plan is computed
against a *current* observation, so a stale command was computed against a
machine that no longer exists.

These are statements about different things. **Grants do not expire; commands
do.** The envelope carries `nonce | expiry` inside the signed region, and:

- expiry on a **command** is mandatory, and a receiver refuses one that has
  passed or that carries none;
- expiry on a **grant** is optional and defaults to absent, and an expired or
  absent expiry never withdraws authority — only a revocation does.

Recorded because the default that arrives with a messaging protocol pushes the
wrong way, and because fuzzypickles' rule, read carelessly, would have made
netcfgd's requirement look like a violation of it.

### 4.4 Chunking and reassembly — the largest and riskiest piece

netcfgd's responses are not small: a `status` is an entire observation — every
link, address, route, backend and DNS scope — and a `show` is a compiled
document. On a router with a dozen interfaces that is past any UDP MTU and past
the practical limit of IP fragmentation, which is to be avoided regardless
since fragmented UDP is widely dropped.

So the core needs **application-level chunking, reassembly, retransmission of
missing pieces, and a hard bound on the memory a half-finished response may
hold**. fuzzypickles has chunking, but for content-addressed assets — a
different problem, where the content has a hash-derived name and the transfer
is pull-based and requester-coordinated.

This is the single largest piece of new work and the highest-risk part, and it
is where the two consumers' needs are least similar. It gets built against
netcfgd's shape, since netcfgd is the consumer whose responses force it.

### 4.5 Sessions and encryption

Key-committing AEAD, and a session established from a prekey. fuzzypickles'
`crypto_msg.c` (197 lines) and `prekey_channel.c` (77 lines) are small and
already carry the properties.

**Monocypher**, vendored once here rather than three times. netcfgd had already
decided C/C++ with Monocypher for its own protocol and agent before this
library existed, so the two agree without having to be reconciled.

### 4.6 Nothing transmitted carries secret material

netcfgd's constraint 5: its desired-state document carries `SecretRef`
indirections only, invariant across local files, `/run` state and any wire
transmission. And a received document may reference only hook paths that
already exist on the device, never inline shell, because *a document that can
carry shell is remote code execution with extra steps.*

Neither is a rule this library enforces — it does not know what a payload
means — but both are reasons the library must never grow a convenience that
makes carrying a blob of executable content easy and obvious.

---

## 5. What the core deliberately does not carry

Naming these matters as much as §4, because a shared library's failure mode is
absorbing one consumer's application until the others are carrying it.

- **Command vocabularies.** fuzzypickles' `control_codec.c` is 4718 lines of
  encoders and decoders for *its* commands. None of it is shared. A project's
  vocabulary is its own, and the library carries the envelope around it.
- **Store-and-forward, retry sweeps, settle tracking.** fuzzypickles is built
  so a message reaches a sleeping peer eventually. Every one of those
  behaviours is wrong for configuration, per §4.3.
- **Content-addressed transfer, group ratchets, geolocation, media.** These
  sit *above* the wire in fuzzypickles already and stay there.
- **Rendezvous, hole punching, relays.** netcfgd's decision 2 is LAN only
  first: the case a person actually wants is "I am at home, fix the wifi".
  fuzzypickles needs all three and keeps them in its own tree until a second
  consumer wants one.
- **The local socket.** §2.

**The test for admitting anything new: two real consumers need it, and neither
would accept the other's version as a special case of their own.** One
consumer needing something is a reason for that consumer to build it.

---

## 6. `situ`, and whether the frame is hand-written

netcfgd's own decision 4 was that **`situ` describes the frame**, with
Monocypher bound as an extern codec, and the hand-written half built to be
deleted as situ absorbs chunking and encryption. `situ` is the workspace's
schema compiler for byte-exact data layouts, and the standing directive in
`build-and-commit.md` is that any project hand-writing wire-format encoders,
parsers or layout assertions is a candidate for it.

**This library is the strongest candidate that has ever existed for it**, and
that evaluation is the first piece of real work, before the frame is written
by hand and becomes the thing somebody has to migrate.

netcfgd's §9 already did half the evaluation against its own control socket
and split the answer: the *framing* is describable, and situ's `unbounded-scan`
rule would have predicted a bound netcfgd reached by judgement; the *payload*
is not describable, because a JSON object has no byte layout to pin. Here both
halves are binary, so the split that constrained netcfgd does not apply.

### The answer, from situ's own tree (2026-08-08)

**situ describes the whole packet, crypto included, and this is built rather
than planned.** Its phases 7 and 8 -- extern codecs, and the cryptographic
model -- both record status complete, and the keywords are in the compiler.
The question "shouldn't situ pack the entire packet, since these are generic
crypto operations" turns out to be the question situ was written to answer:
its §14 opens "the first real use case is compact encrypted protocols, so this
is not an add-on."

What exists:

| construct | what it gives this library |
|---|---|
| `coded(C) { ... }` | a general transform region -- the extern codec, where the implementation is supplied and the schema names it |
| `sealed(codec, nonce = ref) { ... }` | encrypted and tag-covered; per decision 0009 this is `coded` plus authentication rather than a second mechanism |
| `authenticated { ... }` | plaintext covered by a tag -- AEAD associated data |
| `tag T[N] [covers(...)]` | coverage inferred when omitted, explicit when it matters |
| `nonce`, `secret` attributes | nonce binding, and key material marked so it shapes the generated API |

**The permutation explosion is answered by composition, not enumeration**, and
that is the part worth understanding before proposing anything. situ does not
carry a variant per algorithm pairing: the codec is an extern the schema names,
`sealed` is `coded` + tag rather than its own construct, and layer order is an
**explicit pipeline** -- `sealed(aead |> rs)` -- with encrypt-then-code and
code-then-encrypt never inferred. Orthogonal primitives compose; the product
space is never written down. That is why "a huge number of permutations" is not
the objection it looks like.

Three properties land directly on decisions this document already has open:

- **Nested sealing is a solved case.** Tag coverage recomputes *innermost
  first*, which decision 0011 records as the only order that terminates, since
  an outer tag covers the inner tag's bytes. §12's `hostenc(userenc(...))`
  question is therefore expressible today rather than a reason to hand-write.
- **`Uncovered` is where a relay-mutable field must live**, and the compiler
  makes that visible: mutating a `Covered(t)` field sets tag `t` dirty and the
  generated API refuses to hand out a transmittable buffer until it is
  recomputed. A hop counter or routing header outside coverage is exactly the
  shape §3's bridge needs, and `require no_tag_invalidation(expr)` checks it
  statically.
- **Verification is enforced by the type system, not by discipline.** Interior
  accessors take a generated view type that only the open function produces,
  and that function demands the verification result. Parse-before-verify -- the
  defect class this whole family of protocols fears most -- becomes
  unrepresentable rather than merely forbidden.

### Where situ stops, which is the boundary that matters

**situ describes a message; it does not describe a conversation.** State that
precisely, because a first version of this section overstated it: situ's §2
non-goals say **nothing** about protocols, and the "service and RPC definitions
are out of scope entirely" line is from its *protobuf importer*, about what a
`.proto` will not translate. What is actually true is that there is no
construct for retransmission, reassembly or timers, nothing about them in the
thirteen-phase plan, and **no mention of request/response correlation,
conversations or sessions anywhere in an eleven-thousand-line document**. It is
unaddressed and unplanned, not forbidden.

### Should situ describe the send/receive pattern? A narrow yes

Worth raising with that project rather than deciding here, and worth splitting
into two questions that are easy to run together.

**Cross-message *relations* are declarative, and situ is already most of the
way there.** "A response carries the request's `msg`", "`index` is below
`chunks`", "an `ack` names a sequence that was sent" -- these are `require`
-shaped statements about bytes in two messages rather than one. They need no
runtime, no timers and no allocation. Two artifacts situ already generates
would improve immediately:

- **`gen-dissector`.** A Wireshark dissector's most valuable feature after
  field decoding is conversation tracking -- "response to frame N". situ emits
  dissectors today and cannot express the one thing that would make one tell
  that story.
- **`gen-fuzz`.** A harness that knows a response must echo a request's
  identifier can generate sequences that get past the first check, rather than
  rediscovering the correlation by luck.

The `stage` axis is suggestive too: it already reasons about *when* a value
becomes knowable (`CompileTime < ParseTime < TransformTime < VerifyGated`), and
"knowable only from a message already seen" is a recognisable neighbour.

**Protocol *dynamics* are a different product and should stay out.**
Retransmission, timers, windows and congestion need a state machine, and two of
situ's existing non-goals are what it would have to argue with: **no dynamic
allocation, ever**, and "not a parser combinator library -- the layout solver is
a compiler pass, not a runtime interpreter". A schema compiler that grew a
scheduler would also break its own first rule, that the capability lattice wins
when anything conflicts with it.

So the recommendation, if it is put to situ: **describe the relation, not the
behaviour.** Whether it earns its keep there is that project's call, and this
library is a weak witness -- we would be the consumer asking for it, which is
the worst position from which to argue that somebody else's scope should grow.

So §4.4 splits, and this is a genuine refinement rather than a restatement:

- the **chunk frame** -- sequence, offsets, coverage, the sealed payload -- is
  a schema, and situ writes both ends of it;
- the **chunking state machine** -- what to retransmit, when to give up, how
  much memory a half-finished response may hold -- is this library's own C,
  and is where the risk in §4.4 actually lives.

That corrects an expectation carried in netcfgd's decision 4, which had the
hand-written half "built to be deleted as situ absorbs chunking and
encryption". Encryption is absorbed already. **Chunking is not going to be**,
because it is protocol dynamics rather than layout, and waiting for it would be
waiting for something situ has deliberately excluded. Worth telling that
project rather than leaving the expectation standing.

**So the frame is not hand-written.** What remains to measure is narrower than
"can situ do this": whether our specific frame hits any `unbounded-scan` or
canonicality rule, which is a schema-writing exercise and the first real task.

### The first schema, and what measuring it said

`wire/frame.situ` exists and compiles. It is **a revision to be measured, not a
settled frame** -- it encodes §4's decisions and leaves §12's candidates
visible as open rather than quietly choosing them.

**§10's question is answered: nothing trips.** `require canonical(fzn_frame)`
passes, no `unbounded-scan` diagnostic appears, and `situc wire` reports
`size=96..1120` with the tag covering every authenticated and sealed member.
Unknown enum values are an error rather than a silent pass, which is the right
default for a format that has to be byte-exact.

**The `require` lines are enforced, checked by breaking one deliberately.**
Asking for `in_place` on a covered field fails with the blame chain and both
remedies named -- move it outside coverage, or accept the recomputation and say
so with `in_place_dirty`. That is the property worth having: the schema states
what must hold about the *bytes*, and the compiler refuses a build rather than
a reviewer noticing.

Three findings, and the first is the one that matters:

- **96 bytes of fixed overhead per datagram**, 80 of header and 16 of tag. Of
  the 75-byte authenticated header, `capability[32]` and `nonce[24]` are 56.
  Against fuzzypickles' §8, "per-frame overhead is the budget that never
  improves", that is a lot -- on the 512-byte datagram the previous generation
  chose (§12), it would
  be a fifth of every frame. **A 32-byte capability identifier in every
  datagram is the opposite of fuzzypickles' §8, "amortize session setup"**, and the obvious
  answer -- establish the capability once per session and carry a short handle
  -- is a real design question this schema surfaced on its first run rather
  than after an implementation existed. Not decided here.
- **Alignment buys less than the example implies, because the wire is
  big-endian.** Every multi-byte field reports `repr=ValueConverted`: the value
  is not the memory, so a caller cannot take a pointer and every access is a
  read-swap-write whatever its offset. situ's own packet example pays three
  bytes of padding for alignment; copying that reflexively would be paying for
  a property this format's endianness has already spent. Worth deciding
  deliberately rather than by imitation.
- **The sealed region is `mutate=Shifting`**, because the payload is
  `Bounded(0,1024)` rather than fixed. Interior in-place editing is therefore
  not available -- which costs this library nothing, since a frame is built
  once and sent, but it would matter to anyone imagining a mutable interior.

`situc advise` returns one suggestion: move frequently-rewritten fields out of
tag coverage, since each write costs a recomputation over 1099 bytes. **Not
acted on, deliberately.** Its cost model assumes repeated in-place mutation of
a built frame; our access pattern is build-once-then-send, where those fields
are written before the tag is computed at all and cost one recomputation
between them. A suggestion whose cost model does not match the usage is the
same shape as a gate that cannot model what it checks -- understand it before
obeying it.

---

## 7. How a consumer gets this, and how it links

**A git submodule, built from source by each consumer. No shipped archive.**
Decided by counting what the consumers already do rather than by preference.

fuzzypickles vendors all six of its dependencies exactly this way -- monocypher,
iniparser, flog, quirc, miniz, thorvg -- as submodules at the repository root,
with the sources compiled into that project's own objects. Its `core/Makefile`
even records the refinement: `monocypher.o` is kept under the consuming
project's tree rather than inside `monocypher/`, "so that directory stays a
clean checkout". Matching that costs nothing and means one habit works in every
tree, which is `harmonization.md`'s whole argument.

Three reasons it is also right on the merits, beyond harmonising:

- **A submodule pins an exact commit, and this is a protocol.** Two hosts must
  agree about bytes. A floating dependency is precisely how they come to
  disagree silently, and a pinned commit makes a wire change a reviewable diff
  in the consumer rather than an ambient upgrade.
- **Each consumer needs its own flags.** fuzzypickles cross-compiles for
  Android and builds sanitized; netcfgd's agent is an ordinary host binary. A
  prebuilt `.a` serves neither, and shipping several serves nobody.
- **`build-and-commit.md` says not to add an archive step without a specific
  need**, and there is none here: a consumer already builds an archive of its
  own and these objects join it. An archive of our own would also put the same
  symbols in two archives if a consumer ever linked both, which that document
  names as a landmine.

**During bring-up, a sibling directory is fine and should be a variable, not a
second build path**: `FUZZNET_DIR ?= ../fuzznet`, overridden by the submodule
path once there is something stable to pin. One knob with a default, rather
than two ways to build that drift.

**Not a system package, and not a shared library.** A `.so` would put wire
compatibility in the hands of whatever the distribution shipped, which is the
same failure the pinned commit exists to prevent -- and this is a static,
few-thousand-line library where the dynamic-linking argument buys nothing.

## 8. Shape of the tree

Modules, so a consumer links what it needs and no more. Nothing below is built
until §10's order says so.

| module | what it is | who needs it |
|---|---|---|
| `wire/` | canonical encode/decode primitives | everyone |
| `frame/` | envelope, nonce, expiry, signing, verification | everyone |
| `session/` | prekey, AEAD, replay window | everyone |
| `chain/` | capability chains, verification, revocation | everyone |
| `chunk/` | chunking, reassembly, retransmit, memory bound | netcfgd first |
| `local/` | `AF_UNIX` with `SO_PEERCRED` and group gating | raidcfgd, when it exists |

`local/` is deliberately last and deliberately optional — §2.

---

## 9. Authority, and who decides what

Settled with netcfgd in its brief §8, and it generalises to every consumer:

- **For encoding, framing, authentication and encryption, this library
  decides.** netcfgd wrote that down in its design §11.3 before any of this
  came up, so it is not a concession made under pressure.
- **For what a field means, what a device must reject, and how versions skew,
  the consuming project decides.** Its `project.md` is its own source of truth.

netcfgd's constraint 6 — the one-way rule — applies here with more force than
it did to adapters: **no change to a consumer's model, config language or
socket API may be justified solely by this library's convenience.** A shared
library is exactly the leverage that rule exists to resist, and *raidcfgd
wanting something is not a reason netcfgd's protocol gains it.*

Two of netcfgd's gates matter to anyone working in that tree:
`docs/schema/socket.json` is generated and moves only by `make schema-bless`;
and `make conformance` diffs what its Rust and C clients extract from the same
bytes. That gate caught three spellings of one access point's name, and it is
the one worth keeping green.

---

## 10. Order of work

1. **Evaluate `situ` against the frame** (§6), before anything is hand-written.
2. **`wire/`**, lifted from fuzzypickles with its fuzz targets.
3. **`frame/` and `chain/`**, the envelope and the authority model —
   fuzzypickles' identity/capability code is the working implementation and
   netcfgd's most-wanted piece.
4. **`session/`.**
5. **`chunk/`**, against netcfgd's response shapes, since they are what force
   it (§4.4). Highest risk; expect it to take longer than the four above.
6. **netcfgd's `agent/`** becomes the first real consumer — it does not exist
   yet, which is the whole of the timing benefit: consuming a library means
   the second implementation is never written.
7. **fuzzypickles migrates**, as separate deliberate work.
8. **`local/`**, when raidcfgd exists and can say what it needs.

### fuzzypickles migrates later, and does not lead

**Decided rather than assumed**, and the alternative was real: carve
fuzzypickles' core into this library immediately and make it the first
consumer, so that a second implementation never exists at all.

Rejected because fuzzypickles' protocol is nine thousand lines of design
document and a passing sixty-seven-scenario end-to-end suite, and putting that
on the critical path of a library with no users yet risks the working thing to
speed up the unwritten one. netcfgd's `agent/` is the honest first consumer
precisely because it is *not yet written*: nothing regresses if the API is
wrong, and the API finds out early.

The cost is a period where fuzzypickles' core and this library both exist.
That is a duplicate to retire, tracked here, and it is cheaper than the
alternative failure.

---

## 11. Where this is, for whoever picks it up

**Nothing is built.** This document, a `code-style.md` copied from the global
source, the shared `style_gate.py` and `commit-msg`, a `Makefile` with `style`
and `hooks`, and a `VERSION`. `make style` passes over six files.

The reading that produced it, in the order worth repeating:

1. **`../netcfgd/docs/shared-protocol-brief.md`** — written *for this library*
   before it existed, and the single most useful document here. It states
   netcfgd's requirements, what it cannot trade away and why, what it has
   already decided that this library may knowingly overrule, and what it
   cannot tell us. §2 and §4 of this document are largely its argument.
2. **`../netcfgd/docs/socket-protocol.md` §3.1** for why netcfgd's local hop
   is JSON, and `../netcfgd/docs/remote-access-feasibility.md` §5 for the two
   requirements a messaging protocol gets wrong.
3. **`../fuzzypickles/project.md` §6, §7 and §13** for the working
   implementation of nearly everything in §4 here.

What was measured rather than assumed, since it decides how much is actually
being shared: in fuzzypickles, `wire.c` is 101 lines, `crypto_msg.c` 197,
`prekey_channel.c` 77, `peer_wire.c` 100, while `capability.c` and
`identity.c` are about 2200 together and **`control_codec.c` is 4718 lines of
that project's own command vocabulary**. The last of those is the number that
matters: most of what looks like protocol in a mature consumer is application,
and §5 exists to keep it out.

**The maintainer has said the protocol parts of netcfgd are ours to edit**, and
that reading and editing netcfgd and raidcfgd is authorised for this work. Two
of netcfgd's gates matter when doing so: `docs/schema/socket.json` moves only
by `make schema-bless`, and `make conformance` diffs what its Rust and C
clients extract from the same bytes.

## 12. Prior art: three mechanisms from the 2018 generation

A previous `fuzznet` existed. It was a 2018 attempt inside what became
fuzzypickles, and its code is not being kept -- see fuzzypickles' §14, "The
earlier generations are gone". Its whole written design was fifteen lines,
and three ideas in it are worth carrying because two of them land on §4.4,
the largest and riskiest piece of this library.

**These are candidate mechanisms, not decisions**, and the source deserves
its calibration: the same header declared `uint32_t encryption_key` on a host
record. A thirty-two-bit key is the measure of how much of that generation is
worth taking. The shapes travel; none of the crypto does.

1. **Two-layer sealing.** The frame was `hostenc(userenc(payload) | usermac) |
   hostmac` -- a host-level seal wrapped around a user-level one, each with
   its own MAC. A forwarding host can then authenticate the hop it is being
   asked to make without being able to read what it carries. **fuzzypickles
   has no equivalent** (the phrase appears nowhere in its document); it gets
   "serve bytes you cannot read" only for content-addressed blobs, where the
   content is named by its hash and no key is needed at all. That is a
   different mechanism answering a different question, and it does not help a
   relay forwarding a live datagram.

2. **An acknowledgement policy in the header**, two bits: none, ack,
   ack-and-ack-my-ack, and "periodically NACK what went missing". Note what
   that is -- a property the *sender states to the receiver*, per datagram,
   independent of what the datagram carries. Its spec named the payoff in two
   words, **collate response**: any datagram already travelling the right way
   can acknowledge another, so a busy conversation stops paying a dedicated
   frame per message.

   **This is the axis the whole library sits on**, and it is worth naming
   before anything is written: a generic protocol where header bits say what
   is wanted, or narrowly defined commands where the acknowledgement is
   implied by which command was sent. fuzzypickles took the second without
   ever weighing the first (its §9 records that now), and pays for it -- two
   acknowledgements emitted in the same instant to the same address go as two
   datagrams, each with its own header, nonce and tag.

   **This library cannot inherit that choice by accident**, because its two
   consumers disagree about reliability: netcfgd wants commands that expire
   and a response chunked across many datagrams, fuzzypickles wants messages
   that survive a sleeping peer. A policy stated per datagram is how one wire
   serves both without the command vocabulary encoding the reliability model
   -- which matters doubly here, since §5 keeps command vocabularies OUT of
   the core. If acknowledgement is implied by the command, and the commands
   belong to the consumer, then the core cannot reason about acknowledgement
   at all.

3. **Sequence-based continuation.** `CMD_CONTINUE` carried `seq_prev`, so a
   payload larger than a datagram continued an earlier one, and `ACK` carried
   `ack_seq` plus an `ack_bitmap` -- selective acknowledgement over a sequence
   space. **This is §4.4's problem exactly**, and it is not the same as
   fuzzypickles' have-set: that is content-addressed and requester-coordinated,
   which suits a blob with a hash-derived name and does not suit a `status`
   response that exists only as the answer to one question. The 2018 shape is
   the simpler one and is the right starting point to argue against.

Its datagram cap was 512 bytes, which is conservative even for 2018 and worth
knowing as a floor somebody once chose deliberately.

## 13. The capability in every datagram, and the axis underneath it

The schema (§6) surfaced 96 bytes of fixed overhead, of which `capability[32]`
and `nonce[24]` are 56. The obvious fix -- establish the capability once and
carry a short handle -- is **the wrong first move**, and finding out why
settles something larger.

### fuzzypickles already answered this, and chose the expensive side

Its peer frame is `version | cmd | sender_host_pubkey[32] | ephemeral_pk[32] |
commitment[16] | ciphertext | mac[16]`: **82 bytes of header plus a 16-byte
MAC**, against this schema's 96. Two designs reached the same order of overhead
independently, which is worth knowing before treating 96 as an aberration.

More instructive is *what* it spends the bytes on. There is **no nonce field at
all** -- the AEAD nonce is all-zero, which is safe only because a fresh
ephemeral makes the derived key single-use. So it pays 32 bytes for an
ephemeral rather than 24 for a nonce, and 32 more to say who is speaking. That
is a deliberate purchase: **every datagram is self-contained, and no session
state is required at either end.**

Which is §8's "assume the peer is asleep" honoured at the frame level. Store
and forward works because a stored datagram needs no live counterpart to make
sense of it later. A session handle would trade exactly that away: a handle is
meaningless to a host that has forgotten the session, or never had it, or is
being handed the message by a relay hours later.

### So it is the same axis, for the fourth time

Self-contained against session-oriented is not a new question here. It is the
one this document keeps meeting:

| where | fuzzypickles wants | netcfgd wants |
|---|---|---|
| local hop (§2) | one encoding both hops | JSON locally, binary remotely |
| freshness (§4.3) | authority no clock ends | commands that expire |
| acknowledgement (§12) | survives a sleeping peer | a live exchange |
| identity per datagram | self-contained, no session | a handshake it already has |

netcfgd is LAN-only, interactive, and already holds per-response reassembly
state by §4.4 -- a session costs it nothing it is not already paying.
fuzzypickles is offline-capable by construction and a session costs it the
property it most needs. **Neither is wrong, and a library that picks one is
wrong for the other.**

### The shape of the answer, not the answer

**One mechanism serves both, and it is the same mechanism §12's second item
wanted**: a mode stated in the header, so a frame is either self-contained --
carrying identity and deriving its key per message -- or session-bound,
carrying a short handle. That is two candidates converging on one header field,
which is the first evidence that the field is the right idea rather than a
preference.

Two things must be settled before it is written, and neither is settled here:

- **A missing field, found by writing the schema.** `frame.situ` has no key or
  session selector at all. A receiver is given a nonce and a sealed region and
  no way to know which key opens it. fuzzypickles solves this with
  `sender_host_pubkey`, which is the same 32 bytes doing double duty as
  identity and key selector. Whatever replaces `capability[32]` has to answer
  *both* questions, and noticing that they were one question is the useful part.
- **Whether the capability belongs on the wire at all.** It is an identifier
  the receiver must look up regardless, since the chain that proves it is not
  in the frame. If a session binds the capability at establishment, the
  per-datagram field is redundant with the handle; if there is no session, the
  identity field already implies which capabilities that host holds. Either way
  the honest question is not "how do we make 32 bytes smaller" but **"why is
  this field here twice."**

## 14. Open, and named rather than left silent

- **`raidcfgd` does not exist.** Two real consumers and one imagined one. Every
  decision above is made from the two that exist; `local/` is the piece most
  exposed to this and is scheduled last for that reason.
- **Which package the agent ships in** is netcfgd's open question, and matters
  here only in that it is a daemon that listens on a network — a thing netcfgd
  has deliberately never had.
- **Licensing**, unresolved across the whole family per `harmonization.md`, and
  a shared library is where it starts to bite: this one is linked by projects
  that may not agree.
- **Whether `chunk/` belongs in the core at all**, or is a layer a consumer
  opts into. It is in the core because netcfgd cannot function without it, but
  fuzzypickles will not use it — its own transfers are content-addressed.
