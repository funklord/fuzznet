# project.md

**fuzznet** — the authenticated datagram protocol shared by `fuzzypickles`,
`netcfgd` and the planned `raidcfgd`.

This document is the source of truth and **wins over the code**. Where the
implementation learns something this does not say, this gains it.

Created 2026-08-08, on being asked to stop three projects writing the same
protocol three times.

**How this document cites sections.** A bare `§4` is a section of this
document. A section of another project's is named — `fuzzypickles' §8`,
`netcfgd's brief §8` — together with the phrase it is being cited for, since
the phrase is what a reader is actually after. `wire/frame.situ` writes
`sec 4` for the same thing, because `.style-gate.toml` sets `ascii_only` and
a `.situ` file has no lexer here, so it gets the whole-file ASCII check: a
section sign in one is a gate failure, confirmed by putting one there.

Written down because both ways of getting this wrong have already happened,
and neither announced itself. Three references cited a bare §8 for "assume
the peer is asleep" and "receivers may have kilobytes" — both fuzzypickles',
while ours is "Shape of the tree" — so each landed on a real section that
says nothing about its subject. Four others in the schema were written
against a numbering that shifted in the very commit that created the file,
when §9 was inserted above them. **A reference that lands on a section which
exists is one nobody rereads**, which is the property the two share and the
reason habit was not enough.

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

**Built 2026-08-14** as `frame/freshness.c`, which is the half §7a assigns
here: "the field is schema, the policy is ours". It needs no generated code
and was not blocked on anything.

#### Expiry and replay are one mechanism, which is the useful finding

They look like two defences and are not, and seeing that is what makes the
replay window bounded.

Remembering every nonce ever seen is unbounded memory, and §4.4 forbids
exactly that in the reassembly path for exactly the reason it is wrong here —
a stranger can exhaust it. But **an expired command cannot be replayed to any
effect**, because the expiry check refuses it whether or not its nonce is
remembered. So a nonce need only be remembered until its own expiry passes,
and §4.3's *mandatory* expiry on commands is what makes that bound exist at
all. The rule that looked like a concession to netcfgd turns out to be what
pays for replay defence.

That gives the sizing rule a consumer must get right, and it is the only
number this module asks for: **the window must hold as many entries as can
arrive within the longest expiry it will accept.**

**A full window refuses rather than evicting**, and this is the decision to
argue with before changing it. Evicting the oldest live entry to make room is
the obvious move and it silently reopens replay: whatever was evicted is
accepted again on retransmission, so an attacker who can generate traffic
flushes the window and then replays anything they recorded. Refusing keeps
replay closed and turns the failure into something a consumer can log and
alarm on — and §4.4a would rather a configuration change did not happen than
happened twice.

Two smaller consequences, both tested: a frame refused for freshness never
occupies a slot, or a stranger fills the window with rubbish that was going to
be refused anyway; and a grant carrying no expiry is not recorded at all,
since it has nothing to be remembered until and re-presenting one is how a
chain gets verified rather than an attack.

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

### 4.4a The threat model, stated because it is higher than a chat program's

**This library carries traffic that reconfigures infrastructure, remotely,
across untrusted networks.** netcfgd's is the demanding case and it is not
LAN-only (2026-08-08): a forged or replayed frame does not leak a message, it
changes a router's configuration -- and the machine most likely to be attacked
is the one being reconfigured because it is already misbehaving.

What that buys, and what it forbids:

- **Confidentiality of metadata, not just payload.** §13 moved the capability
  identifier inside the seal for this reason: in the clear it announces which
  authority is being exercised, so the frames worth attacking identify
  themselves. Anything the header must expose has to earn its place by being
  needed *before* a key is selected.
- **Replay is a configuration change, so freshness is load-bearing rather than
  hygienic.** §4.3's mandatory command expiry is a security property here, not
  an efficiency one.
- **No downgrade path.** If §12's mode bit is ever built, it sits inside the
  authenticated region and an implementation must refuse a weaker mode it did
  not offer. A negotiable security level reached by flipping a plaintext bit is
  the classic way this goes wrong.
- **Key-committing AEAD is not optional**, per §4.5, and neither is a
  constant-time tag comparison. The extern codec owns the first; this library
  owns the second and must not leave it to the consumer.

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
- **Rendezvous, hole punching, relays** -- **for now, and on borrowed
  justification.** This was excluded because netcfgd's decision 2 is "LAN only
  first" and the case a person actually wants is "I am at home, fix the wifi".
  **That premise has expired**: netcfgd is not going to remain LAN-only
  (stated 2026-08-08), so the second consumer this test asks for is arriving
  rather than hypothetical.

  It stays out today because nobody has built it *here* and fuzzypickles has
  working versions in its own tree -- which is a statement about sequencing,
  not about scope. Treat it as the next thing likely to move in, and do not
  design the core in a way that assumes both endpoints are directly
  reachable. §4's freshness rules and §13's self-contained frame are already
  the right shape for a datagram that crosses a relay; nothing else is.
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

### It was put, and accepted -- with a sharper boundary than ours

`suggestions/fuzznet.md` carried the question; situ's decision **0030,
cross-message relations, is accepted** (2026-08-08) and drew the line in a
better place than "relations, not dynamics":

> **A `relation` is a named, pure predicate over exactly two views. It holds
> no state, allocates nothing, and does not know which messages exist.**

Two parameters exactly, order temporal (first is the message seen first),
bodies say `must` rather than `require` because `require` is already a
build-time capability gate, and the generated function takes two bare views and
returns the existing `SITU_ERR_CONSTRAINT`. Our suggested fifth `stage` value
was rejected with the better argument: a predicate *parameterised* over both
views leaves every field `ParseTime` within its own view, so the existing axis
already answers it -- and a stage value would let a lone struct reference
another message, whose accessor would need somewhere to look that message up.
That lookup is a store, and the store is the boundary gone.

**Three consequences for this library, and the first is a correction:**

- **"A chunk's `index` is below its `chunks`" was miscounted here as a
  cross-message relation.** It is a single-message constraint and was
  expressible all along. `frame.situ` now carries `[max = chunks - 1]`, which
  `situc wire` reports as part of the contract. A constraint filed under "needs
  a feature that does not exist" is a constraint nobody writes, which is the
  more useful half of the mistake.
- **`relation` was designed and is now half-built, and the halves matter.**
  The parser rejected the keyword on 2026-08-08 morning; by that evening
  `situc` parsed and *checked* one -- a relation naming a field that does not
  exist is refused, with the parameter and its type named. The **emitter** is
  phase 26.95, status not started. So
  a schema may declare relations today and have them validated, and no code
  comes out yet. Distinguishing those took one command, which is the
  designed-versus-built property this library asked situ to keep and is
  getting.

  **`--layer` is a `situc` flag now** (measured 2026-08-14), accepting
  `view`, `edit`, `relate`, `frame`, `converse` and `drive`. An earlier
  revision of this line said it was not, and §10 step 4 is the decision that
  was waiting on it.
- **The acknowledgement case is excluded from a *relation*, which is narrower
  than it first looked.** "An ack names a sequence that was actually sent"
  quantifies over the set of messages sent, needing a store with insertion and
  expiry, and 0030 excludes it not for difficulty but because no parameter a
  pure predicate could take would answer it.

  **Do not read that as permanent -- an earlier revision of this section did,
  and was wrong within a day.** The exclusion holds *at that layer*. See below.

### Superseded: situ is taking protocol handling, and the ladder is how

Within a day of the boundary above being argued, the answer changed, and the
argument this document made -- dynamics stay out -- **is overruled by situ's
maintainer, correctly, since it is their project.** It is left standing above
because a recommendation that quietly becomes agreement is worth nothing the
next time one is offered.

Decision **0032, six layers chosen at invocation**, is the shape:

| rung | emits | the new "yes" |
|---|---|---|
| `view` | accessors over caller-owned bytes | *(baseline)* |
| `edit` | build or resize a message | may it allocate? |
| `relate` | predicates over two messages (0030) | may it look at two messages? |
| `frame` | byte stream in, whole messages out | may it hold bytes between calls? |
| `converse` | match a reply to its request | may it hold messages between calls? |
| `drive` | send, receive, retransmit, time out | may it own I/O and the clock? |

**The question this document kept asking was the wrong one.** "Should situ do
X" gets relitigated once per adopter; "at which layer does X live" is answered
once. The choice sits at `situc build --layer` rather than in the schema,
because what a consumer wants generated is not a property of the bytes -- which
also answers, better, the schema-or-companion-file question this document
raised.

What that changes here:

- **§4.4's chunking state machine may stop being ours.** It was assigned to
  this library because situ described messages and not protocols. Rungs
  `frame` and `drive` are exactly that work. Whether we consume them or write
  our own becomes a real choice at §10 step 5, and it should be made then,
  against something built, rather than assumed now in either direction.
- **§12's ack bitmap is a `converse`-or-`drive` question**, not a permanent
  exclusion. The store that 0030 could not have is precisely what rung 5 adds.
- **fuzzypickles is a rung-2 consumer**, per 0031: its 225 call sites hold
  decoded structs that outlive the buffer, so it needs `--owned` rather than
  views. §10 step 7 is where that lands, and knowing it now is cheaper than
  discovering it there.

This library is also situ's **first tester** for protocol handling, verifying
structure and code rather than consuming output. `situ/suggestions/fuzznet.md`
carries what that requires -- an injected clock, an explicit step function,
observable transitions, first-class fault injection, and per-phase status kept.

**The clock correction was taken, and rung 6 now says so.** Phase 26.98 reads
"**It owns I/O and never owns the clock**": time enters as a parameter, I/O is
a caller-supplied vtable so a test substitutes a transcript and injects loss,
reorder and duplication without a network, and a convenience wrapper that reads
the clock is explicitly "not the state machine". Decision 0033 then went
further than was asked -- the step function returns the **next deadline**,
because every multiplexing facility takes a timeout and only the state machine
knows when it next needs waking, so without it each driver invents a polling
interval and the timing contract stops being the schema's; and the vtable is
completion-shaped rather than readiness-shaped so `io_uring` is not excluded.
Neither was in the request, and both are the kind of thing a first tester wants
decided before there is code rather than after.

### This is the first schema to use a relation

`wire/frame.situ` declares two, and they are worth reading as the answer to
"what is a relation actually for":

- **`same_message(first, later)`** is a security property. A reassembler sizes
  its buffer from the first chunk it sees (§4.4), so every later chunk must
  agree with that one on `msg`, on `chunks`, and on `sender`. Each clause is an
  attack if unchecked: a differing `chunks` tries to resize a buffer already
  allocated against the first claim, and a differing `sender` splices two
  senders' chunks into one message that then authenticates as neither.
  Parameter order carries which frame the buffer was sized from, which 0030
  makes load-bearing rather than stylistic.
- **`reply_to(request, reply)`** is the weaker, more ordinary one -- the
  identifiers match and the senders differ -- and it exists because a dissector
  and a fuzz harness both want exactly it.

**What a relation does not do is as important, and it is a property of that
rung rather than a permanent division.** A relation holds no state and does not
know which frames exist, so at `relate` the caller owns the pairing: the schema
says whether a pairing is well-formed and does not remember pairings.

An earlier revision of this section drew a general conclusion from that -- "the
reassembly table remains this library's own state machine" -- and **that is
wrong**. It reads one rung's property as the ladder's shape. The rungs above
are defined by exactly the state a relation refuses: `frame` may hold bytes
between calls, `converse` may hold messages between calls, and `drive` sends,
receives, retransmits and times out. **situ is going to generate the whole
networking scheduler**, and which of it a consumer takes is `--layer`.

> **The five paragraphs that were here are wrong and are cut rather than
> preserved**, because they asserted a fact rather than made an argument, and a
> false fact left standing in a source of truth is read by somebody who never
> reaches the correction. They said §4.4 splits into a chunk frame situ writes
> and a chunking state machine that is "this library's own C", and that
> "chunking is not going to be" absorbed because it is dynamics rather than
> layout.
>
> Both halves are false. situ will generate the whole networking scheduler --
> `frame` holds bytes between calls, `converse` holds messages, `drive` sends,
> retransmits and times out -- and a consumer picks how much with `--layer`.
> §7a has what actually remains here. The argument that produced the error is
> the one preserved above under "Should situ describe the send/receive
> pattern", where it belongs: it was reasoning, and it was overruled.
>
> The mistake is worth one line of its own. It came from reading a scope
> statement out of situ's protobuf importer, and then **surviving the
> correction of that misreading** -- the false conclusion was restated twice
> more after its premise had been withdrawn, because it had become a fact this
> document repeated rather than a claim it checked. That is the failure mode
> §14 warns about, met from the inside.

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

### Measured 2026-08-14: the schema checks, and does not build

**`situc build` refuses `wire/frame.situ`**, and the whole cause is one line:
`[max = chunks - 1]` on `head.index` is rejected as "not a compile-time
constant". Substitute a literal and the same command emits C. So **no code
can be generated from this schema today**, which is a different state from
the one this section has been describing.

Nothing above is retracted, because everything above was measured with the
commands it names -- `situc wire`, `situc map` and `situc advise` all still
pass, `require canonical` still holds, and no `unbounded-scan` diagnostic
appears. **`situc build` was simply never run.** This family's own recurring
failure, met from the inside: a passing check cited as evidence for a
property it does not cover. Worth recording as that rather than as a bug
found in somebody else's compiler.

Whose defect it is is a real question and is not settled here. The bound was
added deliberately -- decision 0030 is what prompted it, and the miscount it
corrected is recorded above -- `situc wire` reports it as part of the
committed contract, and `situc build` rejects it. **Two commands in one
compiler disagree about whether the construct is legal.** That is a finding
to take to situ with its reproduction, on the terms
`situ/suggestions/fuzznet.md` sets out, rather than a reason to quietly drop
the bound and lose the check it buys.

It also decides what `chain/` could be built against, and did (§10 step 3):
the capability model needs no generated code, because §7a already assigned
it to this library as semantics rather than layout.

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

## 7a. What is left of this library once situ generates the scheduler

**situ will generate the entire networking scheduler**, and a consumer chooses
how much with `--layer`. That is not a possibility to plan around; it is the
stated direction, and decision 0033 names the test behind it -- *remove code
from other network projects generically and efficiently*. An `epoll` loop is
"exactly the eighty lines three projects each hand-write, and exactly the kind
where one of them gets the edge-triggered case subtly wrong."

So the honest question is not what this library will build but **what is left
after the generator takes its share.** §4 was written assuming the transport
was ours:

| §4 | who owns it, once the ladder exists |
|---|---|
| 4.1 framing and canonical encoding | **situ** -- `wire/frame.situ`, already |
| 4.2 capability chain and revocation | **ours** -- semantics, not layout |
| 4.3 freshness: commands expire, grants do not | **shared** -- the field is schema, the policy is ours |
| 4.4 chunking and reassembly | **split** -- see below; the datagram half is ours |
| 4.5 sessions and encryption | **situ** at the seam, ours at the extern codec |
| 4.4a threat model | **ours** -- no generator has an opinion about it |

**The 4.4 row was optimistic, and is corrected here** (measured 2026-08-14,
situc 1.0). No rung emits datagram reassembly. Rung 4 `frame` is **stream**
framing -- a byte stream in, whole messages out -- which is a different
problem wearing the same word: situ's own acceptance test for it is "a
length-prefixed schema reassembles across every chunk boundary", which is
about where a read happened to split, not about a message deliberately cut
into self-contained datagrams. Rung 5 `converse` keeps a pending table keyed
by a relation, matching a reply to a request rather than a piece to a whole.
Rung 6 `drive` retransmits what a table says is outstanding.

So holding chunks of one message that arrive out of order, each carrying
`msg`, `index` and `chunks`, is nobody's but ours -- and so is cutting a
message into them in the first place -- and the memory bound on
that holding is §4.4a's requirement rather than an optimisation. Built as
`chunk/reassembly.c`, with `chunk/split.c` as its sending mirror. What stays
situ's is the retransmission that asks for a missing piece, which is rung 6
and which neither module has: §10 names a hand-written retransmission state
machine as the thing to refuse.

**The two halves are tested against each other, not only against
themselves.** A receiver that requires a uniform stride and a sender that
produces one are half a contract each, and both can be self-consistently
wrong -- a splitter that pads its last piece and a reassembler that accepts a
padded one would pass their own suites and lose bytes together.
`chunk/tests/split_test` cuts a payload with one and feeds it to the other,
then compares. Padding the last piece to the full stride breaks twelve of its
checks; shifting every offset by one breaks twenty-three.

The search behind that claim was positive-controlled rather than assumed:
"reassembl" does appear in situ's tree, twice, and reading those two uses is
what showed they are the stream case. A grep that finds nothing because the
word is never used would have read the same as one that finds nothing because
the feature is absent.

And a third axis arrives with the scheduler: `--driver` chooses what pumps the
rung-6 state machine, additively, with **the test harness as just another
driver**. A transcript driver injects loss, reorder and duplication with no
socket and no clock, so *the tested path and the shipped path differ only in
which driver they link.* That is a stronger property than the fault injection
this library asked for, and it removes the last argument for writing our own
loop in order to be able to test it.

**What that leaves is small, and it is the part that was always ours:** the
schema, the extern codec binding, the capability and identity semantics, the
policy decisions §13 keeps meeting, and the judgement about which rung each
consumer should stand on. This library becomes a specification with a thin
seam rather than a transport implementation.

**Which is the right outcome and should be said plainly**, because it is easy
to read as a loss. §5's rule for admitting anything to the core was "two real
consumers need it, and neither would accept the other's version as a special
case of their own". A generator that serves all three consumers from one
description satisfies that test better than a hand-written library could, and
the duplication this project exists to remove is removed further.

**The sequencing question is real, and half of it is now answered.** An
earlier revision said rungs 4 to 6 were "scheduled and unstarted (26.96
through 26.98)". **All six rungs ship** (measured 2026-08-14, situc 1.0):
building one schema at each of `view`, `edit`, `relate`, `frame`, `converse`
and `drive` emits distinct output at every step, and the rung-6 header
compiles clean against the runtime.

Rung 6 is what 0033 describes rather than a placeholder for it. The emitted
`situ_drive_<relation>_step(drive, now_ms, ...)` takes the clock as a
parameter, carries `deadline_ms`, `timeout_ms` and a retry count, and holds
an I/O vtable -- which is the split this library asked for and the phase text
now states as "**It owns I/O and never owns the clock**".

**Rung 6 emits only for a relation that states a policy**, spelled
`[timeout_ms = 5000, retries = 2]` on the relation itself. That is worth
knowing before anyone concludes it does nothing: a first probe here used a
relation without one, got output identical to rung 5, and would have reported
rung 6 as unbuilt. A check that could not have produced a positive is not
evidence -- `examples/dns/dns.situ` is the working example.

So §10's step 5 -- build `chunk/` by hand, or consume rung 6 -- **no longer
waits on situ**. It waits only on when netcfgd needs its agent. What should
*not* happen is building a retransmission state machine by hand while the
same one is being generated, and that is no longer a future risk but a
present one.

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

**Rewritten 2026-08-08**, because the first version was a build order for a
hand-written transport and situ is generating most of it (§7a). Steps 2, 4 and
5 were `wire/`, `session/` and `chunk/` as our own C; two of those are now
`--layer` choices and the third is a schema.

1. ~~Evaluate `situ` against the frame~~ **done** (§6): the frame is a schema,
   the crypto model is built, and `wire/frame.situ` compiles.
2. **Finish the schema against a real payload.** The `[max = 1024]` on the
   sealed region is a placeholder; netcfgd's largest chunk decides it, and the
   96-to-128-byte overhead question in §13 wants settling before anything is
   generated from it twice.
3. ~~**`chain/`** — the capability and identity model~~ **verification is
   built** (2026-08-14). It stayed ours throughout every scope change because
   it is semantics rather than layout or transport, and that is exactly what
   let it go first while step 2 is blocked: `chain/chain.c` parses no bytes.
   It is handed hops somebody else decoded and answers whether they authorise
   a grantee for a capability under a pinned root, now. fuzzypickles'
   `identity.c` and `capability.c` were the reference.

   Three things it does differently from that reference, each because this
   document says so: the root is **pinned rather than adopted** (§4.2), with
   no nullable-root variant, since fuzzypickles needs a TOFU bootstrap and
   this library has no such path; a capability is **32 opaque bytes**, never a
   typed enum, because netcfgd's three are independent rather than a ladder;
   and **nothing reads a clock** — `now` is a parameter.

   Signature verification is a caller-supplied vtable, which is the same
   extern-codec boundary §6 uses for Monocypher and is what makes the whole
   module testable before anything is vendored.

   **Revocation is carried on contact, and that word decided its shape**
   (`chain/revocation.c`, 2026-08-14). §4.2 asks for it and only half
   existed: verification consulted a list, nothing produced one.

   A revocation is **signed by its issuer and pinned to the root**. An
   earlier comment in `chain.h` argued the opposite — that the
   authenticated datagram carrying it made it attributable, so a signature
   of its own would duplicate the envelope's job. That is true for one hop
   and false for the thing §4.2 actually asks for: *on contact* means it
   travels peer to peer, §5 records relays as the next thing likely to move
   in, and §13 that a frame may arrive by relay hours late. The carrier is
   not the issuer, so a revocation trusted because of who handed it over is
   one **any carrier can invent** — and inventing them is a denial of
   service against exactly the hosts an attacker wants disconnected, needing
   no key at all. The comment is corrected in place.

   **Its refusal is the one in this library that fails open, and that is
   worth knowing before sizing anything.** The replay window refuses when
   full and fails closed: the worst case is a good frame rejected. A full
   revocation store fails *open* — the host goes on accepting a capability
   that was withdrawn. Nothing is evicted and nothing expires, because a
   revocation that lapses un-revokes a device and every entry is protecting
   against something, so there is no entry it is safe to choose. The store
   must therefore be sized for a deployment's whole revocation history
   rather than a working set, and `FZN_ERR_STORE_FULL` is an alarm rather
   than a retry. §14 carries the growth as open.

   Only the root revokes today. A grantor revoking what it granted is the
   obvious extension and is deliberately not built: it would let a
   compromised intermediate revoke its own descendants, which may be wanted
   or may be the attack, and this document does not say.

   **Minting and delegation are built too** (2026-08-14), which finishes the
   semantics half of step 3. `fzn_chain_mint` signs hop 0 as the root;
   `fzn_chain_delegate` re-verifies the whole chain, then extends it. Two
   caps apply and both are the same idea — a grantor cannot hand out what it
   does not have: expiry is capped at the chain's own, and asking for *no*
   expiry from a time-boxed chain silently yields the chain's rather than
   widening it, since `FZN_NO_EXPIRY` is zero and reads as "unset".

   **Nothing here takes a secret key.** The signer signs as whoever its
   context is, so a key can live in this process, another one, or hardware,
   and `chain.c` cannot tell. That is §3 honoured at the API rather than by
   convention: a library linked by an unprivileged bridge should not have a
   parameter somebody can hand a user's private key to.

   **The Monocypher binding exists and is optional to build**
   (`chain/sign_monocypher.c`, behind `MONOCYPHER_DIR`), because Monocypher
   is not vendored here yet and §7 says that wants a submodule rather than a
   decision taken in passing. Verified against fuzzypickles' checkout with a
   real Ed25519 round trip — see §11.

### The delegation bit, and why it is not a capability

**A new field on a hop, decided while writing `chain/` and recorded here
because it is a wire-format decision rather than an implementation detail.**

fuzzypickles found, the expensive way, that *holding* a capability must not
by itself entitle a host to *grant* it: its grant path once asked only
whether the granting host held the type being handed over, which "left
CAP_ADMIN gating nothing and let any host promote any other host to its own
capability set". Its fix was to require a second capability, `CAP_ADMIN`,
alongside the one being granted.

**That fix is unavailable here and must not be imitated.** §4.2 keeps
capabilities opaque — netcfgd's three are independent rather than a ladder —
and a library that knew which identifier meant "may grant" would be
interpreting them, which is the one thing this library promises not to do.

So the entitlement travels as a **`delegable` bit on the hop**, set by the
grantor. A chain that continues past a hop without it is refused, and
`fzn_chain_delegate` returns its own error rather than a generic invalid,
because the chain is valid and the holder does hold it — what is missing is
permission to pass it on, and a caller that cannot tell those apart reports
the wrong thing to a user. It defaults closed, so a decoder that forgets the
field or a caller that zeroes a hop produces a grant that cannot be
delegated rather than one that can.

**This is the holder's to confirm.** It says the same thing fuzzypickles'
`CAP_ADMIN` says, without this library learning what any capability is — but
it adds a field to a hop, and no chain layout is committed yet, so it is
cheap to change now and will not stay cheap.
4. **Decide the rung, and say when. This is now the blocking decision.**
   `--layer view` today, but all six rungs ship (§7a, measured 2026-08-14) --
   `relate` emits, and `drive` emits a step function taking `now_ms` for any
   relation carrying `[timeout_ms = ..., retries = ...]`. The sequencing
   question §7a names needed two dates; one has arrived, and the remaining
   one is when netcfgd needs its agent.

   It is blocking because step 5 cannot start without it and step 2 is stuck
   behind the `situc build` refusal (§6). Everything else in this list is
   either done or waiting on somebody outside this document.
5. **netcfgd's `agent/`** becomes the first real consumer — it does not exist
   yet, which is the whole of the timing benefit.
6. **fuzzypickles migrates**, as separate deliberate work, at rung 2 with
   `--owned` (0031).
7. **`local/`**, when raidcfgd exists and can say what it needs.

**What is deliberately absent: a hand-written retransmission state machine.**
Building one while the same one is being generated is the exact duplication
both projects exist to remove, and it is the thing to refuse if a schedule
starts arguing for it.

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

**`chain/` (verification, delegation, revocation), `frame/freshness.c`,
`chunk/reassembly.c` and `chunk/split.c` are built and tested; nothing else
is.**
Alongside them: this document, `wire/frame.situ`, a `code-style.md` copied
from the global source, the shared `style_gate.py` and `commit-msg`, and a
`VERSION`. `make style` passes over twenty-eight files.

Both are the pieces §7a assigns to this library rather than to situ, which is
also why they were buildable while §10 steps 2 and 4 are stuck: neither needs
generated code. `chain/` is the capability model; `frame/freshness.c` is
§4.3's policy half, the expiry rules and the replay window they pay for.

`make` builds the objects and nothing else — the default target does not
build tests, per `build-and-commit.md`. `make test` builds and runs two
binaries: `chain/tests/chain_test` at 64 checks over a stub verifier and an
injected clock, `frame/tests/freshness_test` at 34, and
`chain/tests/revocation_test` at 31, `chunk/tests/reassembly_test` at 58,
and `chunk/tests/split_test` at 52.
None reads a clock, so there is nothing in any of them that can pass on a
quiet machine and fail on a loaded one.

**`make test MONOCYPHER_DIR=../fuzzypickles/monocypher`** additionally builds
the binding and runs 9 more checks against real Ed25519. That is the sibling
-directory-behind-a-variable shape §7 blesses for bring-up, and it is
temporary: the real answer is a submodule, at whatever step takes it.

**The suites were checked by breaking the code, not by watching them pass.**
Twenty-three sabotages, each rebuilt through `make test` rather than
re-running a stale binary. Twenty-two were caught; **one was not, and that is
the useful one.** Removing the arrived-set clearing in reassembly's
`admit_first` passed the whole suite, because `release` already clears it --
so the line was defence in depth that nothing held to account. A partial is a
value, so the test now builds the dirty slot directly rather than trying to
reach it, and the sabotage is caught. A suite that only exercises states
normal operation reaches will not find that class. Six of them are freshness: accepting a
command with no expiry, ignoring a grant's stated expiry, dropping the replay
check, making a full window evict rather than refuse, recording a frame
before checking its freshness, and an expiry sweep that reclaims nothing. On verification: removing the root pinning,
narrowing revocation to the last hop alone, dropping expiry enforcement, and
verifying signatures before the structural checks — the last held by the
call-count assertions that exist to make that ordering claim measurable. On
delegation: dropping the `delegable` requirement in verify and again in
delegate, removing the expiry cap, skipping the re-verification, and removing
the depth ceiling.

### The reassembly fuzzer, and what it can and cannot see

`chunk/tests/reassembly_fuzz` runs a bounded, seeded sweep over
`fzn_reasm_accept` with each slot's buffer inside a canary, asserting after
every call that nothing was written outside a buffer, that no sender exceeds
its quota, and that no slot is sized past what it holds. `make test` runs
20000 cases; `make fuzz CASES=n` runs a campaign. It compiles as a libFuzzer
target too, so a longer run needs no second harness to drift from this one.

**Two things it found were about the harness, not the module, and both are
the reason it exists.**

First, the generator reached almost nothing. Random bytes make `chunks` a
uniform `u16`, which is past `FZN_REASM_MAX_CHUNKS` in 99.6% of draws, so
nearly every offer was refused before a slot was taken — and three of four
planted bugs survived 200000 cases while it reported success. That is the
shape `situ/suggestions/fuzznet.md` names: a target that reaches nothing
looks identical to a clean run. The generator is biased now, and the harness
**counts what it reached and refuses to report success below a floor
proportional to the run.** "More than zero" was the first threshold and was
not enough: with the bias disabled it admitted 2 and completed 1 in 20000
cases, and passed.

Second, the bounds cover each other, which is worth knowing before reading a
single-mutation result. Given the admit-time sizing, `index < chunks` and
`payload_len <= chunk_size`, the offset check is unreachable by
construction — so removing any **one** of them is masked by the others and
the fuzzer sees nothing. Removing **two** produces a real overrun and the
canary catches it, with a reproducible case number and seed. That is
redundancy working as intended, and it means the unit suite rather than the
fuzzer is what holds each individual bound.

**So what the fuzzer covers is memory safety, and what it cannot see is
semantics.** A later chunk disagreeing with the first about its total breaks
no invariant here — it is a splice, not an overrun — and `reassembly_test`
is what catches it. Both are needed and neither substitutes.

### The chain and freshness fuzzers, and what one of them found

`chain/tests/chain_fuzz` and `frame/tests/freshness_fuzz` followed. `chain.c`
owns no buffers, so there is nothing there for a canary to guard: a bug in it
is not an overrun, it is an **acceptance**. Its harness therefore re-derives
the rules independently — a second implementation rather than a call back
into the first, since a checker that asked `chain.c` whether `chain.c` was
right would agree with it always — and holds every verdict to them, plus the
claims nothing else measures over arbitrary input: that a refused chain
leaves `*out` untouched, and that verification never buys more signature
checks than there are hops.

**The freshness fuzzer found a real mismatch on its first run.**
`freshness.h` claimed expired entries were "reclaimed on every call", and
`fzn_replay_admit` returned early — for a refused frame, and for an
unexpiring grant — *before* the sweep. So traffic made entirely of grants, or
entirely of stale commands, left dead entries holding slots indefinitely. The
consequence was memory rather than a hole, because the path that matters (a
fresh command meeting a full window) always swept before the capacity check.
But `fzn_replay_expire` is exported precisely so a quiet receiver can hand
memory back, and a header claim that is only usually true is the kind that
gets relied on. The sweep moved above the early returns.

**The generator question has now decided the answer three times**, and it is
the thing to check first when a fuzz result looks clean:

| harness | what the generator failed to produce | bugs it hid |
|---|---|---|
| reassembly | `chunks` inside the ceiling | 3 of 4 |
| chain | a chain rooted anywhere but the pinned root | the root pin |
| freshness | *(nonces were already drawn from a small set)* | none |

Each was found by planting a bug and watching the harness not care. All three
now count what they reached and refuse to report success below a floor
proportional to the run; `chain_fuzz` additionally requires both acceptances
and refusals to occur, since a run with only one of them would report success
against a verify that answered the same way every time.

**The Monocypher round trip is the positive control for the seam itself**,
and it earns its place by an experiment rather than an argument: inverting
`crypto_eddsa_check`'s sense — it returns 0 for good where the seam wants
nonzero — breaks four of its checks, and `chain_test` still passes, because
a stub cannot see a binding. A seam that has only ever had a fake behind it
is a seam nobody has checked.

Both suites also carry explicit positive controls, since a `fzn_chain_verify`
that refused everything would satisfy almost every other case in them.

There is no archive rule and there will not be one without a specific need
(§7, and `build-and-commit.md`).

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

Which is fuzzypickles' §8, "assume the peer is asleep", honoured at the frame
level. Store and forward works because a stored datagram needs no live
counterpart to make sense of it later. A session handle would trade exactly
that away: a handle is meaningless to a host that has forgotten the session,
or never had it, or is being handed the message by a relay hours later.

### So it is the same axis, for the fourth time

Self-contained against session-oriented is not a new question here. It is the
one this document keeps meeting:

| where | fuzzypickles wants | netcfgd wants |
|---|---|---|
| local hop (§2) | one encoding both hops | JSON locally, binary remotely |
| freshness (§4.3) | authority no clock ends | commands that expire |
| acknowledgement (§12) | survives a sleeping peer | a live exchange |
| identity per datagram | self-contained, no session | a handshake it already has |

**The last row has since collapsed, and the reasoning that put it there was
wrong on a fact.** It read netcfgd as LAN-only and interactive -- from its own
decision 2 -- and concluded a session costs it nothing it is not already
paying. **netcfgd is not going to remain LAN-only** (2026-08-08), and once a
datagram crosses an untrusted network toward a device that may be behind NAT,
asleep, or reached through a relay, the self-contained frame stops being
fuzzypickles' idiosyncrasy and becomes the property both consumers need.

So the axis is real and the four rows are real, but **the identity row is
settled rather than balanced**: carry identity, derive per message, no session
required. A session handle may still be offered as an optimisation for a live
exchange, and §12's mode bit is where it would be stated -- but it is now the
special case rather than one of two equal ends, and a library that shipped
only the handle would be wrong for both consumers rather than one.

The lesson is worth more than the conclusion: **an axis derived from one
project's current constraint is only as stable as that constraint**, and
"LAN only first" always had the word "first" in it.

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
- **The revocation store only grows.** Nothing in it expires or may be
  evicted, so it is the one bound in this library a long-lived deployment
  can grow into, and its refusal fails open. Sizing it needs a number
  nobody has: how many revocations a deployment accumulates over its life.
  Named rather than guessed at.
- **Whether `chunk/` belongs in the core at all**, or is a layer a consumer
  opts into. It is in the core because netcfgd cannot function without it, but
  fuzzypickles will not use it — its own transfers are content-addressed.
- **§4.3's second bullet is ambiguous, and `chain/` had to pick a reading.**
  It says a grant's expiry is optional and defaults to absent, and then that
  "an expired or absent expiry never withdraws authority — only a revocation
  does". Read literally, a *set* expiry is unenforceable and the field is
  pointless. Read as being about the **default** — that none is imposed where
  none was asked for — it agrees with §4.2's named reference implementation,
  which enforces a hop's expiry when one is set.

  `chain/chain.c` implements the second reading and fails closed, which is
  the safer direction for a library that reconfigures infrastructure (§4.4a),
  and `chain.h` says so at the point of decision. **Flagged rather than
  settled**: this document wins over the code, so if the first reading was
  meant, the code is wrong and not the sentence.
