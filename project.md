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
| local encoding | the core's canonical binary wire, one parser for local and remote | newline-delimited JSON | newline-delimited JSON, as netcfgd's |
| local transport | `AF_UNIX` `SOCK_SEQPACKET` | `AF_UNIX` stream, line-delimited | `AF_UNIX` `SOCK_STREAM`, as netcfgd's |
| local authentication | filesystem permissions, owner-only, same user | the kernel, before a byte is parsed | must be group-gated, and see the hazard below |
| already built | yes | yes, specified and pinned by a generated witness, implemented three times | the project exists; the socket does not |

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

**A daemon running as root and serving a group needs the peer's
SUPPLEMENTARY groups, and `SO_PEERCRED` does not carry them.** This document
said "`SO_PEERCRED` / `SCM_CREDENTIALS` and a real gid check" until
2026-08-14, and that requirement is wrong in the way that does not announce
itself.

`SO_PEERCRED` reports pid, uid and the **primary** gid. A user's primary
group is normally their own, so a gate comparing a `disk`- or `raid`-style
group against it **denies nearly everybody it was written to admit, while
reading as correctly configured.** Measured on the machine this family is
developed on, rather than reasoned about:

    primary gid          1000  ("funk" -- the owner's own group)
    supplementary        20 24 25 27 29 30 44 46 60 103 110 111 116 121 132
    netdev 103, cdrom 24, sudo 27   supplementary only, never primary

netcfgd hit this and carries the warning in `netcfgd-sys/src/peer.rs`'s own
header; its decision 0013 describes the cross-check. Reported here by the
raidcfgd session and verified independently before it was written down,
because a security requirement is the wrong thing to relay on trust.

So the requirement is: **pid, uid, primary gid, and the supplementary list
read from `/proc/<pid>/status`.**

**And an empty group list means "could not tell", not "none".** netcfgd's
`Peer` documents its supplementary groups as "where they could be read", and
the two are safe to conflate only because both deny. Flattening a failed
`/proc` read into an empty vector in the *permissive* direction turns a read
that failed into an allow -- which, on a socket whose group is root for that
group, is the hazard below arriving through the back door. Whatever `local/`
hands a caller must let them tell the two apart.

It ships as an **optional module** (`fuzznet_local`, §8) rather than as part
of the core. The original reason was the risk netcfgd's brief named
precisely: raidcfgd did not exist, and an imagined consumer's requirements
are exactly the kind that turn out wrong after an API is fixed.

**That premise expired on 2026-08-14. raidcfgd exists** -- 114 tracked
files, its own remote, in `CLAUDE.md`'s private-project list, reading HP
Smart Array controllers through four backends. Verified here rather than
taken on report. Its `project.md` states its half at commit `7c79281`, and
netcfgd's `docs/shared-protocol-brief.md` line 300 -- "no repository, no
directory, and it is not in the private-project list" -- is false with it.

Two cells of the table above were "undecided; does not exist" and are now
netcfgd's answers, by the copyright holder's instruction that the two are
sister projects working in almost the same way: `AF_UNIX` `SOCK_STREAM`,
newline-delimited JSON, a socket under `/run`, request/response on a held
connection with a `monitor` that turns one into a one-way stream and never
goes back.

#### The hazard raidcfgd states, which `local/` has to answer

**A group that can destroy arrays IS root for that group** -- the lesson of
the docker group, and raidcfgd's words rather than an inference from them.

The consequence is that **a gid check gating the connection is not
sufficient**, and this is the part `local/` cannot simply implement and
call done. If membership admits a caller and nothing bounds what the caller
may then ask for, the group boundary is a root boundary wearing a different
name. Where that bound lives -- in this module, or in the consumer's command
vocabulary -- is open; that it must exist somewhere is not, at raidcfgd's
end. Their two existing privileged helpers are deliberately the opposite
shape, each refusing all arguments and doing exactly one read-only thing, so
this is a position that project already holds rather than a new demand.

It is theoretical while raidcfgd is read-only, which it will be for a long
time by their own deferral of destructive commands. **It stops being
theoretical the moment a write verb exists**, and that is the moment to have
already answered it rather than the moment to start.

So the local module is still written *last* -- §10 step 7 -- but it is now
last against something real, which is what §2 asked for. Everything in §4 is
needed by two real consumers today; `local/` is needed by a third that has
stopped being hypothetical.

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

#### The frame has nowhere to put the commitment (found 2026-08-14)

**Attempting the extern codec is what found this**, and it is a
contradiction between two sections of this document rather than a gap in
either.

§4.4a says key-committing AEAD is "not optional". XChaCha20-Poly1305 as
Monocypher provides it is **not** key-committing, so something has to be
added, and §4.5 points at fuzzypickles as the working implementation. What
fuzzypickles does is derive **48 bytes** from one BLAKE2b over a 240-byte
transcript — a 32-byte AEAD key and a 16-byte commitment — and **put the
commitment in the frame**, rejecting on mismatch. Its own document: "This is
not optional and costs a handful of bytes."

**`fzn_frame` has no such field.** It is `hop | authenticated{head} |
sealed{capability, payload} | tag[16]`, and none of those is a commitment.
So the schema §6 settled cannot carry what §4.4a requires by the route §4.5
names.

**Settled: `commitment[16]` goes in the authenticated header.** Two other
routes were considered and are recorded so they are not relitigated -- a
committing construction needing no wire field, such as replacing the tag
with a hash over key, nonce, associated data and tag, which costs nothing on
the wire but is not the construction this family has reviewed and shipped;
and committing inside the extern codec, which cannot be assessed until
situ's sealed-region ABI is exercisable.

The field is **in the authenticated header rather than inside the seal**,
and that is the point rather than a layout preference: the commitment exists
to be checked *before* a decryption is spent, and inside the seal it could
only be checked after. It would also be unreadable to a receiver holding the
wrong key, which is exactly the receiver it has to warn.

What remains before the codec can be written is situ's sealed-region ABI.
The construction is no longer a guess; the calling convention still is.

**The half that does not wait on it is built** (`session/commitment.c`,
2026-08-14): one hash over a domain-separated transcript producing 48 bytes,
split 32 into the AEAD key and 16 into the commitment, plus a constant-time
check of a received commitment against a derived one.

Deriving both from **one** invocation over **one** input is the whole
mechanism and the thing the tests hold it to. Two separate derivations,
however carefully labelled, would leave the commitment merely accompanying
the key rather than binding it — and would pass any test that only checked a
commitment against itself. So the suite counts hash calls, asserts the
derived length, and asserts that one flipped bit of transcript moves *both*
outputs.

It also asserts the commitment does not appear anywhere inside the key. That
is the worst way to get this wrong — the frame would publish key material in
its plaintext header — and it, too, would satisfy a test that only compared
commitments.

**The transcript is the caller's**, which is the boundary `chain.h` draws for
a signed region and for the same reason: what goes into it depends on the
session model, and §4.5's prekey half is not settled. Two peers who disagree
about the transcript derive different keys and fail to talk, rather than
talking insecurely.

**BLAKE2b is bound behind the same seam** (`session/hash_monocypher.c`,
optional like the signer), and it is the right primitive rather than an
arbitrary one: it takes an output length as a parameter, which is what makes
"derive 48 bytes and split them" one call rather than a construction.

Its test carries **two kinds of evidence and says which is which**. The
64-byte case is RFC 7693 Appendix A's published vector — an independent
check that this is BLAKE2b at all, which nothing in this tree could have
produced. The 48-byte case is a pinned observation from this build: it can
say the answer changed, not that it is right. Both are worth having and a
pinned observation presented as a known-answer test would be a test that
agrees with whatever the code did the day it was written.

A third case exists only because the first two could agree while the binding
was wrong: the 48-byte digest must **not** be a prefix of the 64-byte one.
BLAKE2b puts the digest length in its parameter block, so a binding that
ignored `out_len` would produce a prefix — and would pass the published
vector.

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

### 4.7 The order a receiver runs these checks in

**Unstated until 2026-08-14, and it should not have been.** §9 puts
encoding, framing, authentication and encryption with this library, and the
*order* of authentication checks is squarely that. Every module states its
own rules; none stated the sequence, so a consumer had to derive it from
five headers and would have been inventing a security property.

The order, and each step's reason for preceding the next:

1. **Peer credentials**, if the frame arrived over the local socket rather
   than the network (`local/peer.h`). Cheapest, and it decides whether to
   spend anything else. UNKNOWN denies.
2. **Freshness** (`frame/freshness.h`). A command with no expiry or a passed
   one is refused before any cryptography, because the alternative is
   spending a signature verification on something already dead. This is also
   what bounds the replay window (§4.3).
3. **Replay** (`frame/freshness.h`, same call). Before decryption, because a
   replayed frame is a configuration change (§4.4a) and the cheapest place
   to refuse one is before it costs anything.
4. **Key commitment** (`session/commitment.h`). Derive the key and the
   commitment together, compare against the frame's, refuse on mismatch --
   **before decrypting.** That is the whole reason the field is in the
   authenticated header rather than in the seal: a receiver holding the
   wrong key must learn so without spending a decryption, and must be warned
   rather than handed plaintext that opens under two keys.
5. **Tag verification and decryption** (the extern codec, **unwritten**).
   Nothing above this line has touched the sealed region. §6 asks situ to
   make parse-before-verify unrepresentable, and steps 1 to 4 are the part
   of that this library can enforce today.
6. **Capability chain** (`chain/chain.h`), against a pinned root and the
   revocation store. After decryption because the capability identifier is
   inside the seal (§13), and that placement was chosen so an observer
   cannot see which authority is being exercised.
7. **Reassembly** (`chunk/reassembly.h`), last. A chunk is only admitted to
   a partial message once it has been shown to be fresh, unreplayed,
   authentic and authorised -- otherwise the memory bound protects a table
   any stranger may fill.

**The two rules that are not orderings but constrain the order.** A refusal
at any step must not have cost a slot at a later one -- `freshness` and
`reassembly` both refuse before allocating, and both are tested for it. And
UNKNOWN from step 1 denies, rather than falling through.

**Why this is prose and not a function.** An `fzn_admit()` that ran these in
order would make the sequence unrepresentable-to-get-wrong, which is the
shape this library prefers and uses in `chain.h`. It is not written because
step 5 does not exist and two of its neighbours are unsettled: §13's
overhead question may move what the header carries, and §14 records §4.3's
expiry reading as open. An orchestrator would bake all three in, and a
consumer would then be depending on the guesses rather than on the modules.
**When the codec lands, this section is the specification for that
function**, and the ordering is fixed now so that it is not invented then.

**A consumer sequencing these handles six error vocabularies** --
`fzn_err_t`, `fzn_fresh_err_t`, `fzn_reasm_err_t`, `fzn_split_err_t`,
`fzn_commitment_err_t` and `fzn_peer_verdict_t`. That is a real integration
cost and it is deliberate for now: each module's errors say what that module
knows, and collapsing them early would lose distinctions the modules were
built to make. It is recorded here as a thing to revisit when there is a
consumer to ask, not before -- a convention change wants raising, not
adjusting in passing.

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

- **§4.4's chunking state machine does not stop being ours** (measured
  2026-08-14; this bullet said "may stop being ours" until then). Rungs
  `frame` and `drive` are not that work: rung 4 is *stream* framing, and no
  rung emits datagram reassembly at all. The choice this bullet deferred to
  §10 step 5 has been made by measurement instead, and `chunk/` is built.
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
`size=144..1168` with the tag covering every authenticated and sealed member.
Unknown enum values are an error rather than a silent pass, which is the right
default for a format that has to be byte-exact.

**The `require` lines are enforced, checked by breaking one deliberately.**
Asking for `in_place` on a covered field fails with the blame chain and both
remedies named -- move it outside coverage, or accept the recomputation and say
so with `in_place_dirty`. That is the property worth having: the schema states
what must hold about the *bytes*, and the compiler refuses a build rather than
a reviewer noticing.

Three findings, and the first is the one that matters:

- **144 bytes of fixed overhead per datagram** (measured 2026-08-14): 5 of
  hop, 91 of authenticated header, 32 for the sealed `capability`, and 16 of
  tag. Of the header, `sender[32]`, `nonce[24]` and `commitment[16]` are 72.

  **The 96 this bullet used to record was stale by 32, and had been since
  `efdb098`.** That commit added `sender[32]` as the key selector and moved
  `capability[32]` inside the seal; the frame went to 128 and the figure was
  never re-measured. Worse, the sentence went on describing `capability` as
  part of the header after it had left. §13 argues from this number, so it
  was arguing from one a quarter too low -- see there. The commitment added
  16 on top, which is the only part of the growth this revision is
  responsible for.
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

### What was behind the refusal (2026-08-14, situ `497c1ea`)

Stepping around the `[max = chunks - 1]` refusal with a literal and running
`situc build` for the first time produced **three messages, all of which are
findings about this schema rather than about situ.** situ says each of them
plainly; nobody had run the command that says them.

**1. Neither relation generates anything.**

    no predicate for relation `same_message`: `later.head.sender` is an
    array, and a relation compares one value against another

and the same for `reply_to`. Both compare `sender`, which is `u8[32]`. A
relation is a predicate over two *values*, and an array is not one.

That matters more than it looks. `frame.situ` calls `same_message` **"THE
ONE THAT MATTERS, and it is a security property rather than tidiness"** --
it is what stops two senders' chunks reassembling into one message that
authenticates as neither. It generates no code and never has.

The property is not unenforced: `chunk/reassembly.c` checks exactly these
clauses by hand, and its comment says it is enforcing the relation. So the
practical position is the reverse of what this document implies -- the
**hand-written** check is the only one there is, and the schema's
declaration is documentation. Which is a defensible place to be, and is not
where §6 says we are.

**2. `fzn_frame` has no owned form, at any rung.**

    no owned form for `fzn_frame`: its size is decided by the data, so an
    owned struct would need a pointer or a worst-case array; neither is
    this generator's to choose

§10 step 6 plans fuzzypickles to migrate at rung 2 with `--owned`, per
situ's decision 0031, because its 225 call sites hold decoded structs that
outlive the buffer. **That plan does not work against this frame as it
stands.** The blocker is the `Bounded(0,1024)` payload: a frame's size is
data-decided, so there is no fixed struct to own. Whether the answer is a
worst-case array, a different migration for fuzzypickles, or fuzzypickles
not adopting at rung 2, is a decision this document has not taken and had
no reason to know it needed.

**3. A correction to how the earlier finding was described.** The report to
situ and the paragraphs above called the `[max]` behaviour a disagreement
between commands, which it is. But when this session first probed the
relation behaviour it recorded it as *silent* -- and it is not. situ prints
all three messages above clearly. The probe was swallowing stdout and
grepping only for the word "error", so a notice read as nothing at all. **A
check that cannot see the output it is checking reports the same thing as a
tool that produced none**, which is this document's own recurring lesson met
from the tooling side rather than the code side.

The through-line is worth stating: **one command nobody ran hid three
findings**, two of which change plans recorded here.

**Reported, and re-checked unchanged at situ `cd3708b`** — eight commits
after the report landed as `bdfdbda`. Pinned to a commit rather than dated
because the re-check fell on the same day as the measurement, and a date
that cannot distinguish the two tells the next reader nothing.

The full table at that commit, since the report's value is in the
disagreement rather than in `build` alone:

| | `[max = total - 1]` | `require m.index < m.total` |
|---|---|---|
| `situc wire` | accepts, **and publishes the bound as contract** | accepts |
| `situc map` | accepts | refuses |
| `situc build` | refuses | refuses |
| `situc verify` | refuses | — |

So **§10 step 2 is still blocked**, and the dangerous half is still live: a
schema can declare a constraint nothing can enforce, and `frame.situ` still
carries one.

What situ has been doing in those eight commits is the same lesson from the
other end — running generated code rather than only compiling it ("run a
relation's predicate instead of only compiling it", "run the C++ and Rust
reader and table, not just their compilers", "emit a reader only where a
stream can be framed, and run it"). That is the class this report is about,
arrived at independently there. Worth knowing before anyone reads the
silence as a refusal.

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

**situ generates a networking scheduler for a schema it can reach, and
cannot reach this one** (measured 2026-08-14 — see §10 step 4). The claim
below, that it "will generate the entire networking scheduler", was taken
from decisions 0032 and 0033 and never checked against what `situc` emits
for `wire/frame.situ`. It emits, at every rung above `view`, the same bytes
plus a stream reader.

The general claim is not false — a schema whose relations compare scalars
and carry a `[timeout_ms, retries]` policy does get a driver, and that was
measured too. What was never measured is that **this** frame reaches it, and
it does not: a sealed region whose size the data decides has no owned form,
and relations comparing a 32-byte key emit no predicate, so there is no
table and no driver.

Kept below rather than deleted, because the reasoning it supported is
recorded around it and the correction is more useful attached to the claim
than in place of it. **A consumer chooses how much with `--layer`** That is not a possibility to plan around; it is the
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

**Answered at §10 step 4: `view`, because four of the six rungs cannot
reach this frame** -- no owned form for a sealed region whose size the data
decides, and no predicates for relations that compare a 32-byte key. The
sequencing question below framed it as needing dates; it did not.

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

| module | what it is | state |
|---|---|---|
| `constant_time/` | constant-time comparison | **built** |
| `wire/` | the schema. §7a gives the encoding itself to situ | `frame.situ` written; nothing generates from it yet (§6) |
| `frame/` | freshness: command expiry, and the replay window it bounds. The envelope, signing and verification are situ's | **built** |
| `chain/` | capability chains: verification, minting, delegation, revocation, and the signer seam | **built** |
| `chunk/` | splitting, reassembly, and the memory bound | **built** |
| `session/` | the key schedule, and the AEAD seam | **key schedule and its BLAKE2b binding built**; the codec waits on situ's sealed-region ABI |
| `local/` | `AF_UNIX`, peer credentials including supplementary groups, and a bounded vocabulary | **credentials built**; the socket, the vocabulary and the bound are not |

**Rewritten 2026-08-14, because five of its seven rows were stale.** The
table was written before §7a, which reassigned most of §4 to situ once the
layer ladder arrived, and it was never brought into line. What it described
was the tree as it would have been had this library written its own
transport. Each correction below is the same correction:

- **`wire/` is the schema, not C primitives.** §7a assigns 4.1 to situ, so
  "canonical encode/decode primitives" describes generated code rather than
  anything this library writes.
- **`frame/` holds freshness and nothing else.** The envelope, signing and
  verification the row listed are situ's at the seam.
- **The replay window is in `frame/`, not `session/`.** §13 settled that a
  frame is self-contained and *no session is required at either end*, so a
  window keyed on a per-datagram nonce cannot be session state. The row
  predated that settlement; the code is right and the table was wrong.
- **`chunk/` does not retransmit and will not.** §10 names a hand-written
  retransmission state machine as the thing to refuse, and situ generates
  one at rung 6. Splitting and the bound are ours; asking for a missing
  piece is not.
- **`chain/` gained minting, delegation and the signer seam**, which the row
  never mentioned.

**One placement is left as it is and named rather than moved.** The
Monocypher binding sits at `chain/sign_monocypher.c` because it implements
`chain.h`'s signer vtable, which is a signature rather than an encryption
concern. When AEAD arrives it will want a home that is not the capability
model, and that is the moment to decide whether `session/` becomes a real
directory or whether the extern codec bindings live together somewhere else.
Not worth deciding before there is a second one.

`local/` is deliberately last and deliberately optional — §2.

**`constant_time/` was added 2026-08-14** and is not a module in the sense
the others are: nothing links it for a feature, everything links it for one
function. It exists because §4.4a says a constant-time tag comparison is
"not optional" and that "this library owns it and must not leave it to the
consumer" — and `fzn_ct_memeq` started life declared in `chain.h`, so the
only way for a consumer to get it was to include the capability model.
Somebody asked to include chains, hops, delegation and revocation to obtain
a memcmp writes their own instead, which is the outcome that sentence
forbids. It also fixes the dependency direction: everything may depend on
this and it depends on nothing.

Verified rather than asserted: it compiles and links on its own against
nothing else in the tree, and the `-Os` object has exactly one conditional
branch — the loop's length test — with the accumulator spilled through
memory each iteration. No branch depends on the data, so the `volatile` did
its job.

The discrepancies this section used to carry are resolved in the table
above rather than annotated beneath it.

**`make installcheck` is what holds the table honest from outside.** Every
suite here builds from inside the tree, which is the one arrangement a
consumer never has — §7 has netcfgd's agent taking this as a submodule and
compiling these sources into its own objects. So `tools/consumer_check.c` is
compiled twice, once against an installed tree and once against the source
tree from another directory, and both are run.

It found the defect it was written to look for, in the check rather than in
the code: **`install` hardcoded a line per header while `HDRS` listed them
separately**, so there were two hand-maintained lists that had to agree and
nothing compared them. Dropping a header from `HDRS` changed nothing that
was installed. `install` iterates `HDRS` now, which collapses the two into
one, and removing a header from it fails the check.

**Then it narrowed silently, which is the more interesting failure.** The
target can only catch a break in a header `tools/consumer_check.c` actually
includes, and that file was written before `session/` and `local/` existed.
Both modules' headers were installed and unincluded for several commits, so
`installcheck` was quietly guaranteeing less than it had — not by breaking,
but by the tree growing past it.

So it checks its own coverage now: every header in `HDRS` must appear in the
consumer, and it refuses otherwise. **A check that has to be extended by
hand as a project grows is a check that will stop covering the newest thing,
which is the thing most likely to be wrong.** Both directions confirmed —
dropping a header from `HDRS` fails the compile, and dropping one from the
consumer fails the new self-check.

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
4. ~~**Decide the rung, and say when.**~~ **Answered 2026-08-14: `view`,
   and the question was not the one this step was asking.**

   Measured rather than chosen. Building `wire/frame.situ` at each rung
   emits, for this frame:

   | rung | emitted | bytes |
   |---|---|---|
   | `view` | `f.c`, `f.h` | 18746 |
   | `edit` | identical | 18746 |
   | `relate` | identical | 18746 |
   | `frame` | adds a **stream** reader | 24313 |
   | `converse` | identical to `frame` | 24313 |
   | `drive` | identical to `converse` | 24313 |

   **Every rung above `view` gives this library nothing it can use**, and
   situ says why rather than leaving it to be inferred:

   - **`edit` buys nothing** -- "no owned form for `fzn_frame` at any rung:
     `sealed` is a sealed, which is a shape the data decides rather than a
     length". The payload is `Bounded(0,1024)`, so there is no fixed struct
     to own.
   - **`relate` buys nothing** -- both relations compare `sender`, a
     `u8[32]`, and "a relation compares one value against another".
   - **`converse` and `drive` buy nothing** because they are built on
     relations: "no conversation table for `same_message`" for the same
     reason, and a driver needs a table.
   - **`frame` buys the wrong thing.** Rung 4 is *stream* framing -- a byte
     stream in, whole messages out. This is a datagram protocol and the
     5567 bytes it adds solve a problem this library does not have.

   **So the sequencing question §7a framed was wrong, and that is the more
   useful half of the answer.** It said the decision needed two dates -- when
   the rungs land, and when netcfgd needs its agent. Both have arrived or
   stopped mattering, and the rung is still `view`, because **the binding
   constraint was never a date.** It is that this frame's shape puts four of
   the six rungs out of reach.

   Two routes change that, and choosing between them is a wire decision
   rather than a scheduling one:

   - **Wait for situ.** Fixed-size array comparison in a relation is
     reported (`suggestions/fuzznet.md`, situ `ba10684`) with the argument
     that decision 0030's own first example -- "a response carries the
     request's identifier" -- is usually a key rather than an integer. If
     that lands, `relate` and `converse` become real for us, and `drive`
     follows for any relation given a `[timeout_ms, retries]` policy.
   - **Weaken the relation to fit what situ generates today.**
     `same_message` compares `msg`, `chunks` and `sender`; the first two are
     scalars and would generate. Dropping `sender` from the schema and
     leaving it to `chunk/reassembly.c` -- which already enforces it --
     unlocks the ladder now.

   **The recommendation is the first, and the reason is not patience.**
   `sender` is the clause that stops two senders' chunks reassembling into
   one message that authenticates as neither; `frame.situ` calls it "the one
   that matters". A schema declaring the two harmless clauses and omitting
   the dangerous one would be a security declaration that is partial in the
   direction of looking complete, and the next reader would take the
   generated predicate as the whole check. Whichever way this goes,
   `chunk/reassembly.c` keeps enforcing all three clauses in C, which is
   where the property actually lives today.

   **`view` needs nothing from anybody and is what step 5 should be written
   against.** It is not a placeholder: accessors over caller-owned bytes are
   what a bridge needs to read a frame, and everything this library adds on
   top -- the capability model, freshness, reassembly -- is already built and
   sits above that line.
5. **netcfgd's `agent/`** was named the first real consumer. **It does not
   exist, and whether it will is undecided** — reported by the netcfgd
   session 2026-08-14 and verified here: no directory, no tracked files, a
   layout entry at `project.md:478` and a design in
   `docs/remote-access-feasibility.md`. Their `project.md:2512` records
   "whether `agent/` exists at all is a separate open question", above a
   further one about whether it would ship in netcfgd's packages, framed as
   a question about exposing a network service.

   This step used to say "it does not exist yet, which is the whole of the
   timing benefit", and that framing is wrong in a way worth keeping
   visible: it treats non-existence as **scheduling**. The timing benefit is
   real — nothing regresses if the API turns out wrong — but it only holds
   for a consumer that is coming. For one whose existence is open, "first
   real consumer" is a phrase carrying weight it has not earned, and steps 6
   and 7 are sequenced behind it.

   **So the ordering below is no longer a queue.** `local/` is step 7 and
   waits on raidcfgd's vocabulary bound, not on this; fuzzypickles' step 6
   is its own deliberate work. Neither should be read as waiting for an
   agent that may not be written.
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
`VERSION`. `make style` passes over thirty-two files.

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

### `make coverage`, and the number that is not 100%

Measured rather than assumed, and it answered the question this library kept
hedging: is there test work left.

| file | lines | branches both ways |
|---|---|---|
| `constant_time/constant_time.c` | 100% of 7 | 100% of 2 |
| `chain/chain.c` | 100% of 64 | 85.7% of 84 |
| `chain/revocation.c` | 100% of 41 | 85.2% of 54 |
| `frame/freshness.c` | 100% of 41 | 92.5% of 40 |
| `chunk/reassembly.c` | 100% of 103 | 87.8% of 98 |
| `chunk/split.c` | 100% of 21 | 100% of 22 |

**Lines are the weak number and branches-both-ways is the honest one.** 100%
of lines is compatible with every decision in the library having only ever
gone one way, which is why the target reports both and why the second column
is the one to read.

It found three things. Two were the same gap twice: the malformed-argument
guard of `fzn_revocation_merge` was the only unexecuted code in the library,
and `fzn_split_at`'s went only one way — **each untested while the sibling
function written beside it was tested**, which is what a gap looks like when
two functions are written together and only one is thought about twice. The
third was behaviour nobody had exercised: delegating a grant *shorter* than
the chain allows. Every test asked for more time than it had and none asked
for less, so the cap had never been shown to be a ceiling rather than an
assignment.

**`make coverage` refuses when a source is exercised by nothing**, rather
than printing a blank line and exiting 0. That is the target's job beyond
the numbers, and it exists because the numbers alone were not enough:
**twice in one session a file reached this tree with nothing exercising
it** -- `fzn_peer_is_member`, added to answer a colleague's question rather
than to make a failing case pass, and `local/peer_linux.c`, believed to
need a cooperating process and not. Both were found by a person reading the
table, which is a gate over an empty file list wearing a report's clothes.
Confirmed to fire by adding a source nothing tests and watching it refuse.

**The remainder is deliberately not chased.** What is left is the individual
sub-conditions of null-argument guards — `if (!a || !b || !c)` where the
guard is tested but not every operand is the one that fired. Covering those
tests the compiler's short-circuit rather than the library, and would add
roughly forty assertions that cannot fail for a reason anyone cares about.
The number stays below 100% on purpose, and this paragraph is why, so that
nobody reads it as neglect and nobody "fixes" it.

### `make test SANITIZE=1`, and why the canaries stay

Everything builds and runs under AddressSanitizer and UBSan behind a knob,
at `-Og` and into a separate `BUILD_DIR` so sanitized objects cannot mix
with a plain build's. It is deliberately not the default: §7 has each
consumer compiling these sources with its own flags, and a library that
forced a sanitizer on them would be choosing for fuzzypickles' Android
build.

All five suites and all three fuzzers pass under it, including a 300000-case
campaign per harness. **That the run is real was checked rather than
assumed**: `__asan_init` is present in the sanitized binaries and absent
from the plain ones, and the same flags fire on a deliberate heap overflow.
A sanitizer build that silently failed to engage reports success exactly as
loudly as one that worked.

**It also settled a question the fuzz harnesses raise: does a sanitizer make
their canaries redundant?** It does not, and the reason is structural. ASan
brackets *objects*, and a harness arena is one object — a write from one
slot into its neighbour's canary is in bounds to ASan and passes silently.
Removing two bounds checks in `reassembly.c` produces an overrun the canary
catches and `SANITIZE=1` does not. The two cover different classes: ASan
sees reads of what nothing wrote and use-after-free, the canary sees writes
that stay inside the harness's own allocation. Both stay.

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

### The round-trip harness, over permutations rather than a list

`chunk/tests/roundtrip_fuzz` is the only harness that holds two modules to
each other. Split and reassemble are the one coupling in this library that
can fail while both halves pass their own suites, and it was covered by ten
hand-picked sizes in `split_test` — the thinnest evidence in the tree for
the strongest coupling in it.

It draws the message length and the per-datagram limit from the input, so
the edges nobody thinks to write are reached by exhaustion rather than by
imagination, and it offers the pieces in an input-driven permutation. **The
model is a prediction rather than a re-derivation**: reassembly legitimately
*refuses* some orders, since a short last piece cannot set the stride, so a
harness treating every refusal as failure would be wrong and one treating
every refusal as fine would notice nothing. It predicts from the permutation
alone that a message completes exactly when the first piece offered is not
the last index of a multi-piece message, and holds the outcome to that in
both directions.

Four of five planted bugs are caught, and the fifth is honestly outside its
reach: giving a single-piece plan a stride from `max_payload` changes only
`buffer_needed`, not the piece boundaries, so the round trip cannot see it
and `split_test` does.

**One of those five was reported as not found and was not tested at all.**
The sabotage runner verified that the binary rebuilt, but restoring the
original sources touches their timestamps, so `make` rebuilds whether or not
the mutation applied — and that one had not. Every sabotage now compares the
*source* hash before and after as well as the binary's. It is the same
failure as the stale-binary one recorded above, one level up: the check that
a check ran was itself unable to fail.

### The revocation harness is model-based, and that is the difference

`chain/tests/revocation_fuzz` covers the admission path, which nothing else
touched: `chain_fuzz` feeds the already-verified `fzn_revocation_t` straight
to verification, so the records a peer actually sends — issuer, signature,
signed region — had never been fuzzed. §4.2 carries revocation *on contact*,
so the peer handing one over is not its issuer and every field of it is a
stranger's.

Where the other harnesses assert properties that must hold, this one keeps
an independent **shadow** of what the store should contain, decides for
itself what each record ought to do to it, and asserts the two agree exactly
after every call, in both directions. That is stronger, and it matches the
class this module's failures belong to: a revocation bug is not an overrun,
it is a record admitted that should not have been — a carrier inventing one
— or one silently dropped, which un-revokes a stolen device. Neither breaks
a spot invariant; both break the model.

All five planted bugs are caught with a precise message: unpinning the
issuer, dropping the signature check, removing the duplicate check, evicting
from a full store, and accepting an empty signed region.

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

The schema (§6) surfaces **144 bytes of fixed overhead**, of which
`sender[32]`, `nonce[24]` and `commitment[16]` are 72 in the header and
`capability[32]` is inside the seal. The obvious fix -- establish the
capability once and carry a short handle -- is **the wrong first move**, and
finding out why settles something larger.

**This section was written against 96 and the number was never right.** It
had been 128 since `efdb098`, and is 144 since the commitment landed (§4.5).
The correction does not overturn the conclusion below -- fuzzypickles pays
82 header bytes plus a 16-byte MAC for the same self-contained property, so
two designs still reach the same order independently -- but it does make the
cost real: **half again what this argument thought it was weighing**, and
the case for reclaiming the 32 that `capability` costs is stronger, not
weaker, than the paragraphs below assume.

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
- **Key-committing AEAD has no field to commit into**, and the extern codec
  cannot be written until that is settled. §4.5 carries the three options
  and what each costs. This is the second thing blocking real code, after
  §10 step 4, and unlike step 4 it does not wait on situ.
- **What bounds a group member's requests.** raidcfgd's hazard in §2 --
  a group that can destroy arrays is root for that group -- is not
  answered by `local/peer.c`, which only establishes who a caller is. Where
  the bound lives, in this library or in the consumer's vocabulary, is
  open. It is theoretical while raidcfgd is read-only and stops being so
  the moment a write verb exists; that signal is recorded as an obligation
  at their end.
- **One check in `peer_linux_test` cannot discriminate on this machine.**
  A Debian-style user has uid == gid == 1000 -- the same fact that makes
  `SO_PEERCRED`'s primary gid useless for gating, and the reason `local/`
  exists -- so filling `primary_gid` from `cred.uid` instead of `cred.gid`
  produces identical output. That sabotage was run and **was not caught**,
  and no test written here could catch it. The check stays, because it
  discriminates wherever the two differ; it must not be counted as evidence
  where they do not, and the test says so at run time rather than leaving a
  reader to assume otherwise.

  The previous entry here said `peer_linux.c` needed "a socket and a
  cooperating process" and was **wrong about the second**: a socketpair has
  both ends in one process, so `SO_PEERCRED` reports us. It is tested now,
  against `getgroups()` and `getuid()` rather than against itself.
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
