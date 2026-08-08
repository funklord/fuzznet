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

It ships as an **optional module** (`fuzznet_local`, §7) rather than as part
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
halves are binary, so the split that constrained netcfgd does not apply and
the answer may come out differently.

**Open until measured.** Do not write the frame by hand on the assumption that
situ cannot describe it.

---

## 7. Shape of the tree

Modules, so a consumer links what it needs and no more. Nothing below is built
until §9's order says so.

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

## 8. Authority, and who decides what

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

## 9. Order of work

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

## 10. Where this is, for whoever picks it up

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

## 11. Prior art: three mechanisms from the 2018 generation

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

## 12. Open, and named rather than left silent

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
