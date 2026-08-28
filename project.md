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

### The socket and the framing are raidcfgd's, decided the day they were built

**Raised as an open question and answered by the copyright holder the same
day** (2026-08-18): `local/socket.c` and `local/line.c` moved to raidcfgd.

The paragraph above says fuzznet *does not define the local hop at all*, and
those two modules did. They chose `SOCK_STREAM` and newline framing, which is
netcfgd's and raidcfgd's shape and not fuzzypickles', whose local hop is
`SOCK_SEQPACKET` carrying its own binary wire -- a disagreement this section
calls load-bearing rather than accidental. Offering is not imposing, so they
would have harmed nobody sitting here; what decided it is §5's failure mode,
**absorbing one consumer's application until the others are carrying it.**
fuzzypickles would have reviewed, packaged and audited a listener it can never
call.

**What stays, and why it is a different kind of thing.** `local/peer.*` reads
credentials off a descriptor the consumer made, on a socket the consumer chose;
`local/vocabulary.*` judges verbs the consumer defines and this library cannot
read. Neither chooses a transport or an encoding, so neither is anybody's
application -- which is the test this section now has for what may live in
`local/` at all.

They are in raidcfgd at `local/`, renamed to that project's convention, with
their 95 assertions intact and run by `make local-test`. `local/socket.c` still
reads credentials through this library's `local/peer.h`, which is the seam
working as intended: the half that chooses a shape is theirs, the half that
chooses none is ours.

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

#### The send path had no bound, and the header argued for the wrong number

The receive half was bounded early and thoroughly — `FZN_REASM_MAX_CHUNKS`, a
per-sender quota, `payload_len` checked against the caller's own buffer. The
send half had **one** bound, `max_payload != 0`, and that asymmetry hid a real
defect for as long as it existed.

`wire/frame.situ` declares `u16 length [max = 1024]`, so a payload above 1024
cannot be framed: `situ_fzn_frame_validate` refuses it. `fzn_split_plan`
accepted any stride at all, so it would return `FZN_SPLIT_OK` for a plan whose
every datagram was invalid — and **nothing downstream would have caught it**,
because this library has no encoder yet. Split is the last place on the send
path where the mistake is catchable.

**The reachable case is not an edge case, it is the correct-looking caller.**
`split.h` documents `max_payload` as the caller's, "since it depends on the
MTU and on the frame overhead", so the obvious arithmetic is Ethernet's 1500,
less 28 for IP and UDP, less the frame overhead. That gives 1328 — a
thoroughly reasonable number that produces an entirely unsendable plan.

**And the header's own overhead figure was wrong, in the direction that makes
it worse.** It said 96, which is `hop + head` and omits the sealed
`capability` and the tag — 48 bytes between them. So the comment was
instructing a caller toward 1376 rather than 1328. This is the same stale 96
§13 records, surviving in a second place after §13 was corrected: fixing a
number where it is argued about does not fix it where it is used.

`fzn_split_plan` now refuses above `FZN_SPLIT_MAX_PAYLOAD`, with a distinct
error from the too-many-pieces one, and refuses rather than clamps — a clamp
would leave the caller cutting their buffer with their own number while the
plan used a smaller one, which is precisely the stride disagreement this
module exists to prevent.

**The ceiling is a copy, and the copy is tethered.** `chunk/split.h` must not
include a generated header: that module's independence from the schema is what
kept it buildable while §10 step 2 was blocked, and keeps it independent of
the schema now that step 2 can proceed. So the number is repeated, and
`chunk/test/agreement_test.c` static-asserts it against the generated header,
which is the only place both are visible. Two assertions rather than one,
because the second is the premise of the first:

| assertion | what it catches |
|---|---|
| `FRAME_SIZE_MAX - FRAME_SIZE_MIN == FZN_SPLIT_MAX_PAYLOAD` | the two numbers drifting, in either direction |
| `FRAME_SIZE_MIN == HOP + HEAD + CAPABILITY + TAG` | a second variable-length field making the first line's arithmetic mean something else |

The bound is reachable only as that difference because **`situc` emits no
constant for a scalar's `[max]`** — sizes are emitted per struct, so there is
no `SITU_FZN_HEAD_LENGTH_MAX`. The subtraction works only because
`payload[head.length]` is the sole variable-length member of `fzn_frame`,
which is why that premise is asserted rather than assumed.

Two limits worth stating plainly rather than discovering later:

- **The tether is `make test`, not `make`.** A static assert in a test fires
  only when tests build, and per `build-and-commit.md` the default target does
  not build them. Putting it in the library would mean a library source
  including a generated header, costing the independence above for a constant
  that changes about once. Accepted deliberately.
- **1024 is a placeholder** whose own schema comment says the real number
  wants measuring against netcfgd's largest chunk. When it is measured, the
  assert is what refuses a half-done change — which is the point of having it
  rather than a comment asking politely.

Sabotage-verified in all three directions: removing the check fails
`split_test` on three assertions, and moving the ceiling to 1023 or to 2048
fails the static assert at compile time. A one-sided check would have missed
half of that.

#### An unchecked multiplication, found by asking which branches never ran

`admit_first` sized a slot with `total = payload_len * (size_t)chunks` and
compared that against the buffer. **`payload_len` is a `size_t` the caller
supplies, and the multiplication can wrap.** 2^62 with four chunks is exactly
2^64, which is zero, so the comparison passed and the slot went live claiming a
stride of 2^62.

Measured rather than reasoned about, with a probe before anything was changed:
`slot.live` set, `chunk_size` at 2^62, and `fzn_reasm_accept` returning
`TOO_LARGE` **from the offset guard further down** rather than from the sizing.
So the only thing between a wrapped total and a `memcpy` of 2^62 bytes was
that guard — and gcov says **neither half of it had ever been taken**, in any
test or in 20000 fuzz cases. Defence in depth, one layer deep, with the layer
unexercised.

The fix is division, which cannot overflow, and `payload_len <= capacity /
chunks` is exactly equivalent to `payload_len * chunks <= capacity` over the
integers rather than a stricter bound. The test asserts the thing that
distinguishes the fix from the old behaviour: not that the chunk is refused —
both refuse, with the same error — but that **the slot is not taken**, which is
what separates the sizing rejecting it from the guard behind it catching up.

**How it was found matters more than the bug.** Nothing suspicious was
visible in the source; the multiplication reads like every other sizing
expression. It surfaced from asking gcov which branches had never been taken
and then reading each one to decide whether it was defensive or a gap. Of the
tree's unexercised branches, most were argument-validation chains, and four
were not: two in `revocation.c` and two halves of this guard.

**Reachability, stated plainly.** A correct caller decodes `length` from a
`u16` bounded at 1024, so it cannot supply a wrapping `payload_len`, and this
was never a remote overflow. What it was is the module's own contract not
holding: `reassembly.h` promises to bound what a stranger claims, and it
bounded `chunks` while trusting an arithmetic result derived from a caller's
size. The consumer that would have found it is one that passes a length from
somewhere other than the frame.

Fixing it made the guard unreachable through the public API, which is the
correct outcome and leaves defence in depth with no way to exercise it from
outside. So `reassembly_test.c` builds the state by hand — a live slot whose
`chunk_size` was made inconsistent with its capacity — and covers both halves,
since an offset past the end and an offset inside it with a length running
past fail differently, and only the second exercises the `buf_capacity -
offset` that must not underflow. That is white-box and deliberately so; the
alternative is the guard nothing has ever run, which is what this file was
just bitten by.

#### The same shape again, one file over

Having found one struct trusted where it should not be, the obvious question
was whether there were others, and `chunk/split.c` had the same defect in a
worse position.

`fzn_split_at` validates `plan->chunks` and `plan->chunk_size` -- **so it had
already decided the plan was untrusted** -- and then computed the last piece's
length as `total - start` without checking `total` against either. A plan
claiming ten bytes in pieces of a hundred returns, for piece 3, an offset of
300 and a length of **18446744073709551326**, alongside `FZN_SPLIT_OK`.

**It is worse than the reassembly one because this function copies nothing.**
It hands a caller an offset and a length to copy with, so the overread happens
at the call site, in a consumer's project, with nothing there to suggest where
the number came from. `reassembly.c` at least did its own `memcpy` behind its
own guard.

Fixed the same way and for the same reason -- by division, before the offset is
computed, since `index * chunk_size` is itself capable of wrapping when the
fields disagree. `(total - 1) / chunk_size` is the largest index whose piece
starts inside the message.

**Evidence that it narrows nothing:** `roundtrip_fuzz` reports identical
counters across the change -- 19535 planned and 17741 completed of 20000, the
same numbers before and after -- so the guard refuses no plan the planner
produces. The test covers both halves separately, because a check of only
`chunk_size > total` still underflows on a stride that fits with an index past
the end, and it includes the single-piece case where `chunk_size == total`
exactly and an off-by-one in the bound would refuse a legitimate message.

**The pattern is worth naming, since it has now appeared twice in one
afternoon.** Both functions take a caller-supplied struct, validate some of its
fields, and then do arithmetic on the ones they did not. Partial validation
reads as thoroughness and is the more dangerous state: an unvalidated struct
invites suspicion at every use, while one that is checked in two places out of
three looks handled.

#### A count field is a bound, and three loops were not treating it as one

The same lens once more, asked of a different shape: **which loops are bounded
by a field of a caller-supplied struct rather than by the array's own size?**
Three were, and each indexes storage whose real extent sits in the struct
beside it.

| loop | bound | what a bad count does |
|---|---|---|
| `fzn_peer_group_verdict` | `peer->group_count` over `groups[64]` | reads past the array and can only **add** matches |
| `fzn_revocation_covers` | `store->used` over `entries[capacity]` | scans memory that is not the store |
| `fzn_replay_expire` | `window->used` over `entries[capacity]` | **writes** -- it compacts in place |

**The peer one is the serious one, because it is the only path in that file
that fails open.** Every other refusal there denies. Reading past `groups` can
only add matches, so the answer a nonsense count produces is `MEMBER`, granted
on the strength of whatever happened to sit next to the array — in a module
whose entire purpose is that incomplete information denies.

The struct that produces it is not exotic: one declared on a stack and never
initialised, where `groups_known` is garbage that happens to be non-zero. That
is what a consumer gets for forgetting a `memset`, and this library's consumers
are other projects.

It answers `UNKNOWN` rather than scanning a clamped range, and the choice is
the module's own reasoning applied to itself. A clamp would return `NOT_MEMBER`
**definitely**, from a struct known to be nonsense — and `peer.h` already
names a definite wrong answer as the thing the tri-state exists to prevent.
The primary gid still answers, since it is not in the array and does not
depend on the count.

`fzn_replay_expire` is the one that writes, and it needed a second guard rather
than one: `fzn_replay_admit` calls the sweep first, the sweep now **refuses**
a bad window rather than repairing it, and admit would then have scanned the
bad range anyway. Refusing is not fixing, so the check belongs at every entry
point that reads the field, not at one of them.

Both appends also tested `used == capacity` and now test `>=`. An equality
test is exactly what a count past capacity walks through on its way to writing
at `entries[used]`.

**The test's own setup was the first thing that broke.** Asserting that a
legitimately full window is still `WINDOW_FULL` was done by setting `used = 4`
on a window holding one real entry, which left three slots of uninitialised
stack for the sweep to read as expiry times — so the result depended on what
was in them. The window is filled by four real admissions now. A test whose
setup is itself undefined proves nothing about the code, and this one failed
loudly rather than passing by luck, which is the good version of that mistake.

**And one sabotage did not apply.** The mutation pattern for `peer.c` missed
the `peer->` prefix, so the run reported zero failing assertions for a file
that had not been changed — a vacuous result wearing the appearance of a check
that failed to fire. It was visible only because the script prints whether the
mutation applied. That guard is why the number is trustworthy: 3, 1 and 3
assertions fail when each of the three checks is removed.

#### Two things `revocation.c` claimed and nobody could see

Both came out of the same sweep. `fzn_revocation_merge` keeps the **first**
error and reports it once the batch is done, and every test put exactly one bad
record in a batch — which cannot tell the first from the last. The branch that
skips the assignment on a second failure had never run.

It is observable only with two failures of different kinds, so the test now
fills the store behind a forged record and asserts `WRONG_ROOT` rather than
`STORE_FULL`, then reverses the order and asserts the opposite. The two mean
different things to a caller: a forged record says somebody is lying, a full
store says you may be missing revocations you were told about. Reporting the
last would let whoever appends rubbish to a batch choose which one a host sees.

The second is smaller: `err` is optional, every test passed one, and the branch
that skips writing it had never run. An unguarded store through a null pointer
is not a thing to find out from a consumer's crash report.

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

**Both are settled now** (2026-08-18). The codec is written --
`session/aead.h` is the seam, `session/aead_monocypher.c` the
XChaCha20-Poly1305 binding, `wire/seal.c` the frame path -- and §10 step 2 is
no longer blocked.

**The calling convention turned out to be smaller than the guess, and not the
one the schema names.** situ's tier-1 codec ABI (its §13.2a) is

    situ_err_t x_decode(const uint8_t *in, uint32_t in_len,
                        uint8_t *out, uint32_t out_cap, uint32_t *out_len);

-- no key, no nonce, no associated data, so it cannot express a keyed
authenticated transform at all. `frame.situ` declares `sealed(fzn_aead, nonce =
head.nonce)`, so the nonce is something the compiler *knows* and still does not
pass. Threading a key through a global to satisfy that signature would put
mutable state in the one seam where it must not be, so `impl fzn_aead extern
"fzn_aead_xchacha20poly1305"` stays unbound and this library calls its own
seam.

**Unbound for now rather than permanently, and the distinction matters to
whoever reads this next.** situ's scope is eventually to cover protocol needs
whole -- layered, nested and distributed cryptographic contexts, including a
project plugging in its own routines. So this is a gap on the way there rather
than a boundary either project has drawn, and `session/aead.h` is the shape a
future binding would attach to rather than a permanent detour around one.

Reported to situ, and then **corrected**: the first report recommended they
write the limitation into their specification, which was advice premised on
the boundary being deliberate. It is not, so that recommendation was withdrawn
the same day. Worth recording here because it is the mistake this document
keeps warning about from the other side -- a temporary state written down as a
decision, which the next reader takes for one.

**Nothing is lost by that, because the generated code never calls the codec.**
What situ contributes to a sealed region is the layout and the **gate**:

| what it gives | what it is for |
|---|---|
| `situ_fzn_frame_tag_covered()` | the exact span the tag authenticates, from the layout rather than restated |
| `situ_fzn_frame_sealed_open(view, verified, &gate)` | refuses an interior view unless something says the tag verified |
| every interior accessor takes the gate | the plaintext is unaddressable before that point |

So the discipline situ enforces is **order**, and `wire/seal.c` is the only
file permitted to say the word: shape from the schema's own validator, then
the commitment, then the tag over situ's span, then the gate, then plaintext.
Two sabotages confirm it -- removing the commitment check and opening the gate
regardless of the tag each fail the assertions written for them.

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

### Two testing lessons from code that has since left

`local/socket.c` and `local/line.c` moved to raidcfgd (§2), and their reasoning
went with them -- an over-long line ending a connection rather than
resynchronising into a boundary an attacker chose, a socket mode set before the
path is reachable rather than chmodded after. Both are recorded there, in the
source and in that project's `project.md`.

Two things stay here, because they are about how this workspace tests rather
than about a listener:

**A sabotage that fails to fail is a finding.** Removing the `refusing` guard
from the line reader changed no test result, which meant no test built the only
state it was reachable from. The guard was not wrong; nothing was checking it.
Sabotage is usually read as "the check caught it", and this is the other
direction, which is easy to miss because it looks like a clean run.

**A hanging test is worse than a failing one.** Removing the socket's in-use
check made its suite block for ever rather than report: no probe connection was
made and a blocking `accept` waited for one that was not coming. A hang is
caught only by whatever timeout wraps it and says nothing about which assertion
it was on -- the same distinction as the nonce guard's segfault, where the
sabotage was caught by a crash rather than by an assertion. The listener was
made non-blocking for its own tests, which turned the hang into a returned
error and covered a path nothing else reached.

### 4.8 Bounding what a peer may ask for, once its group has let it in

**raidcfgd exists now, and this is the requirement it stated** (2026-08-18, its
`project.md` under *Receiving fuzznet*), in its own words and not negotiable
there: *a gid check that gates a connection is not enough; what a member of
that group may then ask for has to be bounded, or the group boundary is a root
boundary wearing a different name.* Its reasoning is the docker-group lesson --
**a group that can destroy arrays is root for that group**.

It left one thing to this library: *"whether that bound lives in the module or
in this project is the library author's call."* **It lives here**, and
`local/vocabulary.h` is it.

**§5 is what makes that possible rather than a contradiction.** That section
keeps command vocabularies out of the core, and this module does not carry
one: a verb here is bytes with a length, and the library cannot tell `status`
from `destroy`. The consumer supplies the table; the table is what says which
group may ask for what. It is exactly the split `chain.h` already makes, where
a capability is 32 opaque bytes and the chain is verified without the library
ever learning what the capability permits. **Mechanism, never meaning.**

**The tri-state is `peer.h`'s and carries through**, which is the part worth
the module rather than a line in each consumer. Three answers:

| | when |
|---|---|
| `MEMBER` | a rule names this verb for a group the peer holds |
| `NOT_MEMBER` | no rule names this verb, or it is not a verb a rule could name |
| `UNKNOWN` | a rule names it for some group, and whether the peer holds that group is unknowable |

raidcfgd states the same rule independently -- *"an empty group list means
could not tell, not none"*, and treating a failed read as an empty membership
turns a read that failed into an allow. That is two projects reaching one
conclusion separately, which is worth more than either saying it twice.

**Every rule is scanned, with no early return on a match, and that is a
correctness requirement rather than a timing one.** The verdict goes back to
the peer that asked, so an early return leaks nothing the answer does not. It
is scanned through because a rule matching this verb for a group the peer
cannot be *shown* to hold makes the answer UNKNOWN -- and that rule may sit
after one that matched nothing. Returning on the first hit turns "could not
tell" into "no" for a table in the wrong order, which is a definite wrong
answer from the ordering of a consumer's list. The test builds that table
deliberately and a sabotage confirms it.

**Order independence is fuzzed rather than exemplified**
(`local/test/vocabulary_fuzz.c`). The hand-written test checks it with one
table, built to expose the early-return bug -- which is one permutation of one
table against one peer, and the property is about all of them. A consumer
orders its table however reads well, so the order is not something this library
influences and not something a chosen case covers.

The harness draws a random peer, table and verb, and asserts three things: an
independent **model** of the same question, written out here rather than asked
of the module, since a checker that asked `vocabulary.c` whether it was right
would agree with it always; **the same verdict over a shuffled table**; and
separately, that `MEMBER` never comes back for a peer whose groups could not be
read. That last is asserted on its own because the three verdicts are not
equally serious -- `UNKNOWN` and `NOT_MEMBER` both deny, so confusing them is a
quality-of-message problem, while admitting on an unreadable group list is the
failure raidcfgd's requirement is about.

Reinstating the early return fails it on **case 1**, through the model rather
than through a case anybody chose.

**A verb longer than `FZN_VERB_MAX` is refused rather than truncated.**
raidcfgd adopts netcfgd's newline-delimited JSON and records that its
mitigations -- "a hard bound on framing, and both parsers fuzzed" -- are the
other half of that choice rather than optional extras of it. Truncating would
let `statusXXXX` match a rule for `status`, which is the whole failure the
bound exists to prevent; the sabotage that removes the length comparison is
caught by three assertions.

### 4.7a The order a sender builds a frame in

**§4.7 states what a receiver must do and nothing stated what a sender must,
which is the more dangerous half.** A receiver that runs the checks out of
order spends work it did not need to; a sender that does gets it wrong in ways
the far end cannot see.

The order is **in `fzn_seal_build` rather than in this list**, and that is the
point: a consumer who does not write the order cannot write it wrong. What the
list is for is saying why each step is where it is.

1. **A fresh nonce, before the frame is begun.** Drawn from the entropy seam
   (`session/random.h`), and a source that cannot answer means no frame at
   all -- the caller's buffer is left untouched, so there is no half-built
   frame for anybody to send by mistake.

   **Per FRAME, not per message**, and this is the trap a caller is likeliest
   to walk into, because "one message, one nonce" reads as tidy. Two chunks of
   one message under one nonce is the same key-and-nonce reuse as two
   unrelated frames, and §4.5 records what that costs: not a weaker seal, no
   seal, plus the Poly1305 key. It is also the one sender mistake a receiver
   cannot catch -- the replay window sees a repeated frame, not a repeated
   nonce on two different ones.

2. **Every authenticated byte final before the tag.** The header is the AEAD's
   associated data, so a field written after sealing is a field the tag does
   not cover. `length` is worse than the rest: the sealed region's extent is
   computed from it, so writing it late moves the span the tag was taken over.

3. **The capability and the payload into the seal**, as plaintext, encrypted
   in place by the same call. The gate is opened with a verdict of *verified*
   to write them, which is not the abuse it looks like: the gate exists to
   stop a **receiver** addressing plaintext it has not authenticated, and a
   sender is the author of those bytes rather than a reader of somebody
   else's.

4. **Seal, and finalize.** situ tracks a dirty bit for exactly this: the
   coverage-aware setters mark the tag stale as the header is written, and
   `fzn_seal_close` clears it. The build asserts the bit is **set** before
   sealing, which is what makes the choice of setter visible -- the plain
   `situ_fzn_head_*_set` family writes the same bytes and leaves the layout
   believing the tag still covers them.

**Two mistakes on the way in, both worth keeping.**

The setters take the **frame** view, not the head view, and nothing in the
names says so: `situ_fzn_frame_head_kind_set` reads as "the head's kind" and
writes `view.base[5]`, an offset from the frame. Handed a head view they
compile, run, and put every field five bytes late. Both are `situ_view_t`, so
this is a type-correct wrong argument -- **the second time that exact
confusion has cost time here**, the first being recorded in
`wire/test/generated_test.c`.

And a `situ_fzn_frame_validate` call sat before the seal with a comment about
not spending a tag on a bad shape. `fzn_seal_close` validates through the same
helper before it seals, so the tag was never spent either way. Sabotaging it
and watching all 54 assertions still pass is what found it: **the second piece
of redundant defence this file has grown and had removed**, and duplicated
checks cost a reader the time to work out which one is load-bearing.

### 4.7 The order a receiver runs these checks in

**Unstated until 2026-08-14, and it should not have been.** §9 puts
encoding, framing, authentication and encryption with this library, and the
*order* of authentication checks is squarely that. Every module states its
own rules; none stated the sequence, so a consumer had to derive it from
five headers and would have been inventing a security property.

**THE RULE THAT GENERATES THE ORDER**, which matters more than the list
because the list is derivable from it and was twice derived wrongly without
it:

> A check may run before tag verification **if and only if it is a pure
> predicate** -- it reads, it decides, it drops, and it changes nothing the
> next datagram can observe. And **no attacker-controllable work may be
> superlinear in receiver state** before authentication.

The first clause is sound because of an asymmetry: for a predicate over
tag-covered fields, a PASS before the tag is retroactively confirmed by the
tag, and a FAIL is at worst a wrongly-dropped frame -- a power anyone able to
flip that bit already had. So pre-tag predicates are free and buy latency;
pre-tag mutations buy the same latency and hand a stranger a write into
receiver state. The second clause exists because the first permits leaving an
O(used) scan on the unauthenticated path, which is where the cost turned out
to be.

**A COROLLARY THAT IS NOT OPTIONAL: a verdict produced before the tag is a
verdict the attacker chose.** `commitment`, `expires_at` and `kind` are all
plaintext and flippable in flight, so a pre-tag verdict may be counted in
aggregate and must never name a peer, trigger a rekey, or appear in a
diagnostic sentence about an identity.

The order, and each step's reason for its position:

0. **Peer credentials** (`local/peer.h`) -- **a different channel, and
   usually a different process.** Not step 1 of this sequence: §3 has the
   privileged daemon never linking fuzznet, and §2 gives the local hop's
   socket to the consumer, so the process calling `fzn_peer_from_fd` never
   sees a frame and the process running the steps below made that connection
   and never calls `SO_PEERCRED`. Numbering them together invites the reading
   that a frame may arrive authenticated by either, which is a downgrade path
   in a threat model that forbids one. The rule instead: **exactly one
   authenticator per channel**, established before anything else, and a
   channel that has one does not substitute the other. Per CONNECTION, not
   per datagram -- the group list is read from `/proc/<pid>/status` after
   `SO_PEERCRED` returns the pid, so a peer that exits between the two calls
   and has its pid reused hands the daemon another process's groups.
1. **Shape** (`situ_fzn_frame_validate`). Forced: the tag's offset and covered
   span are computed from the layout, and every field read below is a bounds
   question first. It is now the only thing between a stranger and the AEAD,
   which raises its importance without moving it -- a schema change that made
   validation expensive would be a change to the receiver's DoS posture.
2. **Key selection**, `sender` to a candidate key set. Forced: there is no tag
   check without a key. The constraint here is negative and is the one a
   consumer is likeliest to get wrong -- **an unknown sender must produce a
   drop, not an object.** No session record, no pending-peer entry, no
   negative cache. Every one of those is an unauthenticated write, and they
   are the natural thing to write.
3. **Key commitment** (`session/commitment.h`). Pure, and the one
   discretionary pre-tag step. It earns its place twice: it is what makes the
   AEAD key-committing at all (§4.4a: not optional), and `wire/relay.h` names
   it as the addressing mechanism -- with K candidate keys it turns K tag
   verifications into K derivations plus K compares.

   **THAT USED TO SAY "K compares plus one", and it is K HASHES now.** The
   commitment varies per frame (13a), so a receiver derives one per candidate
   rather than looking one up. Measured through `fzn_seal_open` itself:
   rejecting a candidate costs about 600 ns against 2100 ns of AEAD at maximum
   payload and 1200 ns on a small frame -- so 3.6x and 2.1x, real and not the
   order of magnitude "K compares" implied. A receiver with a large K should
   index on `sender`, which is a per-peer constant already in the cleartext
   head and therefore gives back none of the privacy the change bought.
4. **Tag verification and decryption** (`wire/seal.h`). **The pivot.** Nothing
   above this line has changed anything the next datagram can see; nothing
   below it runs on a stranger's say-so. situ's generated gate enforces the
   plaintext half; the rule above is the half situ cannot see, because situ
   guards the FRAME and not the RECEIVER.
5. **Freshness** (`frame/freshness.h`), now below the tag. §4.7 used to put it
   at step 2 "because the alternative is spending a **signature
   verification** on something already dead" -- and a signature verification
   is the chain, at 200-238 microseconds per hop. **That reason argues for
   freshness-before-CHAIN and the text placed it before the TAG, which the
   reason never asked for.** Below the tag, the stated reason is satisfied
   exactly, and the verdict becomes authentic enough to name a peer.
6. **Replay** (`frame/freshness.h`, same call). The first mutation, and it
   must not precede the pivot -- see §4.7b.
7. **Capability chain** (`chain/chain.h`), after replay rather than before,
   which is where "predicates before mutations" yields to measurement.
   Chain-first would refuse a revoked peer before it touches the window, but
   pays a signature verification on every duplicate and retransmission on a
   lossy link, where the window catches them for 77 ns. A revoked peer filling
   the window costs at most `capacity` entries for at most the horizon; a
   revoked peer forcing 1.6 ms of Ed25519 per datagram is a total denial of
   service at any line rate.
8. **Reassembly** (`chunk/reassembly.h`), last. The largest and longest-lived
   mutation in the path, and every step above it exists so the memory bound
   protects a table no stranger can reach.

### 4.7b Why replay moved below the tag, and how the old order survived review

**The old order wrote the replay window at step 3 and verified the tag at
step 5**, so any stranger who could send datagrams wrote into receiver state.
With no bound on `expires_at` (§4.7c) that is a permanent, total denial of
service for `capacity` datagrams, off-path, with no key.

The cost argument that placed it there **inverts under measurement**.
`fzn_replay_admit` is O(used) twice per datagram -- an expiry sweep and a
linear scan:

    window used    ns per unauthenticated datagram
    256            571
    1024           2251
    4096           11284

against 706 ns to reject a forgery at the tag on a minimum frame and 1627 ns
on a full one. At any window a real deployment would size, the
pre-authentication scan already costs **more** than the verify it was meant
to save -- 6.9x at 4096. And the saving it does claim holds only against a
blind attacker, because `commitment` is a CLEARTEXT field: anyone who has
seen one genuine frame copies it and is past that gate for free.

**The premise survived every attempt to break it.** "A replay is authentic by
construction, so it passes the tag anyway" was attacked on four cases -- a
different receiver, after key rotation, a chunk of a multi-chunk message, and
under a group key -- and holds in all four. Rotation argues FOR the change: an
old frame under a new key is refused at the commitment, but under the old
order it took a window slot on the way.

**`fzn_replay_admit` therefore stays ONE call.** The pressure to split it into
a const check and a separate record existed only to straddle the pivot; with
freshness and replay both below the tag and adjacent, there is no pivot to
straddle, and the combined call keeps its "a rejected frame never occupies a
slot" invariant inside the library rather than re-established by convention at
three call sites. The ordering fix **simplifies** the API, which is the
opposite of what was expected when the change was proposed.

**Three reasons this got past the tree's defences**, each a shape worth
keeping:

- **The invariant was stated about the wrong object.** §4.7 said "Nothing
  above this line has touched the sealed region" -- true, and not the
  assertion needed. It never said *nothing above this line has touched the
  receiver*. situ's gate enforces the first and cannot see the second.
- **The supporting invariant is directional and the bug ran the other way.**
  "A refusal at any step must not have cost a slot at a later one" -- the tag
  was step 5 and the window step 3, so a refusal at 5 costing a slot at 3 is
  not what that sentence forbids.
- **`frame/test/receive_fuzz.c` structurally cannot see it.** Its own header
  says steps 4 and 5 are skipped, so every frame it processes is treated as
  authentic and "state mutated before authentication" is invisible to it by
  construction. It asserts "a frame refused at any step costs nothing at a
  later one" over a step set that **omits the pivot the ordering is about**.

**And the tree already contained the refutation.** `sim/test/network_test.c`
opens the seal first and its scenario 8c derives the property in the right
words -- "if a frame that FAILED its tag were recorded too, anybody who can
put bytes on the wire could burn a victim's nonces without holding any key at
all". It then cites §4.7 for an order §4.7 did not state. **`sim/` was right
and this document was wrong**; the correction is here, and to `receive_fuzz`'s
framing, not to `sim/`'s code.

**The last place the old order survived was a sizing rule** (2026-08-28).
`frame/freshness.h` defined `peak arrival rate` -- the term a consumer
multiplies by `max_ahead` to get `capacity` -- as counting "a stranger's
traffic as well as a peer's, because freshness runs BEFORE signature
verification (sec 4.7) and an unauthenticated frame therefore takes a slot".
The citation named the section that had reversed it, and the sentence
repeated the conflation §4.7 step 5 exists to correct: freshness before the
CHAIN is what saves a signature verification, and that argument never asked
for freshness before the TAG. `sim/test/network_test.c` scenario 8c already
ran the refutation -- a tampered frame refused on its tag, zero replay
refusals, and the genuine frame carrying the same nonce delivered.

**A citation supporting the opposite of what it is cited for is how a stale
rule survives review.** The reference is what a reader checks a sentence
against, so a wrong one does not merely fail to help: following it here led
to the paragraph that contradicts the sentence, and the sentence stood for
ten days anyway.

**The term is narrower now, and the header states which order it assumes**,
because the correction makes a consumer's number SMALLER and a number a
buffer is sized from must not shrink silently. Under §4.7's order it counts
what holders of a key this receiver accepts can offer at their combined peak
-- every session peer, every other holder of an accepted group key, and a
peer whose capability has been revoked, since the chain is step 7 and runs
below the window. A consumer who runs freshness above the tag keeps the old
term, the link's full offered rate, and §4.7c is explicit that the order is
not forced on one. The header says both, and says that sizing is the smaller
half of that choice: §4.7b's measured denial of service is not closed by any
capacity, because the rate filling the window is the attacker's.

### 4.7c The replay window is the most expensive step, not the cheapest

Measured against the sizing rule §4.3 states -- the window holds what can
arrive within the longest expiry it will accept -- the step placed first
because it was cheapest is, at any capacity that rule demands, the most
expensive thing the receiver does: 597 us at 60000 entries, against 2 us to
reject a forgery and 201-238 us for one Ed25519 verification. It is
memory-bandwidth-bound, 60000 x 32 bytes swept twice, well past L2.

**The window needs an index, not a reorder.** The nonce's first 8 bytes are
uniformly random, so a prefix is a sound hash; an open-addressed table with
lazy expiry on probe plus an amortised sweep is O(1) and keeps what
`freshness.h` prizes -- a window stays a value, constructible directly by a
test and `memcmp`-comparable, because a deterministic probe sequence over
deterministic input gives a deterministic array.

The chain is 100-1000x everything else in the path, so **memoizing a verdict
on `(sender, capability)`, invalidated by a generation counter on the
revocation store**, is the one real latency win available: a naive loop
verifies the same chain 256 times for one chunked message, which is 51-487 ms
of signature checking. That memo is itself an instance of the rule -- a
verdict cached AFTER the tag and keyed by an authenticated identity is safe;
the same cache before the tag is the same bug in a new place.

**The order is executed now, not only written down** (`frame/test/
receive_fuzz.c`, 2026-08-18). This section said a consumer deriving the
sequence from five headers "would be inventing a security property", and until
this harness existed the sequence itself was the thing nobody could run. It
drives the five steps that take decoded fields -- 4 and 5 need the wire and are
covered by `wire/test/seal_test.c` -- and asserts what no single-module
harness can see:

- **a refusal at any step costs nothing at a later one**: no slot taken, no
  partial message advanced, no signature verified after a refusal;
- **a replayed nonce never reaches reassembly twice**;
- **an unauthorised capability never advances a message**;
- **signature verification is never spent on a stale frame**, which is the
  entire reason freshness precedes the chain.

It is a **persistent receiver**, and that took three corrections to get right,
each of which is the same mistake in a different module. A fresh window per
case made the replay counter unable to move; a clock that stood still filled
the window permanently, at three admitted in twenty thousand; and partial
messages with no deadline filled the slot table the same way, at four. Each
time the harness was measuring exhaustion rather than order, and each time the
counters said so — which is what the floors are for. A nonce space of sixteen
values rather than 256 is the last of it: with a full byte a nonce almost never
recurs while its window entry is live, so the replay branch was claimed and
never reached.

Confirmed to bite, and against the modules rather than against itself: making
the replay window accept a repeat, and making chain verification buy one extra
signature check, are each caught on case 5. **What it does not do is force a
consumer to follow the order** -- it establishes that the order, followed, has
the properties claimed for it, and that a change to any module beneath it has
not quietly broken one.

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

### Superseded 2026-08-26: the copyright holder has decided to absorb

**The admission test below is answered, and the answer is yes.** The holder's
instruction, recorded as given: fuzznet is to absorb much of what fuzzypickles
carries -- the whole log subsystem, relaying, adding hosts, creating rules and
permissions, the config database, chunked transfer for file transfer, and
streaming media -- generalised for use by other projects. What network code
remains in fuzzypickles is open, and expected to be little.

**The fact that settles it is the one the test was asking for.** fuzzypickles,
netcfgd and raidcfgd will use this library **in almost exactly the same way**,
differing only in *how keys are exchanged* and in *which features they need*.
That is three consumers with one usage, not one consumer with a preference --
and the reasoning below, which turned on there being no second consumer, is
superseded rather than wrong. It was measured against what existed at the
time.

**Two consequences for the shape of the work**, both already the shape of the
library:

- **Key exchange comes IN, as several, not out as a seam.** Corrected the
  same day, by the holder: key exchange belongs in this library too -- the
  point is that different projects may use *different ones*, not that each
  writes its own. So §4.5's prekey half stops being "unsettled and the
  caller's" and becomes a set of exchanges fuzznet provides and a consumer
  chooses between. The existing vtables stay, because a chosen exchange still
  has to plug into a codec and an entropy source, but they are no longer where
  the difference between the three consumers lives.
- **Features are selected, not bundled.** "Which features they need" differs
  per consumer, so each absorbed subsystem is its own module with its own
  header, in the way `chain/`, `chunk/` and `frame/` already are. A consumer
  that wants relaying and not media links one and not the other. The same
  applies to the exchanges: one of them, not all of them.

### A user has many hosts, and that is fundamental (2026-08-26)

**The holder's instruction, and it reaches further into the design than
anything else recorded here.** The identity model is to be *user with multiple
hosts*, on the grounds that it is what most software wants from crypto anyway.

**Today's model has no such thing.** `sender[32]` in the head is a host, a
capability is granted to a public key, and `fzn_chain_verify` answers "may
this key act". Nothing says two keys are the same person, so every capability
must be granted to each host separately, revocation is per host, and a user
adding a laptop needs the root to mint again.

**fuzzypickles already has the concept and calls it by name**, which is
evidence this generalises rather than being invented here:
`sender_host_pubkey` in its peer frame is a *host* key, and `log_relay`
replicates a host's log to "that user's siblings" -- the other hosts of the
same user. So the absorbed subsystems arrive expecting it.

**What it changes is not settled and is not this entry's to settle.** The open
questions, written down so the design pass starts from them rather than
rediscovering them:

- Is a user a key that signs for its hosts, making host membership a chain
  hop like any other -- or a distinct kind of record?
- Is a capability granted to a user and exercised by a host, and if so does a
  frame carry both identities or is the host resolved to its user on receipt?
- Does revoking a host revoke the user, and can a user revoke its own host
  without the root? `chain/revocation.h` deliberately allows only the root
  today and records why.
- What does `sender[32]` become on the wire, given that widening the head
  costs bytes measured against an IPv6 minimum-MTU budget with 64 to spare
  (§13)?

None of these is answerable by reading the code, so they go to the holder as
a design pass rather than being guessed at while implementing something
else.

**And the consequence the holder drew from it: with a shared identity model,
the config and permission system can be LOCKED IN for every consumer of
fuzznet** rather than each project defining its own. That follows -- a
permission is a statement about who may do what, and "who" was the part that
had no shared answer until now.

**It supersedes two decisions recorded above, and they should be read as
overridden rather than as still standing:**

- **§5's "command vocabularies stay out of the core."** `local/vocabulary.c`
  treats a verb as opaque bytes on purpose, and `wire/frame.situ` says of the
  payload that "this library does not know what they mean and must not learn".
  A locked-in permission system is fuzznet knowing.
- **§4.2's "a capability is 32 opaque bytes, never a typed enum."** That was
  argued from netcfgd's three capabilities being independent rather than a
  ladder. A shared permission system is exactly the thing that would give
  those bytes an agreed meaning.

### Answered 2026-08-26: user signs for hosts, and it is not broken

**The holder's model:** a user is a key that configures hosts and signs; a
host is also a key that signs for itself; every permission is a
(user, host, capability) triple. Checked rather than agreed with, because the
instruction asked whether it is broken.

**It is not, and the reason is stronger than "it works": this library already
computes that triple.** `fzn_chain_verify` fills an `fzn_chain_t` with
`root`, `grantee` and `capability`. Under this model the root **is** the user
and the grantee **is** the host, so a verified chain is exactly a permission
and the triple needs no new structure at all. The pieces line up one for one:

| the model | what fuzznet already has |
|---|---|
| user key, signs for its hosts | the pinned root, §4.2 |
| host key, signs for itself | a hop's `grantee`, and `sender[32]` on the wire |
| permission (user, host, capability) | `fzn_chain_t{root, grantee, capability}` |
| a host may confer only what it holds | `delegable`, and `fzn_chain_delegate` narrowing expiry |

**Confirmed against fuzzypickles rather than assumed from the phrase "just
like fuzzypickles".** `identity_internal.h` has `user_pubkey`,
`host_pubkey`, a `host_record` binding one to the other, and a
`trusted_user_pubkey` a joining host adopts. Host management is itself a
capability there -- `cap_host_manage` -- and an approver's grants are
"bounded by what this approver itself holds", which is `delegable` under
another name.

**A host belongs to exactly one user**, on that reading: `trusted_user_pubkey`
is singular, and the record speaks of "this host's own user_pubkey". So the
user is derivable from the host and the triple is explicit rather than
strictly necessary -- which is the safe direction, and it means a frame
carrying only `sender` is never ambiguous. **No wire change is implied**, and
§13's 144 bytes and its 64 bytes of IPv6 headroom stand untouched. Had a host
been able to serve two users, the frame would have had to say which, and that
would have been a format decision with an MTU budget attached.

**The one real friction, and it is where "adding hosts" lands.** fuzzypickles
bootstraps trust by TOFU: a joining host adopts whatever the approval bundle
asserts, because it is establishing its first anchor. **This library
deliberately has no such path** -- `chain.h` says so, §4.2 says so, and the
root is pinned with no nullable-root variant. Absorbing host management means
either fuzznet grows a bootstrap it was designed to refuse, or joining stays
above the library and only the steady state comes in. That is a decision, not
a detail, and it is the holder's.

**One consequence for revocation, which `chain/revocation.h` had already
flagged as an open question.** Today only the root revokes, and the header
records why grantor-revokes-descendant was not built: "it would let a
compromised intermediate revoke its own descendants, which may be wanted or
may be the attack". Under this model the intermediate is *a user, or a host
the user trusted with host management*, and the descendants are that same
user's own hosts. A compromised host revoking its siblings is a denial of
service inside one user's estate rather than an escalation across users --
which is a much smaller risk than the header was weighing, and makes "a user
revokes its own lost laptop without the root" answerable. Still the holder's
call; the risk is now nameable.

### Corrected 2026-08-26: the invariant is smaller than the two entries below

**The holder's correction, and it supersedes both entries that follow.** The
three consumers are equivalent in the only way that matters: they are
**encrypted networks, with encrypted hosts and encrypted users, carrying
permissions that change at runtime**. The joins differ, the typical
configuration differs, the feature selection differs -- and outside that
invariant *very little about the design is predictable*.

**Both entries below tried to predict it anyway.** Whether a host belongs to
one user, whether the actor is the host or the user it acts for, whether a
receiver pins one anchor or several: those are **configuration**, not design,
and settling them in the library would be choosing one consumer's topology and
calling it the model. That is the corner, and it is nearer than
"one user per host" -- the whole *shape* of the permission graph is a thing
projects will disagree about.

**Read positively, this is what the library already gets right.** An identity
is a 32-byte key with no type attached -- there is no `user_t` and no `host_t`,
and there should not be. A capability is 32 opaque bytes (§4.2). A chain is
any depth up to the bound. A root is a parameter, not a constant. None of that
predicts a topology, which is exactly why all three consumers can use it. **The
generality was already correct and the last two entries were arguing to
narrow it.**

**What the invariant DOES predict is the half that is missing: the dynamic
one.** Permissions here are static in the sense that matters -- a chain is
verified when handed one, and nothing in the library moves a grant from where
it was minted to where it will be used:

- `fzn_chain_mint` and `fzn_chain_delegate` produce hops **locally**. There is
  no distribution: no way to publish a grant, request one, or learn that one
  now exists. Every consumer would write that, differently.
- Revocation is a **bounded store that fails OPEN when full**
  (`FZN_ERR_STORE_FULL`, and `revocation.h` says at length that it is "not a
  condition to retry or ignore"). A permission system whose changes arrive at
  runtime will push against that bound as a matter of course rather than as an
  incident.
- Nothing expresses a permission *changing* -- only a grant existing and a
  revocation existing. Grant-then-narrow, or regrant with a shorter expiry, is
  a consumer's problem today.

**So the work the absorption implies is not a permission taxonomy. It is
distribution, revocation at scale, and the config database that holds the
current answer** -- with the shape of the permission graph left to whoever
configures it. That is the direction the entries below should be read against.

### Revised 2026-08-26: one user per host is the wrong invariant to lock

**The holder's worry, and it is justified:** netcfgd may have more than one
admin for a host, so a model in which a host belongs to exactly one user
paints the design into a corner.

**Measured, the corner is not where it looks, because three different
authority questions are being called by one name.** netcfgd already answers
"more than one admin", in its own `project.md`, and not with users at all:

    Principal = Root | Any | User(string) | Group(string)
    control { observe = "any"; wifi = "group:netdev"; admin = "root" }

`wifi = "group:netdev"` is many admins with **no cryptographic identity
whatever** -- a Unix group over a local socket. Separate the three and the
constraint dissolves:

| question | who answers it today |
|---|---|
| Who on THIS machine may command the daemon? | `local/`: uid, gid, `fzn_peer_group_verdict` -- §2 |
| Which REMOTE identity may command this host? | `chain/`: a verified capability chain -- §4.2 |
| Whose estate is this host part of? | the pinned root: the only genuinely singular one |

**Multiple remote admins already work and always did.** A host verifies each
commander's chain independently; nothing in `fzn_chain_verify` constrains how
many distinct identities may hold a capability for one receiver. The
"one user per host" reading came from equating *user* with *pinned root*, and
that equation is the mistake rather than the model.

**So the invariant to avoid locking is the anchor, not the user.** Two things
follow, and they are the recommendation:

- **A host should pin a SET of roots, not one.** `fzn_chain_verify` takes a
  single `root` and a consumer can loop, at one signature verification per
  anchor -- workable for small sets and wrong to bake in as "one". Where an
  organisation is the root and admins are delegatees, one anchor suffices;
  where two co-equal owners share a machine, it does not, and that case
  should not require inventing a fictional common root.
- **Keep ACTOR separate from OWNER.** A permission is better read as
  *(actor, capability, target)* than *(user, host, capability)*: the actor may
  be a remote user, a remote host acting for its user, or a local uid or gid
  with no key at all; the target is normally the receiver itself. The
  (user, host, capability) triple describes fuzzypickles' case, where a host
  acts *for* its user -- and netcfgd's case is the other one, where an admin
  acts *on* a host. Both are wanted, and a model naming only the first is what
  would create the corner.

**What this does not change:** still no wire change. The frame carries
`sender[32]`, the acting host; who that host acts for, and which anchors the
receiver trusts, are both receiver-side questions. §13's 144 bytes stand.

**The open question the holder has not yet answered**, and the one that
decides how much of the wire moves: does a locked-in permission system give
the capability bytes structure, or does it sit *above* them -- a shared
vocabulary and config schema that both resolve to the same opaque 32 bytes
the frame already carries? The second costs no wire change and keeps §13's
144-byte budget; the first is a format decision with an MTU budget attached.
Not guessed at here.

**Sequenced after the integration harness** (§14), at the holder's
instruction. The record below is kept because it is the reasoning the decision
overrode, and because the measurements in it -- what each file actually
couples to -- are the starting inventory for the work.

### The test was applied to a real case and held (2026-08-25)

The copyright holder asked fuzzypickles whether their **log subsystem** and
their **file transfer** should be generalised and moved here. Their answer,
sent to this project rather than left for it to discover, was no on three
measured grounds, and it is recorded because a test nobody has ever run
against a real proposal is one nobody should trust:

- **Content-addressed transfer is already refused above**, by name, in this
  very list. Moving it is the reversal of a recorded decision rather than a
  new proposal, which is a different conversation.
- **There is no second consumer.** Neither netcfgd's nor raidcfgd's
  `project.md` mentions log replication, append-logs, file transfer,
  content-addressing or blobs -- zero hits each. netcfgd logs to syslog.
- **Their log fails §2's shape test.** `append_log.c` carries its own line
  format, `<seq> <escaped text>`, which is an encoding choice -- and
  specifically the one netcfgd would reject, greppable JSON being its stated
  product property.

**What would change the answer is in the entry above this one.** Relays and
store-and-forward are flagged there as the next thing likely to move in. A log
that has to survive a relay hop hours later is a different problem from
syslog, and that is the case where an append log's **sequencing and gap
detection** -- not its line format -- could become something two consumers
need. That is the moment to revisit; it has not arrived.

**Not decided here, and deliberately.** fuzzypickles wrote it up as a signal
in `claude-guidelines`' `project.md` (`4688a51`) so a cross-project pass reads
it rather than either tree deciding it from the inside. The one observation
worth carrying: `flog` is already its own repository and none of the other
thirteen private projects has adopted it, so if the goal is shared logging the
extraction has happened and the gap is adoption -- which is not this library's
to close.

### Signalled from netcfgd, 2026-08-26: the holder's direction, and what a move would cost

**Two of the three grounds above have moved, and the third has not.** Sent
from netcfgd because that is where it was said and where the measurement was
taken. Nothing here decides anything; the entry above is still this library's
position until its holder changes it.

**The direction, stated 2026-08-25.** netcfgd takes fuzznet as it stands, and
"anything it misses will be moved from fuzzypickles". Named as required the
same day: remote logs, chunked file transfers, a remote configuration
database. Asked whether these were netcfgd's vocabulary or generic, the answer
was that they are generic -- content addressing is "a bottom layer for any
file transfer", distributed logs are "useful for any distributed program for
information and troubleshooting" -- and that **the entrypoint for them is
`flog`**.

- **Ground 2, "there is no second consumer", is overtaken.** It was measured
  by grepping netcfgd's `project.md` for file transfer, content-addressing and
  blobs -- zero hits, correctly, on 2026-08-25. netcfgd's `project.md` and
  `doc/remote-access-feasibility.md` now carry the requirement, so the same
  grep answers differently today. That is an instruction arriving, not a
  measurement having been wrong.
- **Ground 1, "already refused above, by name", stands as stated** and is
  exactly what it says: a reversal of a recorded decision rather than a new
  proposal. The holder is the one who can reverse it and appears to be doing
  so, which is a different conversation and still not this entry's to have.
- **Ground 3, the line format, is untouched by anything below.** `append_log.c`
  carrying `<seq> <escaped text>` is a fact about the *log*, and the
  measurement below is about the *blob*. **`flog` may dissolve it rather than
  answer it**: if the entrypoint is flog, a line format is an output's
  business, and flog already has a pluggable output model --
  `flog_output_file` and `flog_output_stdio` are in fuzzypickles' vendored
  copy today. The corollary matters more than the ground: **fuzznet would
  supply transport, not a logging API.** A log API invented here would be a
  third thing for the family to learn, which is the same conclusion the
  paragraph above reaches from adoption rather than from design.

**What a move would cost, measured in fuzzypickles at commit `4e66b5a`.** The
question the three grounds did not ask: they are about whether it *belongs*,
and this is about what it would *take*. So it settles nothing above -- it
removes "it would be a big entangled lift" from the list of reasons, if anyone
was holding one.

| | lines |
|---|---|
| `core/src/blob.c` | 1,772 |
| `core/src/blob_internal.h` | 902 |
| **implementation** | **2,674** |
| `core/tests/blob_test.c` | 2,403 |
| `core/src/file_ref.c` + header, which the test pulls in | 207 |

**Its entire external surface**, by grepping the source for every symbol it
names that the file does not define:

- **Zero uses of `fzp_core_t`.** The type appears once in 2,674 lines, inside
  a comment saying blob keeps "state out of `fzp_core_t`, which deliberately
  holds none". The decoupling is already done and was done on purpose.
- **Two injected vtables**, which are the whole porting seam:
  `fzp_blob_store_ops_t` (`get_chunk`, `put_chunk`, `get_node`, `put_node`,
  `get_have`, `put_have`) and `fzp_storage_ops_t` (`exists`, `load`, `store`).
- **Six byte primitives** from `wire.h`: `fzp_reader_init`, `fzp_read_u8`,
  `fzp_writer_init`, `fzp_write_u8`, `fzp_write_u64be`, `fzp_write_bytes`.
- **One symbol from the command vocabulary**, `FZP_CMD_BLOB`, and seven error
  codes.
- **Monocypher**, which this library already uses. No compression: `miniz` is
  in that tree and blob does not touch it.

**The tests are the part that does not port as-is**, and they are the real
work rather than the 2,674 lines under them. `blob_test.c` names the app 35
times -- `fzp_core_create`, `fzp_core_set_blob_store`,
`fzp_core_handle_blob_frame`, `fzp_core_blob_serve_proof` -- all of it
harness rather than subject: build a core, install a store, feed frames.

**And `group_asset.c` is the part that would stay**: 172 lines plus a 113-line
header and a 441-line test, which is fuzzypickles' own layer on top. That the
split falls there is itself evidence for the vocabulary-versus-infrastructure
line §5 draws.

### The log subsystem, measured the same way (2026-08-26)

Also from netcfgd, at the holder's request, and it says something the blob
measurement did not: **"their log subsystem" is not one object.** It is five
modules whose coupling differs by an order of magnitude, and the refusal above
treats them as a unit because the question arrived as a unit.

Measured in fuzzypickles at `4e66b5a`.

| module | implementation | test | app references in its test |
|---|---|---|---|
| `diag` | 151 | 110 | 0 |
| `append_log` | 678 | 774 | 0 |
| `log_show` | 201 | 227 | 0 |
| `log_relay` | 501 | 421 | 0 |
| `daemon/log_retention` | 165 | -- | -- |
| **total** | **1,696** | **1,532** | |

**Every one of the four implementations uses `fzp_core_t` zero times**, the
same deliberate decoupling the blob has. What separates them is what they take
from `core.h` and `control.h` instead:

- **`diag` (151 lines) includes nothing but its own header.** libc and
  `diag_internal.h`, and that is the whole list. It is a severity/subsystem/
  detail accumulator, and it is the piece that pairs with flog -- fuzzypickles
  maps it across with a `severity_to_flog()`.
- **`append_log` (678 lines) names no command tag at all.** Its surface is two
  vtables (`fzp_log_ops_t`, `fzp_storage_ops_t`), `fzp_escape_text`,
  `fzp_stream_type_t` with two stream-type constants, two error codes, and one
  size constant: `#define FZP_APPEND_LOG_TEXT_MAX FZP_PEER_TEXT_MAX`. Its
  header says it was *generalised out of* `log_relay` -- "written as a copy of
  log_relay's cache. Both now use this" -- so the extraction this list is
  arguing about has already happened once, inside that tree.
- **`log_show` (201 lines) is a command handler and nothing else**:
  `FZP_CMD_LOG`, `fzp_log_entry_t`, `fzp_log_show_resp_t`,
  `FZP_LOG_SHOW_PAGE_MAX`. Paginated query. Vocabulary by §5's definition,
  and it should stay where it is.
- **`log_relay` (501 lines) is the mixed one**, and it is the one that
  actually distributes: two command tags (`FZP_CMD_LOG_RELAY`,
  `FZP_CMD_MANIFEST`), two core API calls (`fzp_core_log_relay_query`,
  `fzp_core_manifest_set`), its own response types, a subcommand constant,
  `FZP_WIRE_FRAME_MODE_PLAINTEXT`, and `prekey_channel_internal.h`.

**`fzp_log_ops_t` is three operations** -- `append`, `read_recent`, `replace`
-- over named, typed streams, with `replace` documented as required to be
atomic because "a repair that can destroy what it was fixing is worse than the
hole".

**Ground 3 is confirmed and bounded.** `append_log.c:9` carries the comment
`/* ---- line format: "<seq> <escaped text>" ---- */` literally, and
`format_line` is `snprintf("%llu ", seq)` followed by `fzp_escape_text`. So
the encoding choice is real, and it is one function and its parse partner in a
475-line file rather than a pervasive design. **That does not make it cheap**:
it is the on-disk format of an append log, so changing it is a compatibility
question rather than a refactor.

**And an asymmetry with the blob worth putting beside it**, since the two
measurements were taken the same way a day apart:

| | implementation ports | tests port |
|---|---|---|
| `blob` | cleanly -- two vtables, six byte primitives, one command tag | **no** -- 2,403 lines naming the app 35 times |
| the log | `diag` and `append_log` cleanly; `log_relay` not | **yes** -- all four tests name the app zero times |

So the piece with the harder implementation has the harder tests too, and the
log's generic half arrives with its tests already free of the application.
**829 lines** -- `diag` plus `append_log` -- carry no command vocabulary
between them and are covered by 884 lines of test that would compile against
anything providing the two vtables.

**None of this decides the entry above.** Ground 1 stands, ground 2 is the
holder's to move, and ground 3 is confirmed rather than answered. What the
numbers add is that a refusal or an acceptance can be *per module*: the
strongest case for moving is `append_log` and `diag`, the strongest case for
leaving is `log_show`, and `log_relay` is the one where the argument actually
lives.

### Suggested from netcfgd, 2026-08-26: move `append_log` and `diag`, and nothing else

**Widened later the same day to include `log_relay` -- see the entry below
the correction.** The heading's "and nothing else" is what this entry
argued from the measurement available when it was written, and the
measurement changed. Left standing because the reasoning about `log_show`
and the three loose ends is still what the wider suggestion rests on.

**A suggestion, not a decision, and deliberately narrower than the question
that was refused above.** That question was "should their log subsystem move",
and the answer to it can stay no while this one is yes, because the
measurement showed the subsystem is five modules and only two of them are the
thing §5 would call infrastructure.

**What is suggested: `append_log` (678 lines) and `diag` (151).** 829 lines of
implementation, 884 lines of test, and no command tag between them.

**What is not, and why each stays:**

- **`log_show`** is a command handler -- `FZP_CMD_LOG`, its own response type,
  a page size. Vocabulary by §5's own definition, and moving it would be the
  exact failure §5 exists to prevent.
- **`log_relay`** is where the argument lives and should be had separately. It
  is the piece that actually distributes, and it is also the piece carrying two
  command tags, two core API calls and a frame mode. It is not obvious that its
  *mechanism* -- sequencing, gap detection, an origin cache -- is separable
  from its vocabulary without doing the work, and no measurement here says it
  is.
- **`daemon/log_retention`** is policy about how much to keep, which is a
  deployment question and belongs to whoever deploys.

**Why these two and not a bigger or smaller cut:**

- **`diag` has no dependencies at all.** libc and its own header. The flog
  worry that this would import a logging library into the core is answered by
  its own comments: "flog is daemon-only", the bridge `severity_to_flog()`
  lives in `daemon/ipc_server.c`, and the header says of the module itself
  that "it has zero knowledge that flog exists". Moving it brings nothing with
  it.
- **`append_log` already survived this extraction once.** Its header records
  that it was generalised out of `log_relay` when the second consumer inside
  that tree needed the same structure -- "written as a copy of log_relay's
  cache. Both now use this." A module that has already been pulled out of one
  caller to serve two is the one most likely to survive being pulled out for a
  third.
- **The tests come with it.** 884 lines naming the application zero times.
  Contrast the blob, whose 2,403 lines of test name it 35 times: there the
  tests are the work, here they are not.

**Three loose ends, named because a suggestion that hides them is a proposal
rather than a measurement:**

1. **`fzp_escape_text`, `fzp_unescape_text` and `fzp_core_hex_encode`** come
   from `common_internal` (199 lines total). `append_log` uses exactly those
   three; `diag` uses none of it. So either three functions move or the whole
   small file does, and that is a judgement for whoever does it rather than a
   blocker.
2. **`#define FZP_APPEND_LOG_TEXT_MAX FZP_PEER_TEXT_MAX`** is a consumer's
   size wired into the module. It has to become a parameter, which is a
   one-line change and a decision about who chooses the bound.
3. **The line format is the on-disk format**, per ground 3 and the measurement
   above. It is `format_line` and its parse partner, but it is what an existing
   append log on an existing machine already contains, so changing it during a
   move is a migration and not a refactor. **Moving it unchanged is the
   cheaper option and keeps the ground-3 objection alive** -- that is a real
   trade and this suggestion does not pretend otherwise.

**And the test §5 actually sets.** Two real consumers, neither accepting the
other's version as a special case. netcfgd is directed to want distributed
logs; fuzzypickles has these two modules in production. What the suggestion
rests on is that `append_log` is already serving two callers *inside*
fuzzypickles, which is the closest thing to evidence available before a second
project has built anything -- and it is weaker than two independent consumers,
which is worth saying rather than glossing.

### Corrected, 2026-08-26: `log_relay` is separable, and two claims above were wrong

**The suggestion above rests on two statements that do not survive being
measured properly**, and both were wrong the same way: they counted mentions
in *comments* as code-level coupling. Re-run with comments stripped
(`gcc -fpreprocessed -dD -E -P`), against fuzzypickles `4e66b5a`.

**Wrong: "`log_relay` ... carrying two command tags, two core API calls and a
frame mode."** Its entire code-level vocabulary dependency is **one symbol,
one occurrence**: `FZP_CMD_LOG_RELAY` at `log_relay.c:101`, inside the frame
encoder. `FZP_CMD_MANIFEST`, `fzp_core_log_relay_query`,
`fzp_core_manifest_set` and `FZP_WIRE_FRAME_MODE_PLAINTEXT` appear only in
doc comments in `log_relay_internal.h` -- lines 29, 41, 61 and 62, every one
of them prose describing neighbouring machinery. `log_relay_internal.h` has
no code-level reference to any of them.

**Wrong: "`log_show` is a command handler and nothing else."** It is 124
lines, and the handler is the last 30. Lines 13-94 are the append log's
sequence and line-format machinery -- `decode_seq_blob`, `encode_seq_blob`,
`fzp_log_retention_next_seq`, `fzp_log_retention_format_line`,
`fzp_log_retention_parse_line` -- with zero command vocabulary between them.
The file is named for the smaller half of what it holds, and the `retention`
prefix on those five is misleading in the other direction: they are declared
in `log_show_internal.h` and implemented in `log_show.c`, not in
`daemon/log_retention.c`.

**So the separability question has an answer, and it is yes.** `log_relay.c`
splits at line 145 with nothing crossing:

| half | lines | code-level vocabulary |
|---|---|---|
| codec -- frame encode/decode, payload pack/parse | 145 | `FZP_CMD_LOG_RELAY`, once |
| mechanism -- cache naming, ingest, show, high water, answering a query | 167 | **none** |

**All four public mechanism functions take `const fzp_log_ops_t *` and nothing
else** -- `fzp_log_relay_show`, `_cache_high_water`, `_ingest`,
`_answer_query`. The sequencing and gap detection this list said "it is not
obvious are separable" are in that half, and they are separable: what they
talk to is the log vtable, `append_log`'s API, and the line helpers above.

**What a move would actually need**, which is smaller than the earlier entry
implied and not nothing:

1. **One command tag parameterised.** `encode_frame` writes
   `FZP_CMD_LOG_RELAY` into the frame; a caller-supplied command id is a
   one-line change and a decision about who owns the number.
2. **`log_show.c` split 82/30.** The line and sequence helpers go with the
   mechanism; the `fzp_log_show` handler stays. That is a real edit to
   fuzzypickles rather than a lift, and it is the piece of work this
   correction adds.
3. **`append_log` first.** The mechanism half calls six of its functions, so
   the order is forced: `append_log` and `diag` move, then this.

**The earlier entry's conclusion still stands, with a different reason.** It
said `log_relay` is "where the argument lives", and it is -- but the argument
is not entanglement. It is that moving it means splitting a file in the
consumer and choosing an owner for a command number, and §5's admission test
still wants two consumers who need it. **The measurement removes the technical
objection and leaves the scope one**, which is the opposite of what the entry
above assumed.

**Recorded rather than quietly fixed**, because the wrong version was signalled
into this document and acted on by nobody yet: a reader who takes the earlier
entry at face value will believe `log_relay` is entangled and it is not.

### Widened, 2026-08-26: `log_relay` too, in that order

**Supersedes the "and nothing else" above**, on the strength of the correction
between them: the entanglement that entry declined to move was four doc
comments and a misnamed file, not code.

**What is now suggested, and the order is forced rather than preferred:**

| step | what moves | implementation | test |
|---|---|---|---|
| 1 | `diag` | 151 | 110 |
| 1 | `append_log` | 678 | 774 |
| 2 | `log_show`'s sequence and line helpers | 82 of 124 | part of 227 |
| 3 | `log_relay` | 501 | 421 |
| | **total** | **~1,412** | **~1,305** |

**Step 2 exists because of where the helpers live, not because anyone wants
it.** `log_relay`'s mechanism calls `fzp_log_retention_parse_line` and two of
its constants, which are declared in `log_show_internal.h` and implemented in
`log_show.c` -- so a file in the consumer gets split 82/30, the helpers going
with the mechanism and `fzp_log_show` staying. That is the one edit to
fuzzypickles this suggestion requires rather than a lift, and it should be
done there, by them, before anything moves.

**Step 3 is last because the mechanism calls six `append_log` functions.**
Moving `log_relay` first would mean either moving `append_log` with it or
leaving a dependency pointing back into the consumer.

**Still not suggested:**

- **`fzp_log_show`, the 30-line handler** -- `FZP_CMD_LOG`,
  `fzp_log_show_resp_t`, a page size. Vocabulary, and the one part of that file
  that genuinely is.
- **`daemon/log_retention`** (165 lines) -- how much to keep is a deployment
  question.

**The codec half is the one open question this does not answer.**
`log_relay.c`'s first 145 lines build a versioned sub-frame -- header, sub-type
QUERY or LINES, mode -- *inside* a command payload, using eight `wire.h`
primitives. It is a payload codec rather than a transport frame, so it does
not collide with §4.1 or §13 by construction. But whether this library wants a
second framing layer inside its own, or wants the relay's payloads expressed
in whatever situ generates, is a design question the measurement cannot
settle. **Moving it verbatim with the command id parameterised is the cheap
option and may well be the wrong one**, and that is worth deciding rather than
defaulting into.

**What has not changed is the part §5 actually tests.** Two real consumers,
neither accepting the other's as a special case. netcfgd is directed to want
distributed logs and has built none of this; fuzzypickles has all four modules
in production. The evidence remains that `append_log` already serves two
callers inside one tree, which is weaker than the test asks and is still the
strongest thing available. **The measurements have moved the cost, not the
admission question** -- and the cost was never what this list was refusing on.

**One caution the numbers do not carry.** Portable is not the same as
mergeable with §4.4. That chunks a message the sender already holds and pushes
it; blob is hash-named, pull-based and requester-coordinated -- §4.4 says so
itself. Two mechanisms with different control flow can share primitives
without becoming one thing, and which of those is wanted is a design question
these measurements do not answer.

---

## 5b. `record/` -- the substrate for dynamic permissions

**Started 2026-08-26**, at the holder's instruction to build distribution,
reception, finalisation, and the permissions and rules systems, generally.

**The generalisation, and it is the whole design.** A grant, a revocation, a
rule, a configuration setting and a log line are the same object: **somebody
signs a statement, it reaches other hosts, they decide whether it was
authorised, and they end up agreeing about what is currently true.** §5's
invariant says the *shape* of the permission graph is configuration rather
than design, so this module knows what none of those statements mean.
`kind`, `subject` and `body` are opaque here exactly as a capability is 32
opaque bytes in `chain/` and a verb is opaque bytes in `local/`.

**No new encoder and no new wire format.** `signed_region` is taken as opaque
bytes, which is the pattern `chain.h` argues for at length: recomputing them
would put a second encoder in the tree for the schema to disagree with later.
So `record/` needs no schema change, and §13's frame is untouched.

**Three questions kept apart, because every distributed-configuration bug
lives between them:**

| question | answered by |
|---|---|
| Is this what its issuer signed? | `fzn_record_verify` |
| May this issuer say it? | **not here** -- `fzn_chain_verify` against a capability the consumer maps from `kind` |
| Is it current, and have we acted on it? | `record/journal.h` |

Keeping authorisation out is what lets one project authorise by capability
chain, another by local uid, and a third by both -- which §5 measured as the
actual difference between the three consumers.

**Order comes from sequences, never clocks.** Each issuer numbers its own
records from 1. Per issuer rather than globally, because a global sequence
needs consensus and this design has none: two hosts that never speak must
still be able to issue. `issued_at` is carried for display and policy and is
never consulted for ordering.

**A gap is not an error, it is an instruction.** `FZN_JOURNAL_ERR_GAP` means a
record arrived that is real, in order, and too far ahead -- so something in
between exists and has not been seen. That is precisely what a distribution
layer acts on, and `fzn_journal_next` says what to ask for. A journal that
silently accepted the jump would leave a hole nobody could later detect, which
is how a permission that was revoked comes back.

**Reception and finalisation are separate numbers**, `received` and `applied`.
A sibling that has received a rule and not yet applied it is in a different
state from one that has, and only the second is safe to depend on. That is
fuzzypickles' "what a given sibling has confirmed it applied for a given
setting", generalised.

**Two refusals that fail closed on purpose**, both following existing
precedent in this tree rather than inventing a policy:

- **A full journal is refused, not evicted.** Dropping an issuer forgets what
  was seen from it, so its next record is accepted at any sequence -- which
  readmits everything it ever sent. `frame/freshness.h` refuses a full replay
  window for the same reason and says so.
- **An unknown issuer starts at 1, or not at all.** Accepting whatever
  sequence arrives lets a stranger open at a large number and suppress every
  real record below it. Joining a stream already in progress is
  `fzn_journal_anchor`, which is deliberate, and which never moves backwards.

**Tested at 100% of `record.c`'s lines and 96% of its branches, and 99%
and 96% of `journal.c`'s**, 180 checks
across two files. The ordering claim is observed rather than asserted: a stub
signer counts calls, and a record refused for its sequence must not have cost
a signature verification.

### `record/sync.h` -- the distribution decision, and only that

**What is left when transport and topology are removed.** §2 keeps transport
out of this library and §5 keeps the permission graph's shape out. Take both
away and distribution is a **comparison of two sets of positions**: given what
this host holds and what a peer says it holds, which ranges are missing and
which way round. That comparison is identical in all three consumers, which is
the test §5 sets for admitting anything.

So `fzn_sync_plan_fetch` and `fzn_sync_plan_offer` decide, and nothing else.
No sending, no scheduling, no encoding, and no opinion about whether a record
fetched will turn out to be authorised. A consumer brings its own timers, its
own choice of peer and its own framing -- `wire/seal.h` and `chunk/` are
already there for the last.

**Pull first, because it survives loss without acknowledgements**: a host that
missed a record asks again at the next comparison. `fzn_sync_plan_offer` is
the other direction for a host that already knows a peer is behind, and
nothing requires it.

**Three refusals that are the point of the file:**

- **A new issuer is counted, never requested.** If a peer advertises an issuer
  this host has never followed, fetching from it because a peer mentioned it
  is how one compromised peer fills every journal in the network with issuers
  nobody chose. `fzn_journal_anchor` makes adopting an issuer deliberate and
  this does not quietly undo it. Offering, by contrast, *is* allowed: offering
  is not adopting, and the peer still decides.
- **Every range is bounded.** `max_per_request` caps a window, and zero is
  refused rather than meaning unlimited -- the same reasoning
  `fzn_reasm_init` gives for a zero quota. "Send me everything from 1" is a
  request a stranger can make of every host at once; the reply to a bounded
  request is bounded work, and the next comparison asks for the next window.
- **Truncation is counted, not dropped.** A plan that returned a short list
  would look complete, and the ranges left out would never be asked for again.
- **An unmentioned stream is counted, never offered** -- the mirror of the
  first refusal, added 2026-08-27. A zero-length digest used to be read as
  "behind on everything", so replying to one offered the whole history of
  every stream, bounded only by `max_per_request x out_cap`: 32768 records
  from a 64-entry journal, measured. "Reply to a digest with an offer" reads
  as safe and was an amplifier.

**AND THE RECEIVER DECIDES THE ORDER OF ITS OWN PLAN.** `fzn_sync_plan_fetch`
walks THIS HOST'S journal and looks each entry up in the peer's digest, rather
than walking the peer's. It used to walk theirs, so a peer claiming huge
positions filled every request slot with phantom ranges and the host's genuine
fetches were the ones truncated -- every round, with `truncated > 0` the only
symptom. Now `out_cap` of `journal->used` cannot be truncated by anything
arriving from outside, and `positions_ignored` is separate from `truncated` so
a padding peer cannot be mistaken for an undersized buffer. `their_count` is
bounded by `FZN_SYNC_MAX_POSITIONS`: 200000 claimed positions against a
64-entry journal went from 2051 ms and zero requests to 19 ms.

81 checks, and the one that matters most is written as a loop over the whole
plan rather than a single assertion: no request may name an issuer this host
does not follow.

### Reception and finalisation, end to end (scenario 9)

**Records distributed across eight hosts on a network dropping a fifth of
everything**, every issuer numbering from 1, forty rounds of pull. The
property: every host ends up holding every record, in order, having applied
all of it -- and no host ever accepts a sequence it has a hole before.

Result: **8 hosts converged, 100 records dropped, 80 gaps refused, nothing
left pending.** The gap count is a check rather than a statistic: a run in
which nothing ever arrived out of order would not have exercised the path
that exists for it, so the scenario fails if `total_gaps` is zero -- the same
discipline as the fuzz harnesses' acceptance floors.

**This path deliberately does not go through `wire/seal.h`.** A record has no
encoding in this library and is not going to get one, for the reason
`record.h` gives about signed regions; framing is the consumer's. What is
under test is the decision and ordering logic. Scenarios 1 to 8 already carry
bytes over the real frame path.

**And it found a design gap the unit tests could not have found.** The first
run converged on *nothing*: 0 dropped, 0 gaps, 0 hosts complete.
`record/sync.h` refuses to request from an issuer this host does not follow --
deliberately, since fetching because a peer mentioned someone is how one peer
populates every journal in the network -- and `record/journal.h` had **no way
to say "I follow this issuer and have nothing yet"**. `fzn_journal_anchor`
refused sequence zero as malformed, in a file whose own header reserves zero
to mean "no record yet, so an entry can start empty without a separate flag".
The reservation existed and the operation that needed it was refused.

**A unit test could not have reached it.** A test that admits records never
needs to follow an issuer *before* receiving from one; only a network does.
Anchoring at zero now means follow-from-the-beginning, anchoring twice is an
echo rather than a rewind, and the journal's own tests cover it -- but the
harness is what asked the question.

## 5l. `wire/seal.c`'s uncovered branches, accounted for one by one

**76% of branches taken both ways is the lowest in the tree, and the number
was never the question.** An unreachable guard and an untested one look
identical from a percentage, so the useful output is which each of them is.
Every remaining branch was traced; **none is a testing gap.**

| what | why it cannot fire |
|---|---|
| `tag_covered != SITU_OK`, `!tag` (open and close paths) | every path here has passed `situ_fzn_frame_validate`, whose last act is `situ_in_bounds(view, tag_offset, 16u)`. The tag is known to be inside the frame, which is exactly what these test. |
| `covered_len < head_len` | the contract states the covered span as "authenticated head ... sealed ...", so it contains the head by construction. |
| the three views in `fzn_seal_build` | the frame was sized by the line above: `total` is the overhead plus a payload already bounded against the schema's maximum, and `frame_cap` was checked against it. A view over exactly `total` bytes cannot fail for room. |
| branches at the accessor call sites | inlined `situ_*` internals, not this file's logic at all. |

**They stay, and the reason is not superstition.** Each is the boundary
between this file's reasoning and the generated code's, and what they refuse
to assume is that `validate` and `tag_covered` **agree**. That is a claim
about situ rather than about a frame -- and situ has moved eleven times in
this project's life, twice in a week. The day it stops holding, this file
returns `SHAPE` rather than computing an AEAD span from numbers that
disagree.

**So the ceiling is the guards, not the tests**, and that is now written at
each of them so the next person hunting the last few branches does not spend
an afternoon building a fixture that cannot exist. If the percentage is ever
to rise, it rises by someone deciding to trust the generated code more, which
is a decision rather than a test.

## 5k. Normalisation of the central types

**A survey of every public enum, identity-shaped field and length constant,
prompted by the holder asking what `head.kind` is.** Eighteen enums, twenty-one
identity fields, eleven length constants. What follows is what disagrees with
itself; everything not listed was consistent.

### Fixed: three constants that were one thing under two names

Four separate **32-byte** constants exist -- `FZN_PUBKEY_LEN`,
`FZN_SENDER_LEN`, `FZN_CAP_ID_LEN`, `FZN_SUBJECT_LEN` -- and two **24-byte**
ones, `FZN_NONCE_LEN` and `FZN_AEAD_NONCE_LEN`. Some pairs are equal by
coincidence and must not be pinned; two are the same *thing* and nothing said
so:

- **A sender is a host key.** `wire/seal.c` hands `opened.sender` to
  reassembly while a chain names its `grantee`, and a receiver compares them.
  If the widths parted, that comparison reads past one of them.
- **The frame's nonce is both nonces.** `frame.situ` says it: "Replay defence
  and the AEAD nonce in one." A divergence would have `fzn_replay_admit`
  comparing a different number of bytes than the AEAD used.

Both are asserted now. `FZN_CAP_ID_LEN` and `FZN_SUBJECT_LEN` are deliberately
**not** pinned to a key's width: both are opaque by design, both are 32 by
coincidence, and asserting it would make a later change look like a
regression. A third assertion pins the claim `record.h` makes -- that a
subject can hold a public key -- as `>=` rather than `==`, which is what that
claim actually says.

### Not fixed, and each needs a decision rather than an edit

- **Two things are called "frame kind", with overlapping values.**
  `fzn_kind` on the wire is `nop | unit | chunk | ack`; `fzn_frame_kind_t` in
  `frame/freshness.h` is `COMMAND | GRANT`. They are unrelated, both named for
  a frame's kind, and **0 and 1 are valid in both**. `fzn_seal_open` fills
  `opened.kind` from the wire enum; `fzn_replay_admit` takes the freshness
  one. A consumer passing the first to the second gets a silent
  misclassification -- wire `unit` reads as `FZN_FRAME_GRANT`, so a unit
  frame's expiry becomes optional, which inverts sec 4.3. Nothing does it
  today. **Suggested:** rename the freshness enum to what it decides --
  `fzn_expiry_rule_t { FZN_EXPIRY_REQUIRED, FZN_EXPIRY_OPTIONAL }` -- since it
  is a receiver's policy about a frame rather than a property of one, and is
  not on the wire at all. No wire change.
- **`chain/` owned the unprefixed error names.** **Done 2026-08-26**: 158
  occurrences across 14 files, `fzn_err_t` to `fzn_chain_err_t`, `FZN_OK` to
  `FZN_CHAIN_OK`, `FZN_ERR_*` to `FZN_CHAIN_ERR_*`. It was the first module
  and took the general name before there were others to collide with -- so
  the odd one out was the header a consumer is most likely to include first,
  and a library handing out `FZN_OK` from one of sixteen modules claims a name
  it has no particular right to.
- **`fzn_link_t` lived in `sched/` while `link/` defined `fzn_link_entry_t`.**
  **Done 2026-08-26**: `fzn_sched_candidate_t`, 16 occurrences across 7 files.
  What it describes is one candidate as a scheduler sees it -- an id it does
  not interpret and four numbers somebody else measured -- and `link/` owns
  the word.

**Both were recorded as "needs a decision rather than an edit" and deferred
partly on the size of the rename. That was the wrong test**, per the holder:
*"If our protocol improves by writing or refactoring code, we do that. I
wasn't talking about cost of implementation, as that cost will multiply if the
protocol is poorly designed."* Neither touches the wire; both were judged on
whether the API reads correctly, and both did badly.

### Confirmed consistent

`OK` is 0 and `ERR_MALFORMED` is -1 in all eighteen enums; every module has an
`_err_str` renderer and all are in the sweep; every fixed-width identifier
goes through a named constant rather than a literal.

### Decided: a real capability in every datagram (2026-08-26)

**The question**, from fuzzypickles and the last thing gating their frame
work: does every datagram carry a real capability, including ordinary chat,
or do chat frames carry a null with authorisation staying event-driven? The
holder delegated it here, on the grounds that this project knows what the
three consumers are for.

**Decision: a real capability, always.** Not because §13 already said so, but
for a reason §13 does not give.

**THE BYTES ARE SPENT EITHER WAY, so cost decides nothing.** The 32 bytes are
in the schema's sealed region and cannot be omitted without a wire change. A
null capability saves not one byte; it only makes the field meaningless in
some frames. Whatever the answer is, it is not about size.

**THE DECIDING REASON IS REVOCATION LATENCY.** §4.2 says revocation is what
ends authority in this design -- not expiry, not disconnection. A capability
presented *per datagram* means a revoked host's **very next frame** is
refused. A capability established per session means it keeps acting until
something tears the session down, and nothing in this library tears sessions
down because it has no sessions.

That is decisive for two of the three consumers and desirable for the third:

- **netcfgd and raidcfgd are configuration daemons.** Every message changes
  system state. A compromised host that keeps reconfiguring the network for
  the lifetime of a connection after being revoked is the failure the whole
  capability model exists to prevent.
- **fuzzypickles is chat, and it gets the same property for free.** Removing
  a peer stops their next message rather than their next session.

**The objection was that chat has no per-message authority to put there, and
it is not true.** `FZP_CAP_SEND` already exists in `core/src`. The authority
is defined; it simply is not being carried. So the choice is not between a
capability and nothing -- it is between carrying an authority they already
have and carrying a zero.

**WHAT FUZZNET ENFORCES: nothing, and that is deliberate.** `fzn_seal_open`
calls `fzn_chain_verify` zero times. The library carries the 32 bytes and
hands them over; the consumer decides whether to verify, per frame or never.
This decision is therefore **advice with a reason attached** rather than a
mechanism, and a consumer may ignore it. What they should not do is ignore it
by accident.

**So the honest statement of the null case:** a consumer putting zero there
has chosen to have **no revocation granularity on that traffic**. That may be
right for something -- a `nop` keepalive from a host whose authority is
checked elsewhere -- and it should be a sentence somebody wrote, not a field
nobody filled in.

**One thing this does not settle**, and it is smaller: whether a host with no
capability at all may send anything. Scenario 11 shows an unanchored host
refused on authority, which covers the joining case. A host that is anchored
but holds nothing is a state no consumer has yet, and it can wait until one
does.

### Corrected the same day: the decision above is right for one realm

**fuzzypickles checked the objection rather than taking it, and it splits.**
The correction is theirs and it is a good one.

**They were wrong about one thing and right about the larger one.**
`FZP_CAP_SEND = 5` is in `core/src/capability.h` and appears nowhere in their
peer frame path -- defined, not carried, exactly as claimed here. But *whose
chain it hangs from* decides whether a receiver can check it, and their §6
splits the wire into four realms on a 2x2 of same-principal against standing
relationship:

- **User realm** -- daemon to daemon of the *same* user, one root, both ends
  under it. **The decision above lands with full force.** A capability per
  datagram is verifiable, and the revocation-latency argument finds a real
  gap: they do not have next-message granularity for a user's own devices
  today.
- **Registered realm** -- a *different* user's principal, TOFU-pinned through
  `peer-add`. Their `FZP_CAP_SEND` hangs from **their** root. The receiver has
  their identity pinned and not their capability tree, so a capability in
  their frames is **an assertion the receiver cannot check**.

**"A real capability, always" is therefore too broad as written.** Where the
receiver holds no anchor for the sender's chain, "real" is not available --
and writing a zero is not a design choice but a *symptom*.

**And the anchored-and-empty question was answered flatly.** This project
recorded it as a state no consumer has yet. It is **half their traffic**:
every Registered peer is anchored in the TOFU sense and holds no capability in
the receiver's chain. Recorded as a correction because guessing that a state
is rare, from outside the consumer, is exactly the error this exchange has
been catching all week.

**The interim they propose is right for today**: a real `FZP_CAP_SEND` on
User-realm frames, and a deliberate zero on Registered-realm frames with the
reason written down -- that the sender's authority is not in the receiver's
chain.

**THIS SENTENCE USED TO END "and revocation there is enforced by peer
removal instead", WHICH IS WRONG ABOUT THEIR TREE.** Corrected
2026-08-27 by the fuzzypickles session, which went looking for the verb
and found none -- no `peer-remove` in the CLI, no `fzp_peer_forget` or
equivalent in the internal headers. What exists is per-peer opt-in
state. The accurate statement is narrower and lands in the same place:
**the Registered realm has no revocation because it has no grants**, not
because removal substitutes for revocation. A capability is never held
by a contact, so there is nothing for a revocation to withdraw.

It is recorded rather than quietly replaced because it is exactly the
shape `evidence.md` names -- a claim about another tree written from
this side, plausible, uncorrected for weeks, and wrong in a way only
its owner could see.

### The better answer, and the holder's principle points at it

**Anchor the peer's ROOT at `peer-add`, not only their identity.** Then a
capability in a Registered peer's frame is verifiable and the exception
disappears.

The holder's guidance, given while this was being written: *"Anything that
decreases latency of operations is a good thing."* That is decisive here,
because anchoring converts a coarse, slow revocation into a fine, immediate
one:

| | today, identity pinned | with the root anchored |
|---|---|---|
| a peer's device is stolen | remove the whole peer, or nothing | that peer revokes that device; the receiver honours it |
| granularity | the entire relationship | one device |
| who acts | the receiver, manually | the owner, and it propagates |
| latency | until somebody notices and removes | the revocation's next delivery |

**Every mechanism it needs already exists here.** `trust/` anchors a root;
`chain/` verifies a device chain against one; `record/` and `record/sync.h`
distribute the owner's revocations to whoever follows that stream. The pieces
were built for the User realm and turn out to serve this.

**The cost stated here was not one, and fuzzypickles checked it rather than
taking it (2026-08-26).** This entry said anchoring "lets that peer add
devices the receiver will accept without being asked again", offered as a
feature worth its price. **It is already the status quo in their tree.**
Verified from here rather than relayed: `peer_sync_internal.h` carries
`root_pubkey[32]` per peer -- "the peer's user root, all-zero if unproven" --
and `manifest_internal.h` verifies a peer's hosts "against that peer's own
stored root_pubkey", with the comment that a chain rooting in another
identity "is exactly what an attacker supplies, which is why this comparison
must never be skipped".

So a registered peer can already add devices that are accepted without asking,
and a friend replacing a phone does not re-pair today. **The anchor exists and
is already load-bearing; what was proposed is a second USE of it rather than
new trust.** That is why the holder took it without hesitation, and it means
the recommendation was cheaper than either side had said.

**The residue they recorded is the honest remainder:** a peer added from a
bare prekey blob carries an all-zero root and is already excluded from
manifest verification for the same reason. Those frames keep the zero and the
sentence.

**Not decided here.** It changes what `peer-add` *means* in fuzzypickles, from
"pin this contact" to "anchor this contact's root", and that is theirs and the
holder's rather than a side effect of adopting a frame. Recommended, with the
reasoning above, and they will put it up as its own decision.

**The holder's qualification, and the correction to how it was first read.**
*"(within reason) Let's not over-engineer or go overboard with other cost"*
was recorded here as an argument from implementation cost -- that anchoring
was worth doing because it needs no new fuzznet code. **That was the wrong
axis.** The holder's clarification: *"If our protocol improves by writing or
refactoring code, we do that. I wasn't talking about cost of implementation,
as that cost will multiply if the protocol is poorly designed."*

So the standing rule for this project is: **a protocol improvement justifies
the code it takes.** Implementation cost is not the constraint, because a
protocol got wrong multiplies that cost across every consumer and every year
afterwards. "Within reason" bounds the *scope of a mechanism*, not the effort
of building one.

Restated on the right axis: root-anchoring should be adopted because it makes
revocation correct at the granularity the model already implies -- a user
revokes their own device and everyone honouring that user honours it. That it
needs no new machinery here is a pleasant fact about timing, not the
argument.

### Settled: commands pass through fuzznet's decision process

**The holder, 2026-08-26:** *"When it comes to commands, we may need a way to
vendor them, but for now everything passes through fuzznet decision
process."*

**This answers a question that reached this project twice with two different
shapes, and the narrower one is the ruling.** fuzzypickles relayed a holder
instruction as "reserve a few kinds for implementors, and the rest belong to
the consumer" -- a consumer assigning freely in the remainder. The holder had
told this project directly, an hour earlier, that further kinds should be
motivated to fuzznet and analysed case by case. §8.7 was left unchanged
pending the holder rather than resolved toward whichever reading unblocked a
consumer faster, and the ruling above is the narrow one.

**So the practical answer to a consumer is unchanged and worth stating
plainly:** a command vocabulary goes in the **sealed payload**, which this
library never reads. That is where §5 always put it. What is *not* available
is taking a spare `fzn_kind` value on your own authority -- the validator
stays the gatekeeper.

**And the anticipated end state is named rather than guessed:** *"we may need
a way to vendor them."* A mechanism by which a project is allotted space it
may assign within, rather than either a permanent monopoly here or a
free-for-all in the remainder. **Not designed and not built.** Until it is,
the process is the mechanism.

**What the measurement says the reserved set actually costs today.** Prompted
by fuzzypickles' reframing -- *a reserved kind is one fuzznet ACTS ON, a
consumer kind is one it CARRIES* -- every library source was checked for what
reads the wire kind. **Nothing does.** It appears twice in the whole tree,
both in `wire/seal.c`, reading it into `opened.kind` and writing it from
`what->kind`. Reassembly takes `index` and `chunks` as arguments; freshness
takes its rule from the caller. `fzn_kind` is documentation plus a validator
gate and nothing else, so the set of kinds fuzznet must *understand* is
currently **empty** -- which is worth knowing when the vendoring mechanism is
designed, because it means the reserved range can be small.

### The `kind` policy, recorded at the enum

The holder's instruction: **an implementor who needs a further frame kind
motivates it to fuzznet first, and each is analysed case by case.** The
reasoning is now in `frame.situ` above the enum -- a kind is the one field
every host must agree about before it can read anything else, so two networks
that assigned `0x04` differently would each refuse the other's traffic as
malformed and neither would be wrong. It is a conversation rather than a wall:
a keepalive carrying a timestamp, a probe, a stream fragment are all plausible
and none of them is a consumer's command vocabulary, which goes in the sealed
payload.

## 5j. Fidelity is a stream, and that required a change

**The question**, raised by fuzzypickles' reserved COARSE flag: how does the
same statement reach different recipients at different fidelities -- exact
location to one peer, city-level to another?

**Three shapes were possible and two are unavailable here.** Redacting a
signed record in transit breaks the signature unless the body has a selective
disclosure structure, which means this library would have to understand body
structure -- and bodies are opaque by design. Layering encrypted detail inside
one record means defining a body format, which is an encoding sec 2 keeps out.
That leaves the third: **fidelity is a separate stream, and entitlement is an
ordinary capability** answered by `chain/`. An issuer signs a coarse record and
a precise one; a recipient follows what it may.

**That shape needed one thing this library did not have, and the gap was
measured rather than assumed.** With a sequence per ISSUER, a recipient not
entitled to some records develops holes it may never fill. Demonstrated before
anything was built: admit sequence 1, then sequence 3, and the journal answers
*"ahead of what is held"* and wants 2 -- **for ever, for a record nobody will
ever send it.** Refusing the gap is correct; one sequence space per issuer is
what is wrong.

**So a position is per (issuer, stream)**, and `stream` is a new field on
`fzn_record_t` carried through the journal, `sync` and `log`. Each stream
numbers from 1 independently, so every recipient's view is contiguous *for
it*.

**`stream` is deliberately not `kind`,** though they will often hold the same
value. Permissions need cross-kind ordering -- a grant and a revocation are
different kinds and must be totally ordered against each other -- so a
consumer puts them in one stream and its telemetry in another. Collapsing the
two would make that unsayable, and it is the kind of thing that is only
noticed once something depends on it.

**What this does not do.** It does not degrade anything: producing a coarse
record from a precise one is the consumer's arithmetic, as packing a fix is.
And it does not decide who may follow which stream -- that is a capability,
and `chain/` already answers it. What the library owes was a sequence space
that partial entitlement can live in, and now there is one.

The journal's test carries the case directly: two streams from one issuer
advance independently, and each keeps its own gap.

### Fidelity across the network (scenario 12)

    fidelity: 5 of 5 complete on coarse, 2 on fine, 0 leaked, 5 dropped

**The case that could not have existed a commit earlier.** One issuer
publishes a precise track and a coarse one. Hosts 1 and 2 are entitled to
both; 3, 4 and 5 to the coarse only. On a network dropping a fifth of
everything, forty rounds of pull.

**Both halves are asserted, and the second is the one a privacy claim rests
on.** Every host reaches the end of the coarse stream contiguously -- which
with one sequence per issuer was impossible, since each precise record a host
was not entitled to see was a hole it could never fill. And the three
unentitled hosts hold **nothing at all** from the fine stream: not a partial
copy, not a position past 1.

Entitlement is expressed by which streams a host anchors, and in a real
consumer that decision is a capability check `chain/` already answers. The
simulation stands in for the check, not for the mechanism.

## 5i. `location` needs no module, and that is the finding

**Asked to absorb it, the honest answer is that there is nothing to
absorb** -- and the way to establish that was to build one and see what was
missing. Nothing was. `log/test/fix_stream_test.c` is the demonstration, and
it is a test rather than a module for exactly that reason.

**fuzzypickles' own header says so first**: `location.c` is "a log-type
subsystem like log_relay and group chat history: the same (origin, seq)
append-only stream over append_log, with the same dedup, high-water and
catch-up behaviour". That machinery is `record/` and `log/`, already here. A
track is a bounded per-issuer stream whose oldest entries age out and answer
`GONE`, served oldest-first for catch-up. The test exercises all of it with a
19-byte fix as the body.

**What stayed out had to.** A fix is packed little-endian latitude, longitude,
time, quantised accuracy and bearing, and a flags byte. That is an
**encoding**, and sec 2 keeps encodings out for the same reason `log/` took
`append_log`'s sequencing and left its `"<seq> <escaped text>"` line format
behind. The test packs and unpacks the fix itself, as a consumer would, and
everything between is fuzznet's -- which is the seam, demonstrated rather than
described.

**The third kind of stream is the point.** Permissions, logs and now telemetry
all ride the same (issuer, seq) machinery. Two kinds would be a coincidence;
three is the claim sec 5 rests on when it says all three consumers use this
library in almost the same way.

**One genuinely general thing is left unsolved, and it is not location's.**
fuzzypickles reserves a COARSE flag for **per-peer precision degradation** --
city-level to one peer, exact to another -- and records it as an open design
question with nothing degrading anything yet. Generalised, that is *the same
statement at different fidelities to different recipients*, which is a
permissions question rather than a telemetry one and would apply to any record
this library carries. Nothing here stands in its way: a degraded fix is
different bytes under the same sequence, and the test shows one being written
and read. **Raised, not designed** -- it needs the holder, and it is bigger
than the module it was noticed in.

## 5h. `link/` -- what each link is actually doing

**Absorbed from fuzzypickles' `link.c`**, the companion to `sched/`: this
measures, that chooses. Their claim is kept because the shape makes it
literally true rather than merely intended --

> A LINK is one transport over one address. A peer advertising several
> addresses, or one address reachable by more than one transport, is several
> links, each with its own measured latency and availability, competing on
> cost.

-- and **nothing here knows what any transport IS**. There is no branch on a
transport tag anywhere; adding a radio, a tunnel or a relay hop is registering
another link rather than extending the file. A link is a `uint32_t` the
consumer chose.

**The declared metric is a prior; measurement is evidence.** A far end's
declared cost is what it believed when it wrote it, and a network degrades
paths in ways no static declaration expresses and the far end may never learn.

**The prior is seeded rather than special-cased, and that avoids a real
hazard.** The obvious shape is a sample count and a branch -- report the
declaration until there is enough evidence, then the measurement -- which has
a cliff in it and has to answer *what latency does an unmeasured link have?*
The honest answer, zero, makes a link nobody has ever used look **infinitely
fast and win every selection in `sched/`**. Seeding the estimate with the
prior removes the question: there is always a number, and it starts out being
the one the far end asserted.

**A loss raises the loss estimate and leaves latency untouched**, which is the
separation the whole design rests on. A lost message has no round trip to
report, and counting it as some large number would blend a loss signal into a
latency one -- the collapsing into a single number `sched/` exists to avoid,
and undetectable in one figure of merit. The test asserts both halves.

**The averaging widens before multiplying**, for the reason `sched/`'s cost
does: a latency near `UINT32_MAX` times seven overflows 32 bits, and a wrapped
average reports a terrible link as excellent -- consistently, which looks
deliberate. Tested at four billion.

**A trap carried across from their header rather than rediscovered:**
congestion control reads the same loss and round-trip signals and is separate
work -- and once a controller is throttling a *healthy* path correctly, it
looks to this table exactly like a degrading link. Telling those apart does
not arise while everything is uncontrolled, so a design that assumed it could
would be untestable today.

75 checks, 100% of `link.c`'s lines and 91% of its branches, and the two
modules are tested
composed: a link that declared itself quick and measures slow loses the
selection.

## 5g. `sched/` -- which link a message should take

**Absorbed from fuzzypickles' `sched.c`**, one of the four files their
measurement found standalone. What came across is the decision; what did not
is any idea of what a link *is*. This module never opens anything, never sends
anything, and does not know whether a link is wifi, Bluetooth or a tunnel: a
consumer describes candidates as numbers it measured and gets back one of
them, or nothing.

**§2 still holds.** Choosing among links a consumer supplied is not choosing a
transport, any more than comparing two capability identifiers is deciding what
a capability means. The local hop stayed out for a different reason -- it is
an *encoding and socket* decision, which is why `local/socket.c` moved to
raidcfgd.

**Importance is not a priority scalar, and that is the whole design.**
fuzzypickles' header is emphatic: *"a max-importance message wants the link
most likely to arrive, which may be the slowest. A fire-and-forget voice frame
wants the fastest link and is happily dropped. Do not collapse these into one
number."* So a class weights the **components** -- declared metric, measured
latency, measured loss -- rather than reweighting a blended total. A single
"link quality" score answers *how is this link doing* and is the wrong answer
to *which link should this message take*, because the two questions disagree
about what good means.

**The test that proves it is two links and two classes giving opposite
answers**, and it is the centre of `sched_test.c`. A voice class takes the
fast, lossy radio; a configuration change takes the slow, reliable path. The
test then asserts the sharper thing: each class **excluded** the other's
choice on a hard constraint rather than merely scoring it lower.

**Hard constraints come first and can exclude everything.** A link too slow
for a deadline is not a worse choice -- it is not a choice, and
`FZN_SCHED_ERR_NONE` is a real answer that means the caller drops. A failing
link is skipped rather than penalised, because a penalty large enough
elsewhere would bring it back, which is exactly the wrong kind of helpful.

**Cost widens before multiplying.** Two `uint32` weights against a `uint32`
latency overflow 32 bits easily, and a wrapped cost makes a terrible link look
excellent -- then chooses it consistently, which looks deliberate. Tested at
four billion.

**What is not modelled: energy.** A consumer reports it if it matters, for
fuzzypickles' reason -- a battery drains because of the screen and forty other
processes, so a library computing its own consumption would produce a number
with no relationship to how much is left.

28 checks at 100% of lines and branches.

## 5f. `wire/relay.h` -- the hop budget, and what relaying still needs

**`fzn_hop.hops_left` has been in every frame since the schema existed and
nothing had ever read or written it** -- a byte on the wire, in every
datagram, paying for a feature that did not exist. This is its first half.

**It is outside the authenticated region, necessarily.** The contract says the
tag covers `head` and the sealed region; `hop` precedes both. It has to,
because a relay decrements the budget and a field the tag covered could not be
changed without invalidating the frame. So **the budget is mutable in flight
by anyone**, and every property follows from taking that seriously:

- **Clamp, never trust.** A stranger can write 255 into the budget of a frame
  it did not create. Believing it turns one datagram into as many forwards as
  the network has paths -- an amplifier built out of a helpful default.
  `fzn_relay_spend` writes back the *clamped* value, so an inflated budget is
  cut at the first honest host rather than surviving to the last.
- **A stranger writing zero costs nothing new.** It drops the frame, which
  anyone able to rewrite a byte in flight could achieve by discarding it. A
  budget cannot defend availability against somebody already on the path, and
  claiming it does would be the wrong claim to make.
- **What it defends is the network against itself**: loops, and one
  misconfigured host multiplying traffic. Real, and narrow.

**What is deliberately absent, and it is the open question rather than an
omission: a relay cannot tell where to send a frame.** The frame has no
recipient field, on purpose -- `frame.situ` puts the capability inside the
seal precisely so an observer cannot see which authority is being exercised,
and a plaintext destination gives back most of what that bought. A receiver
knows a frame is its own because the key commitment matches a key it derived,
which is **addressing by decryption**.

So routing needs one of three, and choosing is a wire decision rather than a
coding one: an out-of-band hint a consumer already holds, flooding within a
known set, or a destination field -- which costs bytes against §13's budget,
where a largest frame has **64 to spare** under the IPv6 minimum MTU. Not
invented here. This file does the part decidable without answering it, as
`record/sync.h` decides what to fetch and never how to send it.

**Relaying proper waits on fuzzypickles' frame replacement**, which their
phase 1 covers and which their measurement explains: `log_relay.c` and
`log_show.c` cannot move while they still speak `peer_wire.h` without dragging
`control_codec.c` behind them.

25 checks, 100% of lines and 90% of branches. The inflated-budget case is the
one that matters and it is tested in both directions -- read and spend.

## 5e. `log/` -- the first piece absorbed from fuzzypickles

**Started 2026-08-26.** What came across is the part fuzzypickles' own
measurement identified as general -- **sequencing, retention and serving a
range** -- and what did not is the part it identified as specific:
`append_log.c`'s `"<seq> <escaped text>"` line format, which is an encoding
choice and the one netcfgd would reject, its stated product property being
greppable JSON. A body here is opaque bytes, as everywhere in `record/`.

**Their measurement also settled the sequencing.** Of 28,332 lines in
`core/src`, **only four files are standalone**: `append_log`, `location`,
`link`, `sched`. Everything else includes `control.h`, `wire.h` or
`peer_wire.h`, so a subsystem cannot leave while it still speaks their wire
without dragging `control_codec.c` -- 145 encoders and 107 decoders -- behind
it, which §5 refuses. So `append_log` is one of the few things that can move
now, and `log_relay.c` and `log_show.c` cannot: they are frame-blocked until
the frame is replaced.

**A log evicts. The journal and the state do not**, and the difference is the
design rather than an inconsistency. A journal refuses when full because
forgetting an issuer readmits everything it ever sent; a state refuses because
dropping a setting reverts it to a default nobody can trace. A log is a
*stream*, and losing its oldest is its normal condition -- one that refused
once full would stop recording exactly when something interesting started.

**`FZN_LOG_ERR_GONE` is the reason this is a module and not a second
journal.** `record/sync.h` plans a fetch from what a peer says it holds, and
`record/journal.h` refuses a jump so a hole is never silently accepted. Put
those together without a "gone" answer and a host that fell far behind asks
for a sequence nobody has any more, for ever, and **neither side can tell that
from a lost datagram**. `GONE` turns it into a decision: the consumer
re-anchors and accepts that it missed some, deliberately.

**A hole in a log is tolerable; a hole in a permission stream is not -- and no
flag was needed for that.** fuzzypickles' append log takes any entry whose
sequence exceeds its high-water mark, so a jump loses what was between and it
does not mind. `fzn_journal_admit` refuses the jump. A log consumer that
accepts the loss calls `fzn_journal_anchor`, which is already deliberate; a
permission consumer never does. The existing API expressed both, which is why
`log/` takes no policy argument.

117 checks, 100% of lines and 96% of branches, and the installed-header check
appends past capacity and requires GONE rather than merely absent.

## 5d. `trust/` -- where a pinned root comes from

**Added 2026-08-26 at the holder's instruction: "we also need TOFU as
fuzzypickles needs it."** This reverses §4.2's "pinned rather than adopted",
which `chain/chain.h` also stated as non-negotiable, and the reversal is
recorded rather than quietly applied.

**The argument that made the old decision right is kept, not discarded.**
`chain.h` said "there is no nullable-root variant on purpose -- one function
with an optional pin is a function somebody calls without the pin". That is
still true, so TOFU did **not** arrive as an optional parameter.
`fzn_chain_verify` is untouched: it still takes a root and still refuses a
chain rooted anywhere else. `trust/` is only about how a host came to *have*
that root, and `fzn_trust_root` returns **NULL** when there is none -- which
`fzn_chain_verify` refuses -- so an unanchored host fails closed rather than
verifying against a key of zeroes an attacker can also produce.

**Why it had to come in.** Refusing to have a bootstrap path did not remove
the path; it moved it into the consumer, to be written three times. §5's
absorption makes host management fuzznet's, and joining is where host
management starts.

**What TOFU is honestly worth, stated in the header rather than implied.**
Nothing authenticates the key adopted at first contact: whoever answers first
is trusted, and an attacker in position at that moment is trusted for ever.
What it buys is that every *later* contact is authenticated. That is real and
narrow, so a consumer using it **owes its user an out-of-band check** -- and
`trust/` records the moment of adoption and whether the anchor was adopted or
configured, precisely so a consumer can show it. A library cannot make first
contact safe; it can refuse to hide when it happened.

**The security content is entirely in the second key.** Once anchored, a
different root is refused: re-anchoring would make it trust on *every* use,
which is no trust at all, and the failure would be silent -- a host quietly
following whoever spoke to it most recently. The comparison is constant-time,
because it is against a value an attacker chooses and repeats. Pinning over an
adopted anchor is refused too, and adopting over a configured one: a caller
that must start again wants a new `fzn_trust_t`, on the reasoning
`record/journal.h` gives for never rewinding.

31 checks at 100% of lines and branches, including a second root differing in
a single byte, and the installed-header check adopts once and is refused a
second time.

## 5c. `state/` -- permissions, rules and config are one thing

**A permission, a rule and a configuration setting are the same object at
this layer**: a value some issuer set, for some subject, of some kind, and the
current one is whichever that issuer set most recently. `record/` moves and
orders statements; this resolves them into **what is true now**, which is the
question a consumer asks on every decision.

**It interprets nothing.** `kind`, `subject` and `body` stay opaque, so the
permission taxonomy remains the consumer's, per §5.

**Order within a WRITER, never across, and that is the whole design
problem.** A writer is **(issuer, stream)**, not an issuer -- `record.h` says
a sequence is unique within a stream and *not* within an issuer, because an
issuer numbers each stream from 1 independently. So a later statement from the
same writer supersedes; a statement from a different ISSUER about something
already set is a **conflict**; and a statement from the same issuer on a
different STREAM is `FZN_STATE_ERR_CROSS_STREAM`, which is the same refusal
for the same reason, reported separately.

**This paragraph said "within an issuer" until 2026-08-26**, and had been
wrong since the day `stream` was added. `state/` was the one module the field
never reached: journal, sync and log all took it, and the commit that added it
named exactly the modules it had changed, which reads as a complete list. The
cost was not the lost write but the ORDER-DEPENDENCE -- stream 7 seq 100 then
stream 9 seq 100 left stream 7's value, and the reverse order left stream 9's,
so two hosts holding an identical set of records held different permissions
with no error either way. §13a records the measurement.

**Why cross-stream is its own code rather than folded into CONFLICT.** A
cross-issuer conflict is exceptional -- "a subject with a single writer cannot
conflict" -- and is worth an alarm. Cross-stream contention is SYSTEMATIC for a
consumer that lays its streams out that way, so folding them makes the
exceptional one unalarmable, which is what CONFLICT exists for.

**Refusing to resolve is the point rather than indecision.** Every tie-break
rule -- highest priority, lowest key, latest clock -- is one consumer's
policy. Taking the newest silently would let any authorised issuer overwrite
any other's configuration with nothing to show it happened; keeping the oldest
silently is first-writer-wins, which freezes a value nobody can change. So
`fzn_state_apply` returns `FZN_STATE_ERR_CONFLICT` and changes nothing, and a
consumer that has a rule calls `fzn_state_resolve` -- deliberate in the way
`fzn_journal_anchor` is. **A subject with a single writer never sees one.**

**Two refusals that fail closed**, both on precedent in this tree: an older
record must not undo a newer one from the same issuer (a re-delivery is
exactly that, and a state that took it would revert settings whenever the
network repeated itself), and a full state is refused rather than evicted,
because dropping a setting reverts it to whatever a consumer's default is --
a change nobody can trace to the moment it happened.

**The body is not copied.** An entry points at the caller's bytes, as a chain
hop points at its signed region, because nothing here allocates. The header
says plainly that a caller must keep a body alive for as long as the entry
refers to it.

**A defect the test caught before the code shipped: clearing leaked
capacity.** `fzn_state_clear` marked a slot dead, `used` never shrank, and
insertion always appended -- so a state that set and cleared the same subject
repeatedly would fill up while holding almost nothing. Found by a case that
cleared one subject and then could not add a third into a state of three.
Cleared slots are reused now.

100% of lines and 92% of branches, 206 checks, and the installed-header check
exercises set, supersede, stale and conflict rather than merely including the
header.

### A host joining, and what TOFU actually buys (scenario 11)

    join: 1 delivered after joining, 2 refused on authority, adopted at 1003

**The sequence is the test.** Before adopting, the joiner refuses everything
-- an unanchored host verifying against nothing is the failure `trust/` exists
to make impossible, and it fails on authority rather than on shape, because
the frame is perfectly well formed and only the anchor is missing. After
adopting, it receives the network it joined. A second, different root is then
refused and the anchor does not move.

**The last step is the one worth having.** An attacker holding a **valid**
chain under its own root is refused -- and the scenario first asserts that the
attacker's chain *does* verify against that root, so what is being tested is a
foreign chain rather than a broken one. It is refused because the root is not
the one this host adopted. First contact is unauthenticated; every contact
after it is not, and that is the whole of what TOFU is worth.

**Verification now goes through each host's own anchor**, not a root the
simulation holds globally, so all eleven scenarios exercise `trust/` rather
than only this one. An established host pins its root out of band in
`sim_init`; the joiner is the one that does not.

### Configuration across the network, and a real conflict (scenario 10)

**Six hosts, 25% loss, two issuers writing the same subject.** Result:

    state: 3 held alice, 3 held bob, 6 saw the conflict, 6 agreed after

**The divergence is the finding, and it is by design rather than in spite of
it.** Records arrive in different orders on a lossy network, so with no
resolution rule whichever issuer a host hears from FIRST is the one it holds.
Half the network held one value and half the other -- and **every host
reported the conflict**. That is the property `state/` is built for: without a
policy, disagreement must be *visible at every host* rather than settled
differently at each and noticed by nobody. A library that silently took the
newest would have produced the same split with nothing to show for it.

Applying a consumer rule uniformly -- lowest issuer key wins, which the
library neither supplies nor endorses -- brought all six back together.

**A usability defect the simulation found that no unit test would have.**
`fzn_state_resolve` returns `FZN_STATE_ERR_STALE` on a host that already holds
the winner, and a rule applied across a network always meets some: the hosts
that happened to hear the winning issuer first were already right. The first
version of the scenario treated anything but OK as failure and reported a
fault on exactly the hosts that had nothing wrong with them. **Resolve is
idempotent and STALE is its ordinary answer**, which the header now says --
found only because the rule was applied to a whole network rather than to one
state.

**The bodies are static, and the reason is in the header.** `state.h` says an
entry points at the caller's bytes and the caller must keep them alive.
A simulation building records on the stack would leave every host's state
pointing at dead frames, and would mostly appear to work.

## 5a. The integration harness

**`sim/test/network_test.c` is a fake network of hosts, and it exists because
every other test here is a module's own.** Chains without bytes, reassembly
without frames, a replay window without a sender: each is the right shape for
finding a defect inside a module and none can find one *between* modules.

Simulated: the hosts, the datagram queue, the clock, loss, duplication and
reordering. Real: everything below them, called in §4.7's order -- seal, then
freshness and replay, then authorisation, then reassembly. The crypto is
stubbed and deliberately not weakened; a wrong key, a forged tag and a forged
signature all fail, because a stub that accepted them would make every
scenario vacuous.

Fifteen scenarios, 195 checks:

| scenario | what it establishes |
|---|---|
| mesh | 16 hosts, 240 multi-chunk messages, all delivered byte-exact |
| replay | every datagram doubled; the second refused, never delivered twice |
| revocation | revoked mid-message; remaining chunks refused, message never completes |
| revocation split | one host told of a revocation and one not; the untold host delivers, which is sec 14's open gap asserted rather than hidden |
| stale | expiry passed, refused on freshness, and the chain never consulted |
| unauthorised | a validly signed grant naming a capability nobody granted |
| delegation | a two-hop chain minted by the library, accepted under the same root |
| lossy | 20% loss and 40% reordering; some messages lost, none wrong |
| splice | two senders, one message id; no cross-sender splice -- and a NEAR-MISS leg, two senders whose keys differ only in the last byte, which is what makes this row's claim falsifiable |
| substitution | a host acting on somebody else's grant is refused |
| tamper | a mutated frame fails its tag, and the failure does not spend the nonce |
| distribution | records converge across 20% loss, and a gap is reported rather than absorbed |
| state | two writers contend for one cell; every host converges and every host sees the conflict |
| join | a host with no anchor refuses, and a rogue root does not become one |
| fidelity | a host not entitled to the fine stream never holds part of it |

**This table said "Eight scenarios, 32 checks" until 2026-08-27** and had
said so through the addition of seven scenarios. The count is measured
from `make test` rather than derived. It is recorded because an inventory
that lags its subject reads exactly like a complete one, and the harness
is the thing this document points at when it claims a property is
integration-tested.

**Four faults, all in the harness, none in the library.** Worth listing
because each is a way an integration test can look like it works:

- `fzn_chain_verify` was called with a NULL `out` and refused everything with
  *"malformed argument"*. The error renderer added the day before turned that
  from a bisection into one line of output.
- The inbox held 8 entries where 15 senders write, so it silently dropped
  deliveries and the byte comparison ran over what fitted. It counts an
  overflow and fails now: an inbox that quietly discards would hide exactly
  the loss the lossy scenario exists to detect.
- `fzn_seal_open` decrypts **in place**, so delivering the queued datagram
  mutated it and a duplicate arrived already-decrypted -- refused on its tag
  rather than as the replay it was. The receiver takes a copy now, which is
  what a real one gets.
- The signer vtable was supplied with `verify` and no `sign`, so
  `fzn_chain_delegate` refused. Half a vtable, answered precisely.

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

`suggestion/fuzznet.md` carried the question; situ's decision **0030,
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
structure and code rather than consuming output. `situ/suggestion/fuzznet.md`
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

### Resolved 2026-08-15: the schema builds

**situ `18b3537` lets a bound name a sibling, and `wire/frame.situ` now
builds unmodified.** Verified here: `frame.c`, `frame.h`, `frame_relate.c`
and `frame_relate.h` all emit from the committed file, `wire`, `map` and
`advise` still pass, and the generated header compiles clean at `-Wall
-Wextra`. Both relations produce entry points.

**It was not the coin-flip this document and situ's session both framed it
as.** We each put it as "either `max` takes a member-relative bound or
`wire` stops publishing one", evenly weighted. situ's session weighed it
instead: parse, wellformed, layout, resolve and `wire` all accepted the
file and only the constraint emitter refused. Making `wire` stricter would
have made five stages agree with one by removing a capability the five
already had. Five against one is not a tie, and `evidence.md`'s rule about
the disagreeing gate being the first suspect settled it.

The cause is worth recording because it is a distinction, not a bug: the
emitter folded every bound to a number. That is genuinely required for a
`[max]` on a **run**, where the cap is a storage budget and a non-constant
would mean allocating. A bound on a **scalar's value** needs no storage at
all -- it is checked against a message already in front of you, so a
sibling's value is simply there to read. One keyword, two uses, never
separated.

**Their `int64_t` widening caveat does not reach us**, checked rather than
assumed: every bound here is `u8` or `u16` -- `version`, `index`, `chunks`,
`length` -- and none involves a 64-bit unsigned.

**What this does NOT change: `chunk/reassembly.c` keeps enforcing all three
clauses.** The predicate is reachable in principle and unreachable in this
build, because **fuzznet consumes no generated code at all.** There is no
situ dependency in the Makefile, no generation step, and no submodule --
§7 says a submodule and §10 has not taken that step. Dropping the
hand-written check would mean depending on code nothing here produces.
Adopting situ as a build dependency is its own decision and belongs in
§10 rather than in a commit about a bound.

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
`situ/suggestion/fuzznet.md` sets out, rather than a reason to quietly drop
the bound and lose the check it buys.

**situ has framed it better than this section did** (2026-08-14), and the
distinction is worth carrying because it decides who can fix it. The array
limitation next door was **undecided** -- no rationale, nothing pinned it,
the refusal existed once -- so situ could simply fill the gap, and did.
This one is not a gap: `build`'s refusal states a position, that only
`const` values and enum members are compile-time constants. So it is **two
positions contradicting each other**, and either `max` should take a
member-relative bound or `wire` should stop publishing a contract the
compiler will not honour.

That is a language question, and situ has declined to settle it on a
consumer's schedule -- correctly, and this library has no schedule to offer:
picking either side quietly would decide the language on the strength of
somebody else's deadline. It is surfaced to situ's holder as **the thing
standing between this library and dropping hand-written enforcement of a
security check**, which is the sharpest true form of the case.

**The practical consequence for us is unchanged and worth stating flatly:
`same_message` compiles from a schema this project cannot commit.** The
predicate is correct and unreachable, and `chunk/reassembly.c` keeps
enforcing all three clauses in C until that changes.

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

**The disagreement is gone since** (2026-08-18): `situc wire`, `map` and
`build` all accept `frame.situ`, so a schema can no longer declare a bound the
compiler refuses to enforce. `situc verify` refuses only for want of test
vectors, which is an argument this reproduction never passed it rather than a
verdict on the schema.

**That unblocks §10 step 2; it does not finish it, and this document said
otherwise for an afternoon.** Step 2 is *finish the schema against a real
payload* -- the `[max = 1024]` placeholder and §13's overhead question -- and
neither is settled by `situc` accepting the file. The AEAD codec, written the
same day, is not step 2 either: it is the extern codec §4.7 step 5 wanted, and
it was never a numbered step. Corrected here because a step recorded as done is
a step nobody picks up, and this one is now the next real piece of work rather
than a finished one.

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

### situ is a build-time dependency and NOT a submodule (2026-08-15)

The distinction that decides it: **submodule what you link, not what you run
at build time.** Monocypher is a submodule because its bytes end up in the
binary and two hosts must agree about them. situ is a compiler. Vendoring it
would make every clone carry a Python toolchain and -- worse -- would push
`situc` onto every consumer, because the paragraphs above have them compiling
these sources into their own objects. fuzzypickles cross-compiles for
Android; requiring `situc` in that build buys nothing at run time.

**What is committed instead is the contract**, which is where §7's reason
actually bites. `wire/frame.situ.wire` and `wire/frame.situ.map` are in the
tree, following situ's own precedent -- it commits `.wire` and `.map` beside
every example and ships `situc wire --check` to compare them. So a consumer
needs nothing extra, and a change to the schema that moved the bytes without
moving the contract is a build failure rather than a surprise on a peer.

    make schema SITU_DIR=../situ

`SITU_DIR` is the sibling-directory-behind-a-variable shape §7 blesses for
bring-up and `MONOCYPHER_DIR` already uses. **Unset, the target refuses
rather than passing**: a check that no-ops when its tool is absent is a gate
over an empty file list, and this project has already been caught by that
class more than once.

Both halves are confirmed to fire. Widening `length`'s bound without
regenerating produces situ's own verdict -- *"the wire contract of frame.situ
is not backward compatible; a deployed peer will misread messages from this
build"* -- and a stale map is caught separately, because one check passing
would otherwise stand in for two.

**The generated C is adopted too** (2026-08-15). `wire/generated/` holds
`frame.c`, `frame.h`, `frame_relate.c` and `frame_relate.h`, committed for
the same reason as the contract: a consumer compiles them and needs no
`situc`. `make schema SITU_DIR=...` regenerates and refuses on drift, so
committing them cannot let them diverge from the schema.

They are compiled with their own flags rather than ours. `code-style.md`
exempts generated sources, and `-Wconversion` against a code generator's
output is noise nobody reads, which is how a warning that matters gets
missed. They happen to be clean under the full set today; that is luck to
enjoy rather than a rule to enforce on somebody else's emitter.

**And the tamper harness** (2026-08-27). `situc gen-tamper wire/frame.situ`
emits `wire/generated/frame_tamper.h`: `situ_fzn_frame_tamper` takes our
verifier as a callback, flips every byte the schema declares tag-covered and
every byte of the tag one at a time, restores each flip, and requires the
verifier to refuse each one. `wire/test/tamper_test.c` drives it with
`fzn_seal_open` behind the same stub AEAD and stub hash `seal_test.c` uses,
so it runs on **every** `make test` rather than only where `MONOCYPHER_DIR`
names a checkout. Against a 168-byte frame it makes 163 flips -- 147 covered
bytes plus the tag's 16 -- and the test asserts that count rather than only
the verdict, because a covered span reported as zero would return `SITU_OK`
having asked nothing.

**The reason to generate this rather than write it** is the one this section
keeps arriving at from the other direction: a hand-written tamper case is a
SAMPLE, chosen once, and it cannot notice a field added to the schema
afterwards or a span that moved under it. Measured rather than asserted --
narrowing the AEAD's sealed span by one byte at both ends, so the last
payload byte falls outside the tag and the round trip still succeeds, leaves
**`seal_test.c` green across all 112 of its checks** and is caught by
`tamper_test.c` naming byte 151. `golden_frame_test.c` catches it too, by
byte comparison, and only where Monocypher is present; the ungated suite had
nothing that would.

**`make schema` verifies it like the rest**, regenerating into
`$(BUILD_DIR)/.gen.new` and refusing on any difference -- confirmed to fire,
by appending a line to the committed copy. `situc gen-tamper` writes
`frame_tamper.h` into the CURRENT DIRECTORY by default, so the recipe passes
`--out` and nothing situc writes ever lands outside `$(BUILD_DIR)`. A
harness that could drift from the schema would keep flipping the bytes the
layout used to have and keep reporting `SITU_OK`, which is worth less than
the hand-written cases it supplements.

**What it does not cover.** gen-tamper's converse half -- bytes OUTSIDE the
covered span must NOT change the answer -- is emitted only for a fixed
layout, and `fzn_frame` is variable length (`payload[head.length]`). So the
five hop bytes are simply never flipped, and nothing in `tamper_test.c` says
a relay can still rewrite `hops_left`. That property stays where it already
is: `seal_test.c` spends the whole hop budget between build and open, and
`golden_frame_test.c` rewrites byte 1 of the frozen vector under the real
AEAD. The test file says so at the top, so a green run is not read as
covering the hop.

#### The vendored runtime is a deliberate exception to "submodule what you link"

`wire/generated/situ.h` and `situ.c` are copied from situ at `18b3537`, and
this **is** linked code -- `situ_view_sub` lives in `situ.c` and the
generated accessors call it. So the rule written one section above points at
a submodule, and this is not it.

The exception is proportion. situ's C runtime is 76 lines of `situ.c` and a
header, inside a repository that is otherwise a Python compiler. A submodule
would drag the whole compiler into every clone of this library and every
consumer's tree to obtain two files. Monocypher is a submodule because it is
a C library that is all runtime; this is a runtime that is a rounding error
inside a tool. Both files carry that reasoning in their own banner, and
`make schema` re-copies and diffs them so the copy cannot drift.

**What would change the answer:** situ shipping its C runtime as its own
repository, or the runtime growing until vendoring it is copying a library
rather than two files.

**A first attempt at that banner claimed the runtime was header-only**, on
the strength of a grep for definitions in `situ.c` that found none. The
linker disagreed on the next command. The claim was wrong for thirty
seconds and is recorded because the grep looked conclusive and was not --
`situ_view_sub` is exactly the kind of name a pattern misses.

**Adopting it created a gap and the guard could not see it.** Three source
files entered the build that nothing touched, and `make coverage` -- written
precisely to refuse that -- was blind to them, because they live in
`GEN_SRCS` and it iterated `SRCS`. **A guard is only as wide as the list it
iterates, and that list was widened an hour after the guard was written.**
It iterates both now.

Widening it then reported all three as exercised by nothing, which was
false: their compile rule carries its own flags, deliberately, and that also
dropped the coverage instrumentation. A false positive from a guard is worth
no more than the false negative it replaced, so the instrumentation was
fixed rather than the guard relaxed.

`wire/test/generated_test.c` exercises them, and it earns its place twice
over. It builds a frame by writing bytes **at the offsets the committed map
records** and reads them back through the generated getters -- two
independent descriptions of one layout, so a generator whose map and emitter
disagreed would pass its own tests and fail this one. And it executes
`[max = chunks - 1]`: index 3 of 4 accepted, 4 of 4 refused, 4 accepted once
`chunks` becomes 8. **That bound took two situ commits to make compile, and
compiling is not enforcing -- nothing here had checked the second until
now.**

#### Every constant stated twice, checked once

`wire/test/constants_test.c` (2026-08-17) exists because **four modules
define the length of a field the schema also defines, and nothing compared
them.** They agreed. Nothing made them keep agreeing, and
`FZN_NONCE_LEN`'s own comment says "which is what wire/frame.situ carries" --
the C asserted the correspondence in prose and left it there.

| C constant | schema field | what drift costs |
|---|---|---|
| `FZN_NONCE_LEN` | `nonce[24]` | `fzn_replay_admit` compares that many bytes of a pointer into a frame, so a larger C constant reads past the field |
| `FZN_SENDER_LEN` | `sender[32]` | the reassembly slot key is truncated or over-read -- the cross-sender splice `reassembly.c` exists to refuse |
| `FZN_CAP_ID_LEN` | `capability[32]` | the capability compared during chain verification is not the one the frame carries |
| `FZN_COMMITMENT_LEN` | `commitment[16]` | the committing half of the 48 bytes, which sec 4.4a says is not optional |

**The duplication is correct and stays.** These modules must not include a
generated header -- that independence is what keeps them buildable while sec
10 step 2 was blocked, and what still lets a consumer take the replay window
   without
taking `situc`. What was missing was anything to notice when a repetition
stopped being a copy. Seven constants are now pinned at compile time,
including the payload ceiling and its premise, moved here from
`agreement_test.c` so that constant agreement lives in one place and that file
stays about behavioural agreement.

**Two independent witnesses, and the second is the point.** The static asserts
compare a C macro against a generated macro -- both emitted from the schema,
so a generator whose `_COUNT` disagreed with the layout it actually produced
would satisfy every one of them. So the test also measures the distance
between `nonce` and `commitment` in a real frame through the generated
pointers, which is the layout itself rather than a claim about it.

Sabotage-verified five ways, and the fifth is the one that tests the design:
moving `FZN_NONCE_LEN` **and** `SITU_FZN_HEAD_NONCE_COUNT` together to 20
leaves every static assert passing, and only the runtime witness fires. Had it
not, that half would have been decoration.

`FZN_PUBKEY_LEN` and `FZN_SIG_LEN` are deliberately absent: the chain proving
a capability is not carried in the frame at all -- `fzn_hop` is 5 bytes -- so
there is no counterpart to check them against. **An assertion that cannot
exist is worth distinguishing from one that is missing**, which is why they
are named in the file rather than omitted silently.

#### The third hand-maintained list

Adding that test needed a line in `.gitignore`, which names each test binary
rather than globbing them -- deliberately, since a pattern would also hide a
source file added under that name by mistake. **That is the third list in this
repo kept in step by hand, and the first two both drifted**: `HDRS` against
`install`, and `GEN_SRCS` against `coverage`. Each was found by something
breaking rather than by anyone comparing them.

So `make style` compares them now: every `TEST_BINS` entry must be named in
`.gitignore`, 17 of them today. It refuses if it inspected none, and skips
loudly rather than vacuously when `BUILD_DIR` is not the in-place default,
where `/build/` covers the output and none of these paths would appear.

The cost of the omission is small and indirect, which is why it is worth
mechanising rather than remembering: a stray build product in `git status` is
noise, and the rule against blanket `git add` depends on that output being
worth reading.

It was confirmed by catching the live omission -- the line I had not yet added
-- and then by dropping a different entry and watching it name that one
instead.

**And the two are now checked against each other** (`chunk/test/
agreement_test.c`, 2026-08-16). Until this existed, "reassembly.c enforces
what the schema declares" rested on three lines of C matching three lines of
schema **by inspection**, which is the weakest evidence in the tree for one
of its strongest claims.

The test asks both, over every combination of sender, message id and chunk
count: situ's generated `situ_rel_same_message` over two encoded frames, and
`fzn_reasm_accept` over the same values decoded. **They answer different
questions and the mapping between them is the thing under test** -- the
relation says "these are pieces of one message", the reassembler says "this
chunk joined that partial message", and they correspond exactly when the
second chunk lands in the same slot and is accepted. A differing `sender` or
`msg` sends it to a different slot; a differing `chunks` lands in the same
slot and is refused. Both are "not the same message" reached by different
routes.

Confirmed to bite: dropping `sender` from the slot key, or accepting a
differing `chunks`, each produces a disagreement. It also carries a positive
control, because two implementations that both answered "no" to everything
would agree perfectly.

**It found a divergence nobody had written down, on its first run.** The
test was extended to the frame's own constraints -- `chunks [must_ne = 0]`
and `index [max = chunks - 1]`, which `reassembly.c` also enforces by hand
-- and it failed immediately on a case written to assert agreement that does
not hold.

`index 3 of 4` is a legal frame and the schema says so. As a **first**
arrival the reassembler refuses it, because a short last piece cannot set
the stride and guessing would let whoever sends the final chunk first decide
how much is held. That is a rule about an arrival **sequence**, and a schema
describes one message rather than a conversation, so there is nowhere in
`frame.situ` for it to live.

**So the reassembler is stricter than the schema in exactly two places, both
permanent and both now pinned by assertion rather than latent:**

| divergence | why the schema cannot express it |
|---|---|
| `FZN_REASM_MAX_CHUNKS` | affordability is not a property of the bytes |
| last chunk first is refused | it is a statement about a sequence |

The test asserts containment in the safe direction -- the code must never
accept a shape the schema calls illegal -- and pins where the extra
strictness begins, so moving either bound shows up here rather than
silently. Three further sabotages confirm it: removing the resource bound,
removing `index >= chunks`, and accepting a last-chunk-first arrival are all
caught.

**What this still does not do: `chunk/reassembly.c` keeps its three
clauses.** The generated `situ_rel_same_message` takes two `situ_view_t` --
views over *encoded* bytes -- and `fzn_reasm_accept` takes decoded fields.
Bridging them means constructing frames at schema-owned offsets, which is
the coupling every module here refuses. The predicate is adopted and
available to a consumer holding encoded frames; it does not replace an
enforcement that runs a layer below it.

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
`chunk/test/split_test` cuts a payload with one and feeds it to the other,
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
| `wire/` | the schema, and the frame path over it. §7a gives the encoding itself to situ | **built**: `frame.situ`, the committed contract and map, situ's generated C vendored, and `wire/seal.c` opening and sealing through the gate |
| `frame/` | freshness: command expiry, and the replay window it bounds. The envelope, signing and verification are situ's | **built** |
| `chain/` | capability chains: verification, minting, delegation, revocation, and the signer seam | **built** |
| `chunk/` | splitting, reassembly, and the memory bound | **built** |
| `session/` | the key schedule, the AEAD seam, and where a nonce comes from | **built**: key schedule, BLAKE2b binding, the AEAD seam with its XChaCha20-Poly1305 binding, and the entropy seam with `getrandom` behind it |
| `local/` | peer credentials including supplementary groups, and a bounded vocabulary. The socket and the framing are the consumer's -- §2 | **built** |

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

**That question is closed, and it was closed by placement rather than by
anybody noticing it was open** (2026-08-19). It read: the Monocypher binding
sits at `chain/sign_monocypher.c` because it implements `chain.h`'s signer
vtable, a signature rather than an encryption concern; when AEAD arrives it
will want a home that is not the capability model, and *that* is the moment to
decide whether `session/` becomes a real directory or whether the bindings live
together somewhere else -- not worth deciding before there is a second one.

AEAD arrived, `session/` became a real directory, and there are five bindings
rather than two. The decision got made one file at a time without the paragraph
above being re-read, which is worth admitting: the document named the moment
and the moment passed unremarked.

**The principle the layout turns out to follow is: a binding lives with the
seam it implements, never with the other bindings.**

| binding | seam | directory |
|---|---|---|
| `chain/sign_monocypher.c` | `chain.h`'s signer | `chain/` |
| `session/hash_monocypher.c` | `commitment.h`'s hash | `session/` |
| `session/aead_monocypher.c` | `aead.h` | `session/` |
| `session/random_linux.c` | `random.h` | `session/` |
| `local/peer_linux.c` | `peer.h` | `local/` |

It is coherent and it is the right rule: grouping by *implementation
technology* would put Monocypher's three together and leave the platform two
elsewhere, which sorts by an accident of who supplies the code rather than by
what the code is for -- and it would break the moment a consumer supplied their
own binding for one seam and not another, which the whole vtable arrangement
exists to allow.

Stated now so it is reviewable rather than emergent. `session/random_linux.c`
is the one worth a second look, since entropy is not obviously a *session*
concern: it is there because `random.h` sits beside `aead.h`, whose nonce
length it fills. Defensible under the rule, and the alternative -- platform
code living together, `peer_linux.c` beside it -- is the grouping the rule
rejects.

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

**That was verified once, by hand, on one compiler, on one day** (2026-08-14),
and the sentence above then sat in this document as though it were a standing
fact. It is a security property, and the compiler, its version or the flags can
move and make it false with nothing saying so -- the same shape as
`reassembly.c` "enforcing what the schema declares" by inspection, and the
weakest evidence in the tree for one of its strongest claims.

`tool/codegen_gate.py` checks it now, run by `make codegencheck` and by `make test`
before any test binary. **It is a tripwire, not a proof, and says so in its own
header**: deciding from a disassembly which branch depends on which value is
not something a hundred lines of Python settles, and claiming otherwise would
be worse than not checking. What it does is pin the shape the function is known
to compile to, so a change stops the build and a person reads the disassembly.
Four properties, each one something that would have to change for a
data-dependent branch to appear:

| property | what it catches |
|---|---|
| exactly one conditional branch | an early exit, or `diff == 0` becoming a jump |
| the boolean comes from a conditional *set* | the final comparison turning into a branch |
| exactly one return | the second `ret` an early exit needs |
| the accumulator is stored to the stack in the loop | `volatile` no longer forcing it through memory |

**Three positive controls, and the second changed what the gate looks for.**
Compiled as deliberate variants rather than by editing the tree: an early-exit
`memcmp`, the same function with `volatile` removed, and an object without the
function at all. All three are refused, the third because "no branches found"
over a missing symbol is a pass reporting nothing.

The variant without `volatile` is the interesting one. At `-Os` today it
compiles to **one** conditional branch, **one** conditional set and **one**
return -- indistinguishable from the correct function on three of the four
properties. Only the missing accumulator store separates them, so that fourth
property carries the whole of the `volatile` claim by itself. Worth stating
precisely what that means: the non-`volatile` build is not vulnerable on this
compiler today, it has lost the thing that stops it becoming so. **The gate
catches the loss of a guarantee, which is earlier than catching a defect and
the only place it is catchable cheaply.**

It skips loudly rather than passing when there is no `objdump` or the object is
not x86-64 -- the mnemonics are architecture-specific and generalising them
without a machine to test on would be guesswork -- and it exits non-zero when
it cannot find the function, because that is indistinguishable from checking
nothing.

**The same gate now covers `fzn_commitment_derive`'s wipe, which was the same
failure one file over.** `session/commitment.c` zeroes `derived` and `input`
through a `volatile` pointer, and its comment recorded the measurement that
proves the qualifier is load-bearing -- 411 bytes of text with it, 337 without,
the compiler deleting 74 bytes of wipe when allowed to. Then it said:
**"re-measure if the wipe is ever rewritten -- the check is one rebuild and a
`size`."** An instruction to a person who will not be there, about key material
left on a stack, in the one place nobody looks twice.

Re-measured while writing the check, and the figures reproduce exactly. Inside
the function there are **two zero-immediate stores with the qualifier and none
at all without it**, so the property to pin is that those stores exist, one per
wipe loop. A count of zero means dead-store elimination took the wipe and the
derived key survives in the frame after the function returns.

The tool was `ct_gate.py` for one commit and is `codegen_gate.py` now, because
"constant time" stopped describing what it checks and a name that has to be
explained is worse than a rename. Both checks are one tool rather than two
parsing the same `objdump` output, and `codegencheck` names its objects one per
line rather than looping, so that adding a third is a line somebody wrote
deliberately.

Each check has been watched to fail, which is the whole of what makes either
worth citing: the wipe check refuses the non-`volatile` build and refuses an
object without the function, and the constant-time check refuses an early-exit
`memcmp`, a non-`volatile` accumulator, and a missing symbol.

**Its own conversion to tabs is worth a line, because the proof refused the
first attempt.** `code-style.md` wants tabs in Python too, and the mechanical
reindent was checked by comparing `ast.dump()` before and after, per
`evidence.md`. The first run was rejected: the docstring has continuation lines
indented five spaces, so rewriting leading whitespace changed a string
constant. `tokenize` now marks the 36 lines inside multi-line strings and
leaves them alone. The proof caught the exact failure it was written for, on
its first use.

The discrepancies this section used to carry are resolved in the table
above rather than annotated beneath it.

**`make schema` was checking against a moving target, and both failure
directions happened within a minute** (2026-08-18).

It compared this repository's committed artifacts against `$(SITU_DIR)` as it
sat on disk. situ has a session working in it most of the time, so that answer
depended on whether anybody was mid-edit.

The target refused, naming `wire/generated/situ.h` as drifted from situ's
runtime. **Our copy was identical to situ's HEAD**; the difference was an
uncommitted change in their working tree. Re-vendoring "to fix the drift" then
took that work in progress and stamped it with a commit hash that does not
contain it -- **a provenance banner that was a lie, and a check that would
afterwards have passed.**

The pass is the dangerous direction, and it is the one nearly committed. A
failure blames this repository for somebody else's edit and gets investigated;
a pass blesses a vendored copy matching no commit anywhere and gets cited.

`git archive HEAD` is extracted read-only now -- no worktree, no stash, no
checkout, all of which would disturb a session working there -- and everything
is compared against that. **The commit is printed**, because "matches situ" is
not a claim and "matches situ at `cd0cb01`" is.

Worth stating plainly: every `make schema` result cited in this document before
that date was a comparison against a working tree rather than a commit. They
were not wrong -- the artifacts did match what was on disk -- but they were not
reproducible, and a reader should read them as weaker than the ones after it.

It also turned up that situ's *compiler* was dirty, not only its runtime, so
the generated C was being compared against an uncommitted emitter as well.

**Replay defence fuzzed, and the oracle was wrong before the code was**
(2026-08-26). `make guided` now covers `frame/freshness.c` against the
property the module exists to provide, plus two of §4.3's rules that fail open
if they break: a command carrying no expiry must be refused, and an expiry
already passed must be refused.

**The first oracle fired within seconds, and the code was right.** It asserted
that no nonce is admitted twice while its first admission is live. Reduced
from the crash unit -- four bytes -- to three lines: admit nonce 0 expiring at
256, then admit nonce 0 again with **no expiry**, and both return OK.

`fzn_replay_admit` returns OK for `expires_at == 0` **without consulting the
window at all**, and the comment above that line says why: a grant may
legitimately carry no expiry, there is nothing to remember it until,
re-presenting one is how a chain is verified rather than an attack, and
recording them would build exactly the unbounded set the design avoids.

**Nor is it a hole**, which is the part worth being sure of before moving on.
A stranger replaying a recorded command cannot turn it into an unexpiring
grant: `expires_at` and `kind` both sit inside the authenticated head, so
changing either invalidates the tag.

So the property is narrower than "no nonce twice", and stating it correctly
was most of the work: **a nonce carrying a stated expiry, once admitted, must
not be admitted again while that expiry is live.** Narrowed, the campaign is
clean over 2.9 million executions reaching 112 edges, and the oracle still
fires -- disabling the nonce lookup produces a deadly signal in under thirty
seconds.

**`now` only moves forward in the harness**, because a fuzzer handed a
free-running clock steps it backwards and manufactures replays no receiver
could experience. A false positive costs more than a missed path: it is the
report nobody trusts twice.

**A name the library owed and did not provide.** `frame/freshness.h` explained
that "`expires_at` of 0 means no expiry stated" in prose while `chain/chain.h`
named the same value `FZN_NO_EXPIRY`, so a consumer of the replay window alone
had no name for it. Both headers define it now, because neither module may
depend on the other -- `frame/` must not pull in the capability model to ask
about a clock. That leaves two copies of a protocol constant, which is what
`constants_test.c` is for.

**And the check it grew could not have caught the divergence it names**
(2026-08-28). This paragraph used to end "it asserts they agree, and the
assertion is not vacuous, because the include guard makes disagreement
*silent*", and `constants_test.c` said the same thing at greater length. The
argument runs backwards: with both headers defining `FZN_NO_EXPIRY` behind
`#ifndef`, the guard means the SECOND header's definition never compiles, so
an assertion on the public name sees exactly one of the two copies -- the one
belonging to whichever header that translation unit read first. Measured
rather than argued: `frame/freshness.h`'s value set to `1u`,
`wire/test/constants_test` rebuilt from scratch, and it compiled clean,
linked, ran, and reported 11 checks and 0 failures. Reversing the include
order is what makes it fail, which is the tell -- a check that depends on
include order is checking include order.

**The fix is two names, not a bigger assertion**, and it is the arrangement
`FZN_NONCE_LEN` and `FZN_AEAD_NONCE_LEN` already had. Each header defines its
own copy unconditionally under its own module prefix --
`FZN_CHAIN_NO_EXPIRY`, `FZN_FRESH_NO_EXPIRY` -- and offers the public
`FZN_NO_EXPIRY` as a guarded alias for it, so the public name and its value
are unchanged for every consumer while both copies are present in
`constants_test.c` whatever the include order. Setting either private value
now fails the build at the static assertion, in both directions.

**A check whose comment argues it is not vacuous is worse than a silent
one**, which is the shape worth keeping out of this document as much as out
of the source: the sentence is what stops the next reader writing the check
that would have worked.

**The authorisation core, fuzzed against a soundness oracle** (2026-08-26).
`make guided` now covers `chain/` as well, and it asks a sharper question than
"does it crash": **when `fzn_chain_verify` says yes, is it right?** Everything
it accepts is re-checked against the six things §4.2 requires -- pinned root,
unbroken grantor/grantee linkage, the capability asked for, nothing expired,
nothing revoked, and the reported grantee being the last hop's.

A false ACCEPT is an authorisation bypass and is the only failure worth
hunting this hard. A false reject fails safe, and `chain_fuzz.c` already
covers that direction against a model.

**The oracle is written from §4.2 rather than from `chain.c`**, deliberately,
so that a mistake shared with the implementation cannot cancel itself out.

**Result: no unsound chain accepted**, over 1.75 million executions reaching
163 edges. **And the oracle was watched firing**: with root pinning removed
from `chain.c` -- one line, `hops[0].grantor` against the pinned root -- the
campaign reports a deadly signal and writes the crash unit within seconds.

**Identities are one byte wide, expanded to fill the key, and that is the
whole harness.** A 32-byte key drawn from fuzzer bytes never collides, so
linkage never holds, so the accept path is never reached and the campaign
explores rejection code for ever -- millions of clean executions that could
not have found anything. Same failure as the reassembly harness's first run,
avoided by design rather than by luck.

**A near-miss worth recording, and the worst of the week.** Restoring
`chain.c` after that sabotage failed silently: a `cd` into the scratch
directory in the previous command persisted, so the `cp` wrote nowhere and
the tree kept a `chain.c` with **root pinning disabled**. The hash check
caught it only because it too ran in the wrong directory and could not find
the file -- had the scratch directory happened to contain a `chain/chain.c`,
it would have reported success. The robust form, used since, is to restore by
absolute path and verify with `git diff --quiet <path>` from a known
directory: **check the artifact against the repository, not against a hash
computed before the thing that moved.**

**Coverage-guided fuzzing, and a run of 61 million executions that proved
nothing** (2026-08-26). `make guided` drives `chunk/reassembly.c` under
libFuzzer with the address and undefined-behaviour sanitizers. It is a
different instrument from `make fuzz`, which generates chunk sequences from a
PRNG and checks them against a model: that finds what the generator was
written to reach, while a guided search keeps whatever reaches a new edge and
mutates it, so it walks into states nobody described in advance.

**Result: no defect.** 1.5 million executions, 209 of 400 instrumented edges,
a 292-unit corpus. The `local/` parsers were run the same way from a scratch
harness -- `fzn_peer_groups_parse` and `fzn_vocabulary_admit` from one input --
for 15.3 million executions, coverage 2 to 82, also clean.

**THE FIRST RUN WAS WORTHLESS AND LOOKED FAR BETTER THAN THE SECOND.** It
reported **61 million executions at half a million per second, zero crashes**.
Every one of them returned at the first line: the harness called
`fzn_reasm_init` before `fzn_reasm_slot_init`, and init verifies that every
slot already has its buffer -- which `reassembly.h` states plainly and the
harness ignored. The tells were `cov: 8` of 400 and `new_units_added: 0`, not
the crash count, and the *faster* number was the broken one, because doing
nothing is quick.

So the discipline this adds to the family is narrow and worth having: **for a
fuzzer, read the coverage, not the clean bill.** A campaign that grows no
corpus is not a campaign. `make guided` therefore refuses a run whose corpus
did not grow past the single unit libFuzzer starts with, and that refusal was
watched: with the original bug restored it reports *"the corpus has 0 unit(s)
-- the harness is not reaching the code"* and exits 2.

**The harness is dual-mode**, so it is not a file that only exists under a
tool most machines lack. Built plainly it is an ordinary test that replays
inputs -- files named on argv, or four built-in byte strings reaching a
completion, a conflicting repeat, a quota refusal and an expiry -- and `make
test` runs it. That is also what makes a future crash reproducible: the bytes
go into the harness as a named constant, reviewable and running everywhere,
rather than into a committed binary corpus. **The corpus is deliberately not
committed**; it is machine-generated, perishable and local.

**situ called this schema's contract BREAKING, and the bytes had not
moved** (2026-08-26, situ `58b5c21`). `situc wire --check` refused with

    BREAKING: a deployed peer misreads these bytes
      fzn_frame[2]: sealed: nothing -> nonce=head.nonce

**Checked before it was believed, because the message is alarming and
specific.** The whole contract diff is one line, and it is an addition:

    -  @0x0060  32..1056  fzn_aead  sealed  codec=fzn_aead
    +  @0x0060  32..1056  fzn_aead  sealed  codec=fzn_aead nonce=head.nonce

Offset, extent and codec are unchanged. And the generated C regenerated
against that situc is **byte-identical in all four files**, which is the
proof that matters: if the wire had moved, the accessors would have moved
with it.

**The cause is situ gaining vocabulary, not this schema changing.** situ
`63be7ba` lets a sealed region name the field that selects its key, so the
contract can now record something it previously could not. `sealed(fzn_aead,
nonce = head.nonce)` has been in `frame.situ` since the region existed -- what
changed is that the contract says so. situ's classifier compares *unspecified*
against *specified* and cannot tell that from a real rebinding, so it takes
the safe reading and calls it breaking.

**Safe is the right default for it and wrong for this case**, which is worth
separating. A consumer upgrading situ across `63be7ba` gets "a deployed peer
will misread messages from this build" for a contract whose bytes are
identical. Signalled to situ with the reproduction rather than worked around
here; the contract is regenerated because the new line is true.

**Two terms of a nine-term guard had never decided anything** (2026-08-26).
`fzn_seal_build` refuses a malformed call with a single `if` over nine
conditions, and branch coverage put `!what->sender` and `!what->capability` at
zero. `!key`, `!commitment` and `!aead` were untested too. The matrix is
complete now, one deliberate line per term.

**The two inside the send struct are the ones that mattered**, and they cannot
be reached by passing NULL for an argument -- only by nulling a field of
`fzn_send_t`, which no test had done. They also fail worse than the plain
arguments: a null `key` or `aead` fails at its first use, while `sender` and
`capability` are `memcpy` sources far down the function, past the nonce draw
and past the `memset`. Without the guard the failure is a read from a null
pointer in the middle of a half-built frame rather than a refusal before one
exists.

**Sabotage confirms it, and the manner is the point.** Deleting both terms
does not produce a FAIL line -- the test **segfaults**, exit 139, because NULL
reaches the `memcpy`. That crash is the demonstration that the guard prevents
a null dereference rather than merely returning a tidier code, and `make test`
still fails loudly.

**And a frame too short to be one.** `situ_fzn_frame_view` refusing inside
`views()` was also never exercised: every other refusal in the open path
happens to a frame that is at least frame-shaped, so nothing had handed it
143 bytes -- one under the fixed part. Now something does, and that branch
went from 0% to 12%.

Branch coverage of `wire/seal.c`: **73.64% to 76.36% of 110**. What remains
uncovered is post-`validate` defensive code that valid arguments cannot reach,
plus branches inside inlined accessors that belong to the generated code
rather than to this file.

**Every integer constant was mutated to see what notices** (2026-08-25).
Twenty `#define FZN_*` values in the public headers, each changed and the
suite re-run: **eighteen caught, two not**. The method is the one-at-a-time
sabotage this project already uses, applied wholesale instead of to whichever
check somebody happened to doubt.

**`FZN_VERB_MAX` not being caught is correct**, and worth stating so it is not
re-investigated. `vocabulary_test.c` tests the boundary at `FZN_VERB_MAX` and
`FZN_VERB_MAX + 1`, expressed in terms of the constant, so moving it moves the
test with it. That is right for a tunable local bound with no counterpart on
the wire -- the verb is the consumer's opaque bytes -- and a test that broke
when the bound was retuned would be testing the wrong thing.

**`FZN_SECRET_KEY_LEN` not being caught was a real gap**, and a double one.
The constant appeared in exactly two places -- the `secret_key` field of
`fzn_sign_monocypher_t` and one test buffer -- and **both tracked it**, so
changing it moved the declaration and its only users together. Undersized,
`crypto_eddsa_key_pair` writes past the field into whatever follows it in the
struct, and nothing said a word.

Monocypher cannot be asserted against at compile time: it declares
`crypto_eddsa_key_pair(uint8_t secret_key[64], ...)`, defines no size macros,
and an array parameter decays to a pointer, so the 64 is not a symbol
anything can compare with. The pin is therefore empirical -- a canary past the
end of a buffer of exactly `FZN_SECRET_KEY_LEN`, catching a write that runs
over. Verified in three directions: **63 is caught by name, 64 and 65 pass**.
65 passing is correct and the test says so: a canary establishes the size is
*sufficient*, never that it is *necessary*, and too large is harmless here in
a way too small is not.

**The sweep had a blind spot worth recording: it only mutated upward.** For a
length constant the dangerous direction is smaller, since an oversized buffer
is harmless. The `+1` result for `FZN_SECRET_KEY_LEN` was the alarm, but `-1`
is what showed the consequence, and eighteen "caught" verdicts were reached
without ever testing the direction that matters. They stand only because
those constants are pinned by identity to a schema constant or a field
length, not by a bound that happens to be generous.

**And the reason it was dark: `make test` does not build the Monocypher
bindings.** Without `MONOCYPHER_DIR` the three of them are not compiled at
all, and a run that never mentions them reads exactly like a run in which
they passed. `make test` now says so when they are skipped, on the same
reasoning as `analyze` and `ctcheck`. The checkout the Makefile's own
example names is present, and the bindings pass with it.

**THE NOTICE WAS NOT ENOUGH, AND 2026-08-27 SHOWED HOW.** At 15:46 that
day, `55f8bb0` gave `fzn_seal_open` a commitment key and a hash and
updated every caller it could see -- `wire/seal.c`, `wire/test/seal_test.c`,
`sim/test/network_test.c`, `tool/consumer_check.c`. It missed
`session/test/aead_monocypher_test.c`, which a default build never
compiles. For the rest of that day the suite printed "the Monocypher
bindings were NOT built", which reads as a skip, and they were in fact
BROKEN: twelve diagnostics, four call sites, zero chance of ever passing.

The sharpest part is that this file had already written the sentence
down. `tool/consumer_check.c` carries a comment reading "Found when
`fzn_seal_open` grew two parameters and every other caller in the tree
failed to build while this one did not" -- which was true of every caller
that WAS COMPILED. The tree recorded its own blind spot and could not see
through it, because the notice tells you a thing was skipped and cannot
tell you it was skipped while broken.

It surfaced only because a fuzzypickles session offered a published
XChaCha20-Poly1305 vector and this tree went to build the gated suite to
verify it. **The vector did not find a crypto fault. It found that a
module nobody could see was not compiling** -- which is the more useful
of the two, and is worth stating in those words because a green vector
would have been reported as a success and this was better.

The vector is in now, `draft-irtf-cfrg-xchacha-03` appendix A.1, frozen
as literal arrays and exercised in both directions. **The UNLOCK
direction is the one that earns its place**: it accepts the draft's own
ciphertext under the draft's own tag, so it catches an encrypt/decrypt
pair that is self-consistent and wrong together -- which is precisely
what a vector generated from our own code cannot express. Demonstrated
rather than asserted: flipping one byte of the draft's tag fails three
assertions, and the one that matters is "the draft's own ciphertext under
the draft's own tag was refused", so the unlock leg is load-bearing and
not mirroring the seal. A one-byte AAD perturbation is a permanent
assertion in the file, and it was itself proved non-vacuous by weakening
the perturbation to `^= 0x00` and watching three checks fire.

**One trap of this class is corrected and not closed.** The skip notice
carried its check count as a hand-maintained number in a Makefile
comment, and it had drifted 27 out of date -- it said 43 where the
bindings carried 70. The number is right now; nothing stops it going
wrong again, because only a count taken at run time would. Recorded
rather than fixed, since a notice that always prints teaches nobody
anything and adjusting its comment does not change that.

**The stale-binary trap caught me a third time**, and in a new costume: with
`BUILD_DIR=build-mono` the target is `build-mono/chain/test/...`, and asking
make for `chain/test/...` builds a different thing while leaving the binary
under test untouched. The canary was briefly reported as not catching 63.
Naming the full output path is what the earlier two occurrences did not
cover.

**The advertised overhead could not have been caught going stale**
(2026-08-25). `FZN_SEAL_OVERHEAD` is hand-written in `seal.h` and
`fzn_seal_build` sizes every frame with it. The only check was
`FZN_SEAL_OVERHEAD == 144u` in `seal_test.c`, under the message *"the
advertised overhead is not the real one"* -- **a literal compared against a
literal**, insensitive to every schema constant by construction.

**Demonstrated rather than argued, and the first attempt did not count.** A
4-byte field was added to `fzn_head` and the schema regenerated consistently:
`SITU_FZN_FRAME_SIZE_MIN` went to 148 while `FZN_SEAL_OVERHEAD` stayed 144,
and that check still PASSED. Every frame would have been sized four bytes
short.

The first attempt at the same experiment doctored the size constants in
`frame.h` by hand without the accessor offsets a regeneration moves with
them. `generated_test` segfaulted, which is not a check firing -- it is an
incoherent probe crashing, and it could not have produced a clean positive.
**A failing check is not evidence either.** Only the regenerated version
answers the question, and it had to be run before the fix to be worth
anything.

The assertion now lives in `constants_test.c`, whose stated job is a constant
this library states twice, and compares `FZN_SEAL_OVERHEAD` against
`SITU_FZN_FRAME_SIZE_MIN` -- a frame carrying no payload IS the overhead. The
vacuous check is gone from `seal_test.c` rather than repaired there, since a
second copy of the question is the same duplication one rung down. Re-run
against the grown schema, the new assertion fails by name.

**Prompted by fuzzypickles**, who found the identical asymmetry in their own
tree the same day and named it exactly: *the principle stated three times and
the discipline zero times*. Their `project.md` asserts "per-frame overhead is
the budget that never improves" in three places and pins the figure in none.
Worth acting on here rather than agreeing with there.

**The payload bound now says what it means** (2026-08-24, situ `35a6c30`).
situ began exporting a field's value bounds as constants, so `length`'s
maximum is stated directly as `SITU_FZN_HEAD_LENGTH_VALUE_MAX`.
`wire/seal.c` used `SITU_FZN_FRAME_SIZE_MAX - SITU_FZN_FRAME_SIZE_MIN` for a
day, which is the same number by a longer road: it is the payload bound only
because the payload is the sole variable-length member.

`constants_test.c` asserts the two agree, and **that is not a tautology** --
add a fixed field to the head and `SITU_FZN_FRAME_SIZE_MIN` moves while the
length bound does not, so the two part company at compile time rather than in
a sender that quietly stops accepting its largest payload. Sabotaged to
0x3E8: both new assertions fail by name.

**A count went stale in the same edit that made it wrong.** The test printed
"8 constants pinned at compile time" from a hand-written literal; adding two
assertions made it a lie in the same commit that added them. Corrected to 10.
A C program cannot count its own static assertions, so the number stays
hand-maintained -- worth naming as the weak spot it is rather than trusting
it because it is printed.

**Regenerated from `git archive HEAD`, not from situ's working tree**, which
was dirty with another session's edits to `situc/wellformed.py` at the time.
`make schema` already does this and it is why: generating from a dirty tree
stamps somebody's uncommitted work into fuzznet's vendored code with a commit
id that does not describe it.

**A refused send wrote into the caller's buffer** (2026-08-24, fixed).
`fzn_seal_build` bounded its payload at `UINT16_MAX`, which only made its cast
to `uint16_t` safe. The schema caps `length` at 1024, so anything between the
two was refused -- but not until `situ_fzn_frame_sealed_open`, well past the
`memset` that zeroes the whole frame. **Measured: a 2000-byte payload returned
`FZN_SEAL_ERR_SHAPE` having modified 2144 bytes of the caller's buffer.**

The function promises the opposite a few lines below, where the nonce is drawn
first so that a source which "cannot answer leaves the caller's buffer
untouched, so there is no half-built frame for anybody to send by mistake".
That promise was written about the nonce and is true there. **The reason it
gives is not specific to the nonce, and neither is the harm** -- a caller
reusing one buffer for successive frames lost the previous frame to a
refusal.

The bound now sits with the other argument checks, before anything is
written, and comes from `SITU_FZN_FRAME_SIZE_MAX - SITU_FZN_FRAME_SIZE_MIN`
rather than a literal 1024 -- the same reasoning as the `validate` call above
it, so a change to `frame.situ` reaches this file by regeneration instead of
by somebody remembering. `constants_test.c` already pins that identity
against `FZN_SPLIT_MAX_PAYLOAD`, so the sender and the splitter cannot come
to disagree about what fits.

**Two checks, because fixing either alone looks like success.** The bound is
tested at exactly 1024 and at 1025, and the caller's buffer is checked
untouched after the refusal. Sabotage confirms they are not redundant:
restoring `> UINT16_MAX` leaves *"a payload one byte past the schema's bound
was accepted"* PASSING -- 1025 still returns `SHAPE`, just late -- and fails
only *"a refused build wrote into the caller's buffer"*. A single check on the
error code would have reported this defect fixed.

**How it was found, which is the part worth keeping.** Not by reading the
guard, which looks reasonable. `wire/seal.c` was the lowest-covered
hand-written module -- 72.73% of 110 branches -- so the uncovered branches
were listed to see what had never run. The oversize path was among them, and
the first probe of it was written expecting a much worse bug: that an
oversize frame would be built and returned as `FZN_SEAL_OK`. **That
expectation was wrong** -- the frame is refused, and the probe said so. The
real defect was the one visible only after asking a second question of the
same probe: not what it returned, but what it had already written.

**situ was re-measured against the schema, and the answer moved**
(2026-08-24, against situ `ac995c2`).

**The blocker fuzznet reported has landed and was already in use.** situ
`f9e5c0e` compares two fixed-size arrays in a relation, which is what
`suggestion/fuzznet.md` asked for. The rung table in sec 10 step 4 said
`relate` emitted output identical to `view`; re-measured, it emits **4781
bytes more** -- `frame_relate.c` and `frame_relate.h`, with real predicates
comparing `sender` byte for byte.

| rung | 2026-08-14 | 2026-08-24 |
|---|---|---|
| `view` | 18746 | 18826 |
| `edit` | identical | identical |
| `relate` | identical | **23607, and its own two files** |
| `frame` | 24313 | 29194 |
| `converse` | identical to `frame` | identical to `frame` |
| `drive` | identical to `converse` | identical to `converse` |

**`converse` and `drive` still emit nothing, and the reason has changed.** It
used to be that relations could not compare arrays at all. Now situ says
precisely why, in its own words:

    no conversation table for `same_message`: its key includes
    `later.head.sender == first.head.sender`, which compares 32 bytes; a
    packed key holds 8, and hashing one would make two exchanges that
    collided indistinguishable

That is the key-width question sec 10 already recorded and declined to
escalate, now stated as a measurement rather than an inference. **sec 4.4's
retransmission is still not generated**, and sec 10's refusal to hand-write
one still stands.

**situ HEAD refused this schema, over two attributes that did nothing.**
`[nonce]` on `head.nonce` and `[must_ne = 0]` on `head.chunks` are gone. The
refusals are situ tightening deliberately, not a regression, and each came
with its argument: *"a nonce is named by `sealed(codec, nonce = field)`, and
this attribute is read by nothing"*, and *"nothing reads it, so the generated
code is byte-identical to the schema without it"*.

**`[must_eq = 1]` on `hop.version` was NOT refused**, which is what makes the
other two believable rather than a blanket change: it is a real attribute and
`situ_fzn_hop_validate` contains the check it produces.

**Was anything lost? Measured, not reasoned.** `chunks == 0` is still refused
for every index, because `index [max = chunks - 1]` evaluates in `int64` as
`index > -1`, which is true for any unsigned index. Probed directly:
`chunks=0 index=0` and `chunks=0 index=7` both return *constraint violated*,
`chunks=1 index=0` and `chunks=4 index=3` pass, `chunks=1 index=1` refuses.
**And `wire/test/generated_test.c` already pinned both invariants
behaviourally** -- "a frame claiming zero chunks validated" and "a frame with
version 2 validated" -- written against the behaviour rather than the
attribute, which is exactly why a decorative attribute could be removed
without anything going quiet.

Regenerating cost almost nothing: `frame.c`, `frame_relate.c` and
`frame_relate.h` came back **byte-identical**, `frame.h` differs only by two
comment blocks swapping order, and the vendored runtime moved 1253 lines. All
gates pass.

**A false finding I nearly reported, and how it was made.** The first
per-rung sweep piped situc through `head -3`. That closed the pipe, situc
took SIGPIPE mid-write, and `frame_relate.c` was missing from the output
directory -- which reads exactly like situ having stopped emitting it. Two
more steps were spent confirming the committed header declares symbols the
committed source defines, i.e. building the case for a regression in somebody
else's compiler. Re-running without the truncation showed situc writing all
four files and exiting 0. **Truncating a tool's output can kill the tool**,
and the corpse looks like evidence.

**The version was in a file nothing read** (2026-08-23). `VERSION` said
0.1.0, and no Makefile, header or packaging referenced it -- there is no
`debian/` here yet either. So a consumer could not log which fuzznet it had
linked, and the number lived in exactly one place by being used in none.
`version/version.h` and `version/version.c` are new.

**Two ways to ask, and the pair is the point rather than a convenience.** The
macros are what the CONSUMER'S HEADERS say and fold at compile time;
`fzn_version_string()` and `fzn_version_number()` are what the LINKED LIBRARY
says, because they are compiled into it. Within one build they agree
trivially. They stop agreeing exactly when a consumer compiles against one
fuzznet's headers and links a different one -- an installed copy that moved
on, a stale archive, two versions on one machine -- and that mismatch is
otherwise silent until a struct changes shape underneath somebody.

**Demonstrated rather than argued.** A consumer built against 0.2.0 headers
and linked against a 0.1.0 library reports both numbers and exits 1; rebuilt
against the matching headers it agrees and exits 0. The check discriminates
in both directions, which is what a version guard has to do to be worth
having.

**They are not `static inline` in the header, and that is the whole design.**
An inline function would be compiled into the consumer, would report the
consumer's own macros back to it, would agree with itself always, and would
detect nothing. The value is that they are compiled once, into the library.

**`VERSION` remains the authority** and the header is a deliberate copy, for
the reason `constants_test.c` gives about the field lengths: a generated
header puts a build step between a consumer and a constant. What was missing
there and here is anything to notice when a copy stops being one, so `make
style` gained an eighth check. Three sabotages, each with its own message:
moving `VERSION` without the header, a `FZN_VERSION_STRING` that no longer
spells the numbers, and a version that does not pack.

**The packing bound is checked rather than assumed.** `FZN_VERSION_NUMBER` is
`major * 10000 + minor * 100 + patch`, so at 100 a minor carries and 0.1.100
compares equal to 0.2.0 -- two releases indistinguishable, which is worse
than either being wrong.

**`installcheck` caught the omission before any gate I wrote did.** Adding an
installed header without adding it to `tool/consumer_check.c` failed with
*"installed but not included by the consumer: version/version.h -- the check
would pass whatever those headers did"*. That guard was written for exactly
this and fired on its first real occasion, which is more than most vacuous-
pass guards ever get to do. The consumer check now makes the skew comparison
itself, so the installed arrangement proves the function is reachable and
answers rather than merely that a header parsed.

**The library derives a key for a consumer and gave them no way to erase
it** (2026-08-21). `fzn_wipe` is exported from `constant_time/`, and
`fzn_commitment_derive` now uses it rather than its own two loops.

The gap is the same shape as the error strings and worse in consequence.
`fzn_commitment_derive` hands back a 32-byte AEAD key; the obvious way to
clear it is a memset, and a memset whose result is never read is a dead store
the compiler may delete. **This project had already measured that happening
in its own code** -- 411 bytes of text with the wipe protected, 337 without,
so 74 bytes of erasure removed at -Os. The library knew, and did not export
what it knew.

**The measurement that changed the design, taken before the code was
written.** Behind a call into another translation unit the compiler cannot
see that the caller's buffer is dead, so it may not remove the stores at all:
compiled at -Os, `fzn_wipe` **without** `volatile` still writes, at 10
instructions against 11 with it. Inside `commitment.c` the same omission
deleted the wipe entirely. So the call boundary is the primary protection and
moving the wipe out **removes the hazard rather than guarding against it**;
`volatile` stays as the backstop for link-time optimisation, where the
boundary stops existing.

**That measurement is also why the gate did not simply follow the code.**
`make codegencheck` counted zero-immediate stores in `fzn_commitment_derive`.
Pointing that same count at `fzn_wipe` would have been the mistake this
family has already paid for: the count passes with or without `volatile`, so
it could not discriminate, and it would have been quoted afterwards as though
it had. The property worth gating moved with the code instead -- **the
derivation must still hand its buffers to the wipe**, checked by counting
`fzn_wipe` relocations inside `fzn_commitment_derive`. Deleting one call
reports *"expected 2 calls to fzn_wipe, one per key-material buffer, found
1"* and exits 2.

Its own objdump run rather than `disassemble`'s, because `-r` interleaves
relocation lines that `body` would count as instructions, and the two
existing checks count instructions for a living.

`fzn_wipe` is NULL- and zero-length-safe, and the header says plainly what it
is not: it erases the bytes at `p`, and promises nothing about a register
spill, a swapped page, or a copy some other library kept.

**A process note worth more than the change.** The bounded-length sabotage --
`i <= len` -- was first reported as *not caught*, twice. Both readings were
wrong and in different ways: the first ran `make`, which by this project's
own convention does not build tests, so the binary was stale; the second ran
`make test`, which aborted at `commitment_test` before ever reaching the
check. The rule in `build-and-commit.md` about never judging a test from a
binary the build did not rebuild was written for exactly the first, and it
was still walked into. Building the one binary by name and running it shows
*"FAIL: fzn_wipe did not stop at its length"*.

**Every error code this library returns can now be rendered** (2026-08-21).
Seven public enums carry forty codes between them, and nothing rendered any
of them: `fzn_err_str`, `fzn_commitment_err_str`, `fzn_fresh_err_str`,
`fzn_reasm_err_str`, `fzn_split_err_str`, `fzn_seal_err_str` and
`fzn_peer_verdict_str` are new.

**The gap was one-sided in a way worth naming.** situ's generated header
already ships `situ_err_str`, so a consumer of both got a name for the
schema's errors and nothing for ours -- and had to write a switch of its own,
which goes stale silently the day a code is added here. That is a defect this
library exports to everybody who uses it, once each.

**The distinctions the enums are careful about were the ones at risk.**
`seal.h` insists that a bad tag and a bad commitment are separate answers;
`chain.h` separates "valid chain belonging to somebody else" from "this is
broken"; `freshness.h` separates a stale command from a sender that sets no
expiries; `peer.h`'s whole point is that UNKNOWN is not NOT_MEMBER. Each of
those survives in the enum and was lost the moment a consumer logged an
integer.

**Two mechanisms, and they cover different failures.** Each renderer is a
switch with **no `default:`**, which is what makes `-Wall`'s `-Wswitch` warn
about an enumerator with no case -- a `default` would silence exactly the
warning worth having and turn a new code into a silent "unknown" in
somebody's log. Verified rather than assumed: adding a code to
`fzn_split_err_t` produces *"enumeration value 'FZN_SPLIT_ERR_INVENTED' not
handled in switch"*, naming it.

`wire/test/err_str_test.c` takes the three things the compiler cannot see --
that no two codes render the same text, that nothing renders NULL, and that a
value off the end renders "unknown" and nothing else does. 253 checks over
16 renderers.
Sabotage: rendering `FZN_SEAL_ERR_COMMITMENT` as `"tag did not verify"`
compiles cleanly and is caught by name.

**The count is measured, not listed.** A list of enumerators in the test
would be an eighth place to keep in step, drifting exactly like the consumer
switch this change exists to spare people. Each renderer is walked from zero
in its own direction until the fallback answers, and that count is pinned --
so adding a code *with* a case moves the count and fails, which makes the
addition deliberate. The direction is per subject because the error enums run
0, -1, -2 while `fzn_peer_verdict_t` runs 0, 1, 2; assuming one direction
would have tested three verdicts as one.

`FZN_PEER_UNKNOWN` renders **"membership unknown"** rather than "unknown", so
that the fallback stays unambiguous. A log line reading "unknown" must mean
"this is not a verdict", never "the verdict is UNKNOWN" -- the two are the
distinction `peer.h` exists to preserve, and collapsing them in the renderer
would have undone it at the last step.

**The constant-time claim is now checked directly, not inferred from an
object file** (2026-08-21). `make ctcheck` marks both inputs to
`fzn_ct_memeq` as undefined and runs it under memcheck, which reports any
conditional jump or memory address computed from data it considers
undefined. A comparison whose control flow never touches the data cannot
vary with it, so this is the property itself rather than a symptom of it.
The technique is Langley's ctgrind; the test is
`constant_time/test/secret_flow_test.c`.

**What was there before did not cover this, and both witnesses said so in
their own words.** The five cases in `chain/test/chain_test.c` -- a leftover
from when the function lived in `chain.h` -- test that the comparison gives
the right ANSWER, which a plain `memcmp` passes identically. `make
codegencheck` counts branches in the emitted object, and
`tool/codegen_gate.py` calls itself "a tripwire rather than a proof". So the
one property sec 4.4a says this library owes its consumers and must not leave
to them had **correctness tests and no property test at all**, for as long as
the module has existed.

**One function is the whole scope, and that is the argument for having a
primitive.** Every secret comparison in the library routes through it:
capability ids and grantee keys in `chain/chain.c` and `chain/revocation.c`,
the commitment in `wire/seal.c`, the verb in `local/vocabulary.c`, and
`session/commitment.c`'s check.

**The target runs the binary twice and fails if the second run is quiet.** A
memcheck that reports nothing and a memcheck that was never able to report
anything are the same silence -- a build that lost `-DFZN_HAVE_VALGRIND`, a
stale binary, valgrind running something else. So the second run swaps in
`memcmp` over the same poisoned buffers and must be REPORTED. Measured: built
without the client requests, that run is silent and exits 0, which is exactly
the case the check refuses.

Three sabotages, all run:

| sabotage | result |
|---|---|
| `fzn_ct_memeq` rewritten to return at the first differing byte | **caught**, three reports, `make` exits 2 |
| `memcmp` over poisoned buffers (the built-in control) | **caught**, named at `vg_replace_strmem.c` |
| the same control built without the client requests | **silent**, which the target treats as failure |

**`fzn_commitment_check` is deliberately outside it**, and the reason is
recorded in the test rather than left as an omission: it selects an enum from
the comparison's result, and that result is the declassification boundary --
accept-or-reject is published the moment it returns, so branching on it leaks
nothing. Valgrind cannot see that boundary, so including the function would
report a correct branch and teach whoever met it to write a suppression. **A
check whose output has to be explained away is one nobody keeps believing.**

The test builds and runs without valgrind too, with the two macros as no-ops,
so it is an ordinary correctness test on a machine that has no valgrind
rather than a file that only exists under a tool most machines lack.
`ctcheck` skips loudly when the tool or its headers are absent.

**Static analysis had never been run at all, and now has a target**
(2026-08-20). `make analyze` runs gcc's `-fanalyzer` over the library and the
tests and cppcheck at `--check-level=exhaustive` over the library. Both report
**zero findings**.

It is not in `make test`, deliberately: both are slow, and neither is a gate
this project owns -- a new release inventing a finding would break a build that
changed nothing, which is the same argument that keeps `-Werror` out. It
reports and does not gate, and both halves skip loudly when the tool is absent,
since a missing analyser and a clean one otherwise produce the same silence.

**The clean result is weaker than it reads, and the limits were measured
rather than guessed.** Two sabotages:

| defect | `-fanalyzer` | cppcheck |
|---|---|---|
| the `!out` null guard removed from `fzn_split_plan` | missed | missed |
| a one-past-the-end write in `local/peer.c` | missed | **caught**, by name and index |

Neither tool crosses translation units, so a public function that stops
checking its arguments is invisible to both -- the call passing NULL lives in a
test, in another file. That is exactly the class `make style`'s guard-chain
tests and the coverage sweep already cover, which is the reason the gap is
tolerable and the reason it is written down: *"static analysis is clean"*
invites a reader to think it covers more than it does.

What it does cover, it covers well: the array write was named with its index on
the first run. **The target has been seen to fire**, which is what separates it
from a check nobody has watched fail.

**No header here carries an `extern "C"` guard, and two of the three
consumers are C++** (2026-08-20). fuzzypickles is Qt, raidcfgd is forty `.cpp`
files, and both will include these headers from C++ while compiling the
sources as C -- which is how raidcfgd already consumes `local/peer.h`.

Demonstrated rather than reasoned about: a C++ translation unit including
`chunk/split.h` and calling `fzn_split_plan` fails at link with *"undefined
reference to `fzn_split_plan(unsigned long, unsigned long, fzn_split*)"*. The
mangled name is the whole story. situ's generated `frame.h` carries the guard;
none of ours does.

**The fix is standard and it is blocked, which is the part worth recording.**
Adding `#ifdef __cplusplus extern "C" {` to sixteen headers takes a minute, and
`make style` then reports an indentation error on every line inside the block:
the gate is a brace-nesting lexer and `extern "C" { ... }` at file scope is a
brace that does not indent. It has special cases for `switch` and for braceless
bodies and none for this, and its config offers `exclude` by path -- excluding
every header would gut the check that matters most.

So the choice was between bending the source to a checker that cannot model
the construct, and leaving the construct out. **Neither is done here**:
`evidence.md` says a gate that disagrees with correct code is the first
suspect, and the gate is shared from `~/.claude/tool/style_gate.py`, so
changing it belongs to a cross-project pass rather than to this session. It is
signalled, beside the `#define`-continuation limitation already on that list --
same lexer, same cause, second construct.

**What consumers do meanwhile costs them one line**, and it is what every C++
project does with an unguarded C header: wrap the include in `extern "C" { }`.
Verified: the same translation unit links and runs that way. So this is a
convenience gap rather than a blocker, which is why it is recorded and not
forced through.

**The codegen gate's branch count could not tell a correct build from a
sabotaged one, and had been failing correct builds to say so** (2026-08-20).

It began as "exactly 1", which was gcc `-Os`'s loop shape. clang rotates the
loop and gives 2, so `make test CC=clang` stopped before running anything. That
was widened to 1-or-2 -- and then `clang -O2` unrolled and gave 4. Two
widenings in one afternoon is a patch over a wrong idea, so the whole matrix
was measured instead: real against both sabotages, two compilers, two levels.

| | branches | sets | rets | stores |
|---|---|---|---|---|
| gcc `-Os` real / early / novol | 1 / 2 / 1 | 1 / **0** / 1 | 1 / **2** / 1 | 2 / **0** / **0** |
| gcc `-O2` real / early / novol | 2 / 3 / 2 | 1 / **0** / 1 | 1 / **2** / **2** | 2 / **0** / **0** |
| clang `-Os` real / early / novol | 2 / 4 / 2 | 1 / 1 / 1 | 1 / **2** / **2** | 1 / **0** / **0** |
| clang `-O2` real / early / novol | 4 / 4 / 9 | 1 / 1 / 1 | 1 / **2** / **2** | 1 / **0** / **0** |

**A correct build ranges 1 to 4 and a sabotaged one 2 to 9, and the ranges
overlap** -- clang `-O2`'s real function has four branches and clang `-Os`'s
early exit has four. The count cannot separate them at all. Every widening was
buying nothing while rejecting correct builds.

The **accumulator store separates real from both sabotages in all twelve
cells**. The return count does in all but one. The conditional set catches
gcc's early exit. Those three fail the gate now; the branch count is printed,
because a human reading a changed number may still want to look, and failing on
zero branches is kept -- that means no loop at all, so the function was
replaced rather than compiled.

Verified across five configurations: real passes and both sabotages are refused
at gcc `-Os`, `-O2`, `-O3` and clang `-Os`, `-O2`. The suite is clean at all of
them, 23 binaries, no warnings.

**Two limits, stated rather than left to be found.** At `-O0` every local is
spilled, so the store check cannot discriminate -- the non-volatile variant has
seven stack stores against the real one's eight. The gate reads DWARF's
producer string and **skips loudly** rather than passing. clang records no
flags there, only its version, so a clang `-O0` build is checked and passes
vacuously; an earlier attempt to treat *absence* of a flag as evidence of `-O0`
silently stopped checking every clang build, optimised ones included, which was
worse than the gap it closed.

Its own failure message says to read the disassembly and decide rather than
relax the gate, so that is what happened. clang's two are `test %rdx,%rdx; je`
-- a zero-length guard -- and `cmp %rax,%rdx; jne`, the back edge. **Both are
on the length and neither touches the data.** gcc emits a top-tested loop, one
conditional plus an unconditional back edge; clang emits a rotated one. Same
control flow, different shape, and the gate was pinned to one compiler's.

Widened to one or two, and the bound is measured rather than generous:

| | branches | sets | returns |
|---|---|---|---|
| real, gcc / clang | 1 / 2 | 1 / 1 | 1 / 1 |
| early exit, gcc / clang | 2 / 4 | **0** / 1 | **2** / **2** |
| no `volatile`, gcc / clang | 1 / 2 | 1 / 1 | 1 / **2** |

gcc's early exit is the one that now fits inside the branch bound, and it is
still refused -- by the missing conditional set and the second return. **All
six sabotages are refused at both compilers**, and none survives on the branch
count alone, which is what makes widening it cost nothing.

The whole suite then passes under clang: 23 binaries, zero failures, and one
real diagnostic gcc does not give -- `situ_fzn_kind_t` narrowing to `uint8_t`
in `wire/seal.c`. The values are 0x00 to 0x03 so nothing is lost, and the cast
is explicit now, because two compilers disagreeing about whether a conversion
is worth mentioning is worth one line in the source.

**Two findings from asking what happens at 32 bits** (2026-08-20), which
nothing here had ever done despite §7 aiming at routers and phones.

**The generated sources were never getting the build's flags, only their own.**
Their compile rule hard-coded `-Os -g` on the reasoning that `-Wconversion`
against a generator's output is noise nobody reads. That reasoning is right and
the implementation dropped everything else with it: no architecture flag, no
optimisation change, and **no sanitizer**.

Measured: in every `SANITIZE=1` campaign this document has cited,
`wire/generated/frame.o` and `situ.o` carried **zero** `__asan` symbols while
`wire/seal.o` carried 21. So situ's bounds arithmetic -- `situ_view_sub`,
`situ_in_bounds`, every offset computation, which is the code an out-of-bounds
access would actually live in -- was the one part never instrumented, in the
runs quoted as evidence that it was. `GEN_EXTRA` existed to thread `--coverage`
through the same hole, which is the tell: each time something needed to reach
those objects another variable was added rather than the rule fixed.

`CFLAGS_WARN` is now separate and `GEN_CFLAGS` is `$(filter-out
$(CFLAGS_WARN),$(CFLAGS))`, so generated and vendored sources get everything
about the build and nothing about our warnings. The generated objects carry 11,
11 and 9 `__asan` symbols now, the plain build is unchanged, and no warning
flag reaches generated code. **The campaign was re-run and is clean** -- 1.6
million cases with situ's code instrumented for the first time. The 12-million
figure quoted earlier stands only for the hand-written half, and re-running it
in full is deferred rather than done: the machine was at load 115 from other
sessions, and a benchmark run against that measures the neighbours.

**And a test that passed by measuring nothing.**
`test_a_wrapping_size_is_refused_before_a_slot_is_taken` used `(size_t)1 << 62`
-- 2^62 on a 64-bit host, undefined on a 32-bit one, where it evaluates to 0.
Its premise check was `huge * 4 == 0`, which **0 satisfies**, and
`fzn_reasm_accept` then refuses a zero-length payload for being zero rather
than for wrapping. Green, and about nothing, on exactly the platform class the
library targets.

`SIZE_MAX / 4 + 1` times four is `SIZE_MAX + 1`, which is zero at any width:
2^62 here, 2^30 there, a real value on both. Removing the division guard now
fails three assertions at **both** widths, where before it failed three at one
and none at the other.

A 32-bit build also links and passes now, 23 binaries, every suite zero
failures. It did not before: the generated objects ignored `-m32` and the link
died with *"i386:x86-64 architecture ... is incompatible with i386 output"*,
which is how the flags finding surfaced at all.

**The same lens on `freshness.h` found coverage rather than a hole, which is
worth recording as such** (2026-08-19). Its "expired entries are reclaimed on
every call" is why `fzn_replay_expire` sits above the early returns, and the
failure it prevents is named: traffic made entirely of grants, or entirely of
stale commands, both return before recording anything, so a sweep below them
never runs and a window filled earlier keeps dead entries for ever.

No unit test measured it. **The fuzzer did** -- moving the sweep back down
fails `freshness_fuzz` on case 25, through the invariant that every live entry
is unexpired. So the property was covered and this is not the `chain.h` case
repeating.

A test was added anyway, and the reason is narrow enough to state: a fuzz
failure reports a case number and an invariant, while the unit suite runs first
and is what somebody reads. The new one asserts the two scenarios the header
names, in its words, and fails on both when the sweep moves. **A second witness
at the named scenario, not a new finding** -- recorded that way so the count of
things this sweep turned up is not inflated by one that was already caught.

**Half of `chain.h`'s ordering claim was the comment its own test file warns
about** (2026-08-19). That header lists six checks and says the order puts the
cheap structural refusals before any signature verification -- a
denial-of-service property, since a stranger's malformed chain must not cost a
receiver the expensive part. `chain_test.c` opens by saying an ordering claim
that nothing measures is a comment.

Four of the six measured it. A foreign root, a broken link, an over-long chain
and an unauthorised delegation each asserted **zero** signature checks. The
spliced capability, the expired hop and the revoked hop asserted only their
error code -- so the claim was pinned for the steps somebody happened to write
a call count for, and stated for the rest.

All three were already true: `chain.c` runs the structural checks in one pass
and the signatures in a second, and revocation is in the first. So this closed
a gap in the evidence rather than in the code, which is the outcome worth
having when the subject is the security core. Verified by sabotage rather than
by reading -- spending one verification at the top of the structural pass fires
all three new assertions and three older ones with them.

**The style gate's floor had gone stale, and its comment claimed more than a
floor can do** (2026-08-19).

It was 30, set against a real count of 39. The tree reached 67, so a collapse
of more than half of it passed -- the number was right and then quietly stopped
being right, which is what an absolute floor does as a tree grows, and nothing
said so because it was passing. Raised to 52, the same proportion of 67 that 30
was of 39.

**The larger finding is that its stated purpose was not achievable.** The
comment said the floor was "far enough over to catch a module dropping out of
the list". Measured: excluding `chain/` leaves 56 files and excluding `chunk/`
leaves 58, both of which pass at any floor low enough to survive ordinary
churn. A module here is nine to eleven files, so catching one means a floor
within that of the real count -- and a floor that close fails every time a file
is added, which is how this key got to 1 in the first place.

The two goals conflict and the comment claimed both. What a floor catches is a
**collapse** and nothing finer: an exclude pattern that guts the list, a walk
that stops early, a path that stops matching. Verified rather than asserted --
excluding five source directories takes it to 16 files and the gate refuses,
naming the count and the expectation.

The finer failure is answered by something else, which is why the overclaim
mattered less than it might have: `make style`'s six list checks compare
`SRCS`, `HDRS`, `TEST_BINS` and `FUZZ_BINS` against the tree rather than
counting, and a directory leaving the gate's reach shows up there as named
files rather than as a number that did not drop far enough.

**Seven now.** The last is `TEST_SRCS` against `TEST_BINS`: the first is what
gets compiled and dependency-tracked, the second is what `test:` iterates, and
a source in one and not the other **builds cleanly and never runs**. It came
back 23 and 23 plain, 26 and 26 with the bindings, so it is a guard rather than
a fix -- but the failure is demonstrated rather than imagined. That is exactly
what happened to `vocabulary_fuzz.c` one list over, and the same slip here
costs a test that never runs at all, which is worse and just as quiet. The
`SRCS`-against-the-tree check does not cover it: a source in `TEST_SRCS` is in
a list, which is all that one asks.

**Six list pairings are mechanised now, and the sixth was the one still
open** (2026-08-19). `installcheck` already refuses when an `HDRS` entry is not
exercised by the consumer check; **nothing looked the other way.** A header in
the tree that `HDRS` does not name is one `make install` never ships, and that
surfaces as a consumer's include failing on a machine that is not this one --
the same failure `installcheck` exists for, arriving from the direction it does
not cover.

`HDRS` turned out complete in both configurations, which is a clean result
rather than a fix. Worth recording is that **the first measurement said
otherwise**: grepping the `HDRS` assignment out of the Makefile found thirteen
entries against sixteen headers and named three as missing. They are the
Monocypher bindings, which `HDRS` gains inside the conditional -- so the probe
had read the file rather than asked `make`, and would have produced a finding
that was entirely an artifact of how it looked.

The full set, each comparing a hand-maintained list against something that
cannot be edited to agree with it:

| list | checked against |
|---|---|
| `HDRS` | `install`, and now the tree's headers |
| `GEN_SRCS` | `coverage`'s iteration |
| `TEST_BINS` | `.gitignore` |
| `SRCS` | the tree's C sources |
| `FUZZ_BINS` | the tree's fuzz harnesses |
| `OBJS`/`TEST_OBJS` | what survives `clean` |
| `TEST_SRCS` | `TEST_BINS`, so a test cannot build without running |

**The copied tools were never checked against their sources until now**
(2026-08-19). `make style` has been cited dozens of times this session, and
nothing had confirmed the gate it runs is the current one. `harmonization.md`
requires the copies to be kept in sync and drift fixed the moment it is
noticed; noticing requires looking, and nobody had.

Two of the three were clean. `tool/style_gate.py` and `tool/hooks/commit-msg`
differ from their sources by exactly the two-line provenance header the
convention asks a copy to carry, and their bodies are byte-identical.

`code-style.md` had drifted in one passage. Both it and the source were last
changed on 2026-08-14 -- one session editing the copy while another edited the
source, which is the case the "re-read the source before reconciling" rule
exists for. Reconciled to the source, since a copy that disagrees is drift
rather than an override, and nothing is lost: the more specific instruction the
copy carried already appears in the source's own later text.

The reconcile was mechanical with a proof rather than a careful read. The
result must be the provenance header, then the source byte for byte, then
fuzznet's own section unchanged -- and the check refuses to write if any of the
three moved. It came to four insertions and five deletions in a 389-line file:
one passage of substance and one re-wrapping.

**Two of these checks refused to run unless `BUILD_DIR` was the default**
(2026-08-19), and both were fixed by asking what they actually compare. The
`.gitignore` and `FUZZ_BINS` checks skipped out of tree on the reasoning that
the paths would not match -- but the prefix is incidental to list membership,
and stripping it makes them answer in every configuration. **A check that skips
for anybody who habitually builds out of tree is a check those people do not
have**, and it announces itself as a skip rather than as an absence, which
reads like diligence.

Confirmed in both configurations, and separately rather than together: the
first sabotage tripped the earlier check, whose `exit 1` meant the second never
ran, so a single measurement showing "one caught" said nothing about the other.

**Dependency tracking is measured rather than assumed** (2026-08-19).
`build-and-commit.md` calls it load-bearing and records the failure -- a struct
gains a field, the library and its test disagree about layout, and the symptom
is a pile of nonsense assertions. `DEPS` covers `TEST_OBJS` as well as `OBJS`
and is `-include`d, which is the rule; touching `chunk/reassembly.h` rebuilds
nine objects, **seven of them test objects** across four directories, including
indirect dependents that reach it through `chunk/split.h`. That is the rule
working rather than the rule being written down.

**A warning sat in the build for a day because every check read for
"error"** (2026-08-19). `-Wshadow` had been reporting a shadowed `ops` in
`chain/test/sign_monocypher_test.c` since the guard tests were added to it,
and it was printed on every build in between. Nothing missed it -- it was
visible each time. What missed it was the reading: the greps used to verify
each change filtered for `error`, `FAIL` and `failure(s)`, and a warning is
none of those.

**The compiler was never wrong and the build was never silent.** That is what
makes it worth recording: the failure was entirely in what got looked at, and a
check that reads for the wrong word is indistinguishable from one that passed.
It surfaced only because a build under a sanitizer printed enough context
around it to be noticed by accident.

Fixed by renaming, and the count is now zero across a clean build with the
Monocypher bindings. **Whether `-Werror` should follow is not settled here**:
it would make this class impossible, and it would also break a build on a
compiler version that invents a new warning, for somebody who changed nothing.
That is a convention change and belongs to a deliberate decision rather than to
the session that tripped over it.

**`make clean` removed less than the build made, and said "clean"**
(2026-08-19). `OBJS`, `TEST_OBJS` and `TEST_BINS` gain the Monocypher half only
inside the `ifneq` on `MONOCYPHER_DIR`, and clean is usually run without it. So
`make test MONOCYPHER_DIR=...` followed by a plain `make clean` left **thirteen
objects and three binaries** in the tree and reported success.

`build-and-commit.md` warns that a clean target which quietly removes nothing
looks exactly like one with nothing to remove. This is the same failure from
the other side -- removing *less* than was built, announced as loudly as
removing everything -- and it is the shape a conditional list produces every
time.

Two changes, and the second is the one that matters. The Monocypher artifacts
are named unconditionally, which they can be because `MONO_SRCS` and
`MONO_TSRC` already sit outside the conditional for the style check. And
**clean checks its own work**: for the in-place default it refuses if any
`.o`, `.d`, `.gcno` or `.gcda` survives, because that is the only way "removed
everything" and "removed what it happened to know about" stop looking alike.
Dropping one entry from its list makes it refuse and name the file.

**A fuzz harness existed that `make fuzz` had never run** (2026-08-18).
`local/test/vocabulary_fuzz.c` was in `TEST_SRCS` and `TEST_BINS`, so
`make test` ran it at the default 20000 cases, and absent from `FUZZ_BINS`, so
`make fuzz CASES=2000000` never touched it. The deep campaign is the one place
that omission costs anything, and nothing said so, because the suite was green
either way.

**That is the fifth hand-maintained list here and the one still unchecked.**
`make style` now asks the filesystem: every `*_fuzz.c` in the tree must appear
in `FUZZ_BINS`, since that suffix is the convention every harness follows and
comparing against another list somebody also maintains is what the first four
did. It reported the real omission the moment it was written, which is the same
positive control the `.gitignore` check gave.

The campaign now covers eight harnesses rather than seven: **16 million cases
under ASan and UBSan**, no invariant broken, every model agreeing. Confirmed
non-vacuous rather than assumed -- the instrumentation is present in the
binaries (23 `__asan` symbols in `seal_test`, 24 in `vocabulary_fuzz`), which
matters because a sanitizer build that silently failed to engage reports
success exactly as loudly as one that worked.

**Everything written since the last campaign has now been through it**:
`wire/seal.c`, `session/random.c`, `local/vocabulary.c`, and the two harnesses
added with them. That was the reason to re-run rather than cite the old
figure -- the previous campaign predated all of it.

**The same question, asked of the other outside tree.** `MONOCYPHER_DIR` points
at a sibling project's checkout, and the three Monocypher tests are the only
results here that depend on anything outside this repository. That one is
clean -- a submodule of fuzzypickles pinned at 4.0.3 -- so the risk is smaller,
but the claim was equally unpinned: *"the AEAD round-trips"* is not a claim
and *"it round-trips against Monocypher 4.0.3"* is. The build prints the
version now, and crypto is where that matters most, since a patched copy at
the same path is exactly the thing worth naming.

**And the new gate paid for itself the same afternoon.** situ committed the
runtime change a few minutes later, at `8257f7f`, and the target then reported
a drift that was real -- the same complaint as before, about a genuine
difference from a genuine commit, so re-vendoring stamped a provenance that is
true. The vendored runtime gains `situ_span_t`, the scattered transform form
of §13.2b, which this library does not use: it is for a codec covering spans
with something uncovered between them, and `head` and `sealed` are adjacent.
It is taken because the vendored copy tracks situ's runtime rather than the
subset we happen to call.

**Reported rather than refused**, and the asymmetry with situ is deliberate:
nothing is vendored *from* Monocypher, so a dirty tree there cannot get a false
provenance stamped on it. The worst case is a result nobody can reproduce,
which naming the version fixes. situ needed a refusal because its worst case
was a lie in a committed file.

**`make install` does not produce an installation anybody can build against,
and that is worth stating rather than discovering.** It installs headers, and
§7 deliberately builds no archive -- consumers compile these sources into their
own objects, with their own flags, from a submodule. So an installed prefix
resolves `<fuzznet/local/peer.h>` and has nothing behind it.

**A consumer walked into exactly that within a day** (2026-08-18). raidcfgd's
build rule for the socket module fuzznet handed it tested for `local/peer.h`
before compiling `local/peer.c` beside it, and its comment offered
`<prefix>/include/fuzznet` as one of two arrangements. The header check passed
against an install and the compile failed a step later, naming a path nobody
would connect back to that variable. Fixed there: the guard tests for the
source file, and the comment says source tree and gives the reason.

The target is not useless -- `installcheck` compiles a consumer against the
installed headers and catches a relative include that resolves only inside this
tree, which is a real defect class it has already found twice. But *installed
headers* and *an installation* are different things, and the second is what a
reader assumes when they see `make install`.

**`make installcheck` is what holds the table honest from outside.** Every
suite here builds from inside the tree, which is the one arrangement a
consumer never has — §7 has netcfgd's agent taking this as a submodule and
compiling these sources into its own objects. So `tool/consumer_check.c` is
compiled twice, once against an installed tree and once against the source
tree from another directory, and both are run.

It found the defect it was written to look for, in the check rather than in
the code: **`install` hardcoded a line per header while `HDRS` listed them
separately**, so there were two hand-maintained lists that had to agree and
nothing compared them. Dropping a header from `HDRS` changed nothing that
was installed. `install` iterates `HDRS` now, which collapses the two into
one, and removing a header from it fails the check.

**Then it narrowed silently, which is the more interesting failure.** The
target can only catch a break in a header `tool/consumer_check.c` actually
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
2. ~~**Finish the schema against a real payload.**~~ **Both halves settled**
   (2026-08-18).

   The overhead is **144 bytes, measured** rather than argued about, and
   `wire/test/constants_test.c` pins it against the generated layout so it
   cannot drift again -- which it had, twice, while it was only prose.

   The `[max = 1024]` is no longer a placeholder, and **the question this step
   asked was the wrong one**. It said netcfgd's largest chunk decides it.
   Netcfgd's documents name no number, and asking would not have helped:
   chunking means a response's size sets how *many* chunks there are, not how
   big one is. What bounds a chunk is **the smallest path it must cross
   whole**, because fragmented UDP is widely dropped and avoiding it is the
   reason this library chunks at all -- netcfgd's own brief says so in the
   paragraph that asks for chunking.

   So the number comes from the path. RFC 8200 guarantees 1280 bytes on every
   IPv6 link; less 40 of IPv6 header and 8 of UDP leaves 1232; a largest frame
   is 1168, which fits with **64 bytes spare** for an extension header or a
   tunnel. The largest payload that would still fit is **1088**, so 1024 sits
   under the real ceiling deliberately rather than by luck.

   | path | UDP payload | 1168-byte frame |
   |---|---|---|
   | IPv6 minimum, RFC 8200 | 1232 | fits, 64 spare |
   | IPv6 over Ethernet | 1452 | fits, 284 spare |
   | IPv4 over Ethernet | 1472 | fits, 304 spare |
   | IPv4 minimum reassembly, 576 | 548 | does **not** fit |

   The last row is left standing rather than designed around: 576 is a floor
   every IPv4 host must be able to reassemble, not an MTU any real path
   offers, and a frame that needed fragmenting to cross it would be dropped
   for being fragmented long before its size mattered.

   `constants_test.c` asserts the binding constraint, so raising `[max]` past
   1088 stops the build rather than stopping traffic on somebody's tunnel.
3. ~~**`chain/`** — the capability and identity model~~ **verification is
   built** (2026-08-14). It stayed ours throughout every scope change because
   it is semantics rather than layout or transport, and that is exactly what
   let it go first while step 2 was blocked: `chain/chain.c` parses no bytes.
   It is handed hops somebody else decoded and answers whether they authorise
   a grantee for a capability under a pinned root, now. fuzzypickles'
   `identity.c` and `capability.c` were the reference.

   **Two** things it does differently from that reference, each because this
   document says so: the root is **pinned rather than adopted** (§4.2), with
   no nullable-root variant, since fuzzypickles needs a TOFU bootstrap and
   this library has no such path; and a capability is **32 opaque bytes**,
   never a typed enum, because netcfgd's three are independent rather than a
   ladder.

   **This said three, and the third was not a difference** (corrected
   2026-08-19). It listed "nothing reads a clock -- `now` is a parameter", and
   the reference does exactly the same: `fzp_capability_verify_chain` takes
   `uint64_t now`, and neither `capability.c` nor `identity.c` calls `time()`
   or `clock_gettime` at all. It is a property fuzznet shares with the
   reference rather than one it departed from -- still worth stating as a
   property, and wrong as a contrast.

   The other two were checked at the same time and both hold.
   `capability_internal.h` describes a "TOFU-style bootstrap" with a
   "pin-or-adopt" split, and `fzp_capability_type_t` is a typed enum threaded
   through every entry point. **The claims were true where they were checkable
   and one was not checked** -- which is what `evidence.md` means about
   corroboration: this paragraph described another project's code from having
   read it once, and nothing since had gone back.

   **And the reverse direction: every requirement in netcfgd's brief is met**
   (checked 2026-08-19, confirmed by that project the same day).

   **A misreading first, corrected by them and recorded because the shape of
   it is instructive.** This paragraph said their brief "still says of the
   `wire/` it wanted that *it does not exist yet*", and that was wrong. The
   full clause is *"Planned as netcfgd's own C, at the repository root beside
   `crates/`. It does not exist yet"* -- the subject is **their** planned
   directory, not this library, and it is still true, since there is no `wire/`
   in netcfgd and now never will be.

   The clause I quoted as support is the one that disproves it: *"which is why
   this news arrived at a good moment: the plan was to copy fuzzypickles'
   design into a second implementation"*. That sentence is about a directory
   they were going to write and did not. I read the passage, quoted it, and
   still attached the wrong antecedent -- **reading a sentence is not the same
   as parsing it**, and having the text in front of me was no protection.

   What is stale there is theirs to fix and sharper than what I claimed: the
   `wire/` bullet is superseded, and the document says so 180 lines later
   rather than at the claim, so a reader of §2 gets the withdrawn text and
   learns of the withdrawal only if they reach §7. A document correcting itself
   downstream of the claim is how a stale sentence keeps being read as current.

   Its §2 asks for six things and its §5 for two more. All eight are built,
   and **that project verified every file by hand rather than taking the
   report** -- which is what makes this corroboration rather than an echo:

   | asked for | delivered |
   |---|---|
   | envelope | `wire/frame.situ`, the committed contract, `wire/seal.c` |
   | capabilities | `chain/` |
   | signing | the signer seam, `chain/sign_monocypher.c` |
   | verification | `chain/chain.c` |
   | chunking | `chunk/split.c` |
   | reassembly | `chunk/reassembly.c` |
   | commands expire, grants do not | `frame/freshness.c`, §4.3 |
   | payload size with a memory bound | `FZN_REASM_MAX_CHUNKS` and the per-sender quota |

   Its hard constraints are unaffected and stay theirs: the daemon grows no
   network listener (§3 here says the same), the capability-to-tier mapping is
   the agent's, and the local hop is netcfgd's own.

   **Not written into their tree, and the reason is the rule rather than
   politeness -- their session agreed the judgement was right.** Their `docs/shared-protocol-brief.md` §8 grants the protocol
   parts of that repository to this library's author to edit, so the edit would
   be permitted -- but the tree has four uncommitted changes from a session
   working in it right now, including its own `project.md`. Recorded here
   instead, per *record first, ask second, edit last*. It is worth their
   knowing: a document that says the library it is waiting for does not exist
   is one somebody plans against.

   **The rest of this document's citations of other trees were checked in the
   same pass, and the rest hold.** They are worth listing, because one
   correction means little unless a reader knows what else was looked at:

   | claim | where it is used | checked |
   |---|---|---|
   | `control_codec.c` is 4718 lines | §5, why vocabularies stay out | exact |
   | `capability.c` + `identity.c` about 2200 | §10, the scale of the reference | 2246 |
   | fuzzypickles pays 82 header bytes and a 16-byte MAC | **§13**, that two designs reached the same order independently | `FZP_PEER_HEADER_LEN (1 + 1 + 32 + 32 + 16)` and a 16-byte MAC at the tail |
   | netcfgd's `peer.rs` carries the `SO_PEERCRED` warning in its own header | §2, why `local/` reads `/proc` | its module comment says so |
   | netcfgd's `Peer` says an empty list means "could not tell", not "none" | §2 and §4.8, the tri-state | word for word at `peer.rs:27` |

   The §13 one carries the most weight and is the one most worth having
   confirmed: that section argues 144 bytes is not an aberration *because a
   second design reached the same order on its own*, and an unchecked number
   there would have been this document corroborating itself through a tree
   nobody opened.

   fuzznet is also *stricter* than the reference in three places nobody had
   written down, found in the same pass: revocation is checked against every
   hop rather than only the final grantee (`capability.c` tests
   `out->grantee_pubkey` alone), the root comparison is constant-time where the
   reference uses `memcmp`, and structural refusals complete for the whole
   chain before any signature is verified where the reference verifies each
   hop inside the same loop iteration. None of those is a criticism of a
   working implementation with different constraints; they are recorded because
   "the reference does it this way" is a sentence this document uses, and it
   should be accurate in both directions.

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

   **A grantor revokes its own descendants (2026-08-28)**, which this
   paragraph used to record as deliberately not built on the grounds that
   "this document does not say" whether it is wanted or is the attack. It
   says now: the holder settled it in §13b, and §13c is the design. The
   entitled issuers for a hop are the root and that hop's ancestors IN THE
   CHAIN BEING VERIFIED -- a set `fzn_chain_verify` derives from the hops
   it was handed and cannot be told wrong -- and admission takes an
   `fzn_revocation_offer_t` carrying the issuer's own chain.

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
4. ~~**Decide the rung, and say when.**~~ **Answered 2026-08-14: `relate`,
   revised the same day from `view` after situ fixed the limitation that
   produced the first answer.**

   **What changed.** situ `f9e5c0e` implements `==` and `!=` between
   fixed-size arrays of the same type and length, in all four backends,
   after this library asked for it (`suggestion/fuzznet.md`). Verified
   here: `f_relate.c` and `f_relate.h` now emit for this frame, both
   relations survive, and the generated header compiles clean at `-Wall
   -Wextra`. The refusal turned out **not** to have been deliberate --
   situ's session confirmed nothing in 0030 mentioned arrays, no test
   pinned it, and the string existed once. This document's guess that the
   neighbouring float refusal was making it look decided was right, and is
   recorded as an amendment on 0030 there.

   **It closes one rung, not four, and situ said so unprompted.** A packed
   conversation key is `KEY_BITS = 64`; `sender` is 256 bits, so rung 5
   still refuses `same_message`, and rung 6 with it since a driver needs the
   table. So the ladder for this frame is now `view` -> `edit` -> `relate`,
   and stops.

   **`relate` is the answer and the analysis below is otherwise unchanged.**
   `edit` still buys nothing -- a sealed region whose size the data decides
   has no owned form. `frame` is still *stream* framing and still the wrong
   problem. `converse` and `drive` are still out of reach, now for a key
   width rather than a missing predicate.

   **situ is a build-time dependency as of 2026-08-15** and the byte contract
   is committed and checked (§7). That pins the bytes; it does not generate
   C, so the note below still holds.

   **The committed schema builds as of 2026-08-15** (situ `18b3537`, §6), so
   `relate` is now an answer somebody could act on rather than one nobody
   could. What stands between here and acting on it is no longer situ: it
   is that **this library consumes no generated code**, has no situ
   dependency in its Makefile and no submodule, and adopting one is a
   decision §10 has not taken. `chunk/reassembly.c` goes on hand-enforcing
   `same_message` until it is.

   **Whether rung 5 is worth asking for is answered no, for now.** situ
   offered to take the key-width question to its holder with fuzznet's case
   attached. Declined: `converse` and `drive` are both eventually wanted --
   §4.4 needs retransmission and §10 refuses to hand-write it -- but no
   consumer exists to need them. netcfgd's `agent/` may never be written,
   fuzzypickles cannot adopt at rung 2 for want of an owned form, and
   raidcfgd waits on its own vocabulary bound. A decision made now would be
   made for nobody.

   ---

   *The measurement that produced the original `view` answer, kept because
   the reasoning still holds for four of the six rungs:*

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
     reported (`suggestion/fuzznet.md`, situ `ba10684`) with the argument
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
7. ~~**`local/`**~~ **done** (2026-08-18). raidcfgd exists and stated what it
   needs, so the module was written against something real rather than an
   imagined consumer: credentials, and the vocabulary bound (§4.8). The framing
   and the listener were written here too and then moved to raidcfgd, because
   they choose a transport and an encoding and §2 says this library does not.

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

**Fourteen modules are built and tested**, measured 2026-08-27 rather than
remembered: `chain/` (verification, delegation, revocation), `chunk/`
(split and reassembly), `constant_time/`, `frame/` (freshness and the
replay window), `link/`, `local/` (peer identity), `log/`, `record/`
(records, journal, sync), `sched/`, `session/` (aead, commitment,
random), `state/`, `trust/`, `version/` and `wire/` (seal, relay,
bytes). `sim/` holds the integration harness and `guided/` the
coverage-guided drivers.

Alongside them: this document, `wire/frame.situ`, a `code-style.md`
copied from the global source, the shared `style_gate.py` and
`commit-msg`, and a `VERSION`. `make style` passes over 107 files.

**THIS PARAGRAPH SAID "`chain/`, `frame/freshness.c`,
`chunk/reassembly.c` and `chunk/split.c` are built and tested; nothing
else is" UNTIL 2026-08-27**, and the paragraph below it said `make test`
builds "two binaries" and then listed five. Section 11 is the section a
reader lands on to find out where the project is, so it is the worst one
in the document to leave lagging -- somebody picking this up would have
concluded that `record/`, `state/`, `trust/`, `log/`, `link/`, `sched/`,
`session/`, `local/` and `wire/` did not exist. The counts below are
taken from `make test` and are the kind of number that goes stale by
being true when written; that is an argument for measuring them when
they are cited, not for leaving them out.

`chain/` is the capability model and `frame/freshness.c` is sec 4.3's
policy half; those two were first because neither needs generated code,
which is why they were buildable while sec 10 steps 2 and 4 were stuck.

`make` builds the objects and nothing else -- the default target does
not build tests, per `build-and-commit.md`. `make test` builds and runs
**43 binaries**: 30 report check counts and the other 13 -- nine
model-based fuzz harnesses and four coverage-guided drivers -- report
cases instead. Zero failures in either group. **The total is
deliberately not written here**; `make test` prints it and any figure in
prose is one commit from being wrong, as the paragraph below this one
records at length.

**THE FIRST VERSION OF THIS PARAGRAPH SAID 33 BINARIES AND 2637
CHECKS, AND BOTH WERE WRONG**, which is worth keeping because of when
it happened. 2637 was measured correctly and then CARRIED across three
further commits that added checks -- revocation_test 125 to 132,
chain_test 260 to 262, network_test 170 to 172, which is exactly the
11 it was short by. It was quoted in a report written after those
landed. "33" was a grep for `failure(s)` that also matched the four
guided drivers' `case(s), 0 failure(s)` lines, so it counted 29 real
summaries plus 4 of something else and missed 9 fuzz harnesses
entirely.

A consumer session caught both by rebuilding this tree and failing to
reproduce the totals, having first ruled out double counting and
confirmed the figure was stable across two consecutive heads. It
happened one commit after this document recorded that a hand-maintained
count had drifted 27 out of date and that only a count taken at run
time would close the trap -- so the same trap was operating in the
report describing it. **A number is measured at the moment it is
quoted, or it is not measured.**

**AND THIS PARAGRAPH THEN WENT STALE AGAIN, which is the most useful
thing in it.** It named six binaries by count. Re-measured 2026-08-27,
five of the six had moved -- `chain_test` 272 to 271, `state_test` 206
to 220, `network_test` 172 to 166, `reassembly_test` 170 to 193 -- and
only `err_str_test` and `peer_test` at 253 still held. The sentence
immediately above says a number is measured when it is quoted; the list
under it was quoted from a run that had already been superseded, twice,
by work in this same session.

**So the list is gone rather than corrected.** A per-binary inventory in
prose is a standing trap: it is wrong the moment anything is added, it
looks authoritative, and correcting it teaches nobody anything because
the next change breaks it again. What replaces it is the command --
`make test` prints every count, and the total is the sum of what it
prints. Where a specific figure matters to an argument, it belongs
beside that argument with the date it was taken, which is how the rest
of this document now carries them.

The shape generalises past this paragraph: **an inventory earns its
place only if something checks it.** Section 5a's scenario table
survives because a reader can run the harness and compare; a list of
counts survives nothing.
None reads a clock, so there is nothing in any of them that can pass on a
quiet machine and fail on a loaded one.

**`make test`** additionally builds the bindings and runs four more binaries
against real Ed25519, BLAKE2b and XChaCha20-Poly1305, because Monocypher is
vendored at `monocypher/` and the default no longer names a sibling. The
count belongs to the run, which prints its own; a figure here would be the
same trap this section has already sprung twice. The
sibling-directory-behind-a-variable shape §7 blessed for bring-up was
temporary and its step has been taken -- §15c decided it, and the paragraph
below §15c records what building it changed. `MONOCYPHER_DIR` survives as an
override, which is what §15c removed the default of rather than the knob.

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

### Guards that were correct and that nothing held to account

A 56-sabotage sweep on 2026-08-27 found two defensive checks whose removal
nothing in the 47-binary suite catches. Both are present and correct in the
shipped code; what was missing in each case was any test that would notice
them going away. They are recorded together because they fail the same way --
a check that cannot be the thing doing the refusing is a check nobody is
measuring.

**`fzn_record_is_open`'s body bound.** Sabotaging `body_len >
FZN_RECORD_BODY_MAX` to `if (0)` in `record/record.h` left every one of the
47 binaries green, `record_fuzz` included. What it costs: a 756-byte buffer
declaring a 600-byte body is refused by `fzn_record_open` as BODY_TOO_LARGE
and, without the bound, admitted by `fzn_record_is_open`, with
`fzn_record_body_len` then reporting 600 against a ceiling of 512.
`fzn_record_verify` gates on `is_open`, and `state/` and `log/` call it
directly before reading, so a record 88 bytes past the bound verifies and is
admitted through a gate `fzn_record_open` closes. The same divergence class as
the sequence-zero gap `record_fuzz` found, and the same consequence.

**`record_fuzz` held both halves of that case and never combined them.**
`corrupt_fields` writes `body_len = 513` and then probes at the genuine
`rec_len`, where the declaration and the buffer disagree -- so the length rule
refuses the buffer and the bound sitting above that rule is never what refuses
it. `sweep_lengths` varies the length and never touches `body_len`. Neither is
short of room: PROBE_CAP is 672 and the case needs 669, with three bytes to
spare, so this was never a capacity shortfall. Each mutated buffer is now
probed twice, at `rec_len` and at the length its own rewritten declaration
implies where that differs and fits, which reaches it -- 669 bytes declaring a
513-byte body, refused by `open` and admitted by a `is_open` without the bound.
The combined class found **nothing beyond the bound itself**, over 200000 cases
under AddressSanitizer and UndefinedBehaviorSanitizer. It costs no storage and
about 3.5 percent more run time (3.86s to 4.00s at 200000 cases), and it moved
real coverage: buffers `open` accepted rose 53676 to 67819 per 20000 cases and
BODY_TOO_LARGE refusals 21087 to 31648. `record_test.c` carries the case
directly as well, on a buffer deliberately larger than FZN_RECORD_MAX_LEN --
nothing this module signs can reach it, because `fzn_record_sign` refuses an
oversized body too, so only a hand-built view gets there, which is exactly the
input class `is_open` exists for.

**`chunk/reassembly.c`'s chunk ceiling.** Sabotaging `chunks >
FZN_REASM_MAX_CHUNKS` away while keeping the `chunks == 0` half left
`reassembly_test`, `reassembly_fuzz`, `reassembly_guided`, `roundtrip_fuzz`,
`split_test` and `sim/test/network_test` all green. Only
`chunk/test/agreement_test` failed, and it failed at the API level --
"chunks=257 should be schema-legal and code-refused" -- without ever reaching
what an admitted count does. `reassembly_test` already had an assertion for
it and that assertion could not fail: its slots are 64 bytes, so `payload_len
> buf_capacity / chunks` -- 8 against 64/257, which is 0 -- refuses a large
count whether the ceiling is there or not. A real refusal standing in as
evidence for a different one, which is `evidence.md`'s vacuous pass wearing a
sizing bound's clothes.

**What an admitted count does.** `seen` is
`uint8_t[FZN_REASM_MAX_CHUNKS / 8]`, 32 bytes, sized against that ceiling and
against nothing else. Measured on a 1-slot table with an 8192-byte buffer,
`chunks = 300` and a 16-byte payload: index 0 is admitted, because 8192/300 is
27 and the payload is 16, and index 260 is admitted too -- at which point
marking it seen writes byte 32 of a 32-byte array, one past its end and onto
the `fzn_partial_t` members that follow it. `live` came back 17. **No
sanitizer sees it**: the write stays inside the slot's own allocation, so the
object it corrupts is one it was allowed to touch, which is why no ASan run
has ever caught it. The new case uses a slot wide enough that division refuses
nothing, with exactly FZN_REASM_MAX_CHUNKS admitted as the control, so the
ceiling is the only thing left that can do the refusing.

### The tamper harness is generated, and it catches what ours did not

**Adopted 2026-08-27: `situc gen-tamper` over `wire/frame.situ`**, emitted
to `wire/generated/frame_tamper.h`, committed beside the other generated
sources and verified current by `make schema` -- which now reports
"contract, map, generated C, tamper harness and vendored runtime all
match", and was confirmed to FIRE by appending a line to the committed
copy. A harness that can drift from the schema is worth less than the
hand-written tests it replaces, so the staleness check is the point of
adopting a generator rather than a detail of it.

It takes our verifier as a callback and flips every byte the schema
declares tag-covered plus every tag byte, requiring refusal for each. On
the golden frame that is **163 flips** -- covered span at 5 for 147, plus
16 tag bytes -- and 164 verifier calls. **The call count is asserted**,
so a span computed as zero cannot return SITU_OK having asked nothing.

**It runs UNGATED, on every `make test`.** The stub AEAD in
`wire/test/seal_test.c` sustains an exhaustive walk because `stub_tag`
folds with `acc*31 + byte` over the associated data and `acc*17 + byte`
over the ciphertext: both multipliers odd, so every step is injective mod
256 and a difference at any byte reaches the tag. That was checked rather
than hoped -- the brief said a stub that could not sustain it would be a
FINDING about `seal_test`'s own tamper cases, not a reason to gate.

**What it buys, measured rather than argued.** Narrowing the AEAD's
sealed span by one byte at each end -- so the last payload byte falls
outside the tag while the round trip still succeeds:

  seal_test   112 checks, 0 failures   -- completely blind
  tamper_test 2 failures, naming byte 151, and its call-count guard fires

That is the case for a generated harness in one line. Our hand-written
tamper cases are sampled and hand-listed; this is exhaustive over the
schema's own coverage function, so it cannot drift when the layout moves.

**The control is permanent, not something run once.** A verifier that
restores byte 130 before opening must produce `SITU_ERR_CONSTRAINT` with
`failed_at == 130` exactly, and a call count showing the harness stopped
at the first byte it wrongly accepted. Without it, SITU_OK would be a
pass nobody had watched fail -- which is the failure this harness exists
to prevent, and reproducing it here would have been absurd.

**Half the generator does not apply, and the test says so.**
`payload[head.length]` makes `fzn_frame` variable-length, so gen-tamper
emits only the coverage half; the "bytes outside coverage must not change
the answer" half is for fixed layouts. The five hop bytes are never
flipped. `seal_test.c`'s hop-budget case and `golden_frame_test.c`'s
byte-1 rewrite are the two places that assert that half, and the file
points at them so a reader does not assume the generator covers it.

**`situc advise` was run at the same time and its one suggestion does not
apply.** It reports nine tag-covered fields writable in place, each write
costing a recomputation over 1147 bytes, and suggests moving the
often-rewritten ones out of coverage. Nothing rewrites them in flight:
the only caller of `expires_at_set` is `fzn_seal_build`, at construction,
before the tag exists. It reasons from DECLARED writability rather than
from actual rewrites. The one genuine in-flight rewrite is `hops_left`,
already outside coverage and declared `no_tag_invalidation` + `in_place`.
Recorded as a checked negative so the next session to run `advise` does
not re-investigate it.

**And `--out` exists.** This document nearly recorded that `gen-tamper`
writes only into the working directory, which is true of its default and
not of the tool; it takes `--out` as `situc build` does, so nothing it
writes lands outside `BUILD_DIR`. The claim was made from one invocation
and corrected by someone who read the interface.

### A mutation's catch belongs to one binary, and the suite hides which

**Rule, 2026-08-27, and it is the sharper half of the one below.** That
rule says what input to build. This one says where to look for the
answer: **run the module's own test, not the suite.** "The suite catches
it" and "this module's test catches it" are different claims, and the
first reads exactly like the second.

Found by paying for it twice on the same day the sweep was run. Four
sites were recorded as covered on the strength of `make test` going red,
without asking WHICH binary went red. Three were genuine. Two were not:

- **`frame/freshness.c`'s nonce comparison.** `freshness_test`: 120
  checks, 0 failures. `receive_fuzz`: order held throughout. Only the
  integration harness objected, and only as "not every message arrived
  on a lossless network" -- a downstream symptom naming nothing. The
  module whose entire job is refusing replays could not tell whether it
  compared whole nonces.
- **`record/journal.c`'s issuer comparison.** `journal_test`: 66 checks,
  0 failures. `record/test/sync_test.c` caught it, reporting "one
  position produced more than one request" -- a different module's test,
  describing a symptom in its own vocabulary.

Both are fixed and both now fail by name in their own suite. Every one
of the eleven mutations in the session's battery is now caught by the
test of the module it lives in.

**Why the suite hides it, mechanically:** `make test` stops at the first
failing binary, so a mutation caught by an early test says nothing about
the later ones -- and a mutation caught only by a LATE test looks
identical to one caught by its own. Neither ordering tells you anything
without asking. The cheap form is `make <path-to-test-binary>` and run
that one binary, checking its mtime moved first.

**And the direction of a missing refusal decides how bad it is.** A
check that fails OPEN is an authorization defect; one that fails CLOSED
is a denial of service, and closed is the harder of the two to notice
because the component's job is to refuse and it is still refusing. The
journal's truncated issuer is the second kind: two issuers share one
position, admitting the twin's record advances the first's, and the
first's genuine next record is refused as a duplicate for ever. Nothing
reports it, because refusing is what a journal does.

### A comparison is only tested by inputs that share a prefix

**Rule, adopted 2026-08-27 in a consumer session's words because they are
better than the ones this tree reached:** a key comparison is only tested
by inputs that AGREE ON A PREFIX AND DIFFER AFTER IT, and nothing
produces those by accident.

Found by an adversarial review of the revocation-issuer fix. Every
identity in every `chain/test/` fixture is `memset(buf, seed, 32)` --
thirty-two copies of one byte -- so any two differ at byte 0, and
truncating `fzn_ct_memeq(..., FZN_PUBKEY_LEN)` to **one byte** left the
whole suite green, 200000 fuzz cases included. The shipped code was
correct. The coverage was theatre.

**THE IDIOM IS NOT THE PROBLEM, WHICH IS WHY THIS IS A RULE AND NOT A
STYLE NOTE.** Told about it, the fuzzypickles session swept its own tree
and found four vacuous pins -- including a root pin whose comment reads
"the check an attacker's chain is built to slip past" -- and their
fixtures are the OPPOSITE idiom: independently generated random keys,
which differ at byte 0 roughly 255 times in 256. Uniform keys and random
keys fail identically. Reaching for "stop using memset" would have been
the wrong lesson.

Swept across this library, ten sites outside the ones already in hand.
**Four caught, six vacuous**: `record/journal.c`, `frame/freshness.c`,
`session/commitment.c` and `trust/trust.c` catch it; `log/log.c` at two
sites, `state/state.c` at two, `record/sync.c` at two and
`chunk/reassembly.c` did not.

`trust/` catches it for exactly the reason the consumer's tree became
testable: its test already used "a second root differing in a single
byte". **That was the only place in this tree with the shape, it had
been there for weeks, and nobody generalised from it -- including this
document, which quotes that test approvingly two sections above.**

Three things the sweep cost, recorded so the next one is cheaper:

- **One case per COMPARISON, not per file.** Closing `log.c`'s `find()`
  left `fzn_log_range` vacuous: separate loop, separate function, same
  file. Caught only by re-running the mutation on both lines rather than
  declaring the file done.
- **Perturb a PARAMETER rather than a fixture where you can.** A value
  the caller supplies can be made to near-miss at the last byte, which
  catches truncation at any prefix; grinding a shared prefix into a
  fixture only ever catches a short one.
- **Some pins are untestable without key grinding, and that belongs IN
  THE TEST.** Where both sides of a comparison come from inside one
  signed object -- `chain/chain.c`'s grantor-against-previous-grantee is
  this shape -- neither can be perturbed from outside. Saying so in the
  file is what stops the next reader assuming three pins means three
  covered.

The failure mode here differs from the consumer's and is worth
distinguishing. Their vacuous pins were on ADMISSION paths, so a short
compare lets something through. All six of ours are on LOOKUP paths --
find an entry by issuer, match a slot by sender -- so the failure is
cross-identity CONFUSION: one issuer's log entry answering another's
question, one sender's reassembly slot taking another's chunks. Less
alarming to read and worse in one respect, because the wrong answer is
returned successfully and nothing reports it.

### Handing a commit to a consumer: make them fetch it

**"Landed and green" and "published" are different facts, and the first
reads like the second.** Recorded 2026-08-27 because this tree got it
wrong with a real consumer on the same day it was being careful about
everything else.

A fuzzypickles session was told the cross-root revocation fix had
"landed and is green", with a SHA, and invited to move its vendored pin.
Every gate had passed -- test, style, installcheck, fuzz, guided -- and
the tree was clean. It was also **66 commits ahead of `origin/master`**,
so the named commit existed nowhere but here. The consumer found out by
trying to act on it: `git fetch` moved origin to a commit that was not
it, and `git log -1 <sha>` said *unknown revision*.

The published head at that moment still had `fzn_revocation_covers` with
no issuer parameter -- the defective signature -- and
`session/commitment.c` still carried the single retired
`FZN_KDF_LABEL "fuzznet-kdf-v1"` rather than the two current labels. So
anyone vendoring on the strength of that message would have taken the
defect, and a frame vector generated from it would have pinned a retired
layout while reading as though it pinned the current one.

**The rule: hand over a commit by having the other side FETCH it, not by
naming a SHA.** A fetch that fails is self-correcting; a named SHA is a
claim the receiver cannot check until they have already reorganised
around it.

This is `evidence.md`'s "a claim about another tree is a measurement you
did not take" pointed the other way, which is the direction it is easy to
miss: the unmeasured claim was about **this** tree's visibility to
somebody else, which feels like the safe case and is not. One
`git status -sb` would have answered it at any point. It was not run
because the gates were green, and green felt like done.

The verification that should accompany a push is `git show
origin/master:<file>` after a fresh fetch -- read the artifact, not a
fresh measurement of where it came from -- rather than looking at the
working tree the push came from.

### The reassembly fuzzer, and what it can and cannot see

`chunk/test/reassembly_fuzz` runs a bounded, seeded sweep over
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
shape `situ/suggestion/fuzznet.md` names: a target that reaches nothing
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
| `session/commitment.c` | 100% of 24 | 100% of 20 |
| `local/peer.c` | 100% of 42 | 100% of 52 |
| `local/vocabulary.c` | 100% of 20 | 100% of 26 |
| `local/peer_linux.c` | 95.7% of 23 | **66.7% of 12** |
| `chain/chain.c` | 100% of 64 | 100% of 84 |
| `chain/revocation.c` | 100% of 42 | 100% of 56 |
| `frame/freshness.c` | 100% of 43 | 100% of 44 |
| `chunk/reassembly.c` | 100% of 98 | 100% of 98 |
| `chunk/split.c` | 100% of 24 | 100% of 28 |
| `wire/seal.c` | 99.0% of 96 | 70.6% of 102 |
| `session/random.c` | 100% of 5 | 100% of 8 |
| `session/random_linux.c` | 86.7% of 15 | **66.7% of 12** |
| `chain/sign_monocypher.c` | 100% of 17 | 100% of 8 |
| `session/hash_monocypher.c` | 100% of 9 | 100% of 6 |

**Every branch in the library goes both ways now, with one exception, and the
exception is the point of the table** (2026-08-18). Closing the rest took
about ninety dull assertions -- every pointer of every entry point refused one
at a time -- and the percentage was never the reason. Nearly every unexercised
branch here was one of those chains, so the report was a wall of
known-defensive gaps, and **two real defects sat in the middle of it for weeks
because nobody read far enough**. The gaps were not hiding the bugs; they were
making the report not worth reading, which is the same thing more slowly.

Three of those assertions were not null checks and had never been taken:
`signed_region_len == 0`, where a hop would be signed over nothing; the zero
length of a **last** chunk, which is a different branch from the sizing path's
because a last chunk may legitimately be short, and an empty one would complete
a message a byte short of what its sender sent; and a slot in a table carrying
a buffer pointer with no capacity.

**And the first thing the newly-quiet report found was in the previous day's
fix.** `if (total > slot->buf_capacity)` had been left in `admit_first` as
defence in depth beside the division guard that replaced it -- and it is
unreachable, since `floor(capacity / chunks) * chunks <= capacity` for every
positive `chunks`. It is deleted along with the wrapping multiplication that
fed it: dead code that cannot be tested is not depth, and leaving a wrapping
multiplication in the file for a reader to puzzle over is worse than not
having it. `reassembly.c` is six lines shorter and the fuzzer's counters are
unchanged.

**Two sources were missing from the table entirely, and from the guard**
(2026-08-18). `chain/sign_monocypher.c` and `session/hash_monocypher.c` build
only when `MONOCYPHER_DIR` names a checkout, and **`SRCS` never listed them** --
so `make coverage`, whose job includes refusing when a source is exercised by
nothing, could not see either. They were built, linked and run by their own
tests the whole time; the guard simply did not iterate over them.

That is `GEN_SRCS` against `SRCS` for the third time in this file, and the
second time in this exact spot: an earlier session had already added
`TEST_SRCS += $(MONO_TSRC)` for the identical reason, writing that "TEST_SRCS
is the list that reads as *every test source*, and one that is quietly
incomplete is a trap for whatever asks it next". The trap was one list over.

**The moment the guard could see them it reported four unexercised branches**,
and one was worth having: `mono_sign` refuses when `can_sign` is clear, because
signing with a zeroed buffer produces a valid signature under the public key a
zero secret derives -- a real key owned by nobody, which a verifier would
accept. Nothing had ever asked it to refuse. Both files are at 100% now.

**And that configuration could not pass its own gates.** With the bindings
built, `install` ships their two headers, so `make installcheck` refused --
correctly, with "the check would pass whatever those headers did", which is a
guard added here for `commitment.h` and `peer.h` firing on a case nobody had
run. `tool/consumer_check.c` exercises both bindings now, behind
`FZN_CONSUMER_MONOCYPHER`, and the Makefile passes the include path and
Monocypher's own source because installcheck compiles sources rather than
linking objects. Absolute paths, since its second arm compiles from inside the
staging directory -- a relative one builds in a single arrangement, which is
the difference that target exists to find.

**The pattern is checked now, not just fixed.** Four times in this repository
a hand-maintained list has gone quietly incomplete, and each time the guard
that should have noticed was only as wide as the list it iterated:

| list | guard | how it was found |
|---|---|---|
| `HDRS` | `install` shipped a hand-written line per header | a break in an uninstalled header |
| `GEN_SRCS` | `coverage` iterated `SRCS` only | three generated sources touched by nothing |
| `TEST_BINS` | `.gitignore` names each binary | a build product in `git status` |
| `SRCS` | everything that reads it | the Monocypher bindings, above |

The first three are compared against another list. `SRCS` has no second list,
so `make style` compares it against **the filesystem**: every `.c` in the tree
must appear in `SRCS`, `TEST_SRCS`, `GEN_SRCS`, the Monocypher names, or be
`tool/consumer_check.c`. 34 today. It refuses if it finds none, and the
Monocypher filenames are declared outside the `ifneq` so the answer is the
same in both configurations -- inside it they would be empty in a plain build
and the check would report two real sources as unlisted, which is a false
finding, and a gate that cries wolf is worse than no gate.

Controlled in both directions, since they are different mistakes: dropping
`chunk/split.c` from `SRCS` names it, and a new `.c` written into the tree
names that instead. The second is the case it exists for.

**The library had been assuming its callers would get randomness right, and
never said so** (`session/random.h`, 2026-08-18). `frame/freshness.h` and
`session/aead_monocypher.c` both explain that 24 bytes is what makes a
*random* nonce safe without a counter negotiated per session -- which is what
lets §13 have a self-contained frame at all. Neither of them, nor anything
else here, produced one.

That is not a small gap. Reusing a nonce under one key with
XChaCha20-Poly1305 does not weaken the seal, it removes it: two frames under
the same key and nonce leak the XOR of their plaintexts and the Poly1305 key
with them, which is forgery for everything after. **It is the one caller
mistake the receiver cannot catch** -- the replay window sees a repeated
frame, not a repeated nonce on two different frames.

A seam, like the signer and the hash, and what it adds over calling
`getrandom` directly is the rule: **all or nothing, and never a fallback**.
`fill` succeeds only if every byte came from the source; a short read is a
failure rather than a smaller nonce, and a failed source is a refusal rather
than a reason to reach for something weaker. `fzn_nonce_next` zeroes the
buffer on failure, so a caller who ignores the return value sends zeroes --
wrong in a way somebody notices -- instead of most of a real nonce, which is
the case that looks fine in a capture.

`session/random_linux.c` loops over `getrandom`, because it is documented to
return fewer bytes than asked, and retries only on `EINTR`. On a platform
without a source it leaves `fill` null and every nonce request fails, which
is `local/peer_linux.c`'s choice and for a stronger reason: a stub returning
plausible bytes would be a nonce source with no entropy in it, and every
frame it sealed would be forgeable.

Its 66.7% is `peer_linux.c`'s situation exactly -- the unexercised branches
are `getrandom` failing, returning zero, and being interrupted, none of which
can be provoked without a fake syscall. The rule they feed is tested where it
lives, against stub sources that fail in each of those ways.

Both sabotages bite, and one of them differently from the rest in this
document: removing the zero-on-failure fails two assertions, and removing the
null-`fill` guard **segfaults**. A crash is a catch -- `make test` fails on
it -- but it is worth naming as a crash rather than counting it as an
assertion, because the two are not the same evidence.

**`wire/seal.c` is at 79.2% and the number is partly an artifact.** Of its
unexercised branches, some are defensive guards that `situ_fzn_frame_validate`
has already made unreachable -- `tag_covered` failing, a null tag pointer, a
covered span shorter than the head -- and the rest are **inside inlined
generated accessors**, attributed to the line that calls them. `out->payload =
situ_fzn_frame_sealed_payload_ptr(gate)` is an assignment with no branch of its
own. So the file's branch count is not entirely its own code, which is worth
knowing before anyone reads it as thin testing: the seam has 34 assertions
over it and two sabotages confirming they bite.

**`local/peer_linux.c` stays at 66.7% deliberately.** Its four unexercised
branches are `getsockopt` returning a short credential struct, `snprintf`
failing on a fixed-size buffer, `fopen` failing, and `ferror` after the read
-- the paths where the system refuses to answer. Reaching them needs a
`/proc` that lies or a pid that has gone, and the file takes no path argument
to inject one. It is left rather than chased because **the decision those
paths feed is tested where it lives**: every one leaves `groups_known` clear,
and `peer.c` turns that into `UNKNOWN`, which denies, and that is asserted
directly. Chasing the branches would test the plumbing around a decision
already covered. Recorded here so the number reads as a judgement rather than
an oversight -- an unexplained gap in an otherwise clean report is how the
next real one gets ignored.

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

**A fourth, and the most serious, came from reading the report differently**
(2026-08-18). The three above were found by the summary numbers moving. This
one needed the per-branch detail: `gcov -b` names which branches never went
both ways, and reading each one to decide whether it was defensive or a gap
turned up an unchecked multiplication in `admit_first` whose only backstop was
a guard neither half of which had ever been taken. See §4.4. Of the tree's
unexercised branches the great majority are argument-validation chains, which
is why nobody had looked: **a report whose gaps are all known-defensive is a
report nobody reads**, and the four that were not defensive were sitting in
the middle of it.

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

All the suites and every fuzzer pass under it. **Re-run 2026-08-18 after the
three arithmetic fixes above: 17 binaries clean, and 2000000 cases per harness
-- 12 million across the six -- with no invariant broken and every model
agreeing.** The fuzzers' counters are identical to the plain build's at the
same case count, which is the check that the instrumented binaries walk the
same paths rather than falling out early somewhere.

That run found nothing in the library, which is worth stating as a result
rather than as an absence of one: the three defects fixed that day were found
by reading, and a sanitizer would not have caught any of them. Each was a
refusal that should have happened and did not, or arithmetic that wrapped
without ever being dereferenced -- ASan sees a bad access, not a bad decision,
and UBSan does not consider unsigned wraparound undefined at all.

**It did find one thing, in the tooling.** `make test SANITIZE=1` was
impossible for a day, because `codegen_gate.py` refused it: under ASan
`fzn_ct_memeq` compiles to 118 instructions with sixteen conditional branches
-- the shadow-memory checks -- and the accumulator moves off the stack frame
the store pattern looks for. None of that is the property failing. The
constant-time claim is about the build people ship and nobody ships a
sanitizer build, so the honest answer is that the check does not apply. The
gate detects `__asan_`/`__ubsan_` symbols now and skips loudly.

Worth naming, because it is the shape of mistake this document keeps
recording: **a check written for one build configuration silently became a
gate on every configuration**, and the target it blocked was one the Makefile
documents in its own header. It was caught by using the feature rather than by
anything checking the checker.

The earlier campaign was 300000 cases per harness. **That the run is real was checked rather than
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

`chain/test/chain_fuzz` and `frame/test/freshness_fuzz` followed. `chain.c`
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

`chunk/test/roundtrip_fuzz` is the only harness that holds two modules to
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

`chain/test/revocation_fuzz` covers the admission path, which nothing else
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
commitment[16] | ciphertext | mac[16]`: 82 bytes of header plus a 16-byte MAC,
**and 8 more inside the ciphertext**, so **106 in all** against this schema's
**144**. Two designs reached the same order of overhead independently, which
is worth knowing before treating 144 as an aberration.

**The 8 was missed twice, and the second time it was handed over.** This
section said 98 -- header plus MAC -- and so did fuzzypickles when they
confirmed the figure and invited us to cite their constants rather than them
(2026-08-25). Taking the invitation is what found it: `peer_wire.h` states
*"Total datagram length = FZP_PEER_HEADER_LEN + 8 + text_len +
FZP_PEER_MAC_LEN"*, and the 8 is the sender's stime, encrypted with the text
and never a cleartext field. `FZP_PEER_MIN_FRAME` corroborates independently
at 82 + 8 + 1 + 16 = 107, which is 106 of overhead and one byte of text.

**The two numbers were being computed by different rules**, which is the
substance rather than the arithmetic. This schema's 144 counts the 32-byte
`capability` that lives INSIDE the sealed region, because those are the
library's bytes and not the consumer's. Their stime is the same kind of thing
-- protocol-owned, in the ciphertext, not the application's text -- and was
being left out. Counted the same way on both sides it is 106 against 144.

**Which sharpens this section's own question.** It exists to ask whether the
32 bytes `capability` costs are worth reclaiming, and the honest contrast is
that fuzzypickles spends **8** in-seal bytes on protocol state where this
schema spends **32**. That is a four-fold difference the old figures hid by
putting their in-seal bytes on the payload's side of the ledger.

**This comparison said 96 twice, in the section that opens by correcting 96.**
The paragraph above it records that the number was stale and gives 144; these
two sentences kept the old one, so the section refuted itself four lines apart
and the arithmetic it invites -- 98 against 96 -- made the two designs look
identical rather than the same order. Found on 2026-08-20 by following a
citation *from* fuzzypickles back here, which is the only reason anybody read
these lines again.

The verified figures are theirs at `peer_wire.h`'s
`FZP_PEER_HEADER_LEN (1 + 1 + 32 + 32 + 16)`, plus `FZP_PEER_STIME_LEN 8`
inside the ciphertext and a trailing `FZP_PEER_MAC_LEN 16`, and ours at 144.
The conclusion is unchanged and better supported at each correction: 106 and
144 are the same order, and neither design found a way to be cheap.

More instructive is *what* it spends the bytes on. There is **no nonce field at
all** -- the AEAD nonce is all-zero, which is safe only because a fresh
ephemeral makes the derived key single-use **for the sender's
contribution, which is the qualifier their own header carries and this
document dropped** (`crypto_msg_internal.h:82`). So it pays 32 bytes for an
ephemeral rather than 24 for a nonce, and 32 more to say who is speaking. That
is a deliberate purchase: **every datagram is self-contained, and no session
state is required at either end.**

**AND CALLING THAT "32 BYTES RATHER THAN 24" UNDERSTATES IT, WHICH THIS
PARAGRAPH DID UNTIL 2026-08-28.** It is not a byte trade, it is a
GUARANTEE difference, and the consumer asking a direct question is what
surfaced it. Their fresh ephemeral per message makes the derived key
SINGLE-USE, so a compromise of their long-lived key does not open
messages already sent. **fuzznet has no equivalent and therefore no
per-message forward secrecy.** `session/commitment.h` says so at the
derivation without drawing the conclusion: the AEAD key is
"**Long-lived, per peer, and IT TAKES NO NONCE**", derived once over a
transcript and reused for every frame, with only the nonce varying.
Compromise that key and every frame ever sealed under it opens.

So the 38-byte adoption delta cuts both ways and should be read that
way. Their side of the decomposition -- 33 bytes we do not carry, 32 of
them the ephemeral -- is not overhead we avoided. It is a property we do
not have. Sec 14 carries it as open; it had been carried nowhere at all,
in a document that compares the two frames four times.

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

## 13a. The design pass of 2026-08-26, and what it settled

Eight parallel reviews, each given a distinct question and several deliberately
not told the position being tested. What follows is what they settled and what
they overturned. Every finding below was reproduced by a probe against this
tree's own sources before it was written down.

**The framing fact, which changes what "expensive" means here.** No consumer
calls this library. `fuzzypickles` vendors it as a submodule and references
zero `fzn_` symbols from its own code; `netcfgd` has no linkage and no crypto
crate in its lockfile; `raidcfgd` compiles exactly one file of it into one test
binary and uses `fzn_peer_from_fd`. So every change below costs the consumer
trees nothing today, and none of them will ever be cheaper. Where an argument
in this document weighs API churn against correctness, that weight is currently
zero.

### The binding defect, and why the reason for it had expired

The three signed objects each carry an opaque `signed_region` plus PARALLEL
decoded fields, and nothing compares them. `chain.h:129-142` and `record.h:23`
decline to reconstruct the bytes because "recomputing them would put a SECOND
encoder in the tree for the schema to disagree with later."

**There is no first encoder.** Measured: no hop or record encoder or decoder
exists anywhere in this tree, `wire/frame.situ` describes neither object (its
`fzn_hop` is the forwarder header, a different object sharing a word), and no
consumer supplies one. The design avoided a second encoder by having zero, and
with zero the correspondence has no producer and therefore no guarantee.

Two consequences the tree already showed and nobody had read that way:

- **`fzn_chain_mint` cannot be used as specified.** It takes `signed_region` --
  the encoded hop -- as an INPUT, so to mint a hop you must already have
  encoded one. Its field parameters are decoration over `sign->sign()`.
- **The only code that produced agreement invented a non-format.**
  `sim/test/network_test.c`'s `sim_sign_hop` memcpy'd the struct, padding
  included. That binds within one process and one ABI and cannot cross a host.

Reproduced: a hop the root minted for one grantee, one capability, expiring,
non-delegable, verifies with signature and region byte-identical as a different
grantee, a different capability, never expiring, and delegable. A single-hop
chain is therefore a complete authorization bypass needing one genuine
root-signed triple, which every deployment has by construction.

**The decision: the three objects become views over a canonical encoding, with
every field an accessor over the bytes the signature covers.** Agreement stops
being contractual because there is nothing left to agree.

The reasoning that settles it against the alternatives: **an encoder is
unavoidable in every option that closes the hole**, including re-encode-and-
compare, since mint must produce bytes and any verifier must relate bytes to
fields. Once the encoder exists, deriving the fields from those bytes costs
nothing and deletes the whole defect class. A caller-supplied binding predicate
was rejected on this document's own argument about the root pin -- "one
function with an optional pin is a function somebody calls without the pin" --
and because it makes the property only as strong as the least careful consumer.

**`fuzzypickles` reached the same place independently and by a third route**,
which is the strongest evidence in the pass. `core/src/capability.c` verifies
with a decode cursor: `hop_start = r.pos`, read the fields, `signed_len =
r.pos - hop_start`, then check over `chain_blob + hop_start`. The signed span
is DERIVED FROM THE DECODE, so fields and covered bytes are one act. Its
encoder exists and is used only on the mint path, so `chain.h`'s objection to
re-encoding is honoured whole while the binding is structural.

**Two bytes go inside the signed range, and they are new protocol rather than
plumbing.** A `version` byte, on `frame.situ`'s own argument applied to objects
that outlive schema revisions harder than a frame does because grants do not
expire; and an `object` byte separating hop from revocation from record,
because one root key signs all three through one seam over opaque bytes.

`fuzzypickles` paid for the second one. Its `core/src/signed_tag.h` exists
because two of its record types collided -- "Both are 73 bytes when the name is
30 long... ONE SIGNATURE VERIFIES AS BOTH" -- and that file names its own
capability chain, whose version and hop count sit OUTSIDE every hop signature,
as the remaining instance of the anti-pattern it was written to fix. This
library is designing that transcript from scratch and takes the tag inside the
signed range from the start rather than inheriting a shape its sibling has
already identified as wrong.

Neither byte can be added later without a wire break.

### `state/`'s clear path, completed 2026-08-27

Three findings from an independent audit turned out to be one: **the clear
path was underdeveloped relative to the apply path, and every gap in it failed
dangerous** -- the direction where a revocation does not land.

**A clear arriving before the apply it supersedes was dropped.** A clear with
no cell answered ABSENT and stored nothing, so:

    { apply(alice, stream 7, seq 5, GRANT), clear(alice, stream 7, seq 10) }
    apply then clear -> revoked
    clear then apply -> THE GRANT STANDS

Two values from one set, which is exactly what `state.h`'s headline invariant
forbids -- and the refusal was byte-identical to clearing a subject nobody
ever set, so a consumer could not tell "your revocation was dropped" from
"there was nothing to revoke".

**A clear of an absent cell now leaves a tombstone**, and the objection a
previous pass raised against that does not survive measurement. It was that a
stream of clears would fill a state holding no values. But `slot()` forgets a
tombstone BEFORE refusing a new subject, so a state full of tombstones still
admits every live setting offered to it -- a flood costs evictions, never
service. The old rule, meanwhile, spent slots on live records for junk
subjects, and those are NOT evictable. It was the worse denial, not the safer
one.

`FZN_STATE_ERR_ABSENT` becomes `FZN_STATE_ABSENT`, same value. It is no longer
a refusal -- the record is stored -- and it reports what was true BEFORE the
clear, which is what a revoker wants to know. That leaves `ERR_` meaning
exactly "stored nothing", which turns "a refusal is visible" from a sentence
into something checkable.

**The fourth combination is a fourth name.** `resolve` is override-and-live,
`clear` is neither; there was no override-and-clear, so a revocation from
another writer could only be installed through `resolve` -- which stores it as
a LIVE setting, and the permission then reads as GRANTED, by the revoker.
`fzn_state_resolve_clear` is a separate entry point rather than a flag, on
`chain.h`'s argument that "one function with an optional pin is a function
somebody calls without the pin". Overriding another writer is the dangerous
half of each axis and now has to be typed.

**THE ALARM COUNTS DO NOT CONVERGE, AND THE HEADER STOPS CLAIMING THEY DO.**
Over the six orders of three same-sequence records, `ABC` gives one
CROSS_STREAM and one CONFLICT while `CAB` gives two CONFLICTs. The
order-dependence is not in the comparison rule but in WHICH WRITER THE CELL
HOLDS, and that is first-writer-wins among incomparable writers -- policy the
header already documents, and already lets make the VALUE order-dependent.

Converging the counts would need every writer that ever contended to be
remembered: unbounded storage in a module that allocates nothing, and a
bounded loser list would go order-dependent on overflow -- trading a visible
divergence for a hidden one. No mechanism was invented. What the header says
instead is the part that IS safe and checkable: a record from a writer other
than the holder is ALWAYS refused as one of the two, never STALE and never
accepted. Both halves are pinned, and folding the two codes together leaves
the safety half passing while the pins go red, which is how they were shown
to be independent claims.

**The permutation property was the test that should have caught A and could
not.** It ran 120 orders of five records and called only `fzn_state_apply`.
It now dispatches per record through apply or clear and runs 40320 orders of
eight. 124 checks to 206.

### The commitment stops being a correlator, 2026-08-27

`commitment[16]` was `f(transcript)`. The transcript is long-lived material --
the simulation models exactly what the design intends, a key and its
commitment per (sender, receiver) pair -- so **the commitment was a constant
per pair, in the clear, on every datagram**, beside `sender[32]`.

Any observer reads both together and gets the endpoints of every conversation.
That includes a relay, which sec 3 makes an unprivileged bridge handling frames
it is not trusted to author, and relays are the next thing arriving. It also
defeats the reason sec 13 gives for moving `capability[32]` INSIDE the seal --
"in the clear it announces which authority is being exercised, so the frames
worth attacking identify themselves." The same argument applies to a per-pair
constant and had never been made about it.

**The fix costs zero wire bytes.** The derivation splits in two:

    fzn_commitment_derive_root(transcript)   -> AEAD key + commitment key
    fzn_commitment_for_nonce(commitment key, nonce) -> this frame's commitment

The nonce is already in the clear and already unique per frame, so the
commitment becomes unlinkable across frames while staying checkable before
decryption, which is what sec 4.7 needs.

**THE KEY MUST NOT DEPEND ON THE NONCE, and that is enforced structurally
rather than by a comment**: the root's declaration has no nonce parameter and
the per-frame hash has no transcript parameter, so neither mistake is
spellable. Two peers must derive one key without having seen each other's
nonces, and a key that varied per frame would need the nonce before the key --
an order the receive path cannot offer, since it picks a key at step 2.

**Two labels, and the collision they prevent is concrete rather than
abstract.** Without them the root hashes `transcript` and the per-frame hash
hashes `commitment_key | nonce`, so a 56-byte transcript equal to some pair's
commitment key and nonce derives an AEAD key whose first 16 bytes are that
pair's published commitment. The suite builds exactly that. The root's label
is bumped to `v2` because the derived block went from 48 bytes to 64 and a
pre-change peer must not appear to agree.

**WHAT IT COSTS, MEASURED, because the brief that commissioned this said "far
cheaper" and that was wrong.** At `-Os` against Monocypher on a loaded
machine, so upper bounds: the per-frame derivation 560 ns against a 47 ns
compare, an AEAD open rejecting a full 1024-byte payload 2120 ns and a
64-byte one 1260 ns. **So the saving is about 3.5x at maximum payload and
about 2x on a small frame -- real, and not the order of magnitude asserted.**
The number is in `commitment.h` rather than the phrase, because a consumer
sizing a candidate-key set needs the figure and not a reassurance.

**What is given up.** `wire/relay.h` calls the commitment "addressing by
decryption" -- a receiver knowing a frame is its own because the commitment
matches one it derived. With K candidate keys that becomes K hashes rather
than K table lookups. A consumer wanting a table back can key it on `sender`,
which is a per-peer constant this change does not pretend to hide.

### The layouts, and what they cost on the wire

Big-endian, fixed width, no padding, fixed fields first so every fixed field
sits at a constant offset, and one variable field last. That shape is situ's
`AbsoluteStatic`, chosen so that adopting a schema for these objects later is
a regeneration that must reproduce the same numbers rather than a rewrite.

    hop body        115 bytes   version | object | grantor[32] | grantee[32] |
                                capability[32] | issued_at | expires_at |
                                delegable
    revocation body 106 bytes   version | object | capability[32] |
                                grantee[32] | issuer[32] | issued_at
    record header    92 bytes   version | object | issuer[32] | subject[32] |
                                stream | kind | seq | issued_at | body_len

Each is followed by a 64-byte signature, giving FZN_HOP_LEN 179,
FZN_REVOCATION_LEN 170, and a record of 92 + body + 64.

**Two consequences worth having in writing**, both computed from the
constants in force rather than asserted:

- **A record always fits one datagram.** At FZN_RECORD_BODY_MAX of 512 the
  largest record is 668 bytes, inside `frame.situ`'s `length [max = 1024]`.
- **A full-depth chain does not.** Eight hops is 1432 bytes, 1434 with a
  container, so chains travel through `chunk/`. fuzzypickles reached the same
  place -- its `FZP_CAP_CHAIN_BLOB_LEN` is `1 + 1 + 8 * FZP_CAP_CHAIN_HOP_LEN`
  for the same reason.

**Canonicality becomes enforceable at parse, which the current design cannot
do at all**: `delegable` must be 0 or 1 rather than "any nonzero", the version
and object bytes must match, the length must be exact, `body_len` must agree
with the buffer. Two byte strings can no longer mean one hop.

**Parse checks layout; verify checks semantics.** `fzn_hop_open` refuses a
wrong length or a non-canonical flag; it does not check `expires_at >
issued_at`, which stays in `fzn_chain_verify` where the error taxonomy
distinguishes it from a shape fault. Both modules gain a `..._ERR_SHAPE`,
because bytes from a peer that are the wrong length are not a caller bug and
MALFORMED means "the caller has a bug" throughout this library.

### What the binding landed as, 2026-08-27

Implemented and merged. The three objects are views; every field is an
accessor over the bytes the signature covers; and the defect is closed in the
only way that closes it, which is to leave nothing for a field to disagree
with.

**Verified against the attack rather than against the suite.** A hop the root
minted for one grantee, non-delegable and expiring, with `grantee`,
`capability`, `expires_at` and `delegable` all rewritten in the buffer and the
signature left untouched, is refused. It verified before, and authorised the
attacker for any capability, for ever. A record with `seq` rewritten is
refused, and so is one with `stream` rewritten -- the first resurrects a
revoked permission through `fzn_state_apply`, the second wedges a cell at
CROSS_STREAM permanently, which is a revocation that never lands.

**Two additions beyond the design as written.** `FZN_CHAIN_ERR_SHAPE` and
`FZN_RECORD_ERR_SHAPE`, because bytes from a peer that are the wrong length
are not a caller bug and MALFORMED means "the caller has a bug" throughout
this library. And a chain container -- `fzn_chain_open` with a matching
`fzn_chain_pack` -- taken on the reasoning that a reader with no writer is a
writer every consumer invents, which is the same argument that produced this
library.

**What the conversion turned up in the callers is the finding worth keeping.**
`tool/consumer_check.c` -- the file a consumer reads to learn the installed
headers -- pointed `signed_region` at the literal "a signed region" while
filling `grantor`, `grantee` and `capability` separately, and asserted
FZN_CHAIN_OK. It was teaching every consumer the exact arrangement that made a
captured signature reusable. And the simulation's `sim_sign_hop` signed the
STRUCT, padding included, which binds within one process and one ABI and
cannot cross a host boundary. That was the only thing in the tree producing
any agreement at all between a hop's fields and its signed bytes, and it was
in a test.

**Three scenarios got shorter.** Delegation minted into a buffer and then
re-pointed the hop at the recipient's storage; a hop is its bytes now, so
minting into the recipient's array is the whole of it. Substitution copied a
chain and re-pointed every region; it copies bytes and opens them, which is
also a truer picture of the attack, since a chain travels in the clear and
copying it is all an attacker does.

**And the guided fuzzer caught the oracle rather than the code.** After the
merge, `record_guided` began crashing on a clause asserting that a sequence at
or above the journal's position answers ABSENT outright. That is false: the
harness drives the log and the journal independently, so a record can sit in
the log with the journal never told, and `fzn_log_get` correctly answers OK.
The invariant is narrower -- HELD IS HELD, and the position decides only which
of the two NOT-HELD answers you get. A model written from the same
understanding as the code is one witness wearing two hats, and this is the
third time today that shape has been found in this tree.

### The receive order: §4.7 step 3 moves below step 5

§4.7 puts replay at step 3 and tag verification at step 5, so the window is
written before authentication. The rationale given is cost -- the cheapest
place to stop a replay.

**The rationale inverts under measurement.** `fzn_replay_admit` is O(used)
twice per datagram, before authentication:

    window used    ns per unauthenticated datagram
    256            571
    1024           2251
    4096           11284

against 706 ns for a 144-byte AEAD verify and 1627 ns for a full payload. At
any window a real deployment would size, the pre-authentication scan already
costs more than the verify it was supposed to save -- 6.9x at 4096.

The saving it does claim holds only against a blind attacker, because
`commitment[16]` is a CLEARTEXT field: anyone who has seen one genuine frame
copies it and is past the commitment gate for free.

**And the premise survived every attempt to break it.** "A replay is authentic
by construction, so it passes the tag anyway" was attacked on four cases --
a different receiver, after key rotation, a chunk of a multi-chunk message,
and under a group key -- and holds in all four. The rotation case argues FOR
the change: an old frame under a new key is refused at the commitment, but
under the current order it takes a window slot on the way.

**The rule to carry forward is stronger than the conclusion.** Two independent
reviews arrived at wordings that combine:

    A check may run before tag verification if and only if it is a PURE
    PREDICATE -- it reads, it decides, it drops, and it changes nothing the
    next datagram can observe. And no attacker-controllable work may be
    SUPERLINEAR IN RECEIVER STATE before authentication.

The first clause is sound because of an asymmetry worth stating: for a
predicate over tag-covered fields, a PASS before the tag is retroactively
confirmed by the tag, and a FAIL is at worst a wrongly-dropped frame -- a
power anyone who could flip that bit already had. Pre-tag predicates are
therefore free and buy latency; pre-tag mutations buy the same latency and
hand a stranger a write into receiver state. The second clause exists because
the first permits leaving the O(used) scan on the unauthenticated path, which
is where the actual cost turned out to be.

**A COROLLARY THAT IS NOT OPTIONAL: a verdict produced before the tag is a
verdict the attacker chose.** `commitment`, `expires_at` and `kind` are all
plaintext and flippable in flight, so a pre-tag verdict may be counted in
aggregate and must never name a peer, trigger a rekey, or appear in a
diagnostic sentence about an identity. `wire/seal.h` currently invites the
opposite -- "A receiver holding the wrong key learns that it holds the wrong
key ... which is the difference between rotating a key and hunting an
attacker" -- and an on-path attacker flipping one bit of `commitment` makes
every frame from a healthy peer say exactly that. The honest signal survives
only as a RATE: mismatch on every frame means the key is wrong; mismatch on
one in a thousand means somebody is flipping bits.

**FRESHNESS MOVES BELOW THE TAG TOO**, which was not the first conclusion and
is what the independent derivation added. §4.7 step 2 justifies putting
freshness early "because the alternative is spending a SIGNATURE VERIFICATION
on something already dead" -- and a signature verification is step 6, the
chain, at 200-238 microseconds per hop. The stated reason argues for
freshness-before-CHAIN and the text placed it before the TAG, which the reason
never asked for. Below the tag, §4.7's own justification is satisfied exactly.

What is given up: refusing a genuinely stale frame now costs a tag check
(0.8-2.0 us) instead of two integer comparisons. That saving does not occur in
practice -- an attacker generating volume sets a valid expiry, since it is a
free field, and honest senders set expiries in the future while networks
deliver in milliseconds. It was a check placed for a saving that does not
happen, in exchange for `EXPIRED` and `NO_EXPIRY` verdicts an attacker picks.

**So `fzn_replay_admit` STAYS ONE CALL.** The pressure to split it into a
const check and a separate record existed only to straddle the pivot. With
freshness and replay both below the tag and adjacent, there is no pivot to
straddle, and the combined call keeps its "a rejected frame never occupies a
slot" invariant INSIDE the library rather than re-established by convention at
three consumer call sites. The ordering fix simplifies the API rather than
complicating it -- which is the opposite of what was expected when the change
was proposed, and is recorded because the split looked obviously necessary
right up until the last step moved.

**The chain runs AFTER replay, not before**, which is where "predicates before
mutations" yields to measurement. Chain-first would refuse an
authenticated-but-revoked peer before it touches the window -- but it pays a
signature verification on every duplicate and every retransmission on a lossy
network, where the window catches them for 77 ns. A revoked peer filling the
window costs at most `capacity` entries for at most the horizon; a revoked peer
forcing 1.6 ms of Ed25519 per datagram is a total denial of service at any line
rate. The bounded, self-draining resource loses to the unrecoverable one.

**And peer credentials are not step 1 of this sequence at all.** They
authenticate a DIFFERENT CHANNEL, and the sequence they belong to has one
step. sec 3 has the privileged daemon never linking fuzznet, and sec 2 gives
the local hop's socket to the consumer -- so the process that calls
`fzn_peer_from_fd` never sees a frame, and the process that runs the steps
above made that connection and never calls `SO_PEERCRED`. **The list describes
a sequence no single process executes**, and numbering them together invites
the reading that a frame may arrive authenticated by either, which is a
downgrade path in a design whose threat model forbids one. The rule instead:
EXACTLY ONE AUTHENTICATOR PER CHANNEL, established before anything else, and a
channel that has one does not get to substitute the other.

Credentials also belong per CONNECTION rather than per datagram, on evidence:
the group list is read from `/proc/<pid>/status` AFTER `SO_PEERCRED` returned
the pid, so a peer that exits between the two calls and has its pid reused
hands the daemon a different process's groups. Doing it once at accept keeps
that window at microseconds; per datagram reopens it for the life of the
connection.

**And `fzn_peer_from_fd` has a demonstrated vacuous pass.** On an `AF_UNIX`
`SOCK_DGRAM` receiver that has just received a datagram, `getsockopt` with
`SO_PEERCRED` RETURNS 0 and reports `pid=0, uid=4294967295`. The function
checks only the return value and the length, so it returns SUCCESS having
learned nothing, filling `uid` with `(uid_t)-1`. It fails closed today only by
luck -- `/proc/0/status` cannot be opened, so `groups_known` stays 0 and a
group gate answers UNKNOWN -- while a consumer gating on `uid` gets a definite
wrong answer. Refusing `cred.pid == 0` is one line.

### The replay window is the most expensive step, not the cheapest

A separable finding that fell out of measuring the ordering, and it changes
what the module needs. §4.7 placed replay first because it was cheapest.
Measured against the sizing rule sec 4.3 states -- the window holds what can
arrive within the longest expiry -- that is wrong by two orders of magnitude:

    window capacity    sweep + scan (-Os)
    1024               9.6 us
    16384              164.9 us
    60000              597.5 us

against 2.0 us to reject a forgery at the tag and 201-238 us for one Ed25519
verification. A window sized honestly for a 300-second horizon at 200
frames/second holds 60000 entries, and at that size the replay window costs 2.5
signature verifications per datagram and is the most expensive thing the
receiver does. It is memory-bandwidth-bound: 60000 x 32 bytes swept twice, well
past L2.

**The window needs an index, not a reorder.** The nonce's first 8 bytes are
uniformly random, so a prefix is a sound hash; an open-addressed table with
lazy expiry on probe plus an amortised sweep is O(1) and preserves what
`freshness.h` prizes -- a window stays a value, constructible directly by a
test and `memcmp`-comparable, because a deterministic probe sequence over
deterministic input gives a deterministic array.

Two more numbers worth carrying: the chain is 100-1000x everything else in the
path, so **memoizing a verdict on `(sender, capability)` with a generation
counter on the revocation store** is the one real latency win available -- a
naive loop verifies the same chain 256 times for one chunked message, which is
51-487 ms of signature checking. And that memo is itself an instance of the
rule: a verdict cached AFTER the tag and keyed by an authenticated identity is
safe; the same cache before the tag is the same bug in a new place.

**The harness cited as establishing this order cannot see the property.**
`frame/test/receive_fuzz.c` skips steps 4 and 5 by its own header, so every
frame it processes is treated as authentic and "state mutated before
authentication" is invisible to it by construction. It DID hit the exhaustion
-- "a window that never expires anything fills after eight datagrams" -- and
the symptom was read as a test artifact and fixed by advancing the test's
clock. Nobody asked whether an attacker could induce it.

### The expiry horizon, which is what makes the window sizable

`freshness.h` states the sizing rule -- the window must hold what can arrive
"within the longest expiry it will accept" -- and **there is no API by which a
receiver states a longest acceptable expiry.** `fzn_freshness_check` tests only
`expires_at <= now`, and `fzn_replay_expire` reclaims on the same test, so
`expires_at = UINT64_MAX` pins a slot for ever. Measured: 4096 forged frames
fill the window, a sweep 100 years later drops nothing, and every genuine frame
after is refused. Permanent, and under the current order it needs no key.

The bound the consumers' own numbers support splits along the line §4.3 already
draws. For `FZN_EXPIRY_REQUIRED` -- commands -- netcfgd's realistic lifetime is
its 60-90 second commit-confirm window and fuzzypickles' longest request
timeout is 300 seconds, so an hour is generous by two orders of magnitude and
still bounds the window. For `FZN_EXPIRY_OPTIONAL` -- grants -- `expires_at ==
0` is the normal case and stays unbounded; fuzzypickles is emphatic that
"losing a device to arithmetic is a worse and far more likely failure than the
one a timer defends against", and where it does set one its ceiling is 400 days.

**Refused, not clamped**, and the distinction is a hole rather than a taste.
Clamping the remembered deadline to `now + horizon` while still accepting the
frame as fresh until its stated expiry means the nonce is forgotten at the
clamp and the frame replays successfully in the gap between the two -- passing
freshness, because its real expiry has not passed. `FZN_FRESH_ERR_HORIZON` is
its own code, distinct from `EXPIRED`, on the reasoning `freshness.h` already
gives for splitting `EXPIRED` from `NO_EXPIRY`.

The horizon is `longest legitimate command lifetime + largest tolerated clock
skew`, and the guidance must say so: a consumer who sets it to the lifetime
alone refuses every frame from a peer whose clock runs fast. That also makes
`freshness.h`'s sizing rule a formula for the first time -- `capacity >= peak
arrival rate x max_ahead` -- where it currently reads as advice because the
API never took the term that would let anyone fail it.

This is needed independently of the ordering change: under the new order an
authenticated peer can still fill the window without it. And the ordering is
needed independently of the horizon -- the horizon alone converts a permanent
outage into an indefinitely repeatable rolling one at negligible cost. Neither
is sufficient.

### `state/` orders by (issuer, stream), and cross-stream is its own verdict

`record.h:101-103` says `seq` is unique within (issuer, stream) and NOT within
issuer. `state/state.c` never reads `record->stream` at all, and compares
sequences from independent spaces. Measured, and the sharp form is not the lost
write but the order-dependence:

    stream 7 seq 100, then stream 9 seq 100  ->  value is stream 7's
    stream 9 seq 100, then stream 7 seq 100  ->  value is stream 9's

The same two records, two answers, no error either way. Two hosts holding an
identical record set hold different permissions.

**The invariant to design against**, which generalises the whole module: the
value of a cell is a function of the SET of records applied to it, never of the
order they arrived in; the only permitted exception is a refused conflict, and
the exception is what the error code reports.

A writer is therefore **(issuer, stream)**, and two streams of one issuer are
exactly as incomparable as two issuers -- so the argument `state.h` already
makes for refusing to resolve applies verbatim. `uint32_t stream` joins
`fzn_state_entry_t`, where it lands in existing padding and costs nothing.

It gets `FZN_STATE_ERR_CROSS_STREAM` rather than folding into `CONFLICT`, on a
reason worth recording: cross-issuer conflict is exceptional and alarmable --
"a subject with a single writer cannot conflict" -- while cross-stream
contention is SYSTEMATIC for a consumer that lays its streams out that way.
Folding them makes the exceptional one unalarmable, which is what `CONFLICT`
exists for.

**The amendment that makes it implementable**, found by attacking it: without
`stream` IN THE ENTRY, `fzn_state_resolve` cannot be used correctly -- a
consumer cannot see which stream holds the value, and after resolving, the
entry carries the loser's sequence space so the next comparison is wrong in the
other direction. The position as first stated moved the incoherence rather than
removing it.

**The key stays (subject, kind).** Keying by (subject, kind, stream) was
rejected: it makes `fzn_state_get` ambiguous about which cell is the value,
and it silos the cross-issuer check so two different issuers on different
streams would both succeed with no conflict ever reported -- destroying the
module's security property.

**`issued_at` was rejected as a cross-stream ordering key**, decisively:
`issued_at = UINT64_MAX` can never be superseded by anything the issuer
publishes afterwards, on any stream, for ever. That freezes a permission,
including freezing a REVOCATION out, unrecoverably. `seq` has no equivalent
and the difference is structural -- `fzn_journal_admit` advances by one and
refuses gaps, so the journal already bounds how far a sequence can be
inflated, and nothing bounds a clock. It also contradicts two headers that say
order comes from sequences and not clocks.

**A tombstone is required rather than optional.** `fzn_state_clear` memsets the
entry, so replaying any older record from that issuer resurrects the cleared
setting -- measured, a record fifty places below the clear, reported `ok`.
Which gives the module one rule instead of two: A CELL IS A REGISTER HOLDING
(writer, seq, value-or-absence), MERGED BY MAX-SEQ WITHIN ONE WRITER, AND
`clear` IS AN APPLY WHOSE VALUE IS ABSENCE.

**A consequence that reaches the binding work: `stream` must be inside the
signed region.** `state/` now derives writer identity from it, so a consumer
carrying `stream` in an unsigned envelope lets an attacker move a genuine
record between streams -- wedging a cell at CROSS_STREAM for ever, which is a
revocation that never lands.

### `log/`: GONE comes from the journal, not from a floor table

`log.h` claims the module "remembers where it now starts". `fzn_log_t` has no
such field, and `fzn_log_get` derives GONE from the oldest entry CURRENTLY
HELD -- so it is wrong in both directions. Everything for an issuer evicted
answers ABSENT and the peer asks for ever, which is the exact failure the
header says the module exists to prevent; a sequence never seen but below the
oldest held answers GONE, and the peer re-anchors and accepts an irreversible
loss that never happened, with `dropped == 0`.

A per-(issuer,stream) floor table was designed and then **overturned under
attack**, on two grounds. It is monotone and can never shrink -- a forgotten
floor is a lost GONE -- while `stream` is a `u32`, so one authorised issuer
mints four billion floors at one record each: the exhaustion problem one level
worse, not one level down. And it cannot express a hole at the TOP, which
global-order eviction produces during catch-up back-fill.

**The answer needs no new state.** The journal already keeps `received` per
(issuer, stream), is already bounded, and already refuses rather than evicts:

    seq <= journal.received and not held  ->  it was evicted     ->  GONE
    seq >  journal.received               ->  it never arrived   ->  ABSENT

Exact, O(1), and it handles the middle-hole and top-hole cases a prefix floor
cannot.

### The journal stops adopting issuers implicitly

`fzn_journal_admit` creates an entry for any (issuer, stream) at `seq == 1`,
and `stream` is a `u32` the issuer chooses. Measured: one authorised key opens
64 entries in a 64-entry journal and a second legitimate issuer can never be
followed again -- permanently, because there is no forget and `journal.h`
explains why there cannot be one.

`sync.h` asserts a protection it does not have: "`record/journal.h` already
makes adopting an issuer deliberate -- `fzn_journal_anchor`. This file does not
quietly undo that." Sync refuses to ASK from strangers; a PUSHED record is
adopted anyway, and `fzn_sync_plan_offer` means unsolicited pushes are part of
the design. The door sync guards has a second one beside it.

**Delete the implicit-creation branch.** Entries come only from
`fzn_journal_anchor`, which is what both headers already claim. The exhaustion
closes with no quota, no new field, and no new error code -- and the
GAP-into-a-full-journal wart disappears with it, since an unknown issuer never
reaches the capacity test and so can never be told to fetch a range it has
nowhere to put.

A per-issuer quota borrowed from `chunk/reassembly.h` was rejected on a
difference the shape does not survive: a reassembly slot is a SELF-CLEARING
resource, returned on expiry or completion, so a sender at quota is served
again a moment later. A journal entry is permanent and unreclaimable, so the
same quota is a LIFETIME allocation cap and an issuer that legitimately needs
one more stream is locked out for ever. Reassembly's quota degrades; a journal
quota is terminal.

The reasoning that permitted the shortcut is visibly stale, and this is
recorded because the same staleness could recur. §5b reads "An unknown ISSUER
starts at 1, or not at all" -- safe when a position was per-issuer, since the
key space was the attacker's keys. `stream` was added the same day and
multiplied that key space by 2^32. The safety argument was never re-derived.

## 13b. The revocation-currency pass of 2026-08-27

Three designs were commissioned independently against one defect, plus an
adversary brief that was told the two directions and forbidden to fix
anything. None of the three saw another's report. What follows is what
they agreed on, what they disagreed on, and what is NOT settled -- which
is most of it, deliberately.

### The defect

A revocation stops a chain only at a host that HAS it. `fzn_revocation_covers` (as called from `fzn_chain_verify`)
consults a local array and nothing else, and `fzn_chain_verify` accepts
`revocations == NULL, revocation_count == 0` as readily as a full store.
So a host that joins fresh, has been offline, or is partitioned verifies
a chain the rest of the network revoked last week, and **cannot tell
that it might be wrong**. Sec 4.2 already had half this sentence: a full
store "says you may be missing revocations YOU WERE TOLD ABOUT". There
was no notion of one that exists and was never handed over.

Restated at the API, which is the sharpest form and is the stream
design's contribution: **`fzn_revocation_covers` returns `int`.** A
boolean has no room for a third answer, so `chain.c`'s
`if (fzn_revocation_covers(...))` is a two-way branch over a three-way
question, and the missing case falls into "not revoked". Every other
fail-open in this file is documented; this one was structural.

### What the three converged on, independently

The convergence is worth more than any single report, and it is genuine
-- the reports were not shown to each other, and two of the three found
the same sentences in this document without being pointed at them:

- **The well-known stream is the transport.** `record.h` reserves the
  range, names revocations as "the obvious candidate", and declines to
  assign one because "naming one before anything follows it would be
  inventing a mechanism ahead of its need." Something follows it now.
- **A signed head announcement** -- an issuer stating the highest
  sequence it has issued -- is what converts a silent floor into a
  claim. Both designs reached it separately, and both put it on a
  SECOND stream, because heartbeats sharing the revocation stream would
  make a fresh joiner fetch a year of unskippable prefix to reach the
  head.
- **A timestamp must never order anything.** Both found sec 13a's
  rejection of `issued_at` as an ordering key and applied it to their
  own field unprompted: `as_of = UINT64_MAX` would freeze a revocation
  stream against everything the issuer publishes afterwards, which is
  the replay-window incident of sec 4.7b reached through a different
  field. `head` orders; the timestamp only measures.
- **Fail-open on "cannot establish currency" is forbidden by name.**
  Sec 4.4a's "No downgrade path -- a negotiable security level reached
  by flipping a plaintext bit is the classic way this goes wrong" reads
  directly on it.

### The one insight that changes the shape

The freshness design separated two gates that everybody else, including
the brief, had entangled:

- **Gate 1, completeness. Clock-free.** `journal.received == head`. A
  host that has never held a head announcement has no `head` and fails.
  A host missing records fails by a known deficit. **This alone closes
  "joining fresh defeats revocation", using integer comparison and no
  clock at all.**
- **Gate 2, recency. Clock-bound.** Bounds how long an attacker can
  freeze Gate 1 by withholding new announcements, since a host holding
  a complete-as-of-last-year view passes Gate 1 for ever.

That split matters because **every contested question lives in Gate 2**
and none of them live in Gate 1. If the holder rejects a recency
tolerance -- and sec 4.3 arms that rejection, since fuzzypickles' whole
position is that no clock may silently disconnect a host -- Gate 1
survives alone and still closes the stated hole. Refusing to decide
because you provably lack an issuer's revocations is not a clock ending
authority; it is the absence of evidence being reported as absence
rather than as innocence.

### What the adversary said that neither design answers

- **Omission is free and invisible.** `sync.c`'s fetch walks this
  host's journal and looks each entry up in the peer's digest --
  `if (!t) continue;`. A peer that simply omits the revocation stream
  causes the victim to request nothing, for ever, with `truncated` and
  `positions_ignored` both zero. Claiming parity is cheaper still. The
  stream makes INTERIOR suppression detectable and leaves TAIL
  suppression exactly as invisible as it is today.
- **Reboot is total revocation amnesia**, and the asymmetry is real:
  the journal has `fzn_journal_anchor` and trust has `fzn_trust_pin`,
  and **the revocation store has no restore path at all**. A consumer
  persisting revocations must either re-verify every record at boot --
  200-238 us each, a cost nobody has budgeted -- or write `store.used`
  behind the API's back from an unauthenticated file that then decides
  authorization.
- **The fail-closed ratio is wrong.** Trigger costs the attacker one
  comparison per datagram, because `expires_at == 0` is a plaintext
  marker for grant-class traffic in the authenticated-but-visible head.
  Exit runs over the path the attacker holds. That is the shape sec
  4.7b already paid for once, where "the refusal is right, which is
  exactly why the outage never ended". For netcfgd it is self-locking:
  the remedy for a bad configuration is the remote administration a
  fail-closed rule has just switched off.
- **A sequenced stream destroys a property the current design has by
  accident.** Today's standalone revocation is a perfect CRDT --
  no sequence, monotone, merge is set union, so any number of holders
  of one key can emit concurrently and every host converges. Sequencing
  it makes two concurrent writers pick the same number, and the loser
  is dropped by `FZN_JOURNAL_ERR_DUPLICATE`, which this document calls
  "not a fault". One genuine revocation would be silently dropped by
  the exact mechanism meant to make dropping detectable.

### Answered by the holder, 2026-08-27, and the answer rejects the design

The three questions went to the copyright holder and came back. They
settle the fork, and they settle it AGAINST the design both independent
reports converged on. That is the pass working rather than failing: two
careful designs agreed with each other and were both wrong about this
tree, because neither could know the answer to the first question.

1. **The revoking key is REPLICATED across a user's hosts.**
2. **Grantor-revokes-descendant IS coming.** Sec 5 records it as
   deliberately not built; it is now deliberately planned.
3. **Completeness gates; recency does not.** Refuse when a host
   provably lacks revocations that exist. Never refuse merely because
   time has passed.

**The sequenced reserved stream is therefore rejected**, on the ground
its own author named: with more than one holder of a key, two writers
pick the same sequence and the loser is dropped by
`FZN_JOURNAL_ERR_DUPLICATE`, which this document calls "not a fault".
One genuine revocation would vanish silently by the exact mechanism
introduced to make vanishing detectable. Answer 2 multiplies writers
again, so the two answers agree.

**What survives is the property today's design already has by
accident**, and the adversary report is what identified it as an asset
rather than an omission: a standalone revocation carries no sequence,
revocation is monotone, and `fzn_revocation_merge` is a set union --
commutative, idempotent, order-free. Any number of holders may emit
concurrently and every host converges. That is a CRDT, it is exactly
what a replicated key needs, and sequencing it would have destroyed it.

### The shape that satisfies all three answers

Answer 3 asked for a completeness gate, and the mechanism the reports
proposed for it -- `journal.received == head` -- is a SEQUENCE
mechanism that answer 1 has just removed. So the gate needs a different
instrument, and the constraint is that it must merge the way the
revocations do.

**A manifest over the set, not a head over a sequence.** A holder of
the revoking key signs a statement naming every revocation it has
issued, by id.

**THE ID CANNOT BE A HASH OF THE REVOCATION'S SIGNED BYTES**, which is
what this entry first said and what sec 13d refuted from the struct.
`fzn_revocation_t` holds `{capability, grantee, issuer}` and admit
copies exactly those three -- `issued_at` is discarded and is read by
no library code at all. **So a host cannot recompute the id of a
revocation it already holds**, which is the one operation the mechanism
needs. Worse, two re-issues of one authority would get different ids,
while admit returns OK and stores nothing for a triple already covered
-- so a re-signed revocation is discarded, its id is never satisfiable,
and the deficit never drains. The gate would refuse for ever on a host
that HAS the revocation. Sec 13d carries the id that works: a hash of
the triple itself, derived on demand, costing no per-entry storage. A host is COMPLETE for an issuer when it holds a
revocation for every id in the union of the manifests it has seen, and
INCOMPLETE by a named deficit otherwise.

Why this fits where a sequence did not:

- **Manifests merge by union**, which is the same CRDT the revocations
  themselves are. Two holders publishing concurrently is not a
  collision, it is two sets, and their union is the answer. There is no
  number for two writers to pick the same value of.
- **The gate is integer-and-set work, no clock**, which is answer 3.
- **Rollback is free rather than defended.** An old manifest names a
  subset, and a subset cannot shrink a union. The sequenced design
  needed the journal's duplicate refusal to reject a replayed head;
  monotonicity means a replayed manifest is simply uninformative. That
  is a property, not a mitigation.
- **It survives answer 2.** When grantors revoke their descendants
  there are many issuers rather than one, and a manifest is per issuer
  by construction -- it is a statement about what THAT key has issued.

What it costs, and the cost is real: **32 bytes per revocation per
manifest**, growing with the deployment's revocation history rather
than its working set. That is the same unbounded growth sec 14 already
records for the store itself, now with a second consumer, and it means
a manifest exceeds a single frame's payload and goes through `chunk/`.

**AT 28 IDS, NOT 32, and the growth is transient rather than
permanent.** 32 was the id bytes alone against FZN_SPLIT_MAX_PAYLOAD,
ignoring a 36-byte header and a 64-byte signature; 28 ids is 996 bytes
and 29 is 1028, so 32 overshoots by a hundred rather than marginally.
And the table grows with the DEFICIT rather than the history if ids
already satisfied are never recorded -- it drains to zero as
revocations arrive, peaks at a fresh join, and is a second permanent
consumer of sec 14's growth only if the design stores the union, which
sec 13d says not to. Both figures were wrong here and are corrected
from the constants rather than re-derived; the paragraph was quoted
twice before anybody multiplied it out.

### Who may issue a revocation, derived rather than accepted

A consumer session (fuzzypickles) raised a design point against the
cross-root fix in sec 14 that is better than the fix, and it is recorded
here because the fix is a step toward it rather than away from it.

Their equivalent defect cannot occur, and not through care at the call
sites: their install function takes NO root parameter. It loads the
host's own key from storage itself, so there is no argument through
which a foreign-rooted revocation could be offered. **Storing the issuer
means every future call site must pass the right root and every future
query must compare it, which is a rule that holds while people are
paying attention. Removing the parameter means there is no wrong root to
pass.**

**Neither of their two moves is available here, and the second reason is
the interesting one.** There is nowhere to derive from: this library has
no I/O and no mutable globals, so the closest move is taking a
`const fzn_trust_t *` rather than a raw pointer, which narrows the
target without removing it. And once grantor-revokes-descendant exists,
**the issuer of a legitimate revocation is not the root at all** -- it is
an intermediate -- so deriving "the root" would reject exactly the
revocations the new model carries. Their shape is correct for their tree
because only the user's own root revokes there, and it stops being
available here by decision rather than by drift.

**The principle survives one level up, and that is the direction for
grantor-revocation.** The set of issuers entitled to revoke a given hop
is neither caller-supplied nor local state: it is derivable from THE
CHAIN BEING VERIFIED. The question is "is this revocation's issuer the
root, or an ancestor of the hop it names, in this chain?", and
`fzn_chain_verify` already walks that chain with every hop's grantor in
hand. It does not need to be told and cannot be told wrong.

That is derive-don't-accept applied to the thing that actually varies,
and it is a better place for it than either tree's current design. It is
also why the sec 14 fix keeps the issuer ON THE ENTRY rather than
binding the store to a root: the entry's issuer is what that ancestry
check will read.

**Still not built.** The shape follows from the answers but the layout,
the id derivation, the merge rule's exact semantics and the deficit
reporting are a design pass of their own, and this document has just
demonstrated what commissioning one against an unsettled premise
produces. What answer 2 does change immediately is the cross-root
finding in sec 14: with grantors revoking, a store holds entries from
many issuers rather than one, so binding a store to a single root is no
longer merely a correctness fix for a multi-root consumer -- it is a
precondition for the revocation model the holder has just chosen, and
the entry there is promoted accordingly.

**Built the same day, and the word "binding" above did not survive
contact with the reason for it.** A store bound to one root would have
to be unbound again the moment answer 2 is implemented, so what was
built keeps the ISSUER on each entry instead: `fzn_revocation_t` carries
it, `fzn_revocation_covers` asks for it, and `fzn_chain_verify`'s call
site passes the pinned root and names itself as the line that changes
when grantors may revoke. Sec 14 carries the detail.

**And the line changed on 2026-08-28**, one day later, which is the
shortest a decision recorded here has ever waited. Keeping the issuer on
the entry is what made it a change to one query -- `fzn_chain_verify`
asks `fzn_revocation_covers_chain` about the whole chain and each entry's
issuer is matched against the chain's own grantors. Sec 13c records what
its own design got wrong.

## 13c. Bounding revocation admission, once grantors may revoke

Commissioned after sec 13b's answers settled, against the half they left
open. **BUILT 2026-08-28** -- see *What building it changed* at the end of
this section, which records the two things this design got wrong and the
one it left out. The reasoning below is unchanged and is still the
expensive part.

### The reframing that decides it

`fzn_revocation_admit`'s root check does TWO jobs, and sec 13b's
answered half moves only one:

- **authorisation** -- "is this issuer entitled to revoke?", answerable
  at admit today only because root-only revocation makes it so;
- **an admission bound** -- "is this record worth 96 bytes of a table
  that never evicts and never expires?"

`FZN_CHAIN_ERR_WRONG_ROOT` was never a storage policy and has been
serving as one for free, because a set of one entitled issuer is also a
very good quota. **Admission is a resource decision, not an
authorisation decision, and it must be allowed to be coarse.** It cannot
grant anything: the worst a wrongly-admitted entry does is occupy
storage, because `fzn_revocation_covers` (as called from `fzn_chain_verify`) decides what is honoured. Admit must
not try to be verify -- which is the trap `revocation.c` already names
in the other direction, where a conservative answer to one question is a
wrong answer to another.

### The recommendation

**Admit a non-root revocation exactly when its issuer presents a chain
that verifies against the pinned root for the capability being
withdrawn, whose last hop is `delegable`.**

**AS STATED THAT RULE IS EXPLOITABLE, AND THE BUILD FOUND IT BY WRITING
THE TEST RATHER THAN BY RE-READING THE PROSE.** It relates the chain to
NOTHING. Chains are public. **A freshly generated keypair signs a
revocation naming itself as issuer and staples somebody else's
delegable chain to it** -- the capability checks out, the root checks
out, the last hop is delegable, both stated conditions hold, and the
bound costs one keypair. That is precisely what the paragraph below
claims this rule prevents.

Two things must be added, and the sharp form of the rule -- "admit if
`fzn_chain_delegate` would let that key GRANT the thing it is
withdrawing" -- already implies the first:

- **The verified chain's grantee must equal the record's issuer.**
  Without it any published chain stands for anybody who copies it.
- **The depth ceiling is part of the rule.** A key at the end of a full
  chain has no room for the hop that would make it an ancestor, so its
  revocations can never be honoured -- the `delegable` argument applied
  to depth.

**The prose and the sharp form disagreed and the prose is what would
have been built from.** Recorded rather than silently corrected,
because this section was written to be built from and was, and the
gap between a rule's careful statement and its one-line summary is
where the exploit lived. Put sharply: admit a
revocation from a key if and only if `fzn_chain_delegate` would let that
key GRANT the thing it is withdrawing. Revoking a descendant is the
inverse of granting one and takes the same standing.

The `delegable` term is free and not decoration: a key can only be an
ancestor if it appears as a grantor of some hop, and `chain.c` refuses
any such hop unless its predecessor was `delegable`. So a non-delegable
holder can never be an ancestor, its revocations can never be honoured,
and admitting them is pure waste. That excludes every leaf in an estate
-- most keys -- from spending the store.

Costs, measured rather than derived: **zero additional bytes per entry**
(still 96), 16 bytes once per store for two quota fields, **zero
persistent per-issuer state**, and up to 1498 bytes of caller stack per
non-root admission. Zero extra CPU for a root-issued record; one chain
verification otherwise.

Two invariants that are cheap to break by accident and invisible when
broken, both of which would destroy the CRDT sec 13b preserved:

- **Admission is revocation-blind.** Verify the issuer's chain with no
  revocations, or admitting the root's revocation of H1 first makes
  H1's earlier revocation inadmissible and the store becomes
  order-dependent.
- **Admission is clock-blind.** Refusing a revocation because the
  REVOKER'S OWN grant lapsed would silently re-connect a revoked device.

And a third temptation to refuse: do not use the store as a cache
("this issuer already has an entry, skip the chain check"). It looks
free and makes the outcome order-dependent.

### Two questions the code raised, both answered

**A revocation does NOT need to name which grant it withdraws, and an
id would fail open.** The motivating case -- two grantors granting the
same capability to the same grantee -- is already separated by the
per-chain ancestry check, which is per-grant-path by construction. What
an id would add is only "withdraw Tuesday's grant but not Friday's",
and it costs +32 on the wire and +32 per entry in the one table that
only grows. Worse, **a hop-id revocation is escaped by re-issuing the
same grant** -- one signature brings a stolen device back. The coarse
`(capability, grantee)` form names the AUTHORITY rather than the paper,
and re-issuing the same authority does not escape it.

**When the revoking grantor is itself later revoked, its revocation
STANDS.** If it fell, adding an entry to the store would REMOVE a
derivable fact, so a host that later learned the root's revocation of H1
would UN-REVOKE H1's descendants -- and an attacker could arrange it:
steal H1, delegate to D, get caught, and the root's clean-up revocation
of H1 rescues D. With "stands", verdicts only accumulate and the union
stays commutative, idempotent and order-free. A grant's validity is
continuously re-evaluated; a revocation is a withdrawal already
performed, by a party entitled at the time, and nothing continues to
re-evaluate. The cost is that a compromised grantor denies its
descendants permanently -- accepted, because the holder already accepted
that class, and because **recovery costs one mint**: the entry bites
only chains in which that grantor appears, so a fresh root-to-descendant
chain is clean. Recovery is by re-granting AROUND the revoker, never by
un-revoking.

### What it does not solve

It does not bound the store; it bounds who may spend it to the estate,
and makes spending it cost compromised delegable keys rather than
generated keypairs. Sec 14's sizing problem now depends on the
delegation graph's WIDTH as well as the history's length -- two unknowns
where there was one. The store still fills legitimately with inert
entries an entitled insider produced against keys it is not an ancestor
of: permanent, by design, unmitigated. And sec 13b's manifest is per
issuer, so grantor-revocation multiplies issuers and makes completeness
gating dearer -- sec 13b recorded "it survives answer 2" as a property
of the manifest; from here it reads as a burden.

### What building it changed, 2026-08-28

The design above was implemented as written except in three places, and
the first of them is a hole rather than a detail. This is the third time
a design recorded here has been corrected by the attempt to implement it
-- sec 13d's id and its flag-clearing rule were the first two -- and it
is the third that was fail-open. **A design pass and a build pass are
different instruments**, and the second one reads the first's prose the
way an attacker reads a protocol.

**THE RULE AS WRITTEN ADMITS ANYBODY WHO CAN COPY A CHAIN.** The
recommendation says to admit a non-root revocation "exactly when its
issuer presents a chain that verifies against the pinned root for the
capability being withdrawn, whose last hop is `delegable`". Nothing in
that sentence relates the CHAIN to the ISSUER. A chain is public -- it is
what a peer presents to prove authority, so every host that has ever been
talked to holds copies -- and a freshly generated keypair can sign a
revocation naming itself as issuer and staple somebody else's delegable
chain to it. Both stated conditions hold. The bound this section exists to
impose would then cost an attacker one keypair, which is exactly what its
own closing paragraph claims it stops: "makes spending it cost compromised
delegable keys rather than generated keypairs."

The fix is one comparison and it is in the sharp form of the rule already:
`fzn_chain_delegate` would let a key grant only if that key IS the chain's
last grantee. So admission checks that the verified chain's grantee is the
record's issuer, and refuses FZN_CHAIN_ERR_CHAIN_INVALID otherwise. Found
by writing the test for "somebody else's chain" rather than by re-reading
the sentence.

**THE DEPTH CEILING IS PART OF THE RULE AND THIS SECTION DOES NOT MENTION
IT.** `fzn_chain_delegate` refuses to extend a chain already at
FZN_CHAIN_MAX_HOPS, and the sharp form of the rule therefore refuses a
revocation from a key at the end of a full one. It is not a technicality
borrowed for symmetry: a key at the ceiling has no room for the hop that
would make it somebody's grantor, so its revocations could never be
honoured -- which is the SAME argument the `delegable` term rests on,
applied to depth rather than to permission. Admission refuses with
FZN_CHAIN_ERR_MALFORMED, as delegate does.

**THE TWO QUOTA FIELDS WERE NOT BUILT.** The costs paragraph promises "16
bytes once per store for two quota fields", and no other sentence here
says what they would count or what they would refuse. Nothing was added,
so a store is the same 96 bytes per entry and the same three fields it
was. The recommendation stands without them -- what bounds admission is
standing in the estate, not a counter -- and inventing a quota from a line
in a cost table would have been building a mechanism ahead of its need.
**Recorded as unbuilt rather than silently dropped**, because sec 14's
sizing question is still open and whoever reopens it should know this was
considered and left.

**One ordering this section does not decide, decided in the build.** A
chain may carry FZN_CHAIN_MAX_HOPS - 1 hops, so checking standing before
the record's own signature would let one unsigned scrap of bytes with a
long chain stapled to it buy seven signature verifications -- a
receiver's CPU for the price of a datagram, which sec 4.4a's threat model
is explicit about. The record's own signature is verified first and the
walk sits below it; the root path is unaffected, since its check is a
comparison and still happens above both.
`chain/test/revocation_test.c` pins it by counting: a forged record with
a three-hop chain must cost one verification, and moving the walk up
makes it cost four.

**What the verify side cost, as written.** The entitled set for hop `i`
is `{fzn_hop_grantor(hops[j]) : j <= i}` -- the root included, because
`fzn_chain_verify` has already pinned `hops[0]`'s grantor to it -- and
the query is hoisted exactly as this section asks. One pass over the
store places each entry once: find the smallest `j` whose grantor is that
entry's issuer, and the entry applies to every hop from `j` onward. That
is **O(R * hops)**, two bounded walks of the chain per entry, which is
what the single-issuer loop it replaced already cost. The naive form --
per hop, per ancestor, a full store scan -- is O(hops^2 * R).

**SMALLEST `j`, NOT ANY `j`, and the two are a security difference rather
than an optimisation.** Matching an entry against every grantor in the
chain would let a key deep in one branch withdraw the ROOT's grant at hop
0 -- an estate's newest leaf disconnecting its own parent, which is an
escalation upwards and the opposite of "descendant". The same rule one
level tighter says a key cannot withdraw the grant that made it, since
its own hop's grantee is itself and its earliest appearance as a grantor
is the hop after. `chain/test/chain_test.c` pins both over a three-hop
chain, which is the shortest one where the difference is observable.

**Where the code lives, and why it is not in `chain.c`.** The walk reads
store entries, and `chain.h` records what a second predicate over that
array cost once already: a heap overflow on the authorization path,
because `chain.c` kept its own copy of "is this revoked?" and the two
disagreed about a corrupt store. So `fzn_revocation_covers_chain` lives
in `chain/revocation.c` beside `fzn_revocation_covers`, the two share one
definition of "corrupt", and `chain.c` asks rather than scans. Its three
answers are the sibling's three answers in the same order: a NULL store
revokes nothing, a corrupt store revokes EVERY hop, and a question with
no subject revokes nothing. That last pairing was reachable through
`fzn_chain_verify` before and had no test at that seam; it has one now,
because the rule moved into new code.

**The three invariants are pinned by tests that fail when they are
broken**, which is the only form in which an invisible property is worth
recording:

- **Revocation-blind.** Two hosts admit the same two offers -- the root's
  withdrawal from a grantor, and that grantor's own withdrawal from its
  descendant -- in opposite orders, and the resulting stores are compared
  as SETS. Passing the caller's store into the issuer's verification
  leaves one store with one entry and the other with two.
- **Clock-blind.** A grantor whose own grant expired long ago still
  revokes. The magic value is asserted in the test rather than assumed:
  verifying at `now = 0` refuses nothing only because FZN_NO_EXPIRY IS
  ZERO, so the one `expires_at` that could satisfy `<= 0` is the one
  `fzn_chain_verify`'s outer test has already excluded. If that constant
  ever moved, admission would start expiring grants and a device would
  quietly un-revoke itself.
- **Not a cache.** The same record is offered twice, the second time with
  a chain that does not entitle it, and must be refused although its
  triple is sitting in the store. Moving the duplicate test above the
  walk -- free, obviously correct -- makes the answer depend on whether
  this host happened to hear the record before.

**Fifteen mutations, each caught by a named check.** The two model-based
harnesses were widened with the rule: `chain_fuzz.c` and
`chain_guided.c` both re-derive the entitled set the NAIVE way, so the
hoisted implementation is checked against the definition rather than
against a second copy of itself. `chain_fuzz.c` also gained a generator
case that names an ANCESTOR'S key as an issuer, and a floor on how often
that decides something -- without one the widened branch was a term no
input could decide, which is how the root pin escaped that file once
already.

**The API break.** `fzn_revocation_admit` and `fzn_revocation_merge` take
an `fzn_revocation_offer_t` -- the record plus the issuer's opened chain
-- rather than a bare record. `hop_count == 0` means root-issued and
reproduces the old behaviour exactly, which is asserted rather than
assumed. Merge takes an array of them because each member of a batch may
be issued by a different key, and a batch of records with one chain
beside it could only ever have carried one issuer's standing.

## 13d. The manifest design, and where it says stop

Commissioned 2026-08-27 once sec 13b's premises were settled. **Not
built.** It corrected two figures sec 13b gave it, which are fixed
there, and it recommends building LESS than sec 13b describes.

### The id, which is the load-bearing correction

**SETTLED 2026-08-27: NAME THE PAIR. The hashing subsystem is not
built.** A manifest line is 64 bytes of `(capability, grantee)`, and
what would have decided the other way -- a manifest crossing an estate
boundary -- does not happen. See the answer below.

The rejected form was **H(version, object tag, issuer, capability,
grantee)** -- a hash of the TRIPLE, not of the revocation's bytes. Derived on demand from a
store entry's three fields, so it costs **zero additional per-entry
storage** on the one table sec 14 says only grows. Two revocations of
one authority collide by construction, which is the wanted answer: one
authority, one id, one store entry, one manifest line, and the store's
existing dedup agrees with the manifest's by definition rather than by
care.

**Why the pair wins, now that the condition is answered.** It needs no
hash seam in `chain/` at all -- that module includes only
`constant_time.h` and `wire/bytes.h`, so hashing meant a new dependency
edge or a second vtable of the same shape, which `code-style.md` warns
about by name. And the completeness predicate becomes
`fzn_revocation_covers` ITSELF, which is already written, already
constant-time, already refusing a corrupt store, and already
mutation-tested. `chain.h` records this tree's own lesson that the
repair is to stop having two predicates. The deficit is also readable
by a human -- "I lack I's withdrawal of C from G" -- where an opaque id
is fetchable only if every peer indexes revocations by id.

**THE ANSWER, from the only consumer positioned to give it.**
fuzzypickles: manifests never cross an estate boundary, and both
directions are closed independently rather than by convention.
OUTBOUND, their propagation is narrowed to siblings -- a contact is not
a recipient. INBOUND, their revocation install takes NO root parameter;
it loads the host's own user key from storage, and the index-add has
exactly one caller inside install, so there is no argument through
which a foreign-rooted revocation could be offered. The root of it is
one line of their `capability.h`: **a peer holds none of our
capabilities**. A contact is never a grantee, so there is nothing a
revocation could withdraw from one.

**WHAT THE ANSWER COSTS, measured rather than waved at.** A pair line
is 64 bytes where a hashed id was 32, so **the pair form halves
per-frame capacity: 14 pairs fit one frame against the hash form's
28.** Both land on 996 bytes, which is a coincidence of the 100-byte
fixed overhead and worth not reading as significance. Above 14 a
manifest goes through `chunk/`, so an issuer with a few dozen
revocations chunks where the hash form would not have. That is the
price of deleting the hashing subsystem and it is the right trade --
the machinery removed is permanent and the bytes are per message -- but
it is a real cost of the settled answer rather than a free win, and
sec 13d's O(history) republication paragraph is where it compounds.

**The condition that would reverse it, recorded as the hinge rather
than the answer**: if fuzzypickles ever grants a capability to another
user's host -- delegating storage or relay to a contact's device rather
than one's own -- then contacts become grantees, revocation becomes the
mechanism for them, and manifests cross. Nothing in their current
design points that way and their realm taxonomy treats outward-into-
Registered as different in kind. But it is a design decision at their
end, not a property of this wire format, so it is theirs to signal and
ours to watch for.

### Build in two stages, and stage 1 has no gate

**Stage 1**: the manifest object, the derived id, follow/admit, the
deficit table with a STICKY OVERFLOW FLAG, and the reporting calls.
`fzn_chain_verify` untouched. It breaks nothing and delivers most of
sec 13b's defect statement -- a host can finally SAY what it is missing
-- without creating a new refusal path. It also turns sec 14's
unanswerable sizing question into an observable: **the manifest is the
number nobody had**, and it arrives before the revocations do, so
`FZN_CHAIN_ERR_STORE_FULL`'s fail-open becomes a fail-closed capacity
refusal at follow time.

**Stage 2**: the gate inside `fzn_chain_verify`, `ERR_INCOMPLETE`, and
UNKNOWN. Sequence it with sec 13c's ancestry walk, not before, because
the entitled-issuer set the gate iterates IS the set that walk
computes; doing them apart means writing one derivation twice.

**UNKNOWN must gate or the design does not close its own defect.** A
union has a property a sequence head does not: no manifest is an empty
union is a zero deficit, so a fresh joiner is COMPLETE by vacuity. A
number's absence is distinguishable from zero; a set's is not.

**Two things are not optional in any version**: the derived-not-stored
id, and the sticky overflow flag. Without the flag a dropped id makes a
host look MORE complete than it is -- a second silent fail-open on top
of the one the exercise exists to close, and the design would then make
storage strictly worse than it found it.

**AND THE FLAG'S CLEARING RULE AS WRITTEN HERE WAS INCOMPLETE.** This
entry said the flag "clears only on a re-admission that appends every
pair it could not record before", which sounds sufficient and is not:
**a REPLAYED OLDER MANIFEST satisfies it.** An earlier manifest names a
subset, every pair of that subset is already held or already listed,
nothing is dropped -- and the flag clears while the pairs that
overflowed are still missing. The host then reports a sound deficit
that is not sound, and **a carrier needs no key to arrange it**, only a
copy of something the issuer signed earlier.

Found by building it, not by reading it. The fix is a per-issuer
high-water mark on the count seen: an honest issuer's count never
shrinks, because revocations only accumulate, so a smaller manifest is
exactly the rollback case and can clear nothing. One word per followed
issuer. `chain/test/manifest_test.c` proves it by removing the guard
and watching the replay case fail by name.

That is the second time a design recorded here has been corrected by
the attempt to implement it -- the id was the first -- and both were
fail-open. **A design pass and a build pass are different instruments**,
and the second one reads the first's prose the way an attacker reads a
protocol.

### What it makes worse, stated rather than buried

- **Manifest omission becomes a denial of service.** Withholding a
  manifest leaves a victim UNKNOWN, which refuses; previously omission
  left it permissive. The trade favours it -- the victim knows what it
  lacks and any honest peer repairs it -- but it is a new attack.
- **An entitled issuer can name unsatisfiable ids** and wedge every
  chain it is entitled for, permanently, and this is CHEAPER than
  revoking since it needs no valid revocation. Mitigation: make the
  issuing call derive its id set from the issuer's own store, so an
  honest implementation cannot name an id it does not hold.
- **`fzn_revocation_issue` becomes half an operation.** A key that
  revokes without republishing has revoked in a way the gate cannot
  see, and it looks successful.
- **Tail suppression gets a green light.** Today a suppressed host has
  no verdict; after this it has a positive COMPLETE verdict that is
  false. The union grows only when somebody hands you a LARGER
  manifest, and a peer handing you last year's leaves you complete
  against a stale set for ever. Only recency catches it and answer 3
  forbids recency. The defence is naming: the verdict is *complete
  against the manifests held*, never *up to date*. That is weak and is
  not dressed up as more.

### O(history) republication is forced, not chosen

A manifest is a full-set statement, re-signed and re-sent whole on
every change: 500 revocations is 16 frames through `chunk/` per new
revocation per follower. Both escapes die on answer 1. A **delta**
needs an ordering to say which last, and ordering is the sequence that
answer removed. A **Merkle root** would make it O(1) on the wire and
**cannot be merged** -- union of two roots is not computable without
the elements. Union merge and accumulators are mutually exclusive.

### Both stages are blocked, on different questions, to different people

Recorded so a later session does not read "stage 1 breaks nothing" as
"stage 1 is ready".

**Stage 1 is UNBLOCKED as of 2026-08-27.** Its one open premise was the
id's form, which turned on whether a manifest crosses an estate
boundary. It was asked of fuzzypickles rather than assumed -- they are
the only consumer where the crossing case is real, since netcfgd's
agent is one hop from the user key and raidcfgd's brief is not known
here -- and the answer is that nothing crosses. Name the pair.

**Asking cost one message and saved a subsystem.** Guessing would have
meant choosing a wire format on an assumption about another tree, which
is what `evidence.md` names and what this session already paid for once
in the other direction. It would also have been the conservative guess
-- hash, more bytes, more machinery, a dependency edge in a module with
none -- so the cautious answer was the expensive one and the question
was the cheap one.

**Stage 2 waits on the holder**, on the sec 4.4a reading below.

The two are independent: an answer to either unblocks its own half.

### A contradiction in this document, flagged rather than resolved

Sec 13b says fail-open on cannot-establish-currency is "forbidden by
name", citing sec 4.4a. The designer reads sec 4.4a's actual text as
forbidding "a negotiable security level reached by flipping a PLAINTEXT
BIT" -- an attacker-reachable downgrade -- and holds that a
consumer-side policy chosen in source is a different object. **Stage 2
is entirely downstream of which reading was meant**, and this document
cannot settle a question about its own sentences. It goes to the
copyright holder.

## 13e. Forward secrecy: what the shapes cost, 2026-08-28

Commissioned when a consumer's adoption turned out to be blocked on the
absence. **Not built.** Two things the brief asserted were wrong and
both cut the same way -- see sec 14 for the consumer's property being
half what was claimed, and below for the CPU.

### The surprise: an ephemeral does NOT cost the self-contained frame

The brief was written expecting a conflict with sec 13's axis and there
is none. **A per-message ephemeral rides IN THE FRAME and the
recipient's key is long-lived, so `DH(recipient_sk, ephemeral_pk)` is
computable at any later time by any host holding the recipient's static
key.** A stored datagram opens hours later, from a relay, on a host
that rebooted and never spoke to the sender. Self-containment survives
an ephemeral completely.

**Only the RATCHET family costs the axis, and there the trade is exact
and unfixable.** Forward secrecy *is* the deletion of key material;
relay-hours-later *is* the requirement to still hold it. One variable
read from two ends, so any parameter improving one degrades the other
by exactly as much. That is the plain statement, and it disqualifies a
symmetric ratchet here regardless of its other merits.

### What an ephemeral costs instead: the receive path

**Rejecting a stranger goes from 640 ns to 158 us -- 247x.** Under an
ephemeral the AEAD key is a function of the DH, so sec 4.7 step 3's
commitment check cannot run until the scalar multiplication has. At
100 Mbit/s of 176-byte frames -- 71,000/s -- that is **eleven cores
saturated rejecting garbage**, against 4.5% of one core today. It
satisfies sec 4.7's rule literally (it is O(1) in receiver state) and
violates its purpose completely.

**X25519 IS 158 us HERE, NOT THE 50-60 THE BRIEF SUPPOSED** -- 2.7x
out. Measured against the Monocypher this family vendors, at -Os, and
calibrated: the same harness reads Ed25519 at 221.7 us, inside this
document's own published 201-238. A first attempt read 301 and was
discarded, because a 60 ms batch on a loaded machine cannot avoid
preemption. **The number was invented in the brief and measured in the
answer**, which is the third figure this session that survived being
quoted and did not survive being checked.

### The shapes worth naming

- **E -- epoch re-derivation, root deleted, N epochs retained.** The
  cheap honest answer. Zero to four wire bytes, no scalar
  multiplication anywhere, sec 4.7 step 3's economics untouched, no
  synchronised state. **Its bound is not arbitrary**: retain each epoch
  key for `max_ahead + skew` and every command frame that was still
  DELIVERABLE is still openable, because `frame/freshness.h` already
  refuses anything outside that horizon. The forward-secrecy window and
  the delivery window become one number. What it cannot protect is
  traffic with no expiry -- grants -- and those are signed rather than
  confidential, so the class it misses is the class that was never
  secret.
- **G + H -- the full property.** A per-message ephemeral with
  ROTATING RECIPIENT PREKEYS distributed through `record/`, plus
  today's long-lived commitment kept as a pre-DH filter. Two-sided
  forward secrecy bounded by the rotation window, self-containment
  intact, chunking at one DH per message via a post-tag cache sec 4.7c
  already blesses, and **the flood closed at 592 ns** because a
  stranger who lacks the commitment key never reaches the DH.
- **D -- epoch re-derivation with the root retained -- IS NOT FORWARD
  SECRECY** and is recorded as refused so it is not proposed again. A
  receiver holding the root derives any epoch in either direction.

### THE DECISION BELOW WAS PREMATURE, AND THE REASON IS SEC 4.5

**Recorded 2026-08-28, within the hour, by the agent that had been
stopped from building it.** Shape E was chosen on the argument below,
which stands as far as it goes and does not go far enough.

**E and D differ only in whether the material the epoch keys derive
from is DELETED, and nothing says what E derives from once the root is
gone.** There are exactly two candidates:

- **From the transcript.** Then the transcript IS the root and deleting
  the derived 64 bytes buys nothing -- a receiver holding the transcript
  derives any epoch in either direction. **That is D**, which this
  section refuses by name.
- **From epoch key k by a one-way step.** A symmetric hash ratchet.
  This section disqualified the ratchet family for the
  RELAY-HOURS-LATER reason, which E's retention window already answers
  -- so this branch may be viable. But it requires the transcript to be
  destroyed after the first epoch, and a rebooted peer holding only its
  identity key then **cannot resynchronise**, because the material it
  would re-derive from is gone. That is a self-containment cost on the
  peer-comes-back axis rather than the stored-datagram axis this
  section checked.

**And the first branch is the live hazard.** `session/commitment.h`
declines to say what the transcript holds -- "a protocol decision that
depends on the session model, and sec 4.5's prekey half is not
settled". If the answer is the obvious one, a static-static DH plus two
identity keys, then **a compromised host recomputes the transcript from
its own identity secret and the peer's public key, and every epoch with
it. E collapses into D silently**, and nothing in this library can
detect it.

**So the real question is not E against the ephemeral. It is WHAT GOES
IN THE TRANSCRIPT, and both shapes are downstream of it.** E does not
remove sec 4.5's prekey half; it relocates it. Rotating prekeys were
one of the two ways to get deletable material into a transcript, which
is why stopping that work does not settle anything by itself.

**This is the second decision in an hour overturned by a reading**, and
both readings were of `session/commitment.h`. The first found that an
ephemeral breaks key commitment; the second that an epoch may provide
no forward secrecy at all. **Neither was a measurement -- both sentences
were in the file the whole time.**

### The argument for E, which stands where it stands

**The ephemeral breaks key commitment, and this pass did not notice.**

`session/commitment.h` states why the commitment BINDS the key rather
than merely accompanying it: "the AEAD key and the commitment key are
the two halves of a single hash over a single input, so producing a
second AEAD key whose frames carry a given commitment still means
finding a second preimage of that hash."

Under a per-message ephemeral the AEAD key comes from the DH. **If the
commitment key stays long-lived so that it can filter strangers before
the scalar multiplication -- which is shape H, and 13e calls it
mandatory -- then the two are no longer halves of one hash and the
commitment stops committing to the key.** It degrades to a per-pair
authenticator meaning "this sender knows our shared secret". Sec 4.4a
calls key-committing AEAD not optional.

So G+H is a three-way trade rather than a design:

| | filter | key commitment | wire |
|---|---|---|---|
| commitment long-lived (H) | 592 ns | **LOST** | +32 |
| commitment from the DH | **158 us** | kept | +32 |
| both tags | 592 ns | kept | **+48**, leaving 16 of 64 headroom |

**E has none of that.** Both halves still come from one hash, one epoch
at a time, so the binding survives untouched. It costs zero to four
wire bytes, needs no scalar multiplication anywhere, adds no fifth
crypto seam, and leaves sec 4.7 step 3's economics exactly as they are.

**AND E IS THE BETTER HALF FOR THIS LIBRARY'S THREAT MODEL, which is
the argument that settles it rather than the costs.** Sec 4.4a names
the likely compromise as the receiver -- "the machine most likely to be
attacked is the one being reconfigured because it is already
misbehaving". The consumer's per-message property is SENDER-SIDE ONLY:
their prekey does not rotate, so compromising a recipient opens
everything ever sent to it. **E gives bounded forward secrecy in BOTH
directions.** Adopting the ephemeral to match them would buy an
unbounded property in the direction that does not cover our threat and
lose key commitment to get it.

**What E does not give** is per-message granularity: a compromise inside
an epoch opens that epoch. **The measurement that decides whether that
is enough is the epoch length**, which is bounded below by clock skew,
since both ends derive it without coordination from `expires_at`, an
authenticated field already bounded by the freshness horizon. That
measurement belongs to the build and is the first thing it should
establish.

**Rotating prekeys are not needed by E** and the work started on them
was stopped. They are specific to the ephemeral, and the questions that
pass had to answer -- retention, selection, what a sender does holding
none -- recur in the epoch shape wearing different clothes, so its
report is kept.

### What the stopped pass established that survives the shape question

Kept because these questions recur in whatever shape wins, and because
the pass answered them better than the design it was given.

- **The epoch number is a MANDATORY WIRE FIELD, not "zero to four
  bytes".** If it is clock-derived the receiver does not know which
  epoch key to derive the per-frame commitment under, so it tries every
  retained one. `commitment.h`'s measured figures make it concrete: 560
  ns to derive plus 47 to compare, so K candidate keys already cost
  ~610K ns at step 3, and a clock-derived epoch makes it 610.K.N where
  N is the retention count. With an hour of `max_ahead` and minute
  epochs, N is 60 and the 640 ns this section defends becomes ~38 us.
  **Carrying it leaks nothing new** -- `expires_at` is already a
  cleartext absolute second in the head and an epoch is coarser, and
  unlike the old per-pair commitment it is not per-pair, so it does not
  recreate the social-graph leak.
- **`max_ahead + skew` is right for E and is NOT a double count**, which
  it looks like since `max_ahead` already includes skew. Under E the
  epoch boundary is IMPLICIT, so a sender may still be sealing under
  epoch k up to one skew after the receiver thinks k ended. A PUBLISHED
  boundary -- a signed `not_after` both sides read off the same bytes --
  would be `not_after + max_ahead` with no second skew. **The formula
  distinguishes the shapes and getting it wrong silently loses
  deliverable traffic.**
- **The retention bound does not cover traffic with no expiry, and this
  section answered the wrong objection.** `frame/freshness.h` keeps
  nothing for `expires_at == 0`, and sec 4.3 says grants do not expire,
  so a grant frame has no deliverability bound and any retention derived
  from `max_ahead` loses it. This section answered "those are signed
  rather than confidential" -- which answers a CONFIDENTIALITY objection
  to an AVAILABILITY problem. The receiver cannot open the frame at all.
  Identical under both shapes, so not a discriminator, but unresolved.
- **Make the downgrade UNSPELLABLE ON THE WIRE, not discouraged.** If
  the field naming a recipient key is a record `seq`, and `seq == 0`
  already means "no record yet", a frame naming 0 is refused
  structurally -- there is no in-band way to say "I could not do the
  secure thing, here is the long-lived key", which is sec 4.4a's
  forbidden shape. **The epoch shape has the same question and the same
  answer: reserve epoch 0 and refuse it.**
- **A body needs its own discriminator only when nothing already inside
  the signed range distinguishes it from another body under the same
  object tag.** A record carries `stream` and `kind`, both 4 bytes at
  fixed offsets inside the signature, so they separate a prekey body
  from a configuration body that share `FZN_OBJECT_RECORD`. A later
  layout revision is a new `kind` rather than a bumped
  `FZN_SIGNED_VERSION`, which would invalidate every signature ever
  issued for every object type.
- **`record.h`'s reason for declining to assign a well-known stream had
  EXPIRED.** It declined because "naming one before anything follows it
  would be inventing a mechanism ahead of its need" -- and a sender
  fetching a peer's keys knowing only its identity is exactly the case
  it anticipated. Whenever anything becomes the first well-known
  stream, that is the argument that admits it. Not stream 0 and not
  kind 0: zero is what a partially-initialised struct lands in.

### Three refusals

**Do not adopt the consumer's construction because the consumer asked
for it.** They are right that the absence matters and right that it was
recorded nowhere. They are describing a property their own header
states more narrowly than this document did, and it is the half that
does not protect the machine sec 4.4a says is most likely to be
attacked.

**Do not build a symmetric ratchet**, which is the only shape costing
the axis. **Do not build D**, which looks like the property and is not.

### Our own receive order does not have the flood, and could lose it

A consumer handed the question back after finding the same shape in
their own path, and it was read rather than reassured. `fzn_seal_open`
runs shape validation, then one hash for the commitment (~640 ns), then
the AEAD (~2100 ns). **No scalar multiplication exists anywhere in this
library.**

**The filter is not gated on public knowledge, and that is the whole
difference.** Passing the commitment check needs the per-pair
commitment key, so a stranger who knows a host's public key -- which
anyone who has seen one datagram has -- cannot produce a commitment
that verifies and dies at 640 ns having cost one hash. The consumer's
equivalent gate is a lookup by host public key, so their price of
admission is knowing something public where ours is knowing something
shared. That is why 2000 packets/s/core is their number and not ours.

**We are one decision away from their position.** Adopting an ephemeral
moves the AEAD key behind the DH, which moves the commitment check
below it, which is the 640 ns to 158 us change above. **Shape H is
therefore not optional if the ephemeral is taken** -- keep the
commitment derived from long-lived material as a pre-DH filter, so a
stranger still dies at 592 ns and only a frame already proving per-pair
knowledge costs a scalar multiplication. It exists in this design only
because the consumer's question sent somebody to measure the flood.

### Two fields agreeing in size is not two fields agreeing

A claim of ours went to the consumer as settled corroboration and did
not survive their read of it. It was that **four fields are identical
in size and purpose across the two protocols** -- sender 32, tag/mac
16, kind/cmd 1, commitment 16 -- offered as two designs converging
independently, which is worth something precisely because two
documents agreeing are one witness when the same hand wrote both.

**It is three.** The commitment does not belong on the list. Both are
sixteen bytes and both commit to a key, and that is where it stops:
theirs comes out of the SAME hash as their AEAD key, over a transcript
containing a per-message DH, so it structurally cannot be checked until
both scalar multiplications are done. Ours takes no per-message DH and
sits AHEAD of the expensive work. **Same width, opposite position in
the pipeline** -- and from outside, comparing layouts, the two are the
same sixteen bytes at the same offset.

The error was comparing a FIELD LIST. Width and stated purpose matched,
so convergence was inferred; what differed was where each sits relative
to authentication, which a layout does not show and only reading the
receive order reveals.

### The gate is the finding, not the microseconds

Recorded because the number was nearly all that got written down. The
headline was 640 ns against 158 us, and the reason is the part another
tree can use: **passing our first filter needs the per-pair commitment
key, which is shared and unguessable. Passing theirs needs a peer's
host public key, which anyone who has seen one datagram has.** Their
stranger dies for three scalar multiplications; ours for one hash.

That is the whole 750x and it has nothing to do with arithmetic speed.
A design that put a cheap filter first but gated it on something public
would have the same ordering and none of the benefit. **What a filter
COSTS is a property of the algorithm; what it is GATED ON is a property
of the design**, and only the second transfers.

### The category change that belongs in the decision

Today **every secret this library touches is a caller-owned array it
only reads** -- confirmed against the complete public struct inventory,
not one of which holds secret material. C, E, F and G all make the
library the owner of a MUTABLE SECRET, and the deletion is only real if
the consumer's persistence cooperates. A consumer that snapshots and
restores has E's costs and today's guarantees, silently, and this
library cannot detect it. That is an argument for saying so loudly in
the header, not for declining to build.

## 13f. What two days of this taught about method

Folded rather than accumulated. The individual findings are in the
sections that produced them; this is what survives paraphrase.

### A design pass reads its own prose charitably; a build reads it as an attacker

**Four designs recorded here were wrong, and all four were found by
BUILDING them, none by reviewing them.**

- The **sequenced revocation stream**, which two independent passes
  converged on and which the holder's answer killed -- with a replicated
  key, two writers pick the same sequence and the loser vanishes by the
  mechanism introduced to make vanishing detectable.
- The **manifest id** as a hash of a revocation's signed bytes. The
  store keeps three fields and discards `issued_at`, so a host cannot
  recompute the id of a revocation it holds -- the one operation the
  mechanism needs.
- **Shape H**, a long-lived commitment kept as a pre-DH filter, called
  mandatory by the pass that proposed it. It silently ends key
  commitment, because the binding exists only while the AEAD key and
  the commitment key are two halves of one hash.
- **Sec 13c's admission rule**, whose prose related the offered chain to
  nothing, so a fresh keypair could staple somebody else's chain and
  revoke under it for the price of one keygen.

The last is the sharpest, because **the same section's one-line summary
was correct**: "admit if `fzn_chain_delegate` would let that key grant
the thing it is withdrawing" implies the missing check; the careful
paragraph did not. **The summary is not a lossy copy of the rule. They
are two statements that can disagree, and the prose is what gets built
from.** Where a design gives both, check them against each other -- the
gap between them is where the exploit lived.

**The practical consequence: prefer building a small thing to designing
a large one.** A build pass has produced a correction every time it has
been run here; a design pass has produced one that needed correcting
every time. That is not an argument against designing, since three of
the four errors above were caught only because a design existed to be
checked. It is an argument against acting on a design that no build has
read.

### Almost every instrument error looked like diligence

Roughly ten edits and probes in this run failed to apply -- a pattern
matching a comment instead of code, a `sed` hitting a line number that
had moved, a grep counting function names inside prose, a filter that
excluded the line it was aimed at. **Not one produced an error. Every
one produced a PASS**, because a mutation that does not apply leaves the
code correct and the suite green.

So the rule is not "be careful with sed". It is: **a probe must prove
it changed something before its result means anything.** Assert the
mutated text is present; check the binary's mtime moved; and where a
script writes, assert before writing so a failed match writes nothing.
Every one of the ten was caught that way and none by noticing a
suspicious result.

The same shape at three other scales, all found here: a check whose
comment argued it was not vacuous while the include guard made it so; a
count quoted three commits after it was measured; an inventory of test
binaries that nothing compared to the binaries.

### Two trees find each other's errors and their own poorly

Measured rather than felt. In one day the consumer corrected this tree
on its forward-secrecy claim, on four fields being three, on a scalar
count bounded by one file, on a stale statement about their own hop
version, and on the object-tag enum. This tree corrected theirs on an
inverted polarity, a fail-open they had documented as a discipline, and
a claim about our constant they had never read.

**None was self-caught, and the mechanism is not diligence but
position**: a claim about another tree decays silently because only its
owner can see it go stale, and only a citation makes them look. So
**cite the other tree's constant by name** -- it is the citation that
produces the correction, and a name you have not read is not a
citation.

**And agreement between two entangled trees is the weakest evidence
either can produce.** Both sides nearly adopted the other's answer to a
branch where the correct answers differ structurally -- whether anything
verified a record before it was stored. Corroboration doing the opposite
of its job is what independent halves, written before exchange, exist
to prevent.

### Where a number came from is part of the number

A figure is measured at the moment it is quoted or it is not measured.
Two consequences that cost something here: a per-binary inventory was
deleted rather than corrected, because an inventory nothing checks is
wrong the moment anything is added and looks authoritative meanwhile;
and every cross-tree count now says which VERSION it read, after both
trees read the same enum correctly and got three against four, one at a
pin and one at HEAD.

### Prose survives a rewrite, so wrong prose survives it too

The consumer's tree carried a documented reason that cited a sibling
function and a stated discipline, applied it faithfully, and inverted a
polarity -- while thirty lines above, the same file did the right thing
with no comment at all. **A consolidation carries the documented one
across and drops the undocumented one.**

This library is the most heavily commented of the family, which makes
that a specific risk rather than a general caution. In one day this
document was found carrying a stale blocker telling the next session
not to start unblocked work, a count superseded twice, an inventory
nothing checked, a claim its owner had to correct, and a design record
whose id could not work. **A reasons list is a list of what will be
preserved whether or not it is right.**

## 14. Open, and named rather than left silent

- **There is NO PER-MESSAGE FORWARD SECRECY, and until 2026-08-28 this
  document did not say so anywhere.** The AEAD key is derived once per
  peer over a transcript -- `session/commitment.h` calls it "long-lived,
  per peer, and it takes no nonce" -- and every frame is sealed under it
  with only the nonce varying. Compromise it and every frame ever sealed
  under it opens, including those already sent.

  Found by a consumer asking a direct question about the key schedule
  rather than deriving one from the layout: their frame carries a fresh
  ephemeral per message, which makes their derived key single-use, and
  they wanted to know whether our 24-byte nonce was doing the same job
  over a static secret. It is not.

  **BUT WHAT THEY HAVE IS HALF OF WHAT THIS DOCUMENT SAID, AND THEIR
  OWN HEADER CARRIES THE QUALIFIER WE DROPPED.**
  `crypto_msg_internal.h:82` reads "per-message forward secrecy **for
  the sender's contribution**". Their construction is one-pass
  ephemeral-static: their open path computes both DHs from the
  recipient's long-lived prekey secret and wire fields, and that prekey
  does not rotate -- their own header calls it "a long-lived" keypair.
  **So compromising the RECIPIENT opens every recorded datagram ever
  sent to it, retroactively.** They have forward secrecy against
  compromise of the SENDING host.

  **That is decisive for this library rather than a footnote.** Sec 4.4a
  names the expected compromise: "the machine most likely to be attacked
  is the one being reconfigured **because it is already misbehaving**".
  That is the RECEIVER. Adopting their construction verbatim would buy
  forward secrecy against compromise of the controller and nothing
  against compromise of the router -- the wrong half, in the threat
  model this document wrote down. **A grep for "forward secrecy" over
  this whole document returned nothing**, in a file that compares the
  two frame layouts four times and had priced their ephemeral as "32
  bytes rather than 24".

  Not recorded as a defect, because nothing here promised it and the
  self-contained-frame axis sec 13 keeps meeting is a real reason to
  land where we did. Recorded because **an absent security property that
  is written down nowhere is indistinguishable from one nobody
  considered**, and a consumer evaluating adoption cannot tell those
  apart. Whether to want it is the holder's, and it is expensive: it
  needs per-message key material in the frame, which is the 32 bytes
  fuzzypickles pays.

  **AND IT IS NOW DECISION-BLOCKING FOR A NAMED CONSUMER**, which is a
  different thing from an open item and should be prioritised as one.
  fuzzypickles recorded our answer against their phase 1 entry
  (`2ad6a19`) and reports it as **the largest single item against
  adoption from their side**. Their sentence changed from "38 bytes for
  relay, chunking and per-frame revocation" to "38 bytes, PLUS GIVING UP
  PER-MESSAGE FORWARD SECRECY, for relay, chunking and per-frame
  revocation" -- because 71 of the delta is capability they lack and 33
  is a property they would surrender, and the net figure hid the second
  half entirely. If this ever closes, they want to re-run the
  arithmetic.

  So this entry has what most of sec 14 does not: a consumer who cannot
  adopt until it moves, and who has said so in writing in their own
  tree. That does not decide it -- the cost is 32 bytes on every
  datagram of a protocol whose whole axis is the self-contained frame --
  but it means the question is live rather than theoretical.

- **`raidcfgd` EXISTS, and the decisions above were made when it did
  not.** This entry said "raidcfgd does not exist -- two real consumers
  and one imagined one" until 2026-08-27, while sec 4.8 said "raidcfgd
  exists now" and quoted a requirement it stated on 2026-08-18. Two
  sentences in one document that could not both be current; the tree is
  on disk and committing. Caught by a design agent reading both.

  The factual half is corrected here. **The design half is not, and is
  the open item**: every decision above was reasoned from two consumers,
  and there are three. `local/` is the piece most exposed and is
  scheduled last for that reason, but sec 2's hazard -- a group that can
  destroy arrays is root for that group -- is the case that most wants
  grantor-revocation, since the natural revoker of a group member is the
  group's administrator and not the root. Whether the decisions want
  re-checking against a third brief is the holder's call, not a thing to
  settle by editing a bullet.
- **Which package the agent ships in** is netcfgd's open question, and matters
  here only in that it is a daemon that listens on a network — a thing netcfgd
  has deliberately never had.
- **Licensing**, unresolved across the whole family per `harmonization.md`, and
  a shared library is where it starts to bite: this one is linked by projects
  that may not agree.
- **~~Key-committing AEAD has no field to commit into.~~ FALSE SINCE THE
  FIELD WAS ADDED, and this entry went on saying it.** Corrected
  2026-08-27. Sec 4.5 line 630 reads "**Settled: `commitment[16]` goes
  in the authenticated header**" and line 692 records the half that does
  not wait on situ as built. The code agrees with sec 4.5 and not with
  this entry: `wire/frame.situ` declares `u8 commitment[16]`,
  `wire/seal.c` asserts it against `FZN_COMMITMENT_LEN` at compile time,
  and `fzn_commitment_for_nonce` derives one per frame.

  **A STALE BLOCKER IS THE EXPENSIVE KIND OF STALENESS.** A stale count
  misleads a reader; a stale blocker tells the next session not to start
  work that is already unblocked, and it does it from the section whose
  whole purpose is to say what is open. This one had two sections of
  this document disagreeing, with the code siding against the one a
  reader consults for what to do next.

  **What is NOT established here is whether the extern codec has OTHER
  blockers.** The clause "cannot be written until that is settled" is
  removed because its stated reason is gone, not because anybody checked
  the codec. If it is still blocked, it is blocked on something nobody
  has written down.
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

  **AND THE FAIL-OPEN IS STRUCTURAL, NOT AN OVERSIGHT** -- established
  2026-08-27 by comparing with a consumer that has the same bound and
  the OPPOSITE disposition. fuzzypickles bounds its revocation list at
  64 and its index-add refuses when full, exactly as this store does.
  It fails toward HONOURING the revocation anyway, because it stores the
  revocation RECORD before it touches the index: past the limit the
  revocation is in force locally and what is lost is the relay hop. Their
  own summary -- "losing a relay hop is recoverable by any other host
  that heard it; refusing to honour a revocation is not."

  **fuzznet cannot do that, and the reason is architectural.**
  `fzn_revocation_store_t` is both the record and the index: it is the
  only memory that a revocation happened. When it is full there is
  nowhere to put the fact, so `fzn_revocation_admit` refuses and the
  revocation is not in force at all. Their split of "in force here" from
  "propagates onward" is what makes failing safe available to them, and
  this library has no such split to exploit.

  So this entry should not be read as a defect awaiting a small fix.
  **The available mitigation is the manifest** (sec 13d), and this is
  the strongest argument for building it: a manifest names the count
  BEFORE the revocations arrive, so a host can refuse at follow time,
  loudly, with a number -- instead of discovering months later that a
  table filled and a revoked device stayed authorised. It does not make
  the store fail safe. It makes the bound checkable while there is still
  something to do about it.

  Recorded as mirror images rather than as a shared defect, because
  "the consumer has the same fail-open" would be wrong in the one
  direction that matters.

  **An entry costs 96 bytes, up from 64**, since the cross-root fix below
  keeps the issuer -- measured with `sizeof`, not derived. It is 50% more
  of the one thing here that only grows, and it is worth what it costs:
  what it buys is that an entry answers for the key that signed it. The
  manifest shape in sec 13b is a second consumer of the same growth.

  **AND 96/64 IS THE PER-ENTRY FIGURE ONLY -- THE ENTRY COUNT NOW SCALES
  WITH THE NUMBER OF ROOTS.** Deduplication is per issuer now, so two
  roots revoking the SAME `(capability, grantee)` take two slots where
  they used to take one. Probed rather than reasoned: admit root B's
  revocation of a pair, then root A's revocation of the same pair, and
  `store.used` is 2. For a host holding R anchors the worst case is
  therefore **1.5 x R** times the old bytes, not 1.5x -- and R > 1 is the
  premise of the fix, since a single-root host never had the defect.

  That is the growth landing on the bound whose refusal fails open, and
  it was not visible from the per-entry number. Found by an adversarial
  review of the fix rather than by the fix's own author, which is the
  argument for having run one: the entry size was measured and reported
  honestly, and it was the wrong quantity.
- **A revocation stops a chain only at a host that HAS it, and a host
  cannot tell "nothing was revoked" from "I am missing the
  revocations".** This is the open half of revocation and it is the
  serious one. Revocations are standalone signed objects that ride no
  stream and carry no sequence, so absence and up-to-date are the same
  observation. A host that joins fresh, has been offline, or is
  partitioned by an attacker anchors an issuer with an empty journal and
  verifies a chain the rest of the network revoked last week. Being a
  relay on the path is enough to hold a victim there.

  **The harness now exhibits it rather than hiding it.**
  `sim/test/network_test.c`'s `scenario_revocation_split` gives two hosts
  the same root and the same sender's chain, tells one of them about the
  revocation, and asserts *both* outcomes: the told host refuses and the
  untold host delivers. Until the revocation store there went per host it
  was one store shared by every simulated host, so two hosts disagreeing
  about what is revoked was not a state the simulation had, and
  `scenario_revocation` proved the cascade while being quoted for
  revocation entire. The assertion that the untold host delivers is a
  record of this gap, not an endorsement of it: **closing the gap must
  break that scenario**, which is the point of writing it as an assertion
  rather than as a comment.

  **The cascade half is NOT this gap, and was re-tested rather than
  assumed.** An audit reported that revoking a granter leaves its grants
  standing. It does not: `chain/chain.c` runs the revocation check over
  EVERY hop rather than the last, so revoking a host in the middle kills
  what it went on to delegate -- which is what a stolen device would do
  first. Narrowing that walk to `i + 1 == hop_count` was tried and
  `chain_test.c:646` failed, so the check discriminates and the test is
  not vacuous. The audit had also filed it against `state/`, which
  declares at `state.h:159` that authorisation is deliberately not its
  business. Recorded because a refuted finding that leaves no trace gets
  found again.

- **`fzn_chain_verify` takes the STORE now, and `hop_is_revoked` is
  gone.** Fixed 2026-08-27. It took `(entries, count)`, so it looped a
  caller's count with no capacity to check it against -- while
  `fzn_revocation_covers` deliberately refuses to scan a store whose
  `used` exceeds its `capacity` and denies. Two parallel implementations
  of one predicate, differing in exactly the case that matters: ASan
  reported a heap-buffer-overflow READ on the authorization path with
  `used = capacity + 1`, which every documented calling pattern
  (`store.entries, store.used`) could produce. There is one
  implementation now and the refusal is inherited rather than
  duplicated. Verified independently of the implementing agent with a
  probe that mints a REAL hop -- the first version passed a zero hop,
  which `fzn_hop_open` refuses, so verification returned MALFORMED
  before ever reaching the revocation walk and the probe proved nothing.

- **The harness could not discriminate the identities whose separation
  it exists to assert. FIXED 2026-08-27.** `sim_identity` zeroed 32
  bytes and set two, so every identity shared bytes 2..31 and differed
  only in the prefix. Measured before the fix: truncating
  `chunk/reassembly.c`'s sender comparison to one byte and rebuilding
  left `network_test` at 172 checks, 0 failures, with the splice
  scenario still printing "0 spliced" -- while `reassembly_test` caught
  the same mutation with 3. Same for the root pin: `chain_test` caught
  it, the harness did not.

  **It landed on a claim rather than on tidiness.** Sec 5a cites the
  splice scenario for "no cross-sender splice", and real public keys
  share a first byte one time in 256 -- so that truncation would splice
  in deployment and the harness asserting the property could not see it.
  Identities now spread across all 32 bytes and two near-miss legs were
  added, one for the sender comparison and one for the root pin. Both
  mutations now fail the harness, verified by re-running them after the
  merge rather than taking the report's word.

  The mechanism the fix exposed is worth keeping: a near-miss intruder's
  chunk is refused as a DUPLICATE INDEX, so the victim's message
  completes without it and the stranger's never completes. Nothing is
  spliced and a message is silently lost, which is why the leg asserts a
  refusal COUNT rather than only the absence of a splice.

- **`sim_verify` was key-blind, and no scenario could catch verification
  against the wrong key. FIXED 2026-08-27.** It was `(void)pubkey;`
  recomputing from the message alone, so every key verified everything.
  Measured: verifying every hop against `hops[0]`'s grantor rather than
  its own -- textbook key confusion -- gave `chain_test` **39 failures**
  and `network_test` **zero**.

  `sim_sign_bytes` folds a signer identity, `sim_verify` folds the
  `pubkey` it is handed, and `sim_sign_op` REFUSES a NULL context so a
  signing site that forgets to name its signer fails loudly rather than
  signing as the all-zero identity. The harness now catches the mutation
  by name: "each hop's signature must be checked against THAT hop's
  grantor, not against the root".

  **The scoping this was commissioned with was wrong and the worker
  measured instead of trusting it.** It was handed "signing happens in
  exactly two places", relayed from an earlier report without
  verification; there are SEVEN, and all seven had to name a signer.
  The brief said to grep before relying on the number, which is the only
  reason it was caught.

  Two proofs beyond the mutation, both worth copying. A second binary
  was built from the PREVIOUS version of the file against the same
  objects and the full output diffed byte-identical, so "no scenario
  changed behaviour" is a measurement rather than a claim. And the two
  new negative legs were proved falsifiable by sabotaging the stub back
  to key-blind: exactly those two fail and nothing else.

- **A layer's signature is only tested where the harness verifies it,
  and `record/` is not.** `fzn_record_verify` is called nowhere in
  `sim/test/network_test.c` -- the harness signs records through
  `fzn_record_sign` and never checks one, so the record layer's
  signature is structural there exactly as chains' was until today.
  Recorded rather than fixed, and the sequencing matters: adding a
  record verification BEFORE the key-blindness fix would have been a
  vacuous check, because every key verified everything. It is worth
  writing now and was not worth writing yesterday.

- **Two gaps this sweep did NOT close, both named rather than left.**
  `sim/test/network_test.c`'s `sim_identity` is still the
  `memset(out, id, 32)` idiom, feeding the integration harness's root
  and every host key -- so the end-to-end suite remains unable to catch
  a truncated comparison in whatever it exercises. And
  `FZN_CAP_ID_LEN == FZN_PUBKEY_LEN == 32`, so a SWAPPED length constant
  is undetectable by any fixture; closing that needs the constants to
  differ or a compile-time distinction between the two types, and no
  test can do it.

- **`make installcheck` failed when Monocypher was built. FIXED
  2026-08-27, and fixing it found something worse.**
  `session/aead_monocypher.h` was in `HDRS` and not included by
  `tool/consumer_check.c`. The comment above that include block says
  "two headers were installable and unverifiable"; the fix that
  followed it covered two of three and missed this one. **Counting the
  headers a fix covers against the headers that exist is the check that
  was missing.**

  Behind it: the block exercising the real bindings hashes a buffer
  named `region` **which is declared nowhere in the file**, so that
  block HAD NEVER COMPILED. It could not be noticed, because it builds
  only under `FZN_CONSUMER_MONOCYPHER` and that arrangement failed the
  header-coverage check first -- the compiler never reached the line. **A
  gate that refuses early hides whatever is behind it**, and this one
  had been hiding a translation unit that does not build. The AEAD
  binding now gets a call to the same standard as the other two, proved
  able to fail by nulling its seal op.

- **A revocation store was single-root by assumption, and is not any
  more. FIXED 2026-08-27**; the finding is kept because the fix that was
  first proposed here is not the fix that was taken, and the reason is
  worth more than the entry. Confirmed by running it, not by reading.
  `fzn_revocation_admit` verified a record's issuer against the `root` it
  was handed and then stored only `{capability, grantee}` -- the issuer was
  discarded. `fzn_revocation_covers` then takes **no root at all**, and
  `fzn_chain_verify` takes `root` and the entries array as independent
  parameters with nothing comparing them. A store holding root B's
  revocation therefore answers "revoked" to a query about root A's realm.

  The probe: root B signs a revocation of (cap, grantee), admitted
  against B's own root, which is correct on B's terms; `covers` then
  returns 1 for that pair with no root in the question. Nothing in the
  headers says a store belongs to one root, and `covers`'s signature
  actively invites the mistake by not asking.

  **It is not theoretical, because fuzzypickles is multi-root by
  design** -- sec 5's User realm has its own root and the Registered
  realm is a different user's, TOFU-pinned, and the recommendation
  adopted was to anchor each peer's root so their revocations are
  honoured. A host therefore holds several, and the natural reading of
  this API gives it one store. The consequence is that any anchored peer
  can revoke any key in any other peer's tree -- which is sec 4.2's own
  named failure mode, "inventing revocations is a denial of service
  against exactly the hosts an attacker wants disconnected", closed for
  unsigned revocations and open for cross-root ones because the
  signature is checked against the wrong question.

  Every test in the tree used a single root, in both directions, so this
  was untested rather than tested-and-passing.

  **What was built keeps the ISSUER; it does not bind the store to a
  root.** This entry used to propose the other shape -- bind the store to
  a root at init, so `admit` refuses a foreign issuer and `covers` cannot
  be asked a rootless question -- and sec 13b calls that shape a
  precondition for the revocation model the holder chose. It is the wrong
  shape for the same answer that promoted the finding: **answer 2 says
  grantor-revokes-descendant IS coming**, so a store will hold entries
  from many issuers, and a store bound to one root would have to be
  unbound again the moment it arrives. So `fzn_revocation_t` carries
  `issuer[32]`, filled by `admit` from the RECORD'S OWN SIGNED BYTES
  rather than from the `root` it is handed -- the same rule the rest of
  that module already follows -- and `fzn_revocation_covers` takes an
  issuer and matches on all three of issuer, capability and grantee.

  `chain.c`'s `fzn_revocation_covers` (as called from `fzn_chain_verify`) passes the pinned root as the issuer,
  because root-only revocation is what is implemented today: `admit`
  refuses any other issuer, so asking about the root asks about every
  entry a store can hold. **That call site is the line that changes when
  grantor-revokes-descendant arrives**, and it says so. Grantor
  revocation is planned and is deliberately not built here.

  **IT ARRIVED ON 2026-08-28 and that line has changed** -- see §13c's
  *What building it changed*. `fzn_chain_verify` asks
  `fzn_revocation_covers_chain` about the whole chain now, and an entry's
  issuer is matched against the chain's own grantors rather than against
  the pinned root. The paragraph above is kept because its reasoning is
  what decided the shape: an entry keeps its ISSUER precisely so that this
  widening was a change to one query rather than to the store's model.
  Note the sentence "`admit` refuses any other issuer" is no longer true
  and was already only true of root-issued offers.

  The API break is real and is taken rather than deferred: `covers` grew
  a parameter, and every caller in the tree was updated. Two tests carry
  the defect so it cannot come back -- one in `chain/test/chain_test.c`
  over `fzn_revocation_covers` (as called from `fzn_chain_verify`)'s third axis, and one in
  `chain/test/revocation_test.c` from a genuinely signed record, where
  root B's revocation must answer `revoked` under B and `not revoked`
  under A. Both were proved by mutation: deleting the issuer term from
  `fzn_revocation_covers` fails the second, and deleting it from
  `fzn_revocation_covers` (as called from `fzn_chain_verify`) fails the first.

  **THE TERM WAS PROVED PRESENT AND NOT PROVED WHOLE**, and an
  adversarial review found the difference. Deleting a comparison is one
  mutation; TRUNCATING it is another, and nothing in the tree could
  catch the second. Every key and capability these suites built was
  `memset(buf, seed, 32)` -- thirty-two copies of one byte -- so a value
  answered any prefix exactly as it answered the whole, and
  `fzn_ct_memeq(a, b, 1)` and `fzn_ct_memeq(a, b, 32)` were the same
  function over every fixture. Measured: cutting the revocation check's
  issuer comparison to one byte left `make test` at exit 0, and so did
  cutting all three of `same()`'s in `chain/revocation.c`, 200000 fuzz
  cases included. `FZN_CAP_ID_LEN == FZN_PUBKEY_LEN == 32`, so a swapped
  length constant was equally invisible.

  The fix is in the fixtures rather than in the assertions: byte 0 stays
  the seed, because the stub verifiers derive identity from `pubkey[0]`
  and keys that differ in every byte would leave signer and verifier
  disagreeing about who is who, and every later byte varies with its
  position. That alone is not enough -- two values built from equal seeds
  are still equal everywhere -- so the suites also build a NEAR MISS, the
  value that ought to match with only its LAST byte changed. One such
  pair settles every truncation from one byte to thirty-one at once, and
  it keeps its identity, so it reaches the comparison under test instead
  of being refused earlier at the signature.

  Both directions of `same()` are asserted, because the two readings fail
  differently. Through `covers` a short comparison reports an unrelated
  entry as revoked and refuses a chain nobody withdrew. Through `admit`
  it reports a genuine revocation as already held, returns
  `FZN_CHAIN_OK`, and DROPS it -- the fail-open direction, and the one
  with no alarm attached, since "already known" is what success looks
  like every time carriage works.

  **And the harness that models admission could not decide the issuer
  term at all.** `chain/test/revocation_fuzz.c` pinned one root, and
  `fzn_revocation_admit` refuses any other issuer, so every entry the
  store or the model could hold carried that single key: deleting the
  issuer comparison from the model left the run's output byte-identical.
  It names two roots now and admits each record under the one it names,
  so the store reaches the state the term exists for -- two revocations
  differing only in who withdrew them, which is an ordinary day for a
  host anchoring two roots, and which no harness in the tree modelled.
  Two coverage counters floor that state and the near-miss state, so a
  generator that stops producing either fails the run rather than
  reporting the same numbers.

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

## 16. Content addressing: the design, 2026-08-28

fuzzypickles' gap list puts this first among the absences and calls it
larger than the gap this tree called largest. Measured there: `merkle`,
`blob`, `convergent` and `content.address` are **zero files here**
against their `blob.c` at 1893 lines, with stickers, `file_ref` and
group assets standing on it.

**The contract below is read from their `core/src/blob_internal.h` at
`2073cbe` and adopted where it is right, which is most of it.** The commit
is part of the citation, per the rule the tag-space pass just produced: a
name alone does not say which of two true readings was taken. Their design is
better than a fresh one would be, and the parts worth restating are
the ones this library changes.

### What is adopted whole, and why each is load-bearing

**The Merkle tree is over CIPHERTEXT, not plaintext, and that ordering
is the design.** Two verifiers answering different questions: any host
checks a leaf against the root **with no key at all**, so a relay or
cache serves bytes it cannot read; the recipient additionally checks
the AEAD, which is what authenticates the plaintext. A relay needs the
first and must never need the second.

**Sealing is deterministic** -- the nonce comes from the leaf index,
not from entropy -- because two people holding the same file must
produce byte-identical ciphertext or dedup does not work at all. Safe
only because a content key is per blob and each (key, index) is used
once. Reusing a content key across different content is catastrophic in
the ordinary way, and the API has to make that hard to spell.

**Key-committing per leaf**, which this library already has the shape
for: `session/commitment.h`'s one hash producing an AEAD key and a
commitment from a single input. The blob's derivation is that
construction with its own label, not a second implementation.

**The leaf is 1024 bytes**, adopted with their arithmetic rather than
re-derived -- `FZP_BLOB_LEAF_SIZE`, sized so a sealed leaf and its
framing fit one datagram inside IPv6's guaranteed 1280 MTU. The
property that matters is not the packing: **the leaf size is exactly
how much UNVERIFIED data an attacker can make a host buffer.** At
datagram size every arriving datagram is independently verifiable on
arrival, so the classic P2P exhaustion vector closes by construction
rather than by a heuristic. It costs ~3% in AEAD overhead forever, and
bisection addressing is what keeps that affordable.

**It is identity-affecting and therefore permanent.** The blob id is
the root over leaves of this size, so a different size is a different
id for the same file and a disjoint swarm.

### What this library changes, and why

**They are LEAVES here, never chunks.** `chunk/` in this tree is
datagram fragmentation with a transient lifecycle; a blob leaf is
content-addressed and permanent. Two things called chunk, one module
apart, is the fifth question arriving inside a single tree rather
than between two -- and the earlier finding stands that a module is its
lifecycle rather than its data structure. The word is spent; blob/ uses
leaf.

**Nothing allocates, which their design does not have to worry about
and this one does.** A tree over a gigabyte cannot hold its leaf hashes.
The construction is therefore STREAMING: a stack of at most
`FZN_BLOB_MAX_DEPTH` interior hashes, folded as leaves arrive, so the
working set is 40 hashes regardless of blob size and the caller owns
every byte. That is the same discipline as the rest of the library and
it is not a compromise -- a streaming tree is what a receiver verifying
in arrival order wants anyway.

**Leaf and interior hashing are domain-separated**, by a distinct
prefix byte on each. Without it a Merkle tree has the classic
second-preimage weakness: an interior node's two child hashes are 64
bytes that can be presented as a leaf's content, so a tree of depth d
over n leaves has forgeries that no key would catch. The keyless
verifier is exactly the one that would accept them, and the keyless
verifier is the one strangers use. Asserted by a test that constructs
the collision, not by a comment.

**Bisection addressing names a subtree by (index, depth)**, so a peer
moves a whole subtree for one small integer. This is what makes a fine
leaf affordable and it is the reason the ~3% is a deliberate purchase
rather than a regret.

### The seam, and what stage 1 is

Stage 1 is the generic half and nothing else: leaf key derivation, leaf
seal and open, the streaming root, an inclusion proof and its verifier,
and subtree verification. It calls `fzn_hash_ops_t` and
`fzn_aead_ops_t` and no primitive, like everything else here.

**Stage 2 is the transfer protocol -- HAVE, WANT, the batch -- and it
is deliberately not in stage 1.** It is transport, their own gap list
marks transport as not blocking if the first switch is crypto and
records, and it carries a decision this tree has not taken: their WANT
needs a return-routability cookie because a ~45-byte query answers with
up to 64 KiB, a ~1500x reflection against the ~388x this tree already
measured for the manifest. That belongs with the rest of the
amplification work in sec 13c, not inside a hashing module.

**Convergent encryption is a stage 2 question too, and it is a policy
rather than a mechanism**: deriving the content key from the content
makes identical files dedup across users and makes a confirmation-of-a-
file attack possible against low-entropy content. Stage 1 takes the
content key as an argument and has no opinion, which is the honest
place for the seam to sit until the holder decides.

### Stage 1 built, and what building it corrected

`blob/blob.c`, `blob/blob.h`, `blob/test/blob_test.c` -- 1445 checks. The
module links `constant_time/` and nothing else: the tree and the sealing are
arithmetic over bytes the caller supplies, and the crypto arrives through the
two vtables, which is the shape sec 16 asked for and is worth having been
checked rather than intended.

**THE ROOT DOES NOT COMMIT TO THE LEAF COUNT, and the design section above
did not know it.** A case was written asserting flatly that a proof does not
verify against a tree of a different size. It failed, correctly: leaf 4 of an
11-leaf tree sits inside the complete left subtree of eight, which is
identical in a 12-leaf tree, so the path, the siblings and the root are all
the same and the proof IS valid for both. Only a leaf whose depth actually
differs -- leaf 10 of 11 against 12 -- is refused.

That is RFC 6962's property inherited whole, and the consequence was
recorded as a caller's: ~~whatever record carries a blob id must carry its
length beside it, inside the same signature.~~ **Superseded within the hour
-- see the entry below. The constraint is gone; the root binds the count
now.**

**The design pass would not have found it.** Sec 16 was written from a
correct reading of a good header and still carried a false claim about the
construction it was adopting -- which is sec 13f's asymmetry again, on the
day after it was recorded: four designs wrong, all four found by building.

**One definition of the tree's shape, deliberately.** `subtree_root`, which
proof building needs, is built on `fzn_blob_tree_push` rather than on its own
recursion. A second recursive definition would agree today and be free to
drift, and the whole apparatus of proofs is worthless the moment the prover
and the builder disagree about what the tree is. It costs O(n log n) for a
proof, which is the seeder's cost over hashes it already holds.

**The test's reference is a THIRD implementation and looks nothing like
either**: RFC 6962's recursion, written from the definition, checked against
the streaming builder for every leaf count from 1 to 130 rather than a
sample. A sample chosen by hand is a sample chosen to pass, and the counts
that catch a fold-direction error are the ones just past a power of two.

**Eight mutations, eight refusals.** The node prefix set equal to the leaf
prefix, the root folded left-to-right, the index dropped from the key
derivation, the sibling count compared with `>` instead of `!=`, the wipe
removed from a refused open, and the commitment check disabled -- each
asserted present before the run.

**Two were caught by the compiler rather than by the suite, and were re-run
without their compile-time guard**, because a `_Static_assert` catching a
mutation says the assert works and nothing about whether the test does. With
the assert deleted, the prefix collision fails the second-preimage case; with
`index` kept syntactically used, dropping it from the derivation fails the
index-binding case. A mutation stopped at compile time is a mutation whose
test has not been tried.

### The fuzz harness, and the mutation that survived it

`blob/test/blob_fuzz.c`, with two oracles. The root oracle is RFC 6962's
recursion, as in the unit suite. The proof oracle is the stronger one and is
why the file exists: **for any (index, leaf_count) the only sibling sequence
that may verify is the one `fzn_blob_proof_build` produces**, so every
accepted proof is compared against the built one and a second proof for the
same leaf is reported as a forgery rather than tolerated as arithmetic.

A spot invariant cannot give that. "The verifier did not crash" is satisfied
by a verifier that accepts everything, and a content-addressed store whose
verifier accepts everything serves whatever it was handed.

**THE HARNESS WAS MUTATION-TESTED AND ONE MUTATION SURVIVED IT.** Relaxing
`sibling_count != depth` to `sibling_count > depth` left the run reporting
"no invariant broken" over two thousand cases -- while the unit suite caught
it. Worth understanding rather than patching, because the reason is a
property of the harness and not of the check.

The climb indexes `siblings[depth - 1]` downwards from the TREE's depth, not
from the count the caller gave, so **a proof shorter than the tree is deep
reads past the caller's buffer.** The check is a memory guard as much as a
strictness one. The harness could not see it because it always passed a
buffer of `FZN_BLOB_MAX_DEPTH` siblings, so an over-read landed inside the
same array and was indistinguishable from a hit.

**The fix is placement, not another assertion.** The offered proof is laid
flush against the END of its buffer, so reading one sibling too many runs off
the array. Under AddressSanitizer the relaxed check now fails on the second
case with a stack-buffer-overflow. It costs one pointer and no allocator,
which is a guard page built out of arithmetic.

**The general form is worth more than the instance**: a harness that always
supplies the maximum buffer cannot express an over-read, however hostile its
inputs. That is `evidence.md`'s probe placed where the error is not
expressible -- and the thing that found it was mutating the code to test the
HARNESS, rather than mutating it to test the module.

### The root binds the leaf count, and the caller constraint is gone

**Adopted from fuzzypickles' `finalise_root`, `core/src/blob.c` at 816fa35**,
after they read the constraint above and answered with the line that removes
it. The root is `H(label | u64be(leaf_count) | apex)`.

**Verified in their source rather than taken from their message**, which is
the rule that has now paid twice in two days. Four call sites: the root
computation, BOTH proof verifiers, and their streaming path. That last check
mattered -- the question was about a PROOF, and a binding that held only at
construction would not have answered it.

**Why take it rather than keep the constraint.** Theirs was the sharper
argument and it is worth stating in their terms: this library's answer was
correct and CONDITIONAL -- on every present and future caller carrying a
length inside the same signature. That is a rule which holds until somebody
writes a caller that does not, fails silently when they do, and lives in a
module that cannot detect it. Binding the count cannot be got wrong by a
caller because no caller is involved. Same guarantee, one hash, no ongoing
obligation.

**The apex and the root are now different things**, which is what adopting it
costs and is worth naming. A sibling in a proof is an APEX -- an interior
node of a larger tree -- and finalising it would make every sibling commit to
the size of the subtree it came from, which is a different tree from the one
being proved. So `tree_apex` is internal and unfinalised, `subtree_root`
returns an apex, and only `fzn_blob_tree_root` and `fzn_blob_proof_verify`
finalise. Mutating `subtree_root` to finalise fails 563 checks, which is what
that separation is worth.

### Adopting a sibling's test brings its rationale, and the rationale may not travel

**Their `test_distinct_leaf_counts_give_distinct_roots` was taken along with
the finaliser, and it does not prove here what it proves there.** Measured by
removing the count from the finaliser AND from the test's reference together:
that case still passes, and **exactly one case in the file fails** -- the
proof verified against a different leaf count.

The reason is a difference between the two constructions. **fuzzypickles
pads** to a power of two, so two different leaf counts can fold to one apex
and their assertion is load-bearing; it is also why they pin CVE-2012-2459 by
name, which is Bitcoin's duplicated final leaf giving two blocks one id.
**This tree does not pad**, so distinct counts have distinct apexes whatever
the finaliser does, and the case cannot fail for the reason it was written.

Kept anyway -- "we do not pad" is a property somebody can change and this is
what would notice -- but with its comment saying what it does and does not
prove. **The general form: a test carries the reasoning of the construction
it was written for, and copying it across copies a claim that may no longer
be true.** Found by mutating both sides at once rather than one, which is the
only way the question can be asked.

## 17. The group ratchet, and why it is not called group

fuzzypickles' gap list has group messaging as a blocking row. Their tree is
`group_ratchet.c` at 280 lines under about 1300 of chat, and they warned
before anything was written that **the seam is not where the file boundary
is**. They then drew it from inside their tree, which is the only place it
could have been drawn from.

### What is generic, per their reading of their own code

- **One KDF step**: chain key in, message key and next chain key out. No
  storage, no names, no group concept.
- **The bounded fast-forward**, and the bound comes WITH the feature rather
  than after it. A receiver that missed messages re-derives forward without
  needing the intermediates to have arrived -- the property that makes a
  chain usable over a lossy transport -- and that same property is an
  unbounded loop driven by whatever sequence number a stranger wrote.
- **Two reasons that had to survive rather than be re-derived**: a target
  behind the stored position is expected rather than hostile, and the step
  must be alias-safe.

### What is theirs

Storage, a group identified by a NAME STRING, and rotation policy. Their
"generic" file already includes their chat headers for `FZP_PEER_NAME_MAX`
and `fzp_is_valid_peer_name`, which is exactly why the file was never the
seam. A generic library wants an opaque id it never interprets -- the way
`chain/` treats a capability as 32 bytes it compares and never reads.

### It is `ratchet/`, not `group/`, and that is sec 15d being spent

`group` means two things in this workspace already: a POSIX gid in `local/`
and a set of people in a chat. That clash was recorded before either tree
moved. **Naming the module for the mechanism rather than for the one
application that wanted it is what having found it early is worth** -- the
second time in two days the fifth question has been applied prospectively
rather than to damage already done, after `blob/`'s leaves.

### It could not have been a port, and they said so first

Their ratchet is storage-backed throughout: it loads, advances and persists
inside one call. Nothing here does I/O. So this is state-in, state-out,
caller-owned, like `record/journal.h` -- the same algorithm with the
persistence turned inside out, which most of their 280 lines do not survive.
They offered the edge cases their tests pin and then said they would rather
this tree derived the shape and asked, **given what a transplanted test had
just cost** -- which is the finding from the blob pass being spent within the
day, by the tree that received it.

### What this library does that theirs does not: skipped keys

`fzn_ratchet_advance` writes the keys for the sequence numbers it jumped over
into a caller's buffer, if one is given, and reports how many did not fit.

**The reasoning is a disagreement worth recording rather than settling.**
fuzzypickles treats a behind-position target as a duplicate whose plaintext
is already in local history. That covers a REPLAY. It does not cover a
genuinely late first delivery, which was never decrypted and so is in
nobody's history -- and on a datagram transport late is ordinary rather than
exceptional. A chain moves one way, so a message that arrives after the chain
has passed it can never be opened again.

Rather than decide that for a consumer, the material is handed back and the
choice is theirs: retaining a skipped key is a real cost, since it stays
decryptable until dropped. Signalled to them as a question about their
transport, not as a defect.

### The bound costs 62 ms, measured, and the number needs a layer to mean anything

`ratchet_test.c` ASSERTS the derivation count -- 100001 for a jump to the
bound -- so the count cannot drift. The wall clock is a separate measurement
against the Monocypher BLAKE2b binding and is asserted nowhere, because a
timing pinned by a test fails on somebody else's laptop: **62 ms, about 620
ns a step.**

A ~40-byte header naming a far-future sequence buys that. Bounded, which is
the difference between a defence and none, and not free -- sec 13c did this
arithmetic for the manifest and did not like the answer either. **Whether it
matters is a layering question rather than a ratchet one**: reached only
after a frame's own AEAD has opened, the cost is an insider's; reached from a
number a stranger can write, it is a stranger's. This module cannot tell
which, so it refuses rather than clamps and hands the caller the size of the
jump it declined.

**The measurement was nearly reported wrong.** The first probe failed to
compile -- a missing feature macro -- and the shell ran a STALE BINARY of the
same name from an earlier benchmarking session, which printed a full table of
plausible, unrelated figures. It was caught because the numbers were the
wrong benchmark's, not because anything checked. `build-and-commit.md` names
this exactly: never conclude anything from a binary the build step did not
produce. Fixed by building to a fresh name and reading its mtime before
running it.

### Seven mutations, and one of them was not a mutation

Six caught: the two halves made one half twice, the bound compared with `>=`,
a behind-position target accepted, the chain committed before the loop rather
than after, the final step dropped, and the dropped count not counted.

**The seventh -- swapping the order of the two output writes -- changed
nothing, and that is a property of the design rather than a hole in the
suite.** Both halves are computed into a temporary before either is written,
so write order cannot matter and no single-line edit reintroduces the alias
hazard. The mutation that CAN express it is a restructuring: two derivations,
each re-reading `chain_key` -- which is the implementation rejected here on
cost, since it doubles the work of the one operation that has a bound. Under
it the suite fails 35 checks, `derive(k, mk, k)` first among them.

Worth separating because "the mutation survived" and "the mutation was not a
mutation" look identical in a results table, and only one of them is a
finding.

### The layering question was not a performance question

This library asked fuzzypickles whether their fast-forward sits above or
below a frame's own AEAD, wanting to know whose 62 ms it was. **They traced
it and found a defect, a311c7f, and it is with their holder.** The CPU cost
was the smaller half.

**Their path, as they reported it**: a group datagram arrives raw on UDP;
nothing authenticates the envelope; `chat_id`, sender and `seq` are cleartext
payload fields; two gates follow and neither needs a secret, both values
being visible in any group datagram an attacker has observed. The advance
then runs on the attacker's `seq` -- **before** the only step that would
prove the frame genuine -- and it PERSISTS the moved chain before returning
the key. The AEAD then fails on the forged ciphertext and the frame is
rejected, with the stored chain already moved.

A ratchet moves one way. So every later genuine message from that sender is
behind the position and is refused as a duplicate, and its keys are gone with
the overwritten chain key. **One forged datagram, from anyone who has seen a
real one, permanently ends that sender's delivery to that receiver** -- no
key material, not a confidentiality break, irreversible, and reported as an
ordinary duplicate, which is what would have kept it invisible.

**It is theirs to fix and it is not fixed here.** What is ours is that this
library's API made the same mistake the natural one to write.

### The fix is a signature, not a warning

`fzn_ratchet_advance` took a chain and moved it. A caller reading a sequence
number off the wire would fast-forward, derive, and only then try to open --
which is the defect, spelled in one call.

It now takes `const fzn_ratchet_chain_t *from` and writes a separate `*to`,
**and returns `FZN_RATCHET_ERR_IN_PLACE` when they are the same chain.** The
commit is a plain assignment the caller makes after the frame opens, which is
the one moment it can be made safely, and there is no way to spell the unsafe
version:

    err = fzn_ratchet_advance(hash, &chain, seq, mk, &next, ...);
    if (frame_opens_under(mk))
            chain = next;

A genuine gap still fast-forwards, because a genuine frame opens. A forged
one costs the derivations and changes nothing.

**Refused rather than documented, and the reason is a day old.** A rule
saying "verify before you commit" holds until somebody writes the caller that
does not, fails silently when they do, and lives in a module that cannot
detect it. That is exactly the argument fuzzypickles made to this tree about
the blob root's leaf count, and it is now paying in the other direction.

### And the skipped-key disagreement was the same bug from another angle

They agree their behind-position reasoning covers a replay and not a late
first delivery, and add the connection this side had not made: **the same
"advance first, verify later" ordering is what makes a forged jump destroy
genuine traffic AND what makes a late arrival unopenable.** One ordering,
two symptoms, and the disagreement was the visible end of it.

That is the second time in three days that declining to settle a
disagreement produced more than either answer would have -- `working
practice.md` says holding one open produces answers neither branch contains,
and this is a worked instance: the branches were "return the skipped keys" and
"do not", and what was actually wrong was the order of two operations in a
tree neither branch was about.


## 15d. Parity before migration, and the first namespace clash

**The holder's ordering, 2026-08-28**: every feature fuzzypickles needs
should exist here BEFORE they move, so the transition is a switch
rather than a co-development. Migration planning, including a namespace
scheme, comes after parity. **fuzzypickles development is frozen**,
which is what makes the ordering work -- a frozen consumer is a
STATIONARY TARGET, so a gap list computed today stays true while it is
closed. A moving one could not be caught up with.

### What this library has no concept of, measured

Grepped every non-test, non-generated header, then read the hits to
separate API from prose:

| concept | in fuzznet |
|---|---|
| group messaging, group key, membership, fan-out | **nothing** |
| ratchet | **nothing** -- zero mentions anywhere |
| prekey distribution | **nothing** -- zero API |
| contact / peer management, roster, presence | **nothing** -- "contact" appears only as prose, in "on contact" and "first contact" |
| media, codecs, streaming | **nothing** -- sec 15b is future work |

That is the visible half of the gap. **The invisible half is the row
neither tree has thought of**, which is why the list has to come from
fuzzypickles rather than be inferred from their headers here -- inferring
it would be the claim-about-another-tree error this session has made
twice and been corrected on both times.

### THE FIRST NAMESPACE CLASH IS ALREADY IN THE TREE, AND IT IS `group`

`local/peer.h` uses `group` to mean a **POSIX group**: `primary_gid`,
`groups[FZN_PEER_MAX_GROUPS]`, `group_count`, populated from
`SO_PEERCRED` and `getgroups()`. `local/vocabulary.h` gates a verb on
one -- "this group may ask for this verb".

fuzzypickles' `group` is **a set of peers sharing a ratchet**. Same
word, and not merely different -- one is a local kernel credential that
never crosses the network, the other is a distributed cryptographic
object that exists only on the network.

**Neither can be renamed away from its own domain.** `primary_gid` is
POSIX's word and `local/peer.h` records that it is spelled that way
deliberately, "so that nobody gates on it by accident". A group ratchet
is what the literature calls it. So the clash is not a naming accident
to be tidied; **both names are correct in their own module** and the
merge has to keep them apart rather than pick one.

This is the fifth question arriving before any migration has started,
and it is the argument for writing the namespace plan from a KNOWN
inventory rather than from a prefix convention. `fzn_` against `fzp_`
prevents symbol collision and prevents nothing about this: after a
migration both concepts live under `fzn_`, and `fzn_group` would mean
two things.

**The plan is not written yet, deliberately.** A namespace scheme that
does not know what is moving is a guess, and the gap list is what tells
it. Three clashes are already foreseeable and recorded so they are not
rediscovered: this one; two copies of Monocypher if both trees vendor
it, answered in sec 15c by vendoring for tests only; and the
transitional period where one function exists under both prefixes,
which is `code-style.md`'s parallel-copy hazard.

### The signed-object tag space: settled, 2026-08-28

**Every one of this library's four tags collided with a DIFFERENT object
in fuzzypickles**, and the collision was arriving on the day the two
trees merge -- which is precisely the failure the byte exists to
prevent, one layer out from where it was designed to work.

Measured from `core/src/signed_tag.h` rather than recalled:

| tag | fuzznet (was) | fuzzypickles |
|---|---|---|
| 1 | `HOP` | `HOST_RECORD` |
| 2 | `REVOCATION` | `PREKEY_RECORD` |
| 3 | `RECORD` | `CONTACT_CARD` |
| 4 | `MANIFEST` | `PAIRING_REQUEST` |

They hold 1..12. Their header forbids renumbering, and is right to:
"a tag is part of a signature's meaning, so changing one silently
revalidates old signatures as a new type."

**So one side had to move, and it was this one.** Nothing here depended
on the values -- they appear symbolically, in three fuzz oracles and in
three test literals -- and something depends on theirs. It was free
exactly once, today.

**The shape is a split byte, not a renumber.** A tag separates
everything ONE KEY signs, and a consumer's root key signs this library's
hops alongside its own contact cards, so library and consumer objects
are in one namespace by necessity. The high bit says which minted it:
1..127 consumers, 128..255 this library. A third consumer needs no
negotiation with the first two, and neither half can allocate into the
other by accident. `FZN_OBJECT_HOP` is 128, and the registry of the
consumer half lives in `wire/bytes.h` because a table both trees read
has to be in one file and the format is ours.

**A retired tag is never reused**, adopted whole from their header.
When their capability hops become this library's, their tag 10 retires
rather than becoming anything else -- which is exactly why the merged
object takes a number from this half instead of inheriting theirs.
During a transition both encodings exist, and they must not be able to
verify as each other.

**Checked by the compiler, not by a test**, since it is a property of
the values: one `_Static_assert` for the high bit and one pairwise for
distinctness. Distinctness is pairwise rather than a count because the
count is what goes stale -- a fifth enumerator with a duplicate value
leaves "four distinct values" true and wrong. Both mutations were run:
`MANIFEST = 4u` fails with "allocated into the consumer half",
`RECORD = 128u` with "two signed-object tags share a value".

### The renumber found an asymmetry between three oracles

**Three fuzz harnesses restate these constants as a second
implementation, and only one of them pointed at itself when the
constant moved.** `record_fuzz` names `WANT_OBJECT` and asserts it
against the header, so the change failed the build at the line needing
the edit. `chain_fuzz` and `revocation_fuzz` wrote bare literals, so the
same change failed as *"the parser and the layout disagree at offset
43"* on seed 8 -- a report about the parser, for an edit in a header,
naming neither.

Both now carry the named constant and the assert. **The oracle must
still restate the value rather than read the enum**: an oracle written
`!= FZN_OBJECT_HOP` agrees with the parser by construction and is a
second copy of it, not a second implementation. The number is written
out and the assert is what keeps the copy honest -- which is the whole
technique in one line, and it was being used correctly in one file out
of three.

**A cross-tree constant needs a COMMIT attached, not only a name.** They
read three values in `wire/bytes.h` where this tree has four, and neither
reading was wrong: they read `76a3485`, the commit they pin, and
`FZN_OBJECT_MANIFEST` landed on master after it. `evidence.md`'s rule --
cite the owner's constant by name -- is incomplete for exactly this
situation, because **a vendored pin and the owner's tip are two facts
wearing one name**, and the consumer reads one while the owner reads the
other. It will recur on every citation either tree makes during the
migration, so every cross-tree reference in this document and in the
headers now carries the commit it was read at.

**Signalled to fuzzypickles rather than acted on there**, per
`harmonization.md`. Two things they may want: their `MANIFEST_STATEMENT`
(9) and this library's `MANIFEST` (131) are different objects with one
name, which is the fifth question again; and their header's rule against
renumbering rests on a reason -- old signatures existing -- that does
not obviously apply while nothing is deployed, which looked like it made
today the last free day for them too.

**They measured it and it is not free, which is the correction worth
keeping.** Signed material persists in their tree and is RE-VERIFIED ON
LOAD rather than trusted for being on disk -- `fzp_capability_is_revoked`
calls `verify_revocation` on every query -- so old signatures do exist,
on a desktop and on a phone carrying a build from this morning.
Renumbering invalidates them. The cost is bounded by re-provisioning
rather than absent, and that is the number their holder's decision
should be taken against. **The argument was right and the premise was
wrong**: "nothing is deployed" is a claim about another tree, which is
exactly the kind this library keeps getting wrong by not asking.

Neither is ours to decide.


## 15c. Vendoring: Monocypher yes, flog no, 2026-08-28

The holder asks whether the crypto library and flog should be vendored
here so that consumers of this library need not.

### Monocypher: yes, and the shape matters more than the answer

**The current arrangement is the antipattern `harmonization.md` names.**
`MONOCYPHER_DIR` points at a LIVE SIBLING CHECKOUT -- in practice
`../fuzzypickles/monocypher` -- and the guideline is explicit that a
live sibling "is whatever its session left it as, mid-work included",
where a vendored copy "is a version you chose, it clones with your
tree, and it fails loudly at update time instead of quietly at build
time". Sec 11 already recorded the intent: *"the real answer is a
submodule, at whatever step takes it."*

**But vendoring it into the LIBRARY would be wrong, and the reason is
the consumer.** fuzzypickles already vendors Monocypher. If fuzznet
vendored it too and fuzzypickles linked both, one program would carry
two copies of `crypto_blake2b` and friends -- the exact hazard
`code-style.md` names under prefixes and visibility, where a deliberate
parallel copy in two archives detonates at a link that changed nothing.

**The shape that answers the holder's question is the one the library
already has.** fuzznet's crypto is four vtables --
`fzn_sign_ops`, `fzn_hash_ops`, `fzn_aead_ops`, `fzn_random_ops` -- and
**the library itself calls no primitive.** Only the optional bindings
and the tests do. So:

- **vendor Monocypher as a submodule for THIS TREE'S tests and its
  optional bindings**, replacing the live-sibling variable;
- **ship the seams, not the implementation.** A consumer plugs in
  whatever it already has, which is precisely "users of this lib do not
  have to".

That is not a compromise between the two answers. It is what makes both
true at once: fuzznet builds and tests standalone, and no consumer
inherits a second copy of a crypto library it already carries.

### flog: no, and it is a fifth-question instance

**fuzznet does not reference flog anywhere** -- grepped across every
source, header and the Makefile. Nothing to vendor.

**And `log/` is not flog.** They share a word and are different
objects: flog is diagnostic logging with levels, outputs and message
ids, writing through `fopen`/`fprintf`; `log/` is a bounded evicting
store of SIGNED APPLICATION STATEMENTS, sequenced per issuer and
servable to peers. Sec 5e records what came across from fuzzypickles as
"sequencing, retention and serving a range" -- not a logging library.

**The decisive point is structural.** This library has one `fopen` in
the entire tree, at `local/peer_linux.c:85`, reading a proc file behind
a documented Linux-only boundary. A diagnostic logger writing to files
and consoles is against the property that every other module holds, and
adopting it would put I/O in a library whose no-I/O invariant is load-
bearing in at least four recorded arguments. **Vendoring flog would
mean acquiring a dependency this library has deliberately never had.**

Where a consumer wants fuzznet's events in its own log, the seam is a
vtable like the other four, or an error string the consumer prints --
which is what `fzn_*_err_str` already exists for.

### What building it changed, 2026-08-28

Built as decided above. `monocypher/` is a submodule of
`https://github.com/LoupVaillant/Monocypher.git` pinned at
**`ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f`** -- the same commit
fuzzypickles pins, tagged 4.0.3. The path and the pin are both
fuzzypickles': it vendors its six dependencies as submodules at the
repository root under the dependency's own lowercase name, §7 records
that matching it costs nothing, and `.style-gate.toml` already excluded
`monocypher` before there was one there to exclude. **Deliberately the
same commit, not merely the current one.** Upstream had moved to
`1830c06` by the day this was taken, and two trees in one family
disagreeing about which Monocypher they trust is a thing somebody should
choose rather than drift into -- so it is chosen here, and moving it is a
pass across both trees rather than an upgrade in one.

**The default moved; the knob did not.** `MONOCYPHER_DIR ?= monocypher`,
and an override still points elsewhere. What is new is that there are
now three cases where there were two, and the Makefile keeps them apart:

- the source is there -- build the bindings;
- `MONOCYPHER_DIR=` -- do not, and say so;
- the source is missing. Where the path is the vendored default this is
  a clone nobody ran `git submodule update --init` in, so it SKIPS and
  names that command. Where it is an override it is an ERROR, because
  somebody asked for those tests by naming a path and quietly not
  running them is the vacuous pass `evidence.md` warns of.

**The test notice had to stop asking the variable.** It read
`[ -z "$(MONOCYPHER_DIR)" ]`, which with a vendored default reports
"built" for exactly the one case they could not have been -- an
uninitialised submodule. It asks `MONO_SKIP` now, set by the same
conditional that decides whether to compile, so the notice and the build
cannot disagree, and it carries the reason because "not built" and "you
have not initialised the submodule" have different fixes.

**Four tree walks had to learn to prune, and this is the finding worth
keeping.** The Makefile holds its hand-maintained lists against the
filesystem -- every `.c` in a list, every `.h` in `HDRS`, every
`*_fuzz.c` in `FUZZ_BINS`, every object gone after `clean`. A vendored
tree answers none of those questions and it is not small: 56 C sources
and 46 headers. Unpruned, `make style` reported 56 real files as
unlisted, which is a gate that has stopped saying anything. `clean` is
the sharper case, because there the prune is a safety property rather
than a nuisance: `build-and-commit.md` forbids a `find .` from the root
that walks a vendored tree, and this build never writes into the
submodule -- `monocypher.o` lands in `$(BUILD_DIR)`, which is
fuzzypickles' own refinement for keeping the checkout clean -- but
somebody who ran the submodule's own makefile would leave objects there
and `clean` would then fail naming files it must not remove. It is one
`VENDOR_PRUNE` variable rather than four spellings, so the next walk
cannot be added without it.

**That the library still calls no primitive was measured, not asserted**,
because it is the claim the whole shape rests on. `nm --undefined-only`
across the **27** library objects finds **zero** references to
`crypto_*`, BLAKE2b, ChaCha, Poly1305, Argon2, X25519 or Ed25519; the
same probe against the three binding objects finds **six**
-- `crypto_aead_lock`, `crypto_aead_unlock`, `crypto_blake2b`,
`crypto_eddsa_check`, `crypto_eddsa_sign`, `crypto_wipe`. The control is
the point: a probe that returns nothing has found nothing only if it
could have found something.

**And what a consumer inherits was measured the same way.** `make
install` stages 28 headers and no Monocypher source or header among
them. The three seam headers are shipped and none of them includes
`monocypher.h` -- confirmed by compiling all three from the installed
prefix with nothing else on the include path, against the control of
compiling `chain/sign_monocypher.c` the same way, which fails on
`monocypher.h: No such file or directory`. So the header offers the
binding and the `.c` beside it is what needs the library, which is the
seam/implementation split holding at the only boundary where it matters.

**One consequence to know rather than to fix.** fuzzypickles vendors
both fuzznet and Monocypher, so a `--recurse-submodules` clone of it now
has two Monocypher checkouts on disk. They are the same commit and only
one is ever compiled, so it costs disk and not correctness -- but if
either tree bumps its pin alone, that is the moment the two disagree,
and the disagreement will be visible as two directories rather than as a
build failure. That is an argument for moving both pins in one pass, not
against vendoring.

### The default flip moved what the gate proved, and nobody would have seen it

**Turning the binding on by default silently changed the subject of
`make installcheck`.** While `MONOCYPHER_DIR` defaulted to empty, a plain
`make installcheck` WAS the core-only arrangement: it compiled a consumer
against `SRCS` with no Monocypher on the command line and thereby
demonstrated, without meaning to, the exact property this section promises.
Vendoring made the binding the default, `SRCS += MONO_SRCS` fired, and the
same command began proving the opposite -- that a consumer builds WITH
Monocypher. The promise stopped being checked by anything, and the gate went
on passing at the same volume.

This is `evidence.md`'s rule in a form it does not yet name: not a check that
inspected an empty list, and not one whose passing condition includes the
failure, but **a check whose SUBJECT changed under it**. It was green before
and green after, and the two greens mean different things. Nothing in the
diff looked like a weakening; the weakening was two words in a variable that
the conditional above it now expanded differently.

**The measurement that found it.** `$(SRCS)` was 27 sources with three
`*_monocypher.c` among them, and handing that list to a compiler with no
Monocypher include path fails on `monocypher.h: No such file or directory`
-- twice, once per binding source that names it. So the Makefile comment
introduced by the same commit, saying `$(SRCS)` "pulls none in", was false
within the hour of being written, and false in the direction that matters:
a consumer handed `SRCS` inherits the dependency this whole section exists
to keep out.

**The fix is a list that means what the prose promises.** `CORE_SRCS` and
`CORE_HDRS` are frozen at the last line before the Monocypher conditional
can append to them, and `make installcheck` gained a THIRD arm, run first:
compile a consumer against `CORE_SRCS` and the installed headers with no
define, no include path and no vendored tree. A core source that included
`<monocypher.h>` cannot compile there; one that CALLED a primitive through
its own declaration compiles and cannot link. Both are hard failures of that
arm.

**And the case neither compiling nor linking can see** is a core source that
*defines* a primitive -- a copy of BLAKE2b pasted into the tree links
perfectly and hands a consumer the second implementation. So a symbol probe
asks the core OBJECTS for definitions rather than the binary for references,
and **carries its control**: the same pattern is run against `monocypher.o`
and must match something (it matches 49) or the probe is refused as proving
nothing. The pattern is spelled once, in `CRYPTO_SYMS`, because a probe and
the control that validates it must not be able to drift apart -- two
patterns would be two claims.

**Four mutations, four refusals**, each with the mutation asserted present
before the run:

- a core source *defines* `crypto_blake2b` -- caught by the symbol probe,
  naming both planted symbols;
- a core source *calls* `crypto_blake2b` -- caught by the link, naming the
  file and line;
- `CRYPTO_SYMS` changed to a string matching nothing -- caught by the
  control, which refused rather than reporting a clean core;
- a shipped binding header made to include `<monocypher.h>` -- caught by
  the core arm.

**The last of those closed a vacuity in the header check.** `installcheck`
requires every installed header to be named in `tool/consumer_check.c`, and
the three binding headers satisfied it from inside `#ifdef
FZN_CONSUMER_MONOCYPHER` -- the check greps for a NAME, so a mention in a
dead branch passed and proved nothing. None of the three includes
`monocypher.h`, so the includes are unconditional now and only the reference
to the vtable objects is guarded. That is the arrangement in which those
headers most need checking: they ship whether or not the consumer has the
primitive.

**The 28th, 27th and 26th headers ship, and that is now argued rather than
inherited.** The default flip added the three binding seam headers to the
installed set. They declare vtables over this library's own types, include
no Monocypher header, and are proved to compile in the arrangement that has
none -- so a consumer without Monocypher carries three headers it will not
include, and one with Monocypher (fuzzypickles, which is the consumer) finds
the bindings already there. Shipping them costs nothing measurable and saves
the consumer a step.


## 15b. Streaming will want multi-path and heavy FEC, 2026-08-28

**Stated by the holder as an eventual requirement**: low-latency
streaming along the lines of ROC-toolkit -- multiple simultaneous
connections and heavy forward error correction. Not now, and that is
why it is written down now: it collides with three things this library
has already decided, and each is cheap to accommodate today and
expensive after the concepts entrench.

### It contradicts `chunk/`'s completion rule, which is all-or-nothing

`chunk/reassembly.c:388` completes on `slot->arrived == slot->chunks`.
Every chunk is required, tracked by a bitmap of seen indices. **FEC is
k-of-n**: reconstruct once ANY k of n symbols arrive, and the remaining
n-k are pure redundancy that should be discarded rather than waited
for. Those are different completion predicates over the same data
structure, and the current one has no `k`.

**AND THE FIRST VERSION OF THIS ENTRY WAS WRONG ABOUT WHAT THAT
MEANS.** It said the `seen` bitmap is "the right shape already" and
that only a second number was missing. The holder pushed back --
download and streaming protocols make OPPOSITE choices in almost every
aspect, one optimising for buffering and the other for eliminating it
-- and the pushback is correct. **A module is its lifecycle, not its
data structure.** The bitmap is a fine primitive; `chunk/`'s lifecycle
is what opposes streaming, and pointing at the primitive to argue the
module generalises was the error.

### The opposition, field by field, from the code

| `chunk/` (transfer) | streaming (ROC-like) |
|---|---|
| accumulate until whole, hand over ONCE (`handed`, `arrived == chunks`) | deliver continuously; accumulating IS the failure |
| every chunk required | k-of-n, loss expected, repaired or concealed |
| `max_hold` is when to RECLAIM MEMORY | the deadline is when data becomes WORTHLESS |
| a late chunk is still valuable | a late symbol is garbage |
| slot buffer up to 262144 bytes | jitter buffer of milliseconds -- ~320 bytes for 40 ms of 64 kbit/s audio |
| order irrelevant | order essential |

**`max_hold` and a playout deadline are the trap.** Same width, same
position, both "a time after which this slot is done" -- and opposite
in kind. One is resource reclamation, where being late costs memory.
The other is a correctness property, where being late costs the data.
That is the fifth question's shape waiting to be walked into, and it
would be walked into by anyone generalising `chunk/` rather than
writing beside it.

Three orders of magnitude between the buffers is the measurable form of
the same point.

### The tree already refused this merge once

`project.md:342` records fuzzypickles' chunking as "for
content-addressed assets -- a different problem, where the content has
a hash-derived name and the transfer is pull-based and
requester-coordinated", and sec 5 adds that **two mechanisms with
different control flow can share primitives without becoming one
thing.** So there are already two chunking-shaped mechanisms this tree
declined to unify, and streaming is a third. The precedent is the
tree's own.

**What is genuinely shared is thin and already lives in the frame**:
the fields that identify a fragment -- `sender`, `msg`, `index` -- and
a per-sender bound so a stranger cannot exhaust memory. Even the bound
differs in kind: `chunk/`'s quota is memory, streaming's constraint is
a latency budget. So the sharing is at the HEAD, and `chunk/` is one
consumer of those fields rather than the general mechanism.

**Verdict: a separate module beside `chunk/`, not a generalisation of
it.** What is missing is not a second number in the existing slot --
it is a different lifecycle over the same wire fields, plus a
reconstruction seam, which is a fifth vtable of the kind this library
already has four of.

### The tuning lever is a different variable in each, and one exists

**Download's lever is the chunk size**, because it sets both the
per-frame overhead ratio and the cost of a retransmission -- a lost
piece costs exactly one chunk to replace. **That lever already exists
and is the caller's**: `fzn_split_plan(total, max_payload, out)` takes
`max_payload` per message, bounded by `FZN_SPLIT_MAX_PAYLOAD` 1024.
Nothing needs adding.

**Streaming's lever is the amount of FEC**, and it has no equivalent
here because there is no FEC. It is also a different KIND of variable:
chunk size is set once per message from what is being sent, while a FEC
ratio is adjusted continuously against measured loss, so it is a
feedback input rather than a plan parameter. A module whose main
tunable is adjusted per-second cannot be `fzn_split_plan`'s caller.

### Watch-and-record: the case that settles the split rather than complicating it

**Flagged as research by the holder, and not designed here.** A stream
that is simultaneously watched live and recorded to disk is the
interesting hybrid, and it is worth stating why it does not argue for
one general module.

Both consumers see the SAME arriving frames and want contradictory
things from them:

- **the playout path** wants deliver-now-or-discard: a symbol past its
  deadline is worthless and holding it costs latency;
- **the recording path** wants keep-everything: no deadline at all,
  gaps noted and filled later, and a late piece is exactly as valuable
  as a punctual one.

A single module would need its deadline field to mean both at once,
which is the `max_hold`-versus-playout trap above. **Two disciplines
over one wire is the only shape that expresses it**, and the recording
half can be `chunk/`'s existing discipline more or less as it stands.
So the hybrid requires the modules to be separate; it is unbuildable if
they are merged.

What research would have to settle, since it is a genuine interaction
rather than a detail: **whether a repair symbol can fill a recording
gap without a retransmission.** If it can, the two paths share the FEC
stream and the recording path's retransmit requests drop sharply; if
not, they are independent and the frame carries traffic for both. That
question decides how much the two modules share, and it cannot be
answered from either module's side alone.

### It contradicts `sched/`, which selects exactly one link

`fzn_sched_select(links, count, class, *chosen)` returns ONE index.
Multi-path striping wants several links carrying complementary symbols
at once, which is not a harder version of choosing one -- it is a
different question with a different answer shape.

**But `sched/`'s own reasoning already points at it.** Its hard
constraints can exclude every link so that `FZN_SCHED_ERR_NONE` is the
answer, and importance is deliberately not a scalar because "a
fire-and-forget voice frame wants the fastest link and is happily
dropped". A striping selector is the same class model answering "which
SET" instead of "which one", and the component weighting survives the
change. The single-link signature does not.

### The head has no room for FEC and the fields that look reusable are not

`fzn_head` carries `msg`, `index [max = chunks - 1]`, `chunks` and
`length`. It is tempting to read `index`/`chunks` as symbol id and n.
**They cannot be, and the constraint is in the schema**: `index` is
bounded by `chunks - 1` and enforced by the generated validator before
decryption. An FEC block needs at minimum a `k`, and a repair symbol's
index is not bounded by the source count in the same way.

**And the frame has 32 bytes of headroom, not more** -- max frame 1168
plus 48 of IPv6/UDP against a 1280 minimum MTU is 64 spare, of which a
per-message ephemeral would take 32 if forward secrecy is also taken.
**Two future features are competing for the same 64 bytes**, and
nothing currently records that they compete.

### What this changes about decisions in front of the holder now

- **The signed-object namespace** (`wire/bytes.h`) is a one-byte enum
  with four values. **THAT WAS RECORDED AS "cannot be extended after
  deployment" AND IT IS WRONG** -- corrected 2026-08-28 after the claim
  reached a consumer and they prioritised on it. `wire/bytes.h` says
  "neither BYTE can be added later without invalidating every signature
  already issued", which is about the version and object bytes existing
  in the format at all, and that is already done. Adding a new
  ENUMERATOR invalidates nothing: an existing object's signed bytes do
  not change, and each decoder refuses a tag that is not its own, which
  is the correct treatment of an unknown type. The space is 255 values,
  not 4.

  **The real constraint is coordination, not capacity**, and it is
  still real: a tag deployed before peers know it is refused by every
  peer that does not, so allocation has to be agreed before either side
  ships. A consumer with twelve signed object types fits with room to
  spare -- what it needs is stable numbers agreed once, not more room.
  FEC does
  not obviously need a new signed object, but streaming might, and this
  is the cheapest thing on the list to get right now.
- **The forward-secrecy decision now has a competitor for the same
  headroom.** Sec 13e priced the ephemeral at 32 bytes against 64
  spare. If FEC needs header room, those 32 bytes are no longer free
  and the epoch shape -- which costs zero to four bytes -- gets
  materially more attractive.
- **`chunk/` should not have its completion rule hardened further**
  until k-of-n is designed, because every assertion that "all chunks
  are required" is a statement a future FEC path must contradict.

**Nothing here is a request to build.** It is recorded so that the next
person to touch `chunk/`, `sched/` or the head knows which of the
current constraints are deliberate and which are merely current.

## 15a. Consumer weighting, fallout tooling, and situ, 2026-08-28

Three corrections and one measurement, from the holder.

### fuzzypickles is the main consumer; netcfgd is not yet one

**Recorded because this document does not read that way.** Sec 5 says
"three consumers with one usage", sec 5's admission test turned on "two
real consumers", and several sections weigh the three as comparable.
The holder's statement: **fuzzypickles is likely the main consumer,
netcfgd will only ever use a SUBSET and is less likely to produce
feedback, and netcfgd is NOT YET A CONSUMER.** raidcfgd exists but is
nascent.

The consequence is a design one, not bookkeeping. **Generalising for
consumers that do not yet exist is speculative generality**, and this
document has been doing it: the admission test asks whether two real
consumers need a thing, in a world where one real consumer does.
Feedback that has actually corrected this library has come almost
entirely from fuzzypickles -- five substantive corrections in one day,
against none from anywhere else, which is what "less likely to produce
feedback" means in practice.

**REFINED THE SAME DAY, BECAUSE THE FIRST VERSION WAS TOO BROAD.** It
concluded that a hypothetical netcfgd need should lose to a measured
fuzzypickles one. The holder's clarification splits that in two, and
the split is the rule:

- **ALL consumers use the most central and the hardest parts.** Those
  are not a subset and must be designed for everyone. Chains,
  revocation, framing, freshness, records, the receive order -- every
  consumer depends on them, and a choice made there to suit one
  consumer is a choice made for all of them.
- **FEATURE BREADTH is fuzzypickles', and they will drive it.** They
  need far more of it and use it far harder. netcfgd is expected to
  want GPS -- for RF-network choice and for navigation -- and audio
  streaming over a Bluetooth network, which is real work rather than a
  thin subset, but it will arrive after fuzzypickles has pushed the
  same machinery forward.

So the corrected rule is not "the hypothetical loses". It is: **in the
core, design for all of them; in features, follow the consumer who is
actually exercising it, and expect the others to arrive at the same
place later.**

**AND THE PATTERN IS ALREADY VISIBLE IN `sched/`, WHICH VALIDATES IT.**
netcfgd's future audio streaming is served by a design already in the
tree -- "a fire-and-forget voice frame wants the fastest link and is
happily dropped", with hard constraints able to exclude every link so
that `FZN_SCHED_ERR_NONE` is the answer and the caller drops rather
than being handed the least-bad survivor. **That reasoning came from
fuzzypickles' own header and is quoted there as theirs.** One consumer
drove it, the module absorbed it, and a different consumer's unbuilt
feature is already accounted for. That is the instruction working
before it was given.

GPS for RF-network choice lands in the same place: `link/`'s prior is
"what the far end declared about it", and an RF link's quality is
predictable from geometry, so position informs a declared metric rather
than adding a fourth axis to `sched/`. GPS for NAVIGATION is
application data and belongs in a record kind this library never
interprets.

### The fallout tool exists, is unused, and works

The holder asked for tools to analyse the fallout of a change, so a
better solution can be taken early rather than after the concept
entrenches. **`situc diff` is that tool and this project has never run
it.**

Demonstrated on the change sec 13e actually costed -- adding a 32-byte
per-message ephemeral to the head:

    Regressions:
      ! fzn_frame.authenticated: size Fixed(91) -> Fixed(123)
      ! fzn_frame.head: size Fixed(91) -> Fixed(123)
    Layout changes:
      ~ eleven field offsets, each named old -> new
    Added:
      + fzn_frame.head.ephemeral

**It classifies rather than lists**, and "Regressions" is its own
category. That is the difference between a diff and a fallout analysis.

### We use four of situc's nineteen subcommands

`build`, `map`, `wire`, `gen-tamper` -- the last adopted yesterday.
Unused: `diff`, `gen-tests`, `gen-fuzz`, `gen-dissector`, `gen-checks`,
`gen-derived`, `gen-codec-tests`, `verify`, `explain`, `pack`, `doc`,
`advise`, `import-proto`, `lsp`, `dump-ast`.

**One correction to what that implies, caught before it was written
here.** `gen-tests` takes `schema vectors` -- it generates test code
FROM a vector file, it does not produce vectors. So it would not have
saved the golden frame this project obtained from fuzzypickles, and it
must not be recorded as though it would: **the vector's value was that
an independent implementation produced it**, which no generator can
supply. What `gen-tests` would replace is the hand-written harness
around the array, which is the cheaper half.

The rest are unevaluated. `gen-fuzz` against nine hand-written
harnesses and `gen-dissector` are the next two worth measuring, on the
same standard `gen-tamper` met: adopt where the generated thing is
exhaustive over something the schema knows and a hand-written one is
sampled.

## 15. The consolidation this library exists for, 2026-08-28

**RESTATED, NOT NEW, AND THAT IS THE FINDING.** The holder said "the
end goal as you know", and the "as you know" is literally accurate:
sec 5 has carried it since **2026-08-26**, in more detail than this
section adds. It names the subsystems -- "the whole log subsystem,
relaying, adding hosts, creating rules and permissions, the config
database, chunked transfer for file transfer, and streaming media --
generalised for use by other projects", with "what network code remains
in fuzzypickles is open, and expected to be little".

So the goal changed nothing. **What changed is that somebody looked.**

**AND THE COST OF NOT LOOKING IS MEASURABLE, in this document, from
yesterday.** Sec 13e's forward-secrecy pass judged session-only forward
secrecy "coherent and beside the point" -- correct against sec 13's axis
and wrong against a target architecture recorded two days earlier in a
section the pass was never told to read. The brief named secs 4.4a,
4.5, 13 and 14 and the `session/`, `wire/` and `trust/` headers. It did
not name sec 5. **That omission is the author's, not the agent's**: a
design pass scoped to the crypto sections cannot see a decision about
which subsystems this library will host, and the shape it dismissed is
the shape a merged library needs, because a group ratchet is
session-oriented and a peer frame is self-contained and consolidation
means hosting both.

**The general form, and it is worth more than the instance: a document
long enough to need scoping is a document whose scope is a decision,
and scoping a design brief to the sections about the SUBJECT will omit
the sections about the DESTINATION.** Two constraints come with the
goal, and they are what make it a design question rather than a
schedule.

**Do not lose work or ideas that came from very costly development.**
That is mostly fuzzypickles' side. Their group ratchet, prekey channel,
propagation, peer frame and revocation model are years of hard-won
work, and a consolidation that reaches the same place by rewriting them
has destroyed the thing it was meant to collect. **An idea can be lost
without a line being deleted** -- it is lost when the reason for it is
not carried across and the next design re-derives something worse.

**Analyse implementation details WITH the larger picture in view, so
later change need not be dramatic.** The failure mode is a sequence of
locally-correct decisions that make the eventual merge expensive. Today
produced several, and one of them reversed on hearing the goal.

### The decision this goal reverses, and it was already in front of the holder

Sec 13e evaluated a shape it called **session-only forward secrecy** --
one wire format, two key schedules, chosen by what the receiver holds
rather than by any bit on the wire. It was judged **coherent and beside
the point**: it protects live exchanges and leaves stored, relayed and
asleep traffic untouched, which is the traffic sec 13's axis exists
for.

**Under consolidation that judgement inverts -- and consolidation was
already decided when the judgement was made.** fuzzypickles' group
ratchet IS session-oriented and their peer frame IS self-contained.
**A merged library must host both**, so a design supporting two key
schedules selected by held material is not a half-measure -- it is the
shape the target needs. The same analysis, the same shape, opposite
verdict, and the only thing that changed was knowing where this is
going.

That is the concrete argument for the holder's instruction, and it is
sharper for the verdict having been reachable at the time. **Sec 13e's
recommendation should not be acted on until the target shape is
known**,
because the cheap option (epoch re-derivation) is cheap partly by
declining to grow a session concept, and declining to grow one is
exactly what consolidation forbids.

### What the shape of the work is, and it is joint

Neither tree can draw this alone. fuzznet knows what it holds and what
its axis costs; fuzzypickles knows which of its pieces are generic,
which are chat-specific, and which carry reasons that would be lost in
translation. Today established that **the two trees find each other's
errors reliably and their own poorly** -- a claim of ours about their
forward secrecy, a claim of theirs about four identical fields, a
number of ours measured in one file, all corrected from the other side.

The questions that need answering together, before any migration
begins:

- **What is generic and what is chat?** Their group ratchet is generic
  cryptography; their contact model is not. The boundary is theirs to
  draw and ours to host.
- **What must survive in reason rather than in code?** Where fuzznet
  would rewrite rather than move, the REASON has to come across or the
  rewrite re-derives something worse. Their "assume the peer is asleep"
  is already load-bearing here and arrived as prose, not as code.
- **What does hosting both traffic models cost?** Self-contained and
  session-oriented in one library, with the receive order, the replay
  window and the key-committing filter all working for both.
- **What order minimises drama?** Which pieces move first so that each
  step is small and no step strands the other tree mid-migration.
- **What must NOT be merged, because it looks mergeable?** The
  consumer's question, adopted as stated: **a shared name is a CLAIM
  that two designs agreed, and every proposed unification must name the
  case where the two behaviours differ. If it cannot, the unification is
  unestablished rather than safe.** Losing code is visible and a diff
  catches it; two things with one name and one width doing different
  jobs is what a consolidation reading headers unifies without noticing.

### The hazard this document is most exposed to

**Prose is what survives a rewrite**, and that cuts against us harder
than against anyone. The consumer's tree proved it twice in one file: a
documented reason citing a sibling function and a stated discipline,
applied faithfully and inverting a polarity -- and thirty lines above
it, the same file doing the RIGHT thing with no comment at all. A
consolidation carries the documented one across and drops the
undocumented one, because prose is what a rewrite reads.

**This library is the most heavily commented of the family**, which is
usually an asset and here is a specific risk: a merge will
preferentially preserve fuzznet's reasoning, INCLUDING WHICHEVER OF IT
IS WRONG. In one day this document was found to carry a stale blocker
telling the next session not to start unblocked work, a count quoted
after it had been superseded twice, an inventory nothing checked, a
claim about a consumer's tree its owner had to correct, and a design
record whose id derivation could not work. Every one was confidently
written, several cited real constants, and all would have been carried
into a merged tree.

So a reasons list is not only a record of what to keep. **It is a list
of what will be preserved whether or not it is right**, and whoever
merges should read it that way.

### Instances of the fifth question, from this side

- **`fzn_revocation_covers` returns `int` and its two callers ask
  different questions.** Verification asks "is this withdrawn";
  admission asks "do I already hold this". A pass this week proposed
  widening it to a tri-state and `chain/revocation.c` refused, because a
  conservative answer to one question is a wrong answer to the other.
  Anything that sees a boolean called `covers` and unifies it with a
  same-named predicate merges two questions sharing a name and a return
  type and nothing else.

- **The failure-class axis, and fuzznet has two classes where a
  consumer may have three.** `covers` distinguishes them explicitly and
  the distinction is load-bearing: an ABSENT store answers 0, because
  NULL means "no revocations known" and that is the contract
  `fzn_chain_verify` rests on; a CORRUPT store answers 1, because
  entries that might answer exist and cannot be read, so they must be
  assumed to say yes; a MISSING TRIPLE OPERAND answers 0, because what
  is absent is the QUESTION rather than the answer, and denying would
  turn one null pointer into a blanket refusal reported as a revocation
  no issuer ever signed.

  **This library has no I/O**, so it has no storage-failure class at
  all -- walked, not grepped: there is no `open`, `read` or `mmap` in
  any non-test source, and every store is caller-owned memory. A
  consumer that reads from disk has a third class whose right answer is
  neither of ours, and **a merged predicate would have to answer for a
  failure mode one side cannot even produce.** That is the fifth
  question's shape exactly, and it is why "same function, both
  correct" is not enough to justify unifying two.

- **The corrupt-store branch is right HERE and wrong THERE, for a
  structural reason, and it is the cleanest instance yet.** Our store
  denies on corruption because entries that might answer exist, cannot
  be read, and are caller-owned memory this function never verified. A
  consumer whose equivalent record FAILS ITS SIGNATURE is in a
  different position: their install path verifies before storing, so
  such a record cannot have arrived by propagation and means disk
  corruption, or a key rotation invalidating records signed under an
  old root. **Denying there would let a corrupt file or a key rotation
  revoke capabilities nobody withdrew.**

  Same-shaped branch, opposite correct answers, and the difference is
  structural rather than a matter of taste: whether anything verified
  the thing before it was stored. **Neither is evidence about the
  other.** The consumer had been carrying their answer as a weakness on
  their side and was about to adopt ours on the strength of our
  agreeing elsewhere -- which would have been corroboration doing the
  opposite of its job.

**Nothing about consolidation is decided here.** This section exists so
that the next decision is made with the target in view rather than
locally, which is the instruction.

