# fuzznet

The authenticated datagram protocol shared by `fuzzypickles`, `netcfgd` and
`raidcfgd`, so that three projects do not write the same envelope, signing,
session and chunking three times.

A C library, using Monocypher, linked by **unprivileged** processes. It carries
messages; it does not know what they mean. Each consuming project keeps its own
command vocabulary and its own semantics.

**Status: every module in the design is built.** `project.md` is the design and
the source of truth; §8 says which modules exist and §10 has the order of work.
What remains there belongs to other projects: netcfgd's agent, which may never
be written, and fuzzypickles' migration.

Built and tested:

| | |
|---|---|
| `chain/` | capability chains: verification, minting, delegation, revocation |
| `frame/` | command expiry and the replay window it bounds |
| `chunk/` | splitting, reassembly, and the memory bound |
| `session/` | the key schedule, the AEAD seam, and where a nonce comes from |
| `wire/` | the `situ` schema, its committed contract, and opening and sealing a frame |
| `local/` | peer credentials including supplementary groups, and a vocabulary bound |
| `constant_time/` | constant-time comparison |

`make test` runs 25 binaries -- suites and eight fuzz harnesses. `make test
SANITIZE=1` runs the lot under ASan and UBSan. `make schema SITU_DIR=../situ`
checks the committed schema artifacts against a situ commit, and `make
codegencheck` checks that two security-critical functions still compile to the
shape they must.

The crypto is a seam rather than a dependency: signing, hashing, AEAD and
entropy are each a vtable a consumer fills, and the library itself calls no
primitive. Monocypher is vendored at `monocypher/` as a submodule so that
`make test` exercises those seams against a real implementation out of a
clean clone -- `git submodule update --init` and nothing else. It is for this
tree's tests and its optional bindings only: `make install` ships headers,
never Monocypher, so a consumer that already carries its own copy does not
inherit a second one. `MONOCYPHER_DIR=<path>` still points the bindings at
another checkout, and `MONOCYPHER_DIR=` builds without them.

Three things to know before reading further, because each contradicts what a
shared protocol library usually looks like:

- **The local hop is each project's own** -- two consumers already have one,
  they disagree about its encoding, and both disagreements are load-bearing.
  §2 argues that rather than asserting it. A socket module and a line framer
  were written here on 2026-08-18 and moved to raidcfgd the same day, because
  they chose a transport and an encoding and this library does not. What stays
  is what chooses neither: who the peer is, and whether they may ask for a
  given verb.
- **The privileged daemon never links this.** Whatever speaks UDP is a
  separate unprivileged process, so a defect here is not a root defect. §3.
- **Grants do not expire; commands do.** The two consumers' rules look like
  they conflict and do not. §4.3.
