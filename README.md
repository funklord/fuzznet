# fuzznet

The authenticated datagram protocol shared by `fuzzypickles`, `netcfgd` and
`raidcfgd`, so that three projects do not write the same envelope, signing,
session and chunking three times.

A C library, using Monocypher, linked by **unprivileged** processes. It carries
messages; it does not know what they mean. Each consuming project keeps its own
command vocabulary and its own semantics.

**Status: every module in the design is built.** `project.md` is the design and
the source of truth; §11 lists the modules, §8 is the scope decision that
placed the first seven, and §10 has the order of work.
What remains there belongs to other projects: netcfgd's agent, which may never
be written, and fuzzypickles' migration.

**The module list is in `project.md` §11**, where `make style` holds every
path in that table against the tree. It is not repeated here: a second copy
would be an inventory nothing checks, and this file carried exactly that until
2026-09-04. §63 records what that cost.

`make test` builds and runs every test binary and prints each one's count;
`make style` prints how many sources, headers, fuzz harnesses and test
binaries it held against the Makefile. Neither total is repeated here either,
for the same reason.

**`make check` runs the suite twice: once plain and once under AddressSanitizer
and UBSan.** The second pass is `make sancheck`, which builds into a separate
directory because sanitized and plain objects are not interchangeable. It runs
`runtests` rather than `test` on purpose -- `make codegencheck` reads the
emitted shape of two security-critical functions and declines a sanitized
build, so putting it under one would report a pass over a check that inspected
nothing. `make test SANITIZE=1` still runs that pass on its own.

It earns the time it costs. §86 has the measurement: one real defect in one
run, a view into a stack buffer whose scope had ended, in a test that had
passed everything else a dozen times because the bytes were still there.

`make schema SITU_DIR=../situ` checks the committed schema artifacts against a
situ commit, and `make codegencheck` checks that two security-critical
functions still compile to the shape they must.

The crypto is a seam rather than a dependency: signing, hashing, AEAD and
entropy are each a vtable a consumer fills, and the library itself calls no
primitive. Monocypher is vendored at `monocypher/` as a submodule so that
`make test` exercises those seams against a real implementation out of a
clean clone -- `git submodule update --init` and nothing else. It is for this
tree's tests and its optional bindings only: `make install` ships headers,
never Monocypher, so a consumer that already carries its own copy does not
inherit a second one. That promise is a gate rather than a sentence --
`make installcheck` builds a consumer against `CORE_SRCS` with Monocypher
nowhere on the command line, and refuses if any core object so much as
defines a primitive's name. Compile `CORE_SRCS` rather than `SRCS`: the
latter gains the three binding sources whenever the bindings are built, and
those do need Monocypher. `MONOCYPHER_DIR=<path>` still points the bindings
at another checkout, and `MONOCYPHER_DIR=` builds without them.

**A consuming build asks for the list rather than copying it.**
`make manifest` prints one `key value` per line -- `source`, `generated`,
`include`, and separately `binding` and `backend` for the two things a
consumer takes deliberately rather than by following a list. A binding needs
the consumer's own Monocypher; a backend carries the define that switches it
on. Nothing is checked in, because a generated list that gets committed is
the stale copy it exists to prevent, and `make installcheck` compiles a
consumer from nothing but that output so an omission fails here rather than
in the consuming tree.

The format is deliberately dull so that no build system is privileged --
`make manifest | awk '$1 == "source" { print $2 }'` is the whole of reading
it, and CMake's `file(STRINGS)` or a `$(shell ...)` in another Makefile do
the same job. A consumer whose build is make may of course skip it and ask
this Makefile for `CORE_SRCS` directly; the manifest exists for the ones
that cannot.


Three things to know before reading further, because each contradicts what a
shared protocol library usually looks like:

- **The local hop is each project's own** -- two consumers already have one,
  they disagree about its encoding, and both disagreements are load-bearing.
  §2 argues that rather than asserting it. A socket module and a line framer
  were written here on 2026-08-18 and moved to raidcfgd the same day, because
  they chose the transport and encoding **of that hop**, which is the one
  place two consumers must be free to differ. What stays is what does not
  bind them: who the peer is, and whether they may ask for a given verb.

  This bullet used to end "and this library does not", unqualified, and that
  sentence is false on its face -- `wire/bytes.h` is nothing but chosen
  encodings, and every signed object in the tree is a fixed byte layout
  somebody chose. Everything generic to a crypto protocol belongs here; what
  does not is a hop between one consumer's own processes. §71 has what the
  unqualified reading cost.
- **The privileged daemon never links this.** Whatever speaks UDP is a
  separate unprivileged process, so a defect here is not a root defect. §3.
- **Grants do not expire; commands do.** The two consumers' rules look like
  they conflict and do not. §4.3.

## Who wrote this

    Copyright (C) 2026 Nabeel Sowan <nabeel@vibes.se>

Attribution, not a licence. Naming the holder states who wrote the work and
grants nothing; this project's licensing is a separate question and is not
settled here.

The same line is available to a program that links the library, as
`fzn_copyright()` in `version/version.h` -- separate from
`fzn_version_string()`, which has machine consumers and keeps its shape.
