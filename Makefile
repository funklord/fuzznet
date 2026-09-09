# fuzznet -- the shared authenticated datagram protocol.
#
# project.md sec 10 step 3 makes chain/ the first real code: sec 7a gave most
# of sec 4 to situ once the layer ladder arrived, and the capability model is
# what stayed ours, being semantics rather than layout or transport.
#
# There is deliberately NO archive rule. project.md sec 7 has consumers
# compiling these sources into their own objects, with their own flags --
# fuzzypickles cross-compiles for Android and builds sanitized, netcfgd's
# agent is an ordinary host binary, and a prebuilt .a serves neither.
# build-and-commit.md says not to add an archive step without a specific
# need, and the need this would answer is one nobody has.

# THE DEFAULT GOAL IS NAMED, not left to whichever rule comes first.
#
# It was `monocypher.o` -- measured with `make -p`, not guessed. The vendored
# Monocypher rule sits at line 594 and `all: $(OBJS)` at 715, and make takes
# the first target of the first rule it reads. So a plain `make` on a clean
# tree built Monocypher, printed nothing, exited 0, and produced NO LIBRARY
# OBJECT AT ALL. Verified by removing chain/chain.o and running it: rc 0 and
# the object still absent.
#
# It stayed silent because nothing depends on the default goal. `make test`,
# `installcheck`, `coverage` and the sanitized build all name what they need,
# so every gate was building the library the long way round while the command
# a reader types first did nothing and said so cheerfully.
#
# build-and-commit.md has this exact failure from bbq-predictor, where an
# include above `all` made a preflight the default goal and "a plain `make`
# runs the preflight, fails for want of a kit, and builds nothing" for four
# sessions. Naming the goal is stronger than ordering the rules, because it
# cannot be undone by adding a rule above.
.DEFAULT_GOAL := all

BUILD_DIR ?= .

# AN EMPTY BUILD_DIR IS REFUSED HERE, WHERE make READS THE FILE, and not in a
# recipe -- because a recipe is too late and two targets proved it.
#
# `coverage` and `installcheck` each open with
# `test -n "$(BUILD_DIR)" || ... exit 1`, written against exactly the hazard
# build-and-commit.md names: an unset variable turning `rm -rf $(VAR)/x` into
# something else. Both checks are correct and `coverage`'s fires. **The one
# in `installcheck` cannot.** Its prerequisites are `$(HDRS) $(SRCS) $(OBJS)`,
# make builds prerequisites before it runs the recipe, and `$(OBJS)` with an
# empty BUILD_DIR is `/constant_time/constant_time.o`. Measured with
# `make -n installcheck BUILD_DIR=`, which prints `mkdir -p /constant_time/`
# and a compile into it before the guard's line appears anywhere. A guard
# that cannot be the thing doing the refusing is a guard nobody is measuring.
#
# Two more targets had no guard at all, and `make -n` says what each would
# have run:
#
#     make schema BUILD_DIR=    rm -rf /.situ-head && mkdir -p /.situ-head
#     make analyze BUILD_DIR=   rm -rf -analyze
#
# The first is six sites operating at the filesystem root, `mkdir` included.
# The second is worse than it looks for being harmless: `-analyze` is a
# leading-dash argument, so rm parses it as options rather than as a path,
# and the failure says nothing about BUILD_DIR.
#
# `$(error)` at parse time closes all four and every target added later,
# because nothing -- no recipe, no prerequisite, no sub-make re-reading this
# file with `BUILD_DIR=$(BUILD_DIR)-coverage` -- runs before the file is
# read. The recipe checks are left where they are: they are correct, they
# cost nothing, and removing a guard to tidy up is how the next one goes
# missing.
#
# ONLY THE EMPTY CASE IS GLOBAL. `coverage` and `installcheck` also refuse an
# ABSOLUTE BUILD_DIR and keep doing so for their own reasons -- installcheck's
# staging tree has to be inside the tree it is staging. Hoisting that one
# would newly forbid `make BUILD_DIR=/tmp/x` for an ordinary build, which
# works today and which nobody has asked to remove. Withdrawing a capability
# is a decision; refusing a value that can only be a mistake is not.
ifeq ($(strip $(BUILD_DIR)),)
$(error BUILD_DIR is empty. Every path this build writes would be rooted at / -- objects at /constant_time/, scratch at /.situ-head. Leave it unset for an in-place build, or name a directory)
endif

CC        ?= cc
DESTDIR   ?=
PREFIX    ?= /usr/local

# -Os because that is the workspace default and this library is aimed at
# routers and phones: it is the instruction cache that is scarce here, not
# the arithmetic. -Og when debugging, deliberately and temporarily.
CFLAGS  ?= -Os -g

# SANITIZE=1 builds everything under AddressSanitizer and UBSan.
#
# It exists because the canaries in the fuzz harnesses are a substitute for
# this, and say so: on a plain -Os build a two-byte overrun into a
# neighbouring slot corrupts somebody else's message and returns success.
# A canary catches a WRITE past the end of a buffer it brackets. It cannot
# see a read of bytes nothing wrote, an off-by-one inside the buffer, or
# signed overflow -- and those are the defects this library's arithmetic
# could plausibly have, since it computes offsets from values a stranger
# chose.
#
# NOT the default, deliberately. project.md sec 7 has each consumer
# compiling these sources with its own flags, and a library that forced a
# sanitizer on them would be choosing for fuzzypickles' Android build. It
# is a knob for this tree's own testing:
#
#   make test SANITIZE=1
#   make fuzz SANITIZE=1 CASES=200000
#
# -Og rather than -Os under it, because a sanitizer report through fully
# optimised code names the wrong line, and BUILD_DIR should be set to keep
# the objects apart from a plain build's -- they are not interchangeable
# and mixing them produces a link nobody can explain.
SANITIZE ?=
ifeq ($(SANITIZE),1)
# Replaces the optimisation and adds the instrumentation. The warning flags
# are NOT repeated here -- they are appended below for both builds, and
# listing them twice put every one of them on the command line twice.
CFLAGS  := -Og -g -fsanitize=address,undefined -fno-omit-frame-pointer \
           -fno-sanitize-recover=all
endif
# Split, because generated and vendored sources need one half and not the
# other. CFLAGS_WARN is about OUR source; everything else in CFLAGS is about
# the BUILD -- architecture, optimisation level, sanitizers, a sysroot.
CFLAGS_WARN := -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
               -Wstrict-prototypes -Wvla
CFLAGS  += $(CFLAGS_WARN)

# WHAT GENERATED AND VENDORED SOURCES GET, and why this is derived rather than
# written out.
#
# Their rules used to hard-code `-Os -g`, on the reasoning that -Wconversion
# against a code generator's output is noise nobody reads. That reasoning is
# right and the implementation dropped far more than warnings: no
# architecture flag, no optimisation change, and no sanitizer reached them.
#
# Measured 2026-08-20. In every SANITIZE=1 run this project has cited,
# wire/generated/frame.o and situ.o carried zero __asan symbols while
# wire/seal.o carried 21 -- so situ's bounds arithmetic, which is the code an
# out-of-bounds access would live in, was the one part never instrumented. And
# `make test CFLAGS="-Os -g -m32"` failed at link with "i386:x86-64 ...
# incompatible with i386 output", because the generated objects had ignored
# the -m32.
#
# GEN_EXTRA existed to thread --coverage through the same hole, which is the
# tell: each time something needed to reach these objects, another variable
# was added instead of the rule being fixed.
GEN_CFLAGS = $(filter-out $(CFLAGS_WARN),$(CFLAGS)) $(GEN_EXTRA)
CPPFLAGS += -MMD -MP

# Generated by situ and vendored from it. Compiled with their own terms
# rather than ours -- code-style.md exempts generated and vendored sources,
# and -Wconversion against a code generator's output is noise nobody reads,
# which is how a warning that matters gets missed. They happen to be clean
# under our full set today; that is luck to enjoy, not a rule to enforce on
# somebody else's emitter.
GEN_SRCS  := wire/generated/frame.c wire/generated/frame_relate.c \
             wire/generated/situ.c
GEN_OBJS  := $(GEN_SRCS:%.c=$(BUILD_DIR)/%.o)

SRCS      := constant_time/constant_time.c session/commitment.c \
             local/peer.c local/peer_linux.c local/vocabulary.c \
             chain/chain.c chain/revocation.c chain/manifest.c chain/authz.c \
             chain/chain_store.c chain/service.c claim/claim.c \
             record/store.c catalog/catalog.c catalog/copy.c catalog/sweep.c \
             catalog/reach.c qr/qr.c \
             frame/freshness.c \
             blob/blob.c ratchet/ratchet.c prekey/prekey.c \
             provision/provision.c \
             disclose/disclose.c \
             persist/persist.c \
             spool/spool.c \
             spool/plan.c \
             spool/message.c \
             spool/transfer.c \
             spool/scrub.c \
             chunk/reassembly.c \
             chunk/split.c \
             tree/tree.c \
             wire/seal.c wire/relay.c \
             session/random.c session/random_linux.c session/agree.c \
             session/session.c \
             version/version.c \
             record/record.c record/journal.c record/sync.c record/ledger.c \
             state/state.c trust/trust.c log/log.c sched/sched.c link/link.c
# RECURSIVE, NOT SNAPSHOT, and that is a fix rather than a style choice.
# This was `:=`, evaluated here -- ABOVE the conditional blocks that append
# the two file backends to SRCS. So OBJS named neither of them, and neither
# did TEST_OBJS or the DEPS derived from both. `make clean` then left
# persist_file and spool_file objects behind and its own self-check caught
# it: "something the build produces is in no list clean reads".
#
# THE BUG WAS IN THIS TREE AND WAS FOUND IN SOMEBODY ELSE'S -- while moving
# fuzzypickles' submodule pin, because a consumer runs `clean` and this tree
# has it in neither `check` nor CI. The Monocypher objects escaped only
# because they are appended with `+=` further down, which is the same
# accident pointing the other way.
OBJS       = $(SRCS:%.c=$(BUILD_DIR)/%.o) $(GEN_OBJS)
HDRS      := constant_time/constant_time.h session/commitment.h \
             local/peer.h local/vocabulary.h \
             chain/chain.h chain/revocation.h chain/manifest.h chain/authz.h \
             chain/chain_store.h chain/service.h claim/claim.h \
             record/store.h catalog/catalog.h catalog/copy.h catalog/sweep.h \
             catalog/reach.h qr/qr.h \
             frame/freshness.h \
             blob/blob.h ratchet/ratchet.h prekey/prekey.h \
             provision/provision.h \
             disclose/disclose.h \
             persist/persist.h \
             spool/spool.h spool/message.h spool/transfer.h \
             spool/scrub.h \
             spool/plan.h \
             chunk/reassembly.h \
             chunk/split.h \
             tree/tree.h \
             wire/seal.h wire/relay.h wire/bytes.h session/aead.h \
             session/random.h session/random_system.h session/agree.h \
             session/session.h \
             version/version.h \
             record/record.h record/journal.h record/sync.h record/ledger.h \
             state/state.h trust/trust.h log/log.h sched/sched.h link/link.h

# THE LIBRARY WITHOUT ITS OPTIONAL BINDINGS, frozen here because the
# Monocypher conditional below appends to SRCS and HDRS and this is the last
# line at which they mean "the core".
#
# WHAT THEY EXIST FOR IS A GATE, not a second build path. `installcheck`
# compiles a consumer against these with no Monocypher anywhere -- no define,
# no include path, no vendored tree -- because that is the arrangement the
# README promises and sec 15c decided: the library calls no primitive, so a
# consumer that already carries its own Monocypher, as fuzzypickles does,
# inherits nothing from us.
#
# IT USED TO BE PROVED BY THE DEFAULT and now has to be proved on purpose.
# While the binding was off unless MONOCYPHER_DIR was set, a plain
# `make installcheck` WAS the core-only arrangement and demonstrated the
# property without meaning to. Vendoring turned the binding on by default, so
# that same command began proving the opposite -- that a consumer builds WITH
# Monocypher -- and the promise stopped being checked by anything while the
# gate went on passing. A check whose subject changes under it is worse than
# one that was never written, because it is quoted afterwards.
CORE_SRCS := $(SRCS)

# The primitive names installcheck looks for, spelled once because the probe
# and the control that proves the probe works must not be able to drift
# apart. Two patterns would be two claims.
CRYPTO_SYMS := crypto_|blake2|chacha|poly1305|argon2|x25519|ed25519
CORE_HDRS := $(HDRS)

TEST_SRCS := chain/test/chain_test.c chain/test/revocation_test.c \
             chain/test/manifest_test.c chain/test/authz_test.c \
             chain/test/chain_store_test.c chain/test/service_test.c \
             claim/test/claim_test.c record/test/store_test.c \
             catalog/test/catalog_test.c \
             catalog/test/copy_test.c \
             catalog/test/sweep_test.c \
             catalog/test/reach_test.c \
             qr/test/qr_test.c \
             blob/test/blob_test.c ratchet/test/ratchet_test.c \
             ratchet/test/ratchet_fuzz.c \
             prekey/test/prekey_test.c prekey/test/prekey_fuzz.c \
             provision/test/provision_fuzz.c \
             record/test/sync_fuzz.c \
             provision/test/provision_test.c \
             disclose/test/disclose_test.c \
             disclose/test/disclose_fuzz.c \
             persist/test/persist_test.c \
             persist/test/persist_fuzz.c \
             wire/test/relay_fuzz.c \
             log/test/log_fuzz.c \
             persist/test/persist_kat_test.c \
             spool/test/spool_test.c \
             spool/test/plan_test.c \
             spool/test/message_test.c \
             spool/test/transfer_test.c \
             spool/test/scrub_test.c \
             spool/test/scrub_fuzz.c \
             session/test/agree_test.c \
             session/test/session_test.c \
             blob/test/blob_fuzz.c \
             frame/test/freshness_test.c \
             chunk/test/reassembly_test.c chunk/test/split_test.c \
             session/test/commitment_test.c local/test/peer_test.c \
             wire/test/generated_test.c chunk/test/agreement_test.c \
             wire/test/constants_test.c wire/test/seal_test.c \
             wire/test/tamper_test.c \
             session/test/random_test.c local/test/vocabulary_test.c \
             local/test/vocabulary_fuzz.c local/test/admit_test.c \
             local/test/peer_fuzz.c local/test/peer_linux_test.c \
             spool/test/message_fuzz.c \
             chunk/test/reassembly_fuzz.c chain/test/chain_fuzz.c \
             frame/test/freshness_fuzz.c chain/test/revocation_fuzz.c \
             chain/test/manifest_fuzz.c \
             frame/test/receive_fuzz.c \
             chunk/test/roundtrip_fuzz.c \
             constant_time/test/secret_flow_test.c \
             wire/test/err_str_test.c \
             version/test/version_test.c \
             chunk/test/reassembly_guided.c \
             chain/test/chain_guided.c \
             frame/test/freshness_guided.c \
             sim/test/network_test.c \
             record/test/journal_test.c \
             record/test/record_test.c \
             tree/test/tree_test.c \
             record/test/sync_test.c record/test/ledger_test.c \
             state/test/state_test.c \
             trust/test/trust_test.c \
             log/test/log_test.c \
             wire/test/relay_test.c \
             sched/test/sched_test.c \
             sched/test/sched_fuzz.c \
             link/test/link_test.c \
             log/test/fix_stream_test.c \
             record/test/record_guided.c \
             record/test/record_fuzz.c \
             tree/test/tree_fuzz.c \
             tree/test/tree_kat_test.c \
             wire/test/seal_fuzz.c \
             record/test/record_kat_test.c
# Recursive for OBJS's reason: the file backends append to TEST_SRCS below.
TEST_OBJS  = $(TEST_SRCS:%.c=$(BUILD_DIR)/%.o)
TEST_BINS := $(BUILD_DIR)/chain/test/chain_test \
             $(BUILD_DIR)/chain/test/revocation_test \
             $(BUILD_DIR)/chain/test/manifest_test \
             $(BUILD_DIR)/chain/test/authz_test \
             $(BUILD_DIR)/chain/test/chain_store_test \
             $(BUILD_DIR)/chain/test/service_test \
             $(BUILD_DIR)/claim/test/claim_test \
             $(BUILD_DIR)/record/test/store_test \
             $(BUILD_DIR)/catalog/test/catalog_test \
             $(BUILD_DIR)/catalog/test/copy_test \
             $(BUILD_DIR)/catalog/test/sweep_test \
             $(BUILD_DIR)/catalog/test/reach_test \
             $(BUILD_DIR)/qr/test/qr_test \
             $(BUILD_DIR)/blob/test/blob_test \
             $(BUILD_DIR)/ratchet/test/ratchet_test \
             $(BUILD_DIR)/ratchet/test/ratchet_fuzz \
             $(BUILD_DIR)/prekey/test/prekey_test \
             $(BUILD_DIR)/provision/test/provision_test \
             $(BUILD_DIR)/disclose/test/disclose_test \
             $(BUILD_DIR)/persist/test/persist_test \
             $(BUILD_DIR)/persist/test/persist_kat_test \
             $(BUILD_DIR)/spool/test/spool_test \
             $(BUILD_DIR)/spool/test/plan_test \
             $(BUILD_DIR)/spool/test/message_test \
             $(BUILD_DIR)/spool/test/transfer_test \
             $(BUILD_DIR)/spool/test/scrub_test \
             $(BUILD_DIR)/spool/test/scrub_fuzz \
             $(BUILD_DIR)/session/test/agree_test \
             $(BUILD_DIR)/session/test/session_test \
             $(BUILD_DIR)/frame/test/freshness_test \
             $(BUILD_DIR)/session/test/commitment_test \
             $(BUILD_DIR)/local/test/peer_test \
             $(BUILD_DIR)/wire/test/generated_test \
             $(BUILD_DIR)/wire/test/constants_test \
             $(BUILD_DIR)/wire/test/seal_test \
             $(BUILD_DIR)/wire/test/tamper_test \
             $(BUILD_DIR)/session/test/random_test \
             $(BUILD_DIR)/local/test/vocabulary_test \
             $(BUILD_DIR)/local/test/vocabulary_fuzz \
             $(BUILD_DIR)/local/test/admit_test \
             $(BUILD_DIR)/chunk/test/agreement_test \
             $(BUILD_DIR)/local/test/peer_fuzz \
             $(BUILD_DIR)/local/test/peer_linux_test \
             $(BUILD_DIR)/chunk/test/reassembly_test \
             $(BUILD_DIR)/chunk/test/split_test \
             $(BUILD_DIR)/spool/test/message_fuzz \
             $(BUILD_DIR)/chunk/test/reassembly_fuzz \
             $(BUILD_DIR)/chain/test/chain_fuzz \
             $(BUILD_DIR)/frame/test/freshness_fuzz \
             $(BUILD_DIR)/frame/test/receive_fuzz \
             $(BUILD_DIR)/chain/test/revocation_fuzz \
             $(BUILD_DIR)/chain/test/manifest_fuzz \
             $(BUILD_DIR)/chunk/test/roundtrip_fuzz \
             $(BUILD_DIR)/constant_time/test/secret_flow_test \
             $(BUILD_DIR)/wire/test/err_str_test \
             $(BUILD_DIR)/version/test/version_test \
             $(BUILD_DIR)/chunk/test/reassembly_guided \
             $(BUILD_DIR)/chain/test/chain_guided \
             $(BUILD_DIR)/frame/test/freshness_guided \
             $(BUILD_DIR)/record/test/journal_test \
             $(BUILD_DIR)/record/test/record_test \
             $(BUILD_DIR)/record/test/record_kat_test \
             $(BUILD_DIR)/tree/test/tree_test \
             $(BUILD_DIR)/tree/test/tree_kat_test \
             $(BUILD_DIR)/record/test/sync_test \
             $(BUILD_DIR)/record/test/ledger_test \
             $(BUILD_DIR)/state/test/state_test \
             $(BUILD_DIR)/trust/test/trust_test \
             $(BUILD_DIR)/log/test/log_test \
             $(BUILD_DIR)/wire/test/relay_test \
             $(BUILD_DIR)/sched/test/sched_test \
             $(BUILD_DIR)/sched/test/sched_fuzz \
             $(BUILD_DIR)/link/test/link_test \
             $(BUILD_DIR)/log/test/fix_stream_test \
             $(BUILD_DIR)/record/test/record_guided \
             $(BUILD_DIR)/record/test/record_fuzz \
             $(BUILD_DIR)/tree/test/tree_fuzz \
             $(BUILD_DIR)/wire/test/seal_fuzz \
             $(BUILD_DIR)/blob/test/blob_fuzz \
             $(BUILD_DIR)/prekey/test/prekey_fuzz \
             $(BUILD_DIR)/provision/test/provision_fuzz \
             $(BUILD_DIR)/record/test/sync_fuzz \
             $(BUILD_DIR)/disclose/test/disclose_fuzz \
             $(BUILD_DIR)/persist/test/persist_fuzz \
             $(BUILD_DIR)/wire/test/relay_fuzz \
             $(BUILD_DIR)/log/test/log_fuzz

# ---------------------------------------------------------------------------
# SUBSYSTEMS: detected, overridable, and loud about which.
#
# The holder's shape, 2026-08-29: like a kernel or an embedded build --
# detect where detection is possible, and always leave a manual setting,
# "as it cannot always be known". So each subsystem below is TRI-STATE:
#
#     auto   probe, and build it if the probe passes
#     1      build it, and FAIL THE BUILD if it cannot be built
#     0      do not build it
#
# FORCED-ON-BUT-UNAVAILABLE IS AN ERROR RATHER THAN A SKIP, which is the
# half worth stating. Somebody who wrote FZN_PERSIST_FILE=1 asked for a
# subsystem by name; quietly not building it is the vacuous pass wearing a
# build flag, and on an embedded target it is the difference between "no
# filesystem backend, as configured" and "no filesystem backend, and nobody
# noticed". `analyze`, `ctcheck` and the Monocypher bindings already skip
# loudly for the same reason; this makes the third state explicit.
#
# WHAT IS NEVER OPTIONAL. `persist/persist.c` is the format and the contract
# -- it allocates nothing and does no I/O, so there is no target that cannot
# have it, and a consumer needs the pack functions whether or not it uses
# our backend. Only the backend is a subsystem.
FZN_PERSIST_FILE ?= auto

# THE PROBES ARE BUILT THE WAY THE LIBRARY IS, AND THERE IS A CONTROL
# BESIDE THEM. Both halves were missing and both were reported from outside
# this tree on 2026-09-03.
#
# They ran `$(CC)` bare -- no CPPFLAGS, no CFLAGS -- while every real rule
# below passes both. A toolchain needing a flag the user keeps in CFLAGS
# therefore BUILDS THE LIBRARY and FAILS THE PROBE, and the notice blames
# the platform's POSIX for a flag mismatch. Demonstrated, not supposed.
#
# FZN_PROBE_CC IS THE POSITIVE CONTROL, and it is the rule the rest of this
# tree runs on: an answer of "no" from a check with no control has not
# discriminated anything. A CC that cannot link a trivial program fails both
# probes below for a reason that has nothing to do with POSIX -- so when the
# control fails, the notices say THAT rather than naming a cause nothing
# tested. The comment beside those notices already argued that "off" and
# "you have no POSIX" are different problems with different fixes; a
# toolchain the probe was configured differently from is a third, and it was
# being reported as the second.
#
# DEPENDENCY FLAGS ARE FILTERED OUT AND NOTHING ELSE IS. `-MMD` against
# `-o /dev/null` tries to open `/dev/null.d` and the probe fails with
# "Permission denied" -- measured here the moment CPPFLAGS was first passed
# through, and caught by the control above rather than by noticing two
# backends had quietly switched off. A probe wants the build's SEARCH and
# LANGUAGE flags, which is where a `-I`, a `-D` or a `--target` lives; it
# does not want its dependency bookkeeping.
FZN_PROBE_CPPFLAGS := $(filter-out -MMD -MP -MD,$(CPPFLAGS))

# AND COVERAGE INSTRUMENTATION IS FILTERED OUT OF CFLAGS, for the same reason
# and found the same way. `make coverage` builds with CFLAGS="-Og -g
# --coverage", the probes below compile stdin against `-o /dev/null`, and gcc
# derives the note file's name from the input -- so each probe wrote `a--.gcno`
# INTO THE SOURCE TREE. Harmless to the verdict and not harmless at all as a
# habit: `clean` then reported a file it had no list for, which is the target
# working. A probe wants the build's search and language flags; instrumenting
# a compile whose output is /dev/null instruments nothing. project.md sec 219.
FZN_PROBE_CFLAGS := $(filter-out --coverage -fprofile-arcs -ftest-coverage \
                                 -fprofile-abs-path,$(CFLAGS))

# IT CALLS THE C LIBRARY, and that is the whole of what makes it a control.
# `int main(void){return 0;}` was the first version and it is useless here:
# it links under `-nostdlib` -- no libc, no POSIX, nothing -- because it
# references nothing, so the control passed and the notice went on blaming
# POSIX for a toolchain with no C library at all. `strtol` is ISO C rather
# than POSIX, so this separates "cannot link against libc" from "libc is
# here and lacks the POSIX file API", which are the two the notices must
# not confuse.
FZN_PROBE_CC := $(shell printf '%s\n' '#include <stdlib.h>' \
                 'int main(void){return (int)strtol("0", 0, 10);}' \
                 | $(CC) $(FZN_PROBE_CPPFLAGS) $(FZN_PROBE_CFLAGS) -x c - -o /dev/null 2>/dev/null \
                 && echo yes || echo no)
ifeq ($(FZN_PROBE_CC),yes)
FZN_BLAME_POSIX := no POSIX file API was detected.
FZN_BLAME_PWRITE := no positional read/write was detected.
FZN_BLAME_FIX := Set FZN_PERSIST_FILE=1 to insist.
FZN_BLAME_FIX_SP := Set FZN_SPOOL_FILE=1 to insist.
else
# THE ADVICE CHANGES WITH THE CAUSE, and that is the other half of the
# report: insisting is the right next step when a platform genuinely lacks
# the API and is useless when the toolchain could not be asked. The old
# notice offered it either way, so following it turned a skip into a hard
# error naming the same wrong cause.
FZN_BLAME_POSIX := $(CC) could not link against the C library with this build's \
own CPPFLAGS and CFLAGS, so the feature probe says nothing about POSIX.
FZN_BLAME_PWRITE := $(FZN_BLAME_POSIX)
FZN_BLAME_FIX := Fix the toolchain or the flags it is given -- insisting will not help.
FZN_BLAME_FIX_SP := $(FZN_BLAME_FIX)
endif

# The probe: does this toolchain have the POSIX the backend uses? Compiled
# rather than guessed from a platform name, because a name is a claim about
# a toolchain and this is a question about one.
FZN_PROBE_POSIX := $(shell printf '%s\n' '#define _POSIX_C_SOURCE 200809L' \
                    '#include <fcntl.h>' '#include <unistd.h>' \
                    'int main(void){int f=open("/dev/null",O_RDONLY);fsync(f);return close(f);}' \
                    | $(CC) $(FZN_PROBE_CPPFLAGS) $(FZN_PROBE_CFLAGS) -x c - -o /dev/null 2>/dev/null && echo yes || echo no)

ifeq ($(FZN_PERSIST_FILE),auto)
ifeq ($(FZN_PROBE_POSIX),yes)
PERSIST_FILE_ON := 1
else
PERSIST_FILE_SKIP := $(FZN_BLAME_POSIX) $(FZN_BLAME_FIX)
endif
else ifeq ($(FZN_PERSIST_FILE),1)
ifeq ($(FZN_PROBE_POSIX),yes)
PERSIST_FILE_ON := 1
else
$(error FZN_PERSIST_FILE=1 was asked for and $(FZN_BLAME_POSIX) \
        Set FZN_PERSIST_FILE=0 to build without it, or auto to let the probe decide)
endif
else ifeq ($(FZN_PERSIST_FILE),0)
PERSIST_FILE_SKIP := FZN_PERSIST_FILE=0.
else
$(error FZN_PERSIST_FILE must be auto, 1 or 0 -- got "$(FZN_PERSIST_FILE)")
endif

# Named OUTSIDE the conditional, for the reason MONO_SRCS is: `make style`
# compares the source lists against what is in the tree, and a list that
# empties itself when a subsystem is off makes the gate report two real
# files as unlisted. A false finding in a gate is worse than no finding.
PERSIST_FILE_SRCS := persist/persist_file.c
PERSIST_FILE_HDRS := persist/persist_file.h
PERSIST_FILE_TSRC := persist/test/persist_file_test.c

ifdef PERSIST_FILE_ON
CPPFLAGS  += -DFZN_PERSIST_FILE_ON
SRCS      += $(PERSIST_FILE_SRCS)
HDRS      += $(PERSIST_FILE_HDRS)
TEST_SRCS += $(PERSIST_FILE_TSRC)
TEST_BINS += $(BUILD_DIR)/persist/test/persist_file_test
endif

# The spool's sparse-file backend, gated the same way and SEPARATELY.
#
# Separately because they are different capabilities and a target can have
# one without the other: a device with a small config partition can persist
# four keys and have nowhere to assemble a 4 GiB blob, and that host wants
# FZN_PERSIST_FILE=1 FZN_SPOOL_FILE=0 rather than a single switch that makes
# it choose between both and neither. The cost of the separation is one more
# probe; the cost of merging them is a knob nobody can express their machine
# with.
FZN_SPOOL_FILE ?= auto

# ITS OWN PROBE, asking about pread and pwrite rather than reusing the one
# above. The two overlap almost entirely and reusing it would be shorter --
# and would mean persist refusing to build on a toolchain that has `open`
# and lacks `pwrite`, which is a subsystem failing for a function it never
# calls. A probe belongs to the thing it gates.
FZN_PROBE_PWRITE := $(shell printf '%s\n' '#define _POSIX_C_SOURCE 200809L' \
                     '#include <fcntl.h>' '#include <unistd.h>' \
                     'int main(void){char b=0;int f=open("/dev/null",O_RDWR);' \
                     'if(pwrite(f,&b,1,0)<0){}if(pread(f,&b,1,0)<0){}fsync(f);return close(f);}' \
                     | $(CC) $(FZN_PROBE_CPPFLAGS) $(FZN_PROBE_CFLAGS) -x c - -o /dev/null 2>/dev/null && echo yes || echo no)

ifeq ($(FZN_SPOOL_FILE),auto)
ifeq ($(FZN_PROBE_PWRITE),yes)
SPOOL_FILE_ON := 1
else
SPOOL_FILE_SKIP := $(FZN_BLAME_PWRITE) $(FZN_BLAME_FIX_SP)
endif
else ifeq ($(FZN_SPOOL_FILE),1)
ifeq ($(FZN_PROBE_PWRITE),yes)
SPOOL_FILE_ON := 1
else
$(error FZN_SPOOL_FILE=1 was asked for and $(FZN_BLAME_PWRITE) \
        Set FZN_SPOOL_FILE=0 to build without it, or auto to let the probe decide)
endif
else ifeq ($(FZN_SPOOL_FILE),0)
SPOOL_FILE_SKIP := FZN_SPOOL_FILE=0.
else
$(error FZN_SPOOL_FILE must be auto, 1 or 0 -- got "$(FZN_SPOOL_FILE)")
endif

# The claim backend's own probe, asking about `flock` rather than reusing
# either of the two above. project.md sec 132 explains why this and not
# `fcntl` record locks: a record lock is dropped when the process closes ANY
# descriptor for the file, which would silently give up the exclusivity a
# ratchet chain depends on. A probe belongs to the thing it gates, so this
# one asks for the call the backend actually makes.
FZN_PROBE_FLOCK := $(shell printf '%s\n' '#define _POSIX_C_SOURCE 200809L' \
                    '#include <fcntl.h>' '#include <sys/file.h>' '#include <unistd.h>' \
                    'int main(void){int f=open("/dev/null",O_RDWR);' \
                    'if(flock(f,LOCK_EX|LOCK_NB)<0){}if(flock(f,LOCK_UN)<0){}return close(f);}' \
                    | $(CC) $(FZN_PROBE_CPPFLAGS) $(FZN_PROBE_CFLAGS) -x c - -o /dev/null 2>/dev/null && echo yes || echo no)

FZN_BLAME_FLOCK := this toolchain has no usable flock.
FZN_BLAME_FIX_CL := Set FZN_CLAIM_FILE=0 to build without it.

ifeq ($(FZN_CLAIM_FILE),)
FZN_CLAIM_FILE := auto
endif

ifeq ($(FZN_CLAIM_FILE),auto)
ifeq ($(FZN_PROBE_FLOCK),yes)
CLAIM_FILE_ON := 1
else
CLAIM_FILE_SKIP := $(FZN_BLAME_FLOCK) $(FZN_BLAME_FIX_CL)
endif
else ifeq ($(FZN_CLAIM_FILE),1)
ifeq ($(FZN_PROBE_FLOCK),yes)
CLAIM_FILE_ON := 1
else
$(error FZN_CLAIM_FILE=1 was asked for and $(FZN_BLAME_FLOCK) \
        Set FZN_CLAIM_FILE=0 to build without it, or auto to let the probe decide)
endif
else ifeq ($(FZN_CLAIM_FILE),0)
CLAIM_FILE_SKIP := FZN_CLAIM_FILE=0.
else
$(error FZN_CLAIM_FILE must be auto, 1 or 0 -- got "$(FZN_CLAIM_FILE)")
endif

# THE RECORD STORE'S FILE BACKEND REUSES FZN_PROBE_PWRITE rather than adding
# a probe of its own, and that is consistent with the rule the spool states
# rather than an exception to it. A probe belongs to the thing it gates
# because it must ask about the calls that thing MAKES -- spool declined to
# reuse persist's because the two ask different questions. This backend calls
# `open`, `pread`, `pwrite` and `close`, which is exactly what FZN_PROBE_PWRITE
# asks, so reusing it asks the right question. The probe is named for the
# capability rather than for the subsystem, which is what makes that true.
ifeq ($(FZN_RECORD_STORE_FILE),)
FZN_RECORD_STORE_FILE := auto
endif

ifeq ($(FZN_RECORD_STORE_FILE),auto)
ifeq ($(FZN_PROBE_PWRITE),yes)
RECORD_STORE_FILE_ON := 1
else
RECORD_STORE_FILE_SKIP := $(FZN_BLAME_PWRITE)
endif
else ifeq ($(FZN_RECORD_STORE_FILE),1)
ifeq ($(FZN_PROBE_PWRITE),yes)
RECORD_STORE_FILE_ON := 1
else
$(error FZN_RECORD_STORE_FILE=1 was asked for and $(FZN_BLAME_PWRITE) \
        Set FZN_RECORD_STORE_FILE=0 to build without it, or auto to let the probe decide)
endif
else ifeq ($(FZN_RECORD_STORE_FILE),0)
RECORD_STORE_FILE_SKIP := FZN_RECORD_STORE_FILE=0.
else
$(error FZN_RECORD_STORE_FILE must be auto, 1 or 0 -- got "$(FZN_RECORD_STORE_FILE)")
endif

# THE CLI VOCABULARY, WHICH HAS NO PROBE AND DOES NOT WANT ONE. Every other
# option here gates a POSIX call and asks the compiler whether it exists;
# `cli/` is plain C11 with no platform surface, so there is nothing to ask and
# an `auto` setting would be a probe that always says yes. It is on or off,
# and it exists as an option at all because a consumer with no command line --
# a library, a plugin, a GUI launched by a desktop file -- should not carry a
# parser for one. project.md sec 137, and the copyright holder's rule that
# what a build omits is a build-time question rather than a repository one.
ifeq ($(FZN_CLI),)
FZN_CLI := 1
endif

ifeq ($(FZN_CLI),1)
CLI_ON := 1
else ifeq ($(FZN_CLI),0)
CLI_SKIP := FZN_CLI=0.
else
$(error FZN_CLI must be 1 or 0 -- got "$(FZN_CLI)")
endif

# THE GUI, AND THE FIRST C++ IN THIS TREE.
#
# project.md sec 137 and sec 140. The copyright holder's rule is that what a
# build omits is a build-time question rather than a repository one -- the
# same answer the kernel gives, and the one this Makefile already gives five
# times for POSIX backends. So the widgets live here and a build without Qt
# simply does not compile them; netcfgd on a router carries nothing.
#
# THE PROBE ASKS pkg-config RATHER THAN THE COMPILER, which is the difference
# between this and every other probe here. The others ask "does this call
# exist", which only a compile can answer; this asks "is there a Qt to build
# against", which is exactly what pkg-config is for, and asking the compiler
# would mean guessing include paths in order to test whether they were right.
#
# Qt 6 IS PREFERRED AND Qt 5 ACCEPTED, in that order, because a machine with
# both should build against the newer -- and because qtty, which is the reason
# these are Widgets rather than QML, targets Qt 6.
FZN_PROBE_QT := $(shell pkg-config --exists Qt6Widgets 2>/dev/null && echo Qt6Widgets \
                  || (pkg-config --exists Qt5Widgets 2>/dev/null && echo Qt5Widgets) \
                  || echo no)

FZN_BLAME_QT := no Qt Widgets development files were found by pkg-config.

# A C++ COMPILER, ASKED ABOUT SEPARATELY FROM Qt. The headers must parse as
# C++ whether or not anybody is building a widget: a consumer may be C++ and
# have no Qt at all, and until 2026-09-06 three of them did not parse at all
# -- caught by the first widget rather than by any gate. sec 140.
FZN_PROBE_CXX := $(shell printf '%s\n' 'int main(){return 0;}' \
                   | $(if $(CXX),$(CXX),c++) -x c++ - -o /dev/null 2>/dev/null \
                   && echo yes || echo no)

ifeq ($(FZN_GUI),)
FZN_GUI := auto
endif

ifeq ($(FZN_GUI),auto)
ifneq ($(FZN_PROBE_QT),no)
GUI_ON := 1
else
GUI_SKIP := $(FZN_BLAME_QT)
endif
else ifeq ($(FZN_GUI),1)
ifneq ($(FZN_PROBE_QT),no)
GUI_ON := 1
else
$(error FZN_GUI=1 was asked for and $(FZN_BLAME_QT) \
        Set FZN_GUI=0 to build without it, or auto to let the probe decide)
endif
else ifeq ($(FZN_GUI),0)
GUI_SKIP := FZN_GUI=0.
else
$(error FZN_GUI must be auto, 1 or 0 -- got "$(FZN_GUI)")
endif

# THE LISTS ARE WRITTEN WHOLE, NEVER PATCHED. sec 199: deleting one entry
# from a backslash-continued list by string replacement has broken this file
# four times -- a dangling continuation swallows the next line, and make
# reports it against somewhere else entirely.
GUI_SRCS := gui/trust_view.cpp gui/qr_view.cpp
GUI_HDRS := gui/trust_view.h gui/qr_view.h
GUI_TSRC := gui/test/trust_view_test.cpp gui/test/qr_view_test.cpp
# THE CONFIGURATION FORM NEEDS BOTH OPTIONS, and that is the design rather
# than an accident of the build. sec 164: it does not validate, the CLI parser
# does -- so a GUI build without FZN_CLI has no validator for it to be a front
# door to. Listed here rather than guarded inside the file, so a consumer that
# asks for one and not the other simply does not get the form instead of
# getting one that compiles and cannot check anything.
#
# THE LOG VIEW IS THE SAME SHAPE, settled by the copyright holder 2026-09-07.
# sec 168: it does not compose a log's screen, `cli/log_print` does -- so the
# summary wording has one implementation instead of two matched by hand.
#
# THE ANCHOR VIEW IS HERE FOR A DIFFERENT REASON, and it is the only one.
# sec 201: it takes the printer's CLASSIFICATION and none of its wording,
# because sec 158 breaks a fingerprint into lines at fixed positions and a
# status line is one line by definition. What it declines to duplicate is
# which of the four sources this anchor has, which is the half that drifts.
ifdef CLI_ON
GUI_SRCS  += gui/config_view.cpp gui/log_view.cpp gui/sync_view.cpp \
             gui/journal_view.cpp gui/sweep_view.cpp gui/transfer_view.cpp \
             gui/capability_view.cpp gui/state_view.cpp \
             gui/revocation_view.cpp gui/authz_view.cpp \
             gui/provision_view.cpp gui/link_view.cpp gui/peer_view.cpp \
             gui/manifest_view.cpp gui/ledger_view.cpp \
             gui/sched_view.cpp
GUI_HDRS  += gui/config_view.h gui/log_view.h gui/sync_view.h \
             gui/journal_view.h gui/sweep_view.h gui/transfer_view.h \
             gui/capability_view.h gui/state_view.h \
             gui/revocation_view.h gui/authz_view.h \
             gui/provision_view.h gui/link_view.h gui/peer_view.h \
             gui/manifest_view.h gui/ledger_view.h \
             gui/sched_view.h
GUI_TSRC  += gui/test/config_view_test.cpp gui/test/log_view_test.cpp \
             gui/test/sync_view_test.cpp gui/test/journal_view_test.cpp \
             gui/test/sweep_view_test.cpp gui/test/transfer_view_test.cpp \
             gui/test/capability_view_test.cpp gui/test/state_view_test.cpp \
             gui/test/revocation_view_test.cpp gui/test/authz_view_test.cpp \
             gui/test/provision_view_test.cpp gui/test/link_view_test.cpp \
             gui/test/peer_view_test.cpp gui/test/manifest_view_test.cpp \
             gui/test/ledger_view_test.cpp \
             gui/test/sched_view_test.cpp
endif

# NAMED OUTSIDE THE CONDITIONAL, and for the third time in this file: the
# build that made these and the one running `clean` need not agree about
# whether the GUI was on. GUI_SRCS and GUI_TSRC are already unconditional for
# the style check, so the names are here to be had. project.md sec 219.
GUI_CLEAN := $(GUI_SRCS:%.cpp=$(BUILD_DIR)/%.o) $(GUI_SRCS:%.cpp=$(BUILD_DIR)/%.d) \
             $(GUI_TSRC:%.cpp=$(BUILD_DIR)/%.o) $(GUI_TSRC:%.cpp=$(BUILD_DIR)/%.d) \
             $(GUI_TSRC:%.cpp=$(BUILD_DIR)/%)

ifdef GUI_ON
CXX       ?= c++
QT_CFLAGS := $(shell pkg-config --cflags $(FZN_PROBE_QT))
QT_LIBS   := $(shell pkg-config --libs $(FZN_PROBE_QT))
# SPLIT THE SAME WAY CFLAGS IS, AND FOR THE REASON THE SANITIZER BUILD
# TAUGHT. `SANITIZE=1` replaces CFLAGS and left CXXFLAGS alone, so the C
# objects carried the instrumentation and the C++ link did not carry the
# runtime -- an undefined `__asan_init` at link time, and the tree's only C++
# would have been the one thing the sanitizer never saw. Assigned rather than
# `?=` for the same reason: an inherited CXXFLAGS must not be able to drop the
# instrumentation quietly. A command line still wins, as make intends.
#
# NO `-fPIC`. The C objects are built without it, so forcing it here made the
# linker add text relocations to a PIE and say so. An executable linking Qt
# needs neither.
ifeq ($(SANITIZE),1)
CXXFLAGS_BUILD := -Og -g -fsanitize=address,undefined -fno-omit-frame-pointer \
                  -fno-sanitize-recover=all
else
CXXFLAGS_BUILD := -Os -g
endif
# QT_NO_KEYWORDS, AND IT STANDS ON sec 140 ALONE NOW. sec 179 added it while a
# public field was still called `slots`, which collides with Qt's macro of that
# name; sec 180 renamed the field, so this is no longer holding anything up.
#
# It stays because sec 140 already forbids what those keywords are for: none of
# these widgets has a Q_OBJECT, declares a slot, or emits anything, and the
# gate below proves it. The flag turns that convention into something the
# compiler keeps, so a widget that later wants a signal gets a clear error
# rather than a silent moc dependency.
#
# THE COLLISION IS FIXED FOR CONSUMERS, WHICH IS THE PART THIS FLAG NEVER DID.
# `gui/transfer_view.cpp` now compiles with the Qt keywords ON, which is the
# check that proves it -- see sec 180.
CXXFLAGS_WARN := -std=c++17 -Wall -Wextra -Wpedantic -DQT_NO_KEYWORDS
CXXFLAGS   = $(CXXFLAGS_BUILD) $(CXXFLAGS_WARN)
GUI_OBJS   := $(GUI_SRCS:%.cpp=$(BUILD_DIR)/%.o)
# NAMED SO THEIR DEPENDENCIES CAN BE READ BACK. sec 210: `TEST_OBJS`
# substitutes `%.c`, so no C++ object has ever reached it -- and `DEPS` is
# derived from `OBJS` and `TEST_OBJS`, so 30 `.d` files under gui/ were
# written on every build and `-include`d by nothing.
GUI_TOBJ   := $(GUI_TSRC:%.cpp=$(BUILD_DIR)/%.o)
TEST_BINS  += $(BUILD_DIR)/gui/test/trust_view_test \
              $(BUILD_DIR)/gui/test/qr_view_test
ifdef CLI_ON
TEST_BINS += $(BUILD_DIR)/gui/test/config_view_test \
             $(BUILD_DIR)/gui/test/log_view_test \
             $(BUILD_DIR)/gui/test/sync_view_test \
             $(BUILD_DIR)/gui/test/journal_view_test \
             $(BUILD_DIR)/gui/test/sweep_view_test \
             $(BUILD_DIR)/gui/test/transfer_view_test \
             $(BUILD_DIR)/gui/test/capability_view_test \
             $(BUILD_DIR)/gui/test/state_view_test \
             $(BUILD_DIR)/gui/test/revocation_view_test \
             $(BUILD_DIR)/gui/test/authz_view_test \
             $(BUILD_DIR)/gui/test/provision_view_test \
             $(BUILD_DIR)/gui/test/link_view_test \
             $(BUILD_DIR)/gui/test/peer_view_test \
             $(BUILD_DIR)/gui/test/manifest_view_test \
             $(BUILD_DIR)/gui/test/ledger_view_test \
             $(BUILD_DIR)/gui/test/sched_view_test
endif
endif

CLI_SRCS := cli/cli.c cli/qr_print.c cli/log_print.c cli/sync_print.c \
            cli/journal_print.c cli/sweep_print.c \
            cli/transfer_print.c cli/capability_print.c \
            cli/state_print.c cli/revocation_print.c \
            cli/authz_print.c cli/provision_print.c \
            cli/trust_print.c cli/link_print.c cli/peer_print.c \
            cli/manifest_print.c cli/ledger_print.c cli/replay_print.c \
            cli/reasm_print.c cli/sched_print.c
CLI_HDRS := cli/cli.h cli/qr_print.h cli/log_print.h cli/sync_print.h \
            cli/journal_print.h cli/sweep_print.h \
            cli/transfer_print.h cli/capability_print.h \
            cli/state_print.h cli/revocation_print.h \
            cli/authz_print.h cli/provision_print.h \
            cli/trust_print.h cli/link_print.h cli/peer_print.h \
            cli/manifest_print.h cli/ledger_print.h cli/replay_print.h \
            cli/reasm_print.h cli/sched_print.h
CLI_TSRC := cli/test/cli_test.c cli/test/qr_print_test.c \
            cli/test/log_print_test.c cli/test/sync_print_test.c \
            cli/test/journal_print_test.c cli/test/sweep_print_test.c \
            cli/test/transfer_print_test.c cli/test/capability_print_test.c \
            cli/test/state_print_test.c cli/test/revocation_print_test.c \
            cli/test/authz_print_test.c cli/test/provision_print_test.c \
            cli/test/trust_print_test.c cli/test/link_print_test.c \
            cli/test/peer_print_test.c cli/test/manifest_print_test.c \
            cli/test/ledger_print_test.c cli/test/replay_print_test.c \
            cli/test/reasm_print_test.c \
            cli/test/sched_print_test.c

ifdef CLI_ON
CPPFLAGS  += -DFZN_CLI_ON
SRCS      += $(CLI_SRCS)
HDRS      += $(CLI_HDRS)
TEST_SRCS += $(CLI_TSRC)
TEST_BINS += $(BUILD_DIR)/cli/test/cli_test \
               $(BUILD_DIR)/cli/test/qr_print_test \
               $(BUILD_DIR)/cli/test/log_print_test \
               $(BUILD_DIR)/cli/test/sync_print_test \
               $(BUILD_DIR)/cli/test/journal_print_test \
               $(BUILD_DIR)/cli/test/sweep_print_test \
               $(BUILD_DIR)/cli/test/transfer_print_test \
               $(BUILD_DIR)/cli/test/capability_print_test \
               $(BUILD_DIR)/cli/test/state_print_test \
               $(BUILD_DIR)/cli/test/revocation_print_test \
               $(BUILD_DIR)/cli/test/authz_print_test \
               $(BUILD_DIR)/cli/test/provision_print_test \
               $(BUILD_DIR)/cli/test/trust_print_test \
               $(BUILD_DIR)/cli/test/link_print_test \
               $(BUILD_DIR)/cli/test/peer_print_test \
               $(BUILD_DIR)/cli/test/manifest_print_test \
               $(BUILD_DIR)/cli/test/ledger_print_test \
               $(BUILD_DIR)/cli/test/replay_print_test \
               $(BUILD_DIR)/cli/test/reasm_print_test \
               $(BUILD_DIR)/cli/test/sched_print_test
endif

RECORD_STORE_FILE_SRCS := record/store_file.c
RECORD_STORE_FILE_HDRS := record/store_file.h
RECORD_STORE_FILE_TSRC := record/test/store_file_test.c

ifdef RECORD_STORE_FILE_ON
CPPFLAGS  += -DFZN_RECORD_STORE_FILE_ON
SRCS      += $(RECORD_STORE_FILE_SRCS)
HDRS      += $(RECORD_STORE_FILE_HDRS)
TEST_SRCS += $(RECORD_STORE_FILE_TSRC)
TEST_BINS += $(BUILD_DIR)/record/test/store_file_test
endif

CLAIM_FILE_SRCS := claim/claim_file.c
CLAIM_FILE_HDRS := claim/claim_file.h
CLAIM_FILE_TSRC := claim/test/claim_file_test.c

ifdef CLAIM_FILE_ON
CPPFLAGS  += -DFZN_CLAIM_FILE_ON
SRCS      += $(CLAIM_FILE_SRCS)
HDRS      += $(CLAIM_FILE_HDRS)
TEST_SRCS += $(CLAIM_FILE_TSRC)
TEST_BINS += $(BUILD_DIR)/claim/test/claim_file_test
endif

# Outside the conditional, for the reason PERSIST_FILE_SRCS is.
SPOOL_FILE_SRCS := spool/spool_file.c
SPOOL_FILE_HDRS := spool/spool_file.h
SPOOL_FILE_TSRC := spool/test/spool_file_test.c

ifdef SPOOL_FILE_ON
CPPFLAGS  += -DFZN_SPOOL_FILE_ON
SRCS      += $(SPOOL_FILE_SRCS)
HDRS      += $(SPOOL_FILE_HDRS)
TEST_SRCS += $(SPOOL_FILE_TSRC)
TEST_BINS += $(BUILD_DIR)/spool/test/spool_file_test
endif

# The Monocypher binding, built against the VENDORED submodule by default.
#
# project.md sec 15c took the step sec 7 named and sec 11 called temporary.
# The variable used to default to empty and be pointed at a live sibling --
# `../fuzzypickles/monocypher` in practice -- which harmonization.md names as
# the antipattern: a live sibling "is whatever its session left it as,
# mid-work included", where a vendored copy "is a version you chose, it
# clones with your tree, and it fails loudly at update time instead of
# quietly at build time". A crypto test that says "the AEAD round-trips" is
# not a claim unless the reader can say which bytes it round-tripped against.
#
# WHAT IS VENDORED IS FOR THIS TREE'S TESTS AND ITS OPTIONAL BINDINGS ONLY.
# The library calls no primitive -- crypto is four vtables, and only
# chain/sign_monocypher.c, session/hash_monocypher.c and
# session/aead_monocypher.c reach past them. So `make install` ships no
# Monocypher, and CORE_SRCS pulls none in: a consumer that already vendors
# it, as fuzzypickles does, cannot end up linking two copies of
# crypto_blake2b. That is code-style.md's landmine under prefixes and
# visibility, and it detonates at a link that changed nothing.
#
# CORE_SRCS, NOT SRCS, AND THE DISTINCTION IS WHAT THE DEFAULT FLIP COST.
# SRCS gains the three binding sources whenever the binding is built, which
# is now every build -- so a consumer handed $(SRCS) is handed three files
# that `#include <monocypher.h>` and does not compile without it. The first
# draft of this comment said SRCS and was measured false the same hour.
# CORE_SRCS is the list that means what this paragraph promises, and
# `installcheck` now compiles a consumer from it with Monocypher nowhere,
# so the promise is a gate rather than a sentence.
#
# The override survives, because sec 15c removes the default and not the
# knob. A consumer or developer with its own checkout points this elsewhere:
#
#   make test MONOCYPHER_DIR=../fuzzypickles/monocypher
#   make test MONOCYPHER_DIR=            # off, and the notice below says so
MONO_VENDORED  := monocypher
MONOCYPHER_DIR ?= $(MONO_VENDORED)

# WHETHER THE BINDING IS BUILT IS DECIDED BY THE SOURCE BEING THERE, not by
# the variable being non-empty, and the three cases are deliberately not one.
# A clone without `--recurse-submodules` leaves monocypher/ an empty
# directory, so a default that only checked for a non-empty variable would
# turn the binding on and fail in the linker talking about a missing
# `monocypher/src/monocypher.c` -- an error about the build for what is
# really an unfinished clone. It skips instead, and names the command.
#
# An OVERRIDE that points at nothing is the other way round and is an error,
# not a skip. Somebody asked for those tests by naming a path; quietly not
# running them is exactly the vacuous pass evidence.md warns about, wearing
# the costume of a build that succeeded.
MONO_SRC := $(wildcard $(MONOCYPHER_DIR)/src/monocypher.c)

# FLOG, THE DIAGNOSTIC LOGGER, VENDORED AND GATED THE WAY MONOCYPHER IS.
# sec 209. The copyright holder's requirement: the first line of
# troubleshooting is always a log.
#
# It is the holder's own repository, pinned at the commit fuzzypickles is on,
# so the two trees log through one library rather than two -- which is the
# whole of the uniformity this was asked for. A consumer names a sublog
# `fuzznet`, hangs it under its own root, and this library's subsystems
# compose into its path automatically: flog prefixes each log's name as a
# message passes up the tree, so `chain/verify` here arrives as
# `theirs/fuzznet/chain/verify` there.
#
# WITH ITS DEFAULT CONFIG IT ALLOCATES NOTHING, which is what makes it usable
# from a library whose whole shape is caller-owned tables. Verified rather
# than read: `nm -u` over flog.o, flog_string.o and flog_msg_id.o built with
# stock config.h names no malloc, calloc, realloc, free, strdup, asprintf or
# vasprintf. It wants snprintf, vsnprintf, gettimeofday, localtime and
# strerror, which is why it is gated rather than required -- the same POSIX
# question `persist/` and `spool/` already answer.
#
# THE OUTPUT BACKENDS ARE NOT BUILT HERE. `flog_output_file.c` and
# `flog_output_stdio.c` are separate translation units and are the consumer's
# to link: a target with no file API links neither and still has the logger,
# which is flog's own structure doing the gating rather than anything this
# file has to arrange.
# Named for the rules that link it. flog is a prerequisite of every test
# binary at once, further down, so it is NOT named here -- see sec 211.
LINK_OBJ = $(BUILD_DIR)/link/link.o

FLOG_VENDORED := flog
FLOG_DIR      ?= $(FLOG_VENDORED)
FLOG_SRC      := $(wildcard $(FLOG_DIR)/flog.c)

ifeq ($(FLOG_DIR),)
FLOG_SKIP := FLOG_DIR is empty, so this library emits no diagnostics.
else ifneq ($(FLOG_SRC),)
FLOG_ON   := 1
else ifeq ($(FLOG_DIR),$(FLOG_VENDORED))
FLOG_SKIP := the vendored $(FLOG_VENDORED)/ is empty. Run 'git submodule update --init'.
else
$(error FLOG_DIR=$(FLOG_DIR) has no flog.c. Leave it unset to use the \
        vendored $(FLOG_VENDORED)/, or set it to empty to build without \
        diagnostics)
endif

# NAMED OUTSIDE THE CONDITIONAL, for the reason MONO_SRCS and MONO_TSRC are
# sixty lines below: this file exists in the tree whether or not this build
# compiles it, `make style` compares the source lists against what is actually
# there, and `clean` has to remove what some other build made. Inside the
# `ifdef FLOG_ON` they are empty in a build that skipped flog -- so a CI job
# that deliberately checks out WITHOUT submodules reported a real source as
# unlisted, which is a false finding and worse in a gate than none. The
# precedent was already written down here and it was not followed; see
# project.md sec 219.
FLOG_TSRC  := link/test/link_log_test.c
FLOG_CLEAN := $(BUILD_DIR)/flog.o $(BUILD_DIR)/flog.d \
              $(BUILD_DIR)/flog_string.o $(BUILD_DIR)/flog_string.d \
              $(BUILD_DIR)/flog_msg_id.o $(BUILD_DIR)/flog_msg_id.d \
              $(FLOG_TSRC:%.c=$(BUILD_DIR)/%.o) \
              $(FLOG_TSRC:%.c=$(BUILD_DIR)/%.d) \
              $(FLOG_TSRC:%.c=$(BUILD_DIR)/%)

ifdef FLOG_ON
CPPFLAGS  += -DFZN_FLOG_ON -I$(FLOG_DIR)
# VENDORED CODE IS EXEMPT FROM OUR WARNING SET, and per-target rather than by
# policy, which is how quirc and qtty are already handled here.
# THE OBJECTS LAND AT THE TOP OF $(BUILD_DIR), NOT UNDER flog/, which is
# monocypher's arrangement here and is not a matter of taste: BUILD_DIR
# defaults to `.`, so `$(BUILD_DIR)/flog/flog.o` writes INSIDE the submodule
# and leaves it dirty. Measured by doing it once.
FLOG_OBJS := $(BUILD_DIR)/flog.o $(BUILD_DIR)/flog_string.o \
             $(BUILD_DIR)/flog_msg_id.o

# GATED LIKE THE MONOCYPHER SUITES, and for the same reason: without flog the
# library compiles and behaves identically, and there is nothing to assert
# about a logger that is not there. Kept in TEST_SRCS as well, because that is
# the list that reads as "every test source" and a quietly incomplete one is a
# trap for whatever asks it next. The name itself is defined above, outside
# this conditional, where the reason is.
TEST_SRCS += $(FLOG_TSRC)
TEST_BINS += $(BUILD_DIR)/link/test/link_log_test

$(BUILD_DIR)/link/test/link_log_test: $(BUILD_DIR)/link/test/link_log_test.o \
                                      $(LINK_OBJ) $(BUILD_DIR)/sched/sched.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(FLOG_OBJS): $(BUILD_DIR)/%.o: $(FLOG_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(GEN_CFLAGS) -w -I$(FLOG_DIR) -c $< -o $@
endif

ifeq ($(MONOCYPHER_DIR),)
MONO_SKIP := MONOCYPHER_DIR is empty, which switches them off.
else ifneq ($(MONO_SRC),)
MONO_ON   := 1
else ifeq ($(MONOCYPHER_DIR),$(MONO_VENDORED))
MONO_SKIP := the vendored $(MONO_VENDORED)/ is empty. Run 'git submodule update --init'.
else
$(error MONOCYPHER_DIR=$(MONOCYPHER_DIR) has no src/monocypher.c. \
        Leave it unset to use the vendored $(MONO_VENDORED)/, or set it to \
        empty to build without the bindings)
endif

# EVERY TREE WALK IN THIS FILE PRUNES THE VENDORED SUBMODULE, and it is one
# variable rather than four spellings so that the next walk cannot be added
# without it and the reason cannot drift between copies.
#
# The walks exist to hold OUR hand-maintained lists against the filesystem --
# every .c in a list, every .h in HDRS, every *_fuzz.c in FUZZ_BINS, every
# object gone after `clean`. A vendored tree answers none of those questions:
# its 56 C sources and 46 headers are in no list of ours by design, `make
# install` ships none of them, and `clean` must not remove a file this build
# did not create. Measured unpruned: the C-source walk fails first, naming
# all 56 as "in no list", and the header walk behind it would have named 46
# more. A gate reporting 102 files nobody can act on is a gate that has
# stopped saying anything, which is why the prune is not a nicety.
# EVERY VENDORED TREE, READ FROM .gitmodules RATHER THAN LISTED HERE.
#
# It was `-not -path './$(MONO_VENDORED)/*'` -- one tree, named literally --
# and vendoring quirc and qtty in sec 169 made three source-enumeration gates
# report fourteen of somebody else's C files as unlisted. A list that has to
# be edited every time a submodule is added, with nothing announcing that it
# exists, is the shape this tree keeps removing; .gitmodules already holds
# the answer, so it is read instead. tool/enum_gate.py and tool/status_gate.py
# were the same defect and take the same fix.
VENDOR_DIRS  := $(shell sed -n 's/^[ \t]*path *= *//p' .gitmodules 2>/dev/null)
# AND THE STAGING COPY THE RENDER TARGET MAKES OF ONE OF THEM. `qtty` unpacks
# `git archive HEAD` into `$(BUILD_DIR)/.qtty` and removes it from a trap --
# which does not run when the target is KILLED rather than signalled, and a
# `timeout` around a slow render is exactly how that happens. The comment on
# that target already said .gitignore is "the backstop rather than the fix" and
# does nothing about the gate that reads the working tree; this is the fix.
# Left behind once, it made `make style` walk 26 of somebody else's headers and
# refuse -- a gate reporting files nobody can act on, from a run that was
# interrupted rather than wrong. sec 205.
#
# THE NAME CARRIES THE PID SINCE sec 208, so the prune is a PREFIX match. A
# fixed scratch name is what let two concurrent runs delete each other's tree.
VENDOR_DIRS  += .qtty
VENDOR_PRUNE := $(foreach d,$(VENDOR_DIRS),-not -path './$(d)/*') \
                -not -path './.qtty-*/*'

# Named OUTSIDE the conditional, because these files exist in the tree whether
# or not this build compiles them, and `make style` compares the source lists
# against what is actually there. Inside the `ifdef MONO_ON` they would be
# empty in a build that skipped the binding, and the check would report two
# real sources as unlisted -- a false finding, which is worse in a gate than
# no finding at all.
MONO_SRCS  := chain/sign_monocypher.c session/hash_monocypher.c \
              session/aead_monocypher.c session/agree_monocypher.c
MONO_HDRS  := chain/sign_monocypher.h session/hash_monocypher.h \
              session/aead_monocypher.h session/agree_monocypher.h
# AND THE HEADERS SHIP OUTSIDE THE CONDITIONAL TOO, which the sources
# deliberately do not. `HDRS += $(MONO_HDRS)` lived inside `ifdef MONO_ON`
# until `make installcheck MONOCYPHER_DIR=` was first run and could not
# compile at all: tool/consumer_check.c includes the four binding headers
# unconditionally and argues why, so the two arms that use installed headers
# looked for files `install` had not shipped.
#
# THE ASYMMETRY IS THE POINT. A source is compiled or it is not, and
# MONO_SRCS stays conditional because without the submodule there is nothing
# to compile it against. A header is a declaration: these four declare
# vtables over this library's own types, include no <monocypher.h>, and
# compile standalone -- which is exactly what the consumer check exists to
# prove, in the arrangement that has no Monocypher at all.
#
# What decides it is that the gate is a property of the CHECKOUT rather than
# of the platform. MONO_ON is off when nobody ran `git submodule update`;
# persist/ and spool/ are off when the target has no POSIX. An installed
# header set that varies with the first is describing somebody's working
# copy rather than the library, and this project installs headers and
# nothing else -- a consumer compiles the sources itself, so whether OUR
# tree had the submodule is not a fact about what THEY can build.
HDRS       += $(MONO_HDRS)
MONO_TSRC  := chain/test/sign_monocypher_test.c \
              session/test/hash_monocypher_test.c \
              session/test/aead_monocypher_test.c \
              session/test/agree_monocypher_test.c \
              sim/test/real_crypto_test.c \
              sim/test/provision_test.c \
              sim/test/disclosure_test.c \
              wire/test/golden_frame_test.c \
              session/test/session_kat_test.c \
              ratchet/test/ratchet_kat_test.c \
              blob/test/blob_kat_test.c \
              chain/test/hop_kat_test.c

ifdef MONO_ON
MONO_OBJS  := $(BUILD_DIR)/chain/sign_monocypher.o \
              $(BUILD_DIR)/session/hash_monocypher.o \
              $(BUILD_DIR)/session/aead_monocypher.o \
              $(BUILD_DIR)/monocypher.o
MONO_TOBJ  := $(MONO_TSRC:%.c=$(BUILD_DIR)/%.o)
# Kept in TEST_SRCS as well as TEST_OBJS. Nothing was broken by its absence
# -- the objects, deps and binaries were all reached through MONO_TOBJ --
# but TEST_SRCS is the list that reads as "every test source", and one that
# is quietly incomplete is a trap for whatever asks it next. Found by asking
# it exactly that question.
TEST_SRCS  += $(MONO_TSRC)
# SRCS too, and for the same reason TEST_SRCS was fixed: it is the list that
# reads as "every library source", and `make coverage` iterates it. Without
# this the two bindings were built, linked and run by their own tests while
# the guard written to refuse an unexercised source could not see them --
# which is `GEN_SRCS` against `SRCS` a third time.
#
# It must come after OBJS is computed, which it does: OBJS took its value from
# SRCS above, and MONO_OBJS is added to it separately below, so the objects are
# named once rather than twice.
SRCS       += $(MONO_SRCS)
# What `tool/consumer_check.c` needs to exercise the bindings: the define that
# switches its optional block on, the include path, and Monocypher itself,
# since installcheck compiles sources rather than linking objects.
# Absolute, because installcheck's second arm compiles from inside
# $(BUILD_DIR)/installcheck -- which is why the SRCS beside it are put through
# $(CURDIR) as well. A relative path here builds in one arrangement and not the
# other, which is the difference the whole target exists to find.
MONO_ABS      := $(abspath $(MONOCYPHER_DIR))
MONO_CONSUMER := -DFZN_CONSUMER_MONOCYPHER -I$(MONO_ABS)/src \
                 $(MONO_ABS)/src/monocypher.c
MONO_BIN   := $(BUILD_DIR)/chain/test/sign_monocypher_test
MONO_HASH  := $(BUILD_DIR)/session/test/hash_monocypher_test
MONO_AEAD  := $(BUILD_DIR)/session/test/aead_monocypher_test
MONO_AGREE := $(BUILD_DIR)/session/test/agree_monocypher_test
MONO_GOLD  := $(BUILD_DIR)/wire/test/golden_frame_test
MONO_KAT   := $(BUILD_DIR)/session/test/session_kat_test
MONO_RKAT  := $(BUILD_DIR)/ratchet/test/ratchet_kat_test
MONO_BKAT  := $(BUILD_DIR)/blob/test/blob_kat_test
MONO_HKAT  := $(BUILD_DIR)/chain/test/hop_kat_test
MONO_REAL  := $(BUILD_DIR)/sim/test/real_crypto_test
MONO_PROV  := $(BUILD_DIR)/sim/test/provision_test
MONO_DISC  := $(BUILD_DIR)/sim/test/disclosure_test
OBJS       += $(MONO_OBJS)
TEST_OBJS  += $(MONO_TOBJ)
TEST_BINS  += $(MONO_BIN) $(MONO_HASH) $(MONO_AEAD) $(MONO_AGREE) $(MONO_GOLD) \
              $(MONO_KAT) $(MONO_RKAT) $(MONO_BKAT) $(MONO_HKAT)
CPPFLAGS   += -I$(MONOCYPHER_DIR)/src

# Vendored, so it is compiled with its own terms rather than ours.
# code-style.md exempts vendored sources from our rules, and -Wconversion
# against somebody else's crypto is noise nobody will read, which is how a
# warning that matters gets missed.
#
# WHICH Monocypher is printed, for the reason `make schema` prints which situ:
# these tests are the only ones here whose result depends on a tree outside
# this repository, and "the AEAD round-trips" is not a claim while "it
# round-trips against Monocypher 4.0.3 at ab2b16d" is. Crypto especially --
# a patched copy at the same path is exactly the thing worth naming.
#
# Reported rather than refused, unlike situ's. Nothing is vendored FROM here,
# so a dirty tree cannot get a false provenance stamped on it; the worst case
# is a result somebody cannot reproduce, which the line below fixes.
$(BUILD_DIR)/monocypher.o: $(MONOCYPHER_DIR)/src/monocypher.c
	@mkdir -p $(dir $@)
	@if git -C "$(MONOCYPHER_DIR)" rev-parse --git-dir >/dev/null 2>&1; then \
		echo "monocypher: `git -C $(MONOCYPHER_DIR) describe --tags --always --dirty 2>/dev/null`"; \
	else \
		echo "monocypher: $(MONOCYPHER_DIR) is not a git checkout, so its version is unknown"; \
	fi
	$(CC) $(GEN_CFLAGS) -c $< -o $@

# Each names its own objects rather than linking $(MONO_OBJS) wholesale.
# Linking both bindings into both binaries would work and would hide which
# one each test actually exercises, which is the thing these tests are for.
$(MONO_BIN): $(BUILD_DIR)/chain/test/sign_monocypher_test.o \
             $(BUILD_DIR)/chain/sign_monocypher.o $(BUILD_DIR)/monocypher.o \
             $(BUILD_DIR)/chain/chain.o \
             $(BUILD_DIR)/chain/revocation.o \
             $(BUILD_DIR)/chain/manifest.o \
             $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The AEAD test reaches the frame path, so it links wire/seal.o and situ's
# generated objects as well -- it is the only Monocypher test that does,
# because it is the only one testing something that reads the wire.
$(BUILD_DIR)/session/test/aead_monocypher_test.o: session/test/aead_monocypher_test.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -c $< -o $@

# session/commitment.o for the same reason seal_test links it: wire/seal.o
# derives the commitment now instead of being handed one.
#
# AND session/hash_monocypher.o, WHICH IS THE ONE PLACE THIS FILE'S "each
# names its own objects" RULE ABOVE IS DELIBERATELY NOT FOLLOWED. That rule
# exists so a binary cannot pass on a binding it does not exercise; here the
# AEAD test genuinely exercises both, because the derivation `fzn_seal_open`
# performs is part of the frame path it is testing. A stub hash would leave
# the real AEAD running behind a fake derivation, which is the arrangement
# wire/test/seal_test.c already covers.
$(MONO_AEAD): $(BUILD_DIR)/session/test/aead_monocypher_test.o \
              $(BUILD_DIR)/session/aead_monocypher.o \
              $(BUILD_DIR)/session/hash_monocypher.o $(BUILD_DIR)/monocypher.o \
              $(BUILD_DIR)/wire/seal.o $(BUILD_DIR)/session/commitment.o \
              $(BUILD_DIR)/session/random.o \
              $(BUILD_DIR)/constant_time/constant_time.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The agreement binding names its own objects, per the rule the AEAD test
# above is the one exception to: agree.o, its binding, and Monocypher. It
# reads no wire and derives nothing, so there is nothing else it could be
# passing on.
$(MONO_AGREE): $(BUILD_DIR)/session/test/agree_monocypher_test.o \
               $(BUILD_DIR)/session/agree_monocypher.o \
               $(BUILD_DIR)/session/agree.o $(BUILD_DIR)/monocypher.o \
               $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The golden frame vector, which reads the wire and so needs the generated
# layout on its include path exactly as the AEAD test does.
$(BUILD_DIR)/wire/test/golden_frame_test.o: wire/test/golden_frame_test.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -c $< -o $@

# The same object list as $(MONO_AEAD), for the same reasons, and
# session/hash_monocypher.o is here under the same deliberate exception to the
# "each names its own objects" rule stated above it: the frame this file
# freezes carries a commitment that the real BLAKE2b derived, so a stub hash
# would produce different bytes and there would be nothing to compare.
# session/random.o comes in because this one calls `fzn_seal_build`, which
# draws its nonce through `fzn_nonce_next` -- the seam that makes a fixed
# frame reproducible without letting a caller name a nonce.
$(MONO_GOLD): $(BUILD_DIR)/wire/test/golden_frame_test.o \
              $(BUILD_DIR)/session/aead_monocypher.o \
              $(BUILD_DIR)/session/hash_monocypher.o $(BUILD_DIR)/monocypher.o \
              $(BUILD_DIR)/wire/seal.o $(BUILD_DIR)/session/commitment.o \
              $(BUILD_DIR)/session/random.o \
              $(BUILD_DIR)/constant_time/constant_time.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The session root vector. It recomputes the derivation from the DOCUMENTED
# specification using Monocypher directly, so it needs the real X25519 and the
# real BLAKE2b -- and it needs session/, agree/ and commitment/ to have the
# answer to compare against. `monocypher.o` is linked once and serves both
# sides of that comparison, which is exactly what the file's header comment
# says is NOT a second implementation: the primitives are shared and only the
# construction over them is written twice.
$(MONO_KAT): $(BUILD_DIR)/session/test/session_kat_test.o \
             $(BUILD_DIR)/session/session.o $(BUILD_DIR)/session/agree.o \
             $(BUILD_DIR)/session/agree_monocypher.o \
             $(BUILD_DIR)/session/hash_monocypher.o \
             $(BUILD_DIR)/session/commitment.o \
             $(BUILD_DIR)/constant_time/constant_time.o $(BUILD_DIR)/monocypher.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The two other key schedules, pinned for the reasons project.md sec 45 gives.
# Each links only its own module plus the real BLAKE2b: a green result has to
# say WHICH schedule was exercised, which is the same rule the four binding
# tests follow and the reason real_crypto_test is the only one linking
# everything at once.
$(MONO_RKAT): $(BUILD_DIR)/ratchet/test/ratchet_kat_test.o \
              $(BUILD_DIR)/ratchet/ratchet.o \
              $(BUILD_DIR)/session/hash_monocypher.o \
              $(BUILD_DIR)/constant_time/constant_time.o $(BUILD_DIR)/monocypher.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(MONO_BKAT): $(BUILD_DIR)/blob/test/blob_kat_test.o \
              $(BUILD_DIR)/blob/blob.o \
              $(BUILD_DIR)/session/aead_monocypher.o \
              $(BUILD_DIR)/session/hash_monocypher.o \
              $(BUILD_DIR)/constant_time/constant_time.o $(BUILD_DIR)/monocypher.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The hop layout vector. Ed25519 signing is deterministic, so a hop minted
# from a fixed seed is reproducible with no seam for randomness. The object
# list is $(MONO_BIN)'s: `fzn_chain_verify` consults both the revocation
# store and the manifest, and each was discovered by the linker asking
# rather than by guessing at the dependency.
$(MONO_HKAT): $(BUILD_DIR)/chain/test/hop_kat_test.o \
              $(BUILD_DIR)/chain/chain.o $(BUILD_DIR)/chain/revocation.o \
              $(BUILD_DIR)/chain/manifest.o \
              $(BUILD_DIR)/chain/sign_monocypher.o \
              $(BUILD_DIR)/constant_time/constant_time.o $(BUILD_DIR)/monocypher.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# THE ONLY BINARY THAT LINKS ALL FOUR BINDINGS AT ONCE, which is the whole
# reason it exists -- every other Monocypher test names one binding on purpose,
# so that a green result says which primitive was exercised. This one is the
# opposite claim and needs the opposite link line: a host has all four.
$(MONO_REAL): $(BUILD_DIR)/sim/test/real_crypto_test.o \
              $(BUILD_DIR)/chain/sign_monocypher.o \
              $(BUILD_DIR)/session/hash_monocypher.o \
              $(BUILD_DIR)/session/aead_monocypher.o \
              $(BUILD_DIR)/session/agree_monocypher.o $(BUILD_DIR)/monocypher.o \
              $(BUILD_DIR)/session/session.o $(BUILD_DIR)/session/agree.o \
              $(BUILD_DIR)/session/commitment.o $(BUILD_DIR)/session/random.o \
              $(BUILD_DIR)/session/random_linux.o \
              $(BUILD_DIR)/prekey/prekey.o $(BUILD_DIR)/ratchet/ratchet.o \
              $(BUILD_DIR)/trust/trust.o $(BUILD_DIR)/chain/chain.o \
              $(BUILD_DIR)/chain/revocation.o $(BUILD_DIR)/chain/manifest.o \
              $(BUILD_DIR)/wire/seal.o \
              $(BUILD_DIR)/constant_time/constant_time.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# PROVISIONING FROM NOTHING, then traffic across the subsystems. Links more
# than its sibling because the point is the joins: blob and spool for the
# content-key hand-off, record/journal/state/log for what travels as records,
# link and sched for the send-path decision, relay for the hop budget.
$(MONO_PROV): $(BUILD_DIR)/sim/test/provision_test.o \
              $(BUILD_DIR)/chain/sign_monocypher.o \
              $(BUILD_DIR)/session/hash_monocypher.o \
              $(BUILD_DIR)/session/aead_monocypher.o \
              $(BUILD_DIR)/session/agree_monocypher.o $(BUILD_DIR)/monocypher.o \
              $(BUILD_DIR)/session/session.o $(BUILD_DIR)/session/agree.o \
              $(BUILD_DIR)/session/commitment.o $(BUILD_DIR)/session/random.o \
              $(BUILD_DIR)/session/random_linux.o \
              $(BUILD_DIR)/prekey/prekey.o $(BUILD_DIR)/ratchet/ratchet.o \
              $(BUILD_DIR)/trust/trust.o $(BUILD_DIR)/chain/chain.o \
              $(BUILD_DIR)/chain/revocation.o $(BUILD_DIR)/chain/manifest.o \
              $(BUILD_DIR)/chain/authz.o \
              $(BUILD_DIR)/chunk/split.o $(BUILD_DIR)/chunk/reassembly.o \
              $(BUILD_DIR)/frame/freshness.o \
              $(BUILD_DIR)/record/record.o $(BUILD_DIR)/record/journal.o \
              $(BUILD_DIR)/record/sync.o $(BUILD_DIR)/state/state.o \
              $(BUILD_DIR)/log/log.o $(BUILD_DIR)/tree/tree.o \
              $(BUILD_DIR)/blob/blob.o $(BUILD_DIR)/spool/spool.o \
              $(BUILD_DIR)/spool/plan.o $(BUILD_DIR)/spool/message.o \
              $(BUILD_DIR)/spool/scrub.o \
              $(BUILD_DIR)/spool/transfer.o \
              $(LINK_OBJ) $(BUILD_DIR)/sched/sched.o \
              $(BUILD_DIR)/wire/seal.o $(BUILD_DIR)/wire/relay.o \
              $(BUILD_DIR)/version/version.o $(BUILD_DIR)/persist/persist.o \
              $(BUILD_DIR)/constant_time/constant_time.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The disclosure demonstration links far less than the provisioning one,
# and deliberately: it is a claim about four calls, so linking the whole
# library would let something else account for the result. chain.o comes in
# only because record/ reaches it for FZN_PUBKEY_LEN's neighbours, and it
# drags revocation and manifest with it as everywhere else.
$(MONO_DISC): $(BUILD_DIR)/sim/test/disclosure_test.o \
                       $(BUILD_DIR)/disclose/disclose.o \
              $(BUILD_DIR)/blob/blob.o $(BUILD_DIR)/record/record.o \
              $(BUILD_DIR)/chain/chain.o $(BUILD_DIR)/chain/revocation.o \
              $(BUILD_DIR)/chain/manifest.o \
              $(BUILD_DIR)/session/hash_monocypher.o \
              $(BUILD_DIR)/chain/sign_monocypher.o \
              $(BUILD_DIR)/version/version.o \
              $(BUILD_DIR)/constant_time/constant_time.o $(BUILD_DIR)/monocypher.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(MONO_HASH): $(BUILD_DIR)/session/test/hash_monocypher_test.o \
              $(BUILD_DIR)/session/hash_monocypher.o $(BUILD_DIR)/monocypher.o \
              $(BUILD_DIR)/session/commitment.o \
              $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@
endif

# Every -MMD file is read back, TEST OBJECTS INCLUDED. build-and-commit.md
# names that omission specifically: a test object whose .d is never included
# does not rebuild when a header it includes changes, so a struct that gains
# a field ends up with one layout in the library and another in the binary
# linked against it -- which surfaces as a pile of nonsense assertion
# failures rather than as a build error.
# THE GUI HALVES ARE NAMED SEPARATELY BECAUSE `%.c` CANNOT REACH THEM.
# sec 210, and it is build-and-commit.md's first dependency rule: a test
# object whose `.d` is never read back does not rebuild when a header it
# includes changes, so a struct that gains a field ends up with one layout in
# the library and another in the binary linked against it.
#
# That is not a hypothetical here. `fzn_link_table_t` gained a `log` pointer
# in sec 209 and `gui/test/link_view_test.cpp` kept the old layout, so
# `fzn_link_table_init` wrote eight bytes past the end of the caller's struct
# -- caught by AddressSanitizer as a stack-buffer-overflow in a suite that had
# nothing to do with the change. Both gui variables expand to nothing when the
# GUI is off, so this costs a build without it nothing.
DEPS = $(OBJS:.o=.d) $(TEST_OBJS:.o=.d) $(GUI_OBJS:.o=.d) $(GUI_TOBJ:.o=.d)

.PHONY: check runtests all test fuzz guided guided-one installcheck coverage sancheck schema qtty qrcheck style codegencheck ctcheck analyze sabotage hooks clean install

# The default build does NOT build tests -- build-and-commit.md, and the
# discipline it buys is paid for by the dependency rules above being right.
all: $(OBJS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# GEN_EXTRA exists so `make coverage` can instrument these without their
# warning flags becoming ours. Without it the coverage target reported all
# three as exercised by nothing, which was false -- generated_test drives
# them -- and a false positive from a guard is worth no more than the false
# negative it replaced.
GEN_EXTRA ?=

$(BUILD_DIR)/wire/generated/%.o: wire/generated/%.c
	@mkdir -p $(dir $@)
	$(CC) $(GEN_CFLAGS) -Iwire/generated -MMD -MP -c $< -o $@

# revocation.o IS NOT OPTIONAL HERE, and it became so on 2026-08-27.
# `fzn_chain_verify` asks the module that owns the store rather than keeping a
# second copy of the same predicate -- which is what let the two disagree about
# a corrupt store, and cost a heap overflow on the authorization path. One
# predicate means one definition, and chain.o now carries an undefined
# reference to it. The symbol is `fzn_revocation_covers_chain` since
# 2026-08-28, when the query started asking about a whole chain rather than
# about one issuer; the argument is unchanged and is why the walk did not move
# into chain.c with it.
$(BUILD_DIR)/chain/test/chain_test: $(BUILD_DIR)/chain/test/chain_test.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# record.o is here because a record is now a VIEW over its own encoding: the
# harness builds every record through fzn_record_sign and reads it back with
# fzn_record_open, so the module is linked rather than merely included.
$(BUILD_DIR)/record/test/record_guided: $(BUILD_DIR)/record/test/record_guided.o \
                                        $(BUILD_DIR)/record/record.o \
                                        $(BUILD_DIR)/record/journal.o \
                                        $(BUILD_DIR)/state/state.o \
                                        $(BUILD_DIR)/log/log.o \
                                        $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/log/test/fix_stream_test: $(BUILD_DIR)/log/test/fix_stream_test.o \
                                       $(BUILD_DIR)/log/log.o \
                                       $(BUILD_DIR)/record/record.o \
                                       $(BUILD_DIR)/record/journal.o \
                                       $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/link/test/link_test: $(BUILD_DIR)/link/test/link_test.o \
                                  $(LINK_OBJ) \
                                  $(BUILD_DIR)/sched/sched.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/sched/test/sched_test: $(BUILD_DIR)/sched/test/sched_test.o \
                                    $(BUILD_DIR)/sched/sched.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/sched/test/sched_fuzz: $(BUILD_DIR)/sched/test/sched_fuzz.o \
                                    $(BUILD_DIR)/sched/sched.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/wire/test/relay_test: $(BUILD_DIR)/wire/test/relay_test.o \
                                   $(BUILD_DIR)/wire/relay.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# `log/` LINKS THE JOURNAL NOW, and every binary that uses `fzn_log_get` must.
# The GONE answer is read out of `fzn_journal_next` rather than out of what the
# log still holds -- see log.h -- so a link line that lists log.o without
# journal.o does not fail to answer, it fails to link, which is the direction
# this build wants a missed dependency to fail in.
$(BUILD_DIR)/log/test/log_test: $(BUILD_DIR)/log/test/log_test.o \
                                $(BUILD_DIR)/log/log.o \
                                $(BUILD_DIR)/record/record.o \
                                $(BUILD_DIR)/record/journal.o \
                                $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/trust/test/trust_test: $(BUILD_DIR)/trust/test/trust_test.o \
                                    $(BUILD_DIR)/trust/trust.o \
                                    $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/state/test/state_test: $(BUILD_DIR)/state/test/state_test.o \
                                    $(BUILD_DIR)/state/state.o \
                                    $(BUILD_DIR)/record/record.o \
                                    $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/record/test/sync_test: $(BUILD_DIR)/record/test/sync_test.o \
                                    $(BUILD_DIR)/record/sync.o \
                                    $(BUILD_DIR)/record/journal.o \
                                    $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Links constant_time only: the ledger compares a peer and a subject in
# constant time and calls nothing else in this library.
$(BUILD_DIR)/record/test/ledger_test: $(BUILD_DIR)/record/test/ledger_test.o \
                                    $(BUILD_DIR)/record/ledger.o \
                                    $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/record/test/record_test: $(BUILD_DIR)/record/test/record_test.o \
                                      $(BUILD_DIR)/record/record.o \
                                      $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/tree/test/tree_test: $(BUILD_DIR)/tree/test/tree_test.o \
                                  $(BUILD_DIR)/tree/tree.o \
                                  $(BUILD_DIR)/record/record.o \
                                  $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The byte-level fuzz harness for the same module record_test.c covers with
# named cases. It links record.o alone: nothing above `record/` is on trial
# here, which is what separates it from record_guided.c next door.
# The layout table in record.h, as literals. Its offsets are already
# pinned by _Static_assert in record.c; what this adds is the byte ORDER,
# which nothing else checks -- a little-endian encoder agrees perfectly
# with a little-endian decoder.
$(BUILD_DIR)/record/test/record_kat_test: \
                                      $(BUILD_DIR)/record/test/record_kat_test.o \
                                      $(BUILD_DIR)/record/record.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/record/test/record_fuzz: $(BUILD_DIR)/record/test/record_fuzz.o \
                                      $(BUILD_DIR)/record/record.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The newest decoder of stranger bytes. Links tree.o and record.o and
# nothing else: a node is parsed out of a record body, so record/ is the
# only thing beneath it, and nothing above tree/ is on trial here.
# The layout table in tree.h, as literals. Links the same two objects as
# the fuzz harness for the same reason: a node body is parsed out of a
# record, so record/ is the only thing beneath it.
$(BUILD_DIR)/tree/test/tree_kat_test: $(BUILD_DIR)/tree/test/tree_kat_test.o \
                                      $(BUILD_DIR)/tree/tree.o \
                                      $(BUILD_DIR)/record/record.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/tree/test/tree_fuzz: $(BUILD_DIR)/tree/test/tree_fuzz.o \
                                  $(BUILD_DIR)/tree/tree.o \
                                  $(BUILD_DIR)/record/record.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/record/test/journal_test: $(BUILD_DIR)/record/test/journal_test.o \
                                       $(BUILD_DIR)/record/journal.o \
                                       $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The whole library at once. Its own rule rather than a pattern, because it
# links nearly everything and the list is the point: a module absent here is a
# module the integration test cannot exercise.
$(BUILD_DIR)/sim/test/network_test: $(BUILD_DIR)/sim/test/network_test.o \
                                    $(BUILD_DIR)/provision/provision.o \
                                    $(BUILD_DIR)/local/peer.o \
                                    $(BUILD_DIR)/local/vocabulary.o \
                                    $(BUILD_DIR)/record/ledger.o \
                                    $(BUILD_DIR)/chain/chain_store.o \
                                    $(BUILD_DIR)/spool/message.o \
                                    $(BUILD_DIR)/spool/transfer.o \
                                    $(BUILD_DIR)/spool/scrub.o \
                                    $(BUILD_DIR)/spool/spool.o \
                                    $(BUILD_DIR)/spool/plan.o \
                                    $(BUILD_DIR)/blob/blob.o \
                                    $(BUILD_DIR)/trust/trust.o \
                                    $(BUILD_DIR)/state/state.o \
                                    $(BUILD_DIR)/record/record.o \
                                    $(BUILD_DIR)/record/journal.o \
                                    $(BUILD_DIR)/record/sync.o \
                                    $(BUILD_DIR)/tree/tree.o \
                                    $(BUILD_DIR)/chain/chain.o \
                                    $(BUILD_DIR)/chain/revocation.o \
                                    $(BUILD_DIR)/chain/manifest.o \
                                    $(BUILD_DIR)/chain/authz.o \
                                    $(BUILD_DIR)/chunk/reassembly.o \
                                    $(BUILD_DIR)/chunk/split.o \
                                    $(BUILD_DIR)/frame/freshness.o \
                                    $(BUILD_DIR)/session/commitment.o \
                                    $(BUILD_DIR)/session/random.o \
                                    $(BUILD_DIR)/session/agree.o \
                                    $(BUILD_DIR)/session/session.o \
                                    $(BUILD_DIR)/prekey/prekey.o \
                                    $(BUILD_DIR)/ratchet/ratchet.o \
                                    $(BUILD_DIR)/persist/persist.o \
                                    $(BUILD_DIR)/version/version.o \
                                    $(BUILD_DIR)/wire/seal.o \
                                    $(BUILD_DIR)/constant_time/constant_time.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/frame/test/freshness_guided: \
                     $(BUILD_DIR)/frame/test/freshness_guided.o \
                     $(BUILD_DIR)/frame/freshness.o \
                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chain/test/chain_guided: $(BUILD_DIR)/chain/test/chain_guided.o \
                                      $(BUILD_DIR)/chain/chain.o \
                                      $(BUILD_DIR)/chain/revocation.o \
                                      $(BUILD_DIR)/chain/manifest.o \
                                      $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chunk/test/reassembly_guided: \
                     $(BUILD_DIR)/chunk/test/reassembly_guided.o \
                     $(BUILD_DIR)/chunk/reassembly.o \
                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/version/test/version_test: $(BUILD_DIR)/version/test/version_test.o \
                                        $(BUILD_DIR)/version/version.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/constant_time/test/secret_flow_test: \
                     $(BUILD_DIR)/constant_time/test/secret_flow_test.o \
                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/frame/test/freshness_test: $(BUILD_DIR)/frame/test/freshness_test.o \
                                         $(BUILD_DIR)/frame/freshness.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chunk/test/reassembly_test: $(BUILD_DIR)/chunk/test/reassembly_test.o \
                                          $(BUILD_DIR)/chunk/reassembly.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Links BOTH halves on purpose: this binary is what holds the splitter and
# the reassembler to the same contract.
$(BUILD_DIR)/chunk/test/split_test: $(BUILD_DIR)/chunk/test/split_test.o \
                                     $(BUILD_DIR)/chunk/split.o \
                                     $(BUILD_DIR)/chunk/reassembly.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chain/test/revocation_test: $(BUILD_DIR)/chain/test/revocation_test.o \
                                          $(BUILD_DIR)/chain/revocation.o \
                                          $(BUILD_DIR)/chain/manifest.o \
                                          $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# revocation.o is here for the same reason chain.o is in revocation_test's
# rule: the suite drives the manifest through the calls a consumer makes, and
# one of them is `fzn_revocation_admit` settling a deficit. chain.o comes with
# it because `fzn_revocation_covers` is what the completeness test asks, and
# that is the whole of sec 13d's reason for naming the pair.
$(BUILD_DIR)/chain/test/manifest_test: $(BUILD_DIR)/chain/test/manifest_test.o \
                                        $(BUILD_DIR)/chain/manifest.o \
                                        $(BUILD_DIR)/chain/revocation.o \
                                        $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# session/session.c is the transcript layout and the establish path, so it
# links agree.o for the secret's discipline and commitment.o for the KDF it
# hands the transcript to. It reaches chain/ only in the test, for the tether
# that checks the two agree about an identity's length.
$(BUILD_DIR)/session/test/session_test: $(BUILD_DIR)/session/test/session_test.o \
                                         $(BUILD_DIR)/session/session.o \
                                         $(BUILD_DIR)/session/agree.o \
                                         $(BUILD_DIR)/session/commitment.o \
                                         $(BUILD_DIR)/ratchet/ratchet.o \
                                         $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# session/agree.c links only constant_time: the rotation discipline is
# bookkeeping over a wiped buffer, and the arithmetic arrives through a vtable.
$(BUILD_DIR)/session/test/agree_test: $(BUILD_DIR)/session/test/agree_test.o \
                                       $(BUILD_DIR)/session/agree.o \
                                       $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# sync_fuzz links journal.o because the harness builds its journal through
# fzn_journal_anchor and fzn_journal_admit rather than poking entries: a
# fixture assembled by hand can hold a state the module would never produce,
# and then the planner is being asked about a world that cannot happen.
$(BUILD_DIR)/record/test/sync_fuzz: $(BUILD_DIR)/record/test/sync_fuzz.o \
                                     $(BUILD_DIR)/record/sync.o \
                                     $(BUILD_DIR)/record/journal.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/disclose/test/disclose_fuzz: $(BUILD_DIR)/disclose/test/disclose_fuzz.o \
                                           $(BUILD_DIR)/disclose/disclose.o \
                                           $(BUILD_DIR)/blob/blob.o \
                                           $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# disclose/ links blob because the convention is a leaf preimage and the tree
# over those leaves is blob's -- sec 72 measured that the tree and the proofs
# carry over to small fields and that blob's SEALING does not, which is why
# this module exists at all rather than being a note in blob.h.
$(BUILD_DIR)/disclose/test/disclose_test: $(BUILD_DIR)/disclose/test/disclose_test.o \
                                           $(BUILD_DIR)/disclose/disclose.o \
                                           $(BUILD_DIR)/blob/blob.o \
                                           $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# provision/ links chain and prekey because the harness MINTS its fixtures
# rather than carrying literals -- revocation_fuzz was once found with every
# record pointing at one shared literal, so the field a case set had nothing
# to do with the bytes the module read.
$(BUILD_DIR)/provision/test/provision_fuzz: \
                                       $(BUILD_DIR)/provision/test/provision_fuzz.o \
                                       $(BUILD_DIR)/provision/provision.o \
                                       $(BUILD_DIR)/chain/chain.o \
                                       $(BUILD_DIR)/chain/revocation.o \
                                       $(BUILD_DIR)/chain/manifest.o \
                                       $(BUILD_DIR)/prekey/prekey.o \
                                       $(BUILD_DIR)/trust/trust.o \
                                       $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/prekey/test/prekey_fuzz: $(BUILD_DIR)/prekey/test/prekey_fuzz.o \
                                       $(BUILD_DIR)/prekey/prekey.o \
                                       $(BUILD_DIR)/trust/trust.o \
                                       $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# spool/ is CORE despite being about storage: the bitmap is the caller's and
# the backend is a vtable, so it allocates nothing and writes nothing itself.
# Only a backend needs a subsystem, which is the same split persist/ has.
$(BUILD_DIR)/spool/test/spool_test: $(BUILD_DIR)/spool/test/spool_test.o \
                                     $(BUILD_DIR)/spool/spool.o \
                                     $(BUILD_DIR)/blob/blob.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The backend's own test, built only when the backend is. It drives a REAL
# blob through a real file rather than testing the three ops in isolation,
# because the property it exists for -- a reopened file still holding what it
# held -- is only expressible with a store on top asking for leaves back.
$(BUILD_DIR)/spool/test/plan_test: $(BUILD_DIR)/spool/test/plan_test.o \
                                   $(BUILD_DIR)/spool/plan.o \
                                   $(BUILD_DIR)/spool/spool.o \
                                   $(BUILD_DIR)/blob/blob.o \
                                   $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/spool/test/message_test: $(BUILD_DIR)/spool/test/message_test.o \
                                      $(BUILD_DIR)/spool/message.o \
                                      $(BUILD_DIR)/spool/plan.o \
                                      $(BUILD_DIR)/spool/spool.o \
                                      $(BUILD_DIR)/blob/blob.o \
                                      $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/spool/test/transfer_test: $(BUILD_DIR)/spool/test/transfer_test.o \
                                       $(BUILD_DIR)/spool/transfer.o \
                                       $(BUILD_DIR)/spool/plan.o \
                                       $(BUILD_DIR)/spool/spool.o \
                                       $(BUILD_DIR)/blob/blob.o \
                                       $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/spool/test/scrub_test: $(BUILD_DIR)/spool/test/scrub_test.o \
                                    $(BUILD_DIR)/spool/scrub.o \
                                    $(BUILD_DIR)/spool/plan.o \
                                    $(BUILD_DIR)/spool/spool.o \
                                    $(BUILD_DIR)/blob/blob.o \
                                    $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/spool/test/scrub_fuzz: $(BUILD_DIR)/spool/test/scrub_fuzz.o \
                                    $(BUILD_DIR)/spool/scrub.o \
                                    $(BUILD_DIR)/spool/plan.o \
                                    $(BUILD_DIR)/spool/spool.o \
                                    $(BUILD_DIR)/blob/blob.o \
                                    $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/spool/test/spool_file_test: $(BUILD_DIR)/spool/test/spool_file_test.o \
                                          $(BUILD_DIR)/spool/spool_file.o \
                                          $(BUILD_DIR)/spool/spool.o \
                                          $(BUILD_DIR)/blob/blob.o \
                                          $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# persist/ links the four types whose loss a restart must not cause, which is
# what its contract is about. No I/O here -- persist.c is the format.
PERSIST_OBJS := $(BUILD_DIR)/persist/persist.o $(BUILD_DIR)/trust/trust.o \
                $(BUILD_DIR)/session/agree.o $(BUILD_DIR)/prekey/prekey.o \
                $(BUILD_DIR)/ratchet/ratchet.o \
                $(BUILD_DIR)/constant_time/constant_time.o

$(BUILD_DIR)/persist/test/persist_test: $(BUILD_DIR)/persist/test/persist_test.o \
                                         $(PERSIST_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The on-disk vector. Same objects as persist_test: the blobs are byte
# assembly with no primitive in them, so this needs no binding and runs in
# every build rather than only where Monocypher is.
$(BUILD_DIR)/persist/test/persist_kat_test: \
                $(BUILD_DIR)/persist/test/persist_kat_test.o $(PERSIST_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The backend's own test, built only when the backend is. It runs in a
# directory it makes and removes, and asserts it left nothing -- a cleanup
# nobody counts is one that silently stops working.
$(BUILD_DIR)/persist/test/persist_file_test: \
        $(BUILD_DIR)/persist/test/persist_file_test.o \
        $(BUILD_DIR)/persist/persist_file.o $(PERSIST_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# prekey/ reaches trust/, which is the point rather than an accident: the
# record and the act of pinning it are one feature, and a record with no
# pinning act is a blob nobody adopts.
$(BUILD_DIR)/prekey/test/prekey_test: $(BUILD_DIR)/prekey/test/prekey_test.o \
                                       $(BUILD_DIR)/prekey/prekey.o \
                                       $(BUILD_DIR)/trust/trust.o \
                                       $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# provision/ links chain/ and prekey/ rather than stubbing them, because the
# card's offsets are worth checking against parsers that refuse a wrong length
# rather than against the header's own arithmetic. chain.c drags revocation and
# manifest in with it -- fzn_chain_verify calls both -- which is the tree's
# shape rather than this suite's need.
$(BUILD_DIR)/provision/test/provision_test: \
                                       $(BUILD_DIR)/provision/test/provision_test.o \
                                       $(BUILD_DIR)/provision/provision.o \
                                       $(BUILD_DIR)/chain/chain.o \
                                       $(BUILD_DIR)/chain/revocation.o \
                                       $(BUILD_DIR)/chain/manifest.o \
                                       $(BUILD_DIR)/prekey/prekey.o \
                                       $(BUILD_DIR)/trust/trust.o \
                                       $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# ratchet/ links only constant_time as well, for the same reason: it is a KDF
# step and a bounded loop over it, with the hash arriving through a vtable.
$(BUILD_DIR)/ratchet/test/ratchet_test: $(BUILD_DIR)/ratchet/test/ratchet_test.o \
                                         $(BUILD_DIR)/ratchet/ratchet.o \
                                         $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/ratchet/test/ratchet_fuzz: $(BUILD_DIR)/ratchet/test/ratchet_fuzz.o \
                                         $(BUILD_DIR)/ratchet/ratchet.o \
                                         $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# authz links the chain layer it collapses to a verdict, and manifest because
# revocation.o reaches it.
$(BUILD_DIR)/chain/test/authz_test: $(BUILD_DIR)/chain/test/authz_test.o \
                                     $(BUILD_DIR)/chain/authz.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Links record/journal.o, which no other chain test does. The test asserts
# that admitting a chain does NOT make the journal follow anybody, and there
# is no follow predicate to read -- so it reads the door instead, and the
# door is in record/. An inter-module claim links both modules.
$(BUILD_DIR)/chain/test/chain_store_test: $(BUILD_DIR)/chain/test/chain_store_test.o \
                                     $(BUILD_DIR)/chain/chain_store.o \
                                     $(BUILD_DIR)/record/journal.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# service/ derives a capability id and calls nothing but the hash seam the
# caller hands it, so this links one object. sec 129.
$(BUILD_DIR)/chain/test/service_test: $(BUILD_DIR)/chain/test/service_test.o \
                                     $(BUILD_DIR)/chain/service.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# claim/ arbitrates ownership and calls nothing else. sec 132.
$(BUILD_DIR)/claim/test/claim_test: $(BUILD_DIR)/claim/test/claim_test.o \
                                     $(BUILD_DIR)/claim/claim.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# record/store.o LINKS THE JOURNAL, which it does not call: the suite's last
# case replays an owner's records through a reader's journal, and without
# that the seam would be a correct function nothing uses. sec 134.
$(BUILD_DIR)/record/test/store_test: $(BUILD_DIR)/record/test/store_test.o \
                                     $(BUILD_DIR)/record/store.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/record/journal.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/record/test/store_file_test: $(BUILD_DIR)/record/test/store_file_test.o \
                                     $(BUILD_DIR)/record/store_file.o \
                                     $(BUILD_DIR)/record/store.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# cli/ reads argument strings and calls nothing. sec 137.
$(BUILD_DIR)/cli/test/cli_test: $(BUILD_DIR)/cli/test/cli_test.o \
                                     $(BUILD_DIR)/cli/cli.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The printer turns qr/'s modules into terminal characters and calls nothing
# else. sec 163.
$(BUILD_DIR)/cli/test/qr_print_test: $(BUILD_DIR)/cli/test/qr_print_test.o \
                                     $(BUILD_DIR)/cli/qr_print.o \
                                     $(BUILD_DIR)/qr/qr.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Who is asking over a local socket, and which kind of no this is. sec 204.
$(BUILD_DIR)/cli/test/peer_print_test: $(BUILD_DIR)/cli/test/peer_print_test.o \
                                     $(BUILD_DIR)/cli/peer_print.o \
                                     $(BUILD_DIR)/local/peer.o \
                                     $(BUILD_DIR)/local/vocabulary.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/cli/test/manifest_print_test: \
	$(BUILD_DIR)/cli/test/manifest_print_test.o \
	$(BUILD_DIR)/cli/manifest_print.o \
	$(BUILD_DIR)/chain/manifest.o \
	$(BUILD_DIR)/chain/revocation.o \
	$(BUILD_DIR)/chain/chain.o \
	$(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/cli/test/ledger_print_test: \
	$(BUILD_DIR)/cli/test/ledger_print_test.o \
	$(BUILD_DIR)/cli/ledger_print.o \
	$(BUILD_DIR)/record/ledger.o \
	$(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/cli/test/replay_print_test: \
	$(BUILD_DIR)/cli/test/replay_print_test.o \
	$(BUILD_DIR)/cli/replay_print.o \
	$(BUILD_DIR)/frame/freshness.o \
	$(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/cli/test/reasm_print_test: \
	$(BUILD_DIR)/cli/test/reasm_print_test.o \
	$(BUILD_DIR)/cli/reasm_print.o \
	$(BUILD_DIR)/chunk/reassembly.o \
	$(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/cli/test/sched_print_test: \
	$(BUILD_DIR)/cli/test/sched_print_test.o \
	$(BUILD_DIR)/cli/sched_print.o \
	$(BUILD_DIR)/sched/sched.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# What paths this host has, and which numbers are measurements. sec 202.
$(BUILD_DIR)/cli/test/link_print_test: $(BUILD_DIR)/cli/test/link_print_test.o \
                                     $(BUILD_DIR)/cli/link_print.o \
                                     $(LINK_OBJ) \
                                     $(BUILD_DIR)/sched/sched.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# This host's anchor, and how it came to be trusted. sec 201.
$(BUILD_DIR)/cli/test/trust_print_test: $(BUILD_DIR)/cli/test/trust_print_test.o \
                                     $(BUILD_DIR)/cli/trust_print.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# One provisioning card, and the root it may not name. sec 200.
$(BUILD_DIR)/cli/test/provision_print_test: \
                                     $(BUILD_DIR)/cli/test/provision_print_test.o \
                                     $(BUILD_DIR)/cli/provision_print.o \
                                     $(BUILD_DIR)/provision/provision.o \
                                     $(BUILD_DIR)/prekey/prekey.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# What a kind requires and which origins reach it. sec 199.
$(BUILD_DIR)/cli/test/authz_print_test: $(BUILD_DIR)/cli/test/authz_print_test.o \
                                     $(BUILD_DIR)/cli/authz_print.o \
                                     $(BUILD_DIR)/chain/authz.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# What a revocation store holds, in force and withdrawn apart. sec 198.
$(BUILD_DIR)/cli/test/revocation_print_test: \
                                     $(BUILD_DIR)/cli/test/revocation_print_test.o \
                                     $(BUILD_DIR)/cli/revocation_print.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# One state cell, including what fzn_state_get deliberately hides. sec 197.
$(BUILD_DIR)/cli/test/state_print_test: $(BUILD_DIR)/cli/test/state_print_test.o \
                                     $(BUILD_DIR)/cli/state_print.o \
                                     $(BUILD_DIR)/state/state.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# One capability's usability, and which of two reasons it is not. sec 196.
$(BUILD_DIR)/cli/test/capability_print_test: \
                                     $(BUILD_DIR)/cli/test/capability_print_test.o \
                                     $(BUILD_DIR)/cli/capability_print.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# One blob's assembly, and which of three stopped states it is in. sec 195.
$(BUILD_DIR)/cli/test/transfer_print_test: \
                                     $(BUILD_DIR)/cli/test/transfer_print_test.o \
                                     $(BUILD_DIR)/cli/transfer_print.o \
                                     $(BUILD_DIR)/spool/spool.o \
                                     $(BUILD_DIR)/spool/plan.o \
                                     $(BUILD_DIR)/spool/transfer.o \
                                     $(BUILD_DIR)/blob/blob.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# A planned deletion, and why one is not happening. sec 194.
$(BUILD_DIR)/cli/test/sweep_print_test: $(BUILD_DIR)/cli/test/sweep_print_test.o \
                                     $(BUILD_DIR)/cli/sweep_print.o \
                                     $(BUILD_DIR)/catalog/sweep.o \
                                     $(BUILD_DIR)/catalog/catalog.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# One stream's position and the table's own condition. sec 192.
$(BUILD_DIR)/cli/test/journal_print_test: \
                                     $(BUILD_DIR)/cli/test/journal_print_test.o \
                                     $(BUILD_DIR)/cli/journal_print.o \
                                     $(BUILD_DIR)/record/journal.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# One peer's sync position, on two channels. sec 191.
$(BUILD_DIR)/cli/test/sync_print_test: $(BUILD_DIR)/cli/test/sync_print_test.o \
                                     $(BUILD_DIR)/cli/sync_print.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# It renders a log against a journal, and signs its own fixtures. sec 167.
$(BUILD_DIR)/cli/test/log_print_test: $(BUILD_DIR)/cli/test/log_print_test.o \
                                     $(BUILD_DIR)/cli/log_print.o \
                                     $(BUILD_DIR)/log/log.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/record/journal.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# catalog/ is a membership relation over ids and calls nothing. sec 144.
$(BUILD_DIR)/catalog/test/catalog_test: $(BUILD_DIR)/catalog/test/catalog_test.o \
                                     $(BUILD_DIR)/catalog/catalog.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The copy layer decides what to fetch and calls nothing either -- it holds a
# seam for "do you have these bytes" rather than a blob store. sec 154. It
# links catalog.o because the retention table it consults lives there.
$(BUILD_DIR)/catalog/test/copy_test: $(BUILD_DIR)/catalog/test/copy_test.o \
                                     $(BUILD_DIR)/catalog/copy.o \
                                     $(BUILD_DIR)/catalog/catalog.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Planned deletion. sec 155. Links copy.o for the holdings seam it shares --
# the deletion side of the same question about which host has which bytes.
$(BUILD_DIR)/catalog/test/sweep_test: $(BUILD_DIR)/catalog/test/sweep_test.o \
                                     $(BUILD_DIR)/catalog/sweep.o \
                                     $(BUILD_DIR)/catalog/copy.o \
                                     $(BUILD_DIR)/catalog/catalog.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Reachability. sec 156. Proposes what nothing links; it deletes nothing, so
# it links neither sweep.o nor copy.o -- the composition is the consumer's.
$(BUILD_DIR)/catalog/test/reach_test: $(BUILD_DIR)/catalog/test/reach_test.o \
                                     $(BUILD_DIR)/catalog/reach.o \
                                     $(BUILD_DIR)/catalog/catalog.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The QR encoder calls nothing and is called by the widget and the CLI. sec 160.
$(BUILD_DIR)/qr/test/qr_test: $(BUILD_DIR)/qr/test/qr_test.o $(BUILD_DIR)/qr/qr.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# THE C++ RULE, AND IT IS SEPARATE FROM THE C ONE ON PURPOSE. Qt's flags reach
# only the widgets: a C source that picked them up would gain include paths it
# has no use for, and the library's own build would start depending on
# pkg-config having run. sec 140.
ifdef GUI_ON
$(BUILD_DIR)/gui/%.o: gui/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/gui/test/%.o: gui/test/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) -MMD -MP -c $< -o $@

# The anchor view classifies through cli/trust_print and words itself. sec 201.
$(BUILD_DIR)/gui/test/trust_view_test: $(BUILD_DIR)/gui/test/trust_view_test.o \
                                     $(BUILD_DIR)/gui/trust_view.o \
                                     $(BUILD_DIR)/cli/trust_print.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# The view renders through cli/log_print now, so it links it. sec 168.
$(BUILD_DIR)/gui/test/log_view_test: $(BUILD_DIR)/gui/test/log_view_test.o \
                                     $(BUILD_DIR)/gui/log_view.o \
                                     $(BUILD_DIR)/cli/log_print.o \
                                     $(BUILD_DIR)/log/log.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/record/journal.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# The QR widget draws what qr/ encodes and calls nothing else. sec 161.
$(BUILD_DIR)/gui/test/qr_view_test: $(BUILD_DIR)/gui/test/qr_view_test.o \
                                     $(BUILD_DIR)/gui/qr_view.o \
                                     $(BUILD_DIR)/qr/qr.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# The permissions view asks chain/authz.h its questions rather than answering
# them, so it links what answers. sec 165.
$(BUILD_DIR)/gui/test/authz_view_test: $(BUILD_DIR)/gui/test/authz_view_test.o \
                                     $(BUILD_DIR)/gui/authz_view.o \
                                     $(BUILD_DIR)/cli/authz_print.o \
                                     $(BUILD_DIR)/chain/authz.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# The admission screen shows cli/peer_print's line and adds the group list,
# which the line can only count. sec 204.
$(BUILD_DIR)/gui/test/peer_view_test: $(BUILD_DIR)/gui/test/peer_view_test.o \
                                     $(BUILD_DIR)/gui/peer_view.o \
                                     $(BUILD_DIR)/cli/peer_print.o \
                                     $(BUILD_DIR)/local/peer.o \
                                     $(BUILD_DIR)/local/vocabulary.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# The issuer list shows cli/manifest_print's line per issuer and adds the
# aggregate no single call to the printer can make. sec 226.
$(BUILD_DIR)/gui/test/manifest_view_test: \
	$(BUILD_DIR)/gui/test/manifest_view_test.o \
	$(BUILD_DIR)/gui/manifest_view.o \
	$(BUILD_DIR)/cli/manifest_print.o \
	$(BUILD_DIR)/chain/manifest.o \
	$(BUILD_DIR)/chain/revocation.o \
	$(BUILD_DIR)/chain/chain.o \
	$(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# Who has acknowledged this subject. sec 228.
$(BUILD_DIR)/gui/test/ledger_view_test: \
	$(BUILD_DIR)/gui/test/ledger_view_test.o \
	$(BUILD_DIR)/gui/ledger_view.o \
	$(BUILD_DIR)/cli/ledger_print.o \
	$(BUILD_DIR)/record/ledger.o \
	$(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# One class against the link table, with a row per link. sec 248.
$(BUILD_DIR)/gui/test/sched_view_test: \
	$(BUILD_DIR)/gui/test/sched_view_test.o \
	$(BUILD_DIR)/gui/sched_view.o \
	$(BUILD_DIR)/cli/sched_print.o \
	$(BUILD_DIR)/sched/sched.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# The paths table shows cli/link_print's line and adds a row per link. sec 202.
$(BUILD_DIR)/gui/test/link_view_test: $(BUILD_DIR)/gui/test/link_view_test.o \
                                     $(BUILD_DIR)/gui/link_view.o \
                                     $(BUILD_DIR)/cli/link_print.o \
                                     $(LINK_OBJ) \
                                     $(BUILD_DIR)/sched/sched.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# The pairing screen is a code plus a fingerprint, so it links the encoder,
# the QR widget and the provisioning card's parsers. sec 171.
$(BUILD_DIR)/gui/test/provision_view_test: \
                                     $(BUILD_DIR)/gui/test/provision_view_test.o \
                                     $(BUILD_DIR)/gui/provision_view.o \
                                     $(BUILD_DIR)/cli/provision_print.o \
                                     $(BUILD_DIR)/gui/qr_view.o \
                                     $(BUILD_DIR)/provision/provision.o \
                                     $(BUILD_DIR)/prekey/prekey.o \
                                     $(BUILD_DIR)/qr/qr.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# It walks a journal for the row and shows the table's own state. sec 186.
$(BUILD_DIR)/gui/test/journal_view_test: \
                                     $(BUILD_DIR)/gui/test/journal_view_test.o \
                                     $(BUILD_DIR)/gui/journal_view.o \
                                     $(BUILD_DIR)/cli/journal_print.o \
                                     $(BUILD_DIR)/record/journal.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# It asks a manifest state what it can and cannot say. sec 185.
$(BUILD_DIR)/gui/test/sync_view_test: \
                                     $(BUILD_DIR)/gui/test/sync_view_test.o \
                                     $(BUILD_DIR)/gui/sync_view.o \
                                     $(BUILD_DIR)/cli/sync_print.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# It reads a state cell and walks for the tombstone. sec 184.
$(BUILD_DIR)/gui/test/state_view_test: \
                                     $(BUILD_DIR)/gui/test/state_view_test.o \
                                     $(BUILD_DIR)/gui/state_view.o \
                                     $(BUILD_DIR)/cli/state_print.o \
                                     $(BUILD_DIR)/state/state.o \
                                     $(BUILD_DIR)/record/record.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# It walks a revocation store and mutates nothing. sec 182.
$(BUILD_DIR)/gui/test/revocation_view_test: \
                                     $(BUILD_DIR)/gui/test/revocation_view_test.o \
                                     $(BUILD_DIR)/gui/revocation_view.o \
                                     $(BUILD_DIR)/cli/revocation_print.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# It reads a plan and a sweep job and mutates neither. sec 181.
$(BUILD_DIR)/gui/test/sweep_view_test: \
                                     $(BUILD_DIR)/gui/test/sweep_view_test.o \
                                     $(BUILD_DIR)/gui/sweep_view.o \
                                     $(BUILD_DIR)/cli/sweep_print.o \
                                     $(BUILD_DIR)/catalog/sweep.o \
                                     $(BUILD_DIR)/catalog/catalog.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# It reads a spool and a scheduler and mutates neither. sec 179.
$(BUILD_DIR)/gui/test/transfer_view_test: \
                                     $(BUILD_DIR)/gui/test/transfer_view_test.o \
                                     $(BUILD_DIR)/gui/transfer_view.o \
                                     $(BUILD_DIR)/cli/transfer_print.o \
                                     $(BUILD_DIR)/spool/spool.o \
                                     $(BUILD_DIR)/spool/plan.o \
                                     $(BUILD_DIR)/spool/transfer.o \
                                     $(BUILD_DIR)/blob/blob.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

# It asks the chain and the revocation store their own questions, so it links
# both. sec 166.
$(BUILD_DIR)/gui/test/capability_view_test: \
                                     $(BUILD_DIR)/gui/test/capability_view_test.o \
                                     $(BUILD_DIR)/gui/capability_view.o \
                                     $(BUILD_DIR)/cli/capability_print.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/trust/trust.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@

ifdef CLI_ON
# The form is a front door to the CLI parser, so it links it. sec 164.
$(BUILD_DIR)/gui/test/config_view_test: $(BUILD_DIR)/gui/test/config_view_test.o \
                                     $(BUILD_DIR)/gui/config_view.o \
                                     $(BUILD_DIR)/cli/cli.o
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ $(QT_LIBS) -o $@
endif
endif

$(BUILD_DIR)/claim/test/claim_file_test: $(BUILD_DIR)/claim/test/claim_file_test.o \
                                     $(BUILD_DIR)/claim/claim_file.o \
                                     $(BUILD_DIR)/claim/claim.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# blob/ links only constant_time -- it calls no other module, which is the
# shape sec 16 wanted: the tree and the sealing are arithmetic over bytes the
# caller supplies, and the crypto arrives through the two vtables.
$(BUILD_DIR)/blob/test/blob_test: $(BUILD_DIR)/blob/test/blob_test.o \
                                   $(BUILD_DIR)/blob/blob.o \
                                   $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/blob/test/blob_fuzz: $(BUILD_DIR)/blob/test/blob_fuzz.o \
                                   $(BUILD_DIR)/blob/blob.o \
                                   $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The fuzz harness. It runs a FIXED number of cases from a seeded generator
# -- argv[1] or its own default -- so `make test` terminates and a failing
# case is reproducible from the source alone. `make fuzz CASES=n` runs a
# longer campaign without editing anything.
$(BUILD_DIR)/chunk/test/reassembly_fuzz: $(BUILD_DIR)/chunk/test/reassembly_fuzz.o \
                                          $(BUILD_DIR)/chunk/reassembly.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/spool/test/message_fuzz: $(BUILD_DIR)/spool/test/message_fuzz.o \
                                      $(BUILD_DIR)/spool/message.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chain/test/chain_fuzz: $(BUILD_DIR)/chain/test/chain_fuzz.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/chain/revocation.o \
                                     $(BUILD_DIR)/chain/manifest.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The only binary that links four modules, because it is the only one testing
# something none of them owns: the ORDER sec 4.7 puts them in.
$(BUILD_DIR)/frame/test/receive_fuzz: $(BUILD_DIR)/frame/test/receive_fuzz.o \
                                       $(BUILD_DIR)/frame/freshness.o \
                                       $(BUILD_DIR)/chain/chain.o \
                                       $(BUILD_DIR)/chain/revocation.o \
                                       $(BUILD_DIR)/chain/manifest.o \
                                       $(BUILD_DIR)/chunk/reassembly.o \
                                       $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/frame/test/freshness_fuzz: $(BUILD_DIR)/frame/test/freshness_fuzz.o \
                                         $(BUILD_DIR)/frame/freshness.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The same objects as manifest_test, because this harness admits real signed
# manifests against a real revocation store rather than filling structs.
$(BUILD_DIR)/chain/test/manifest_fuzz: $(BUILD_DIR)/chain/test/manifest_fuzz.o \
                                        $(BUILD_DIR)/chain/manifest.o \
                                        $(BUILD_DIR)/chain/revocation.o \
                                        $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The persisted formats. sec 232: one encoding per blob, and every short
# prefix refused.
# Rendering a body: it stands between an issuer's bytes and a terminal, and
# escaping is what stops one entry forging a neighbour. sec 233.
$(BUILD_DIR)/log/test/log_fuzz: $(BUILD_DIR)/log/test/log_fuzz.o \
                                          $(BUILD_DIR)/log/log.o \
                                          $(BUILD_DIR)/record/record.o \
                                          $(BUILD_DIR)/record/journal.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The hop budget: the one field outside the authenticated region, so every
# byte it reads is one anybody on the path may choose. sec 233.
$(BUILD_DIR)/wire/test/relay_fuzz: $(BUILD_DIR)/wire/test/relay_fuzz.o \
                                          $(BUILD_DIR)/wire/relay.o \
                                          $(BUILD_DIR)/wire/generated/frame.o \
                                          $(BUILD_DIR)/wire/generated/situ.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/persist/test/persist_fuzz: $(BUILD_DIR)/persist/test/persist_fuzz.o \
                                          $(BUILD_DIR)/persist/persist.o \
                                          $(BUILD_DIR)/trust/trust.o \
                                          $(BUILD_DIR)/prekey/prekey.o \
                                          $(BUILD_DIR)/ratchet/ratchet.o \
                                          $(BUILD_DIR)/chain/chain.o \
                                          $(BUILD_DIR)/chain/revocation.o \
                                          $(BUILD_DIR)/chain/manifest.o \
                                          $(BUILD_DIR)/session/agree.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chain/test/revocation_fuzz: $(BUILD_DIR)/chain/test/revocation_fuzz.o \
                                          $(BUILD_DIR)/chain/revocation.o \
                                          $(BUILD_DIR)/chain/manifest.o \
                                          $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Links both halves, like split_test: this binary is what holds the
# splitter and the reassembler to the same contract over permutations.
$(BUILD_DIR)/chunk/test/roundtrip_fuzz: $(BUILD_DIR)/chunk/test/roundtrip_fuzz.o \
                                         $(BUILD_DIR)/chunk/split.o \
                                         $(BUILD_DIR)/chunk/reassembly.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/session/test/commitment_test: \
		$(BUILD_DIR)/session/test/commitment_test.o \
		$(BUILD_DIR)/session/commitment.o \
		$(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Links peer.c only. peer_linux.c is the system half and holds no
# decisions, so the suite drives every one of them without a socket.
$(BUILD_DIR)/local/test/peer_test: $(BUILD_DIR)/local/test/peer_test.o \
                                    $(BUILD_DIR)/local/peer.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/local/test/peer_fuzz: $(BUILD_DIR)/local/test/peer_fuzz.o \
                                    $(BUILD_DIR)/local/peer.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The one test that links the system half. It needs no cooperating
# process: a socketpair has both ends here, so SO_PEERCRED reports us.
$(BUILD_DIR)/local/test/peer_linux_test: $(BUILD_DIR)/local/test/peer_linux_test.o \
                                          $(BUILD_DIR)/local/peer.o \
                                          $(BUILD_DIR)/local/peer_linux.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Four tests read situ's output and need the generated include path, so each
# has its own compile rule rather than the pattern's. This comment said "the
# only test" until there were three of them, and three until tamper_test
# arrived -- which is the one that reads a generated header nothing else
# includes, `wire/generated/frame_tamper.h`.
$(BUILD_DIR)/wire/test/generated_test.o: wire/test/generated_test.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -c $< -o $@

$(BUILD_DIR)/wire/test/constants_test.o: wire/test/constants_test.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -c $< -o $@

# Links peer and vocabulary, which is the seam it tests. It linked four
# modules until local/line.c and local/socket.c moved to raidcfgd.
$(BUILD_DIR)/local/test/admit_test: $(BUILD_DIR)/local/test/admit_test.o \
                                     $(BUILD_DIR)/local/peer.o \
                                     $(BUILD_DIR)/local/peer_linux.o \
                                     $(BUILD_DIR)/local/vocabulary.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/local/test/vocabulary_fuzz: $(BUILD_DIR)/local/test/vocabulary_fuzz.o \
                                          $(BUILD_DIR)/local/vocabulary.o \
                                          $(BUILD_DIR)/local/peer.o \
                                          $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/local/test/vocabulary_test: $(BUILD_DIR)/local/test/vocabulary_test.o \
                                          $(BUILD_DIR)/local/vocabulary.o \
                                          $(BUILD_DIR)/local/peer.o \
                                          $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/session/test/random_test: $(BUILD_DIR)/session/test/random_test.o \
                                        $(BUILD_DIR)/session/random.o \
                                        $(BUILD_DIR)/session/random_linux.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/wire/seal.o: wire/seal.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -c $< -o $@

# Same reason as seal.o: it reads the hop header through the generated
# accessors, so it needs the generated headers on its include path.
$(BUILD_DIR)/wire/relay.o: wire/relay.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -c $< -o $@

$(BUILD_DIR)/wire/test/relay_test.o: wire/test/relay_test.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -MMD -MP -c $< -o $@

$(BUILD_DIR)/wire/test/seal_test.o: wire/test/seal_test.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -c $< -o $@

# The generated tamper harness is a header of static inline functions, so it
# reaches the compiler through this test and nowhere else -- there is no
# object of its own to build and none to install. `make schema` is what keeps
# it honest against the schema; this rule only has to put
# wire/generated on the include path so `#include "frame_tamper.h"` resolves,
# exactly as the three rules above do for `frame.h`.
$(BUILD_DIR)/wire/test/tamper_test.o: wire/test/tamper_test.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -c $< -o $@

$(BUILD_DIR)/wire/test/err_str_test: $(BUILD_DIR)/wire/test/err_str_test.o \
                                      $(BUILD_DIR)/qr/qr.o \
                                      $(BUILD_DIR)/provision/provision.o \
                                      $(BUILD_DIR)/disclose/disclose.o \
                                      $(BUILD_DIR)/blob/blob.o \
                                      $(BUILD_DIR)/spool/message.o \
                                      $(BUILD_DIR)/spool/transfer.o \
                                      $(BUILD_DIR)/spool/scrub.o \
                                      $(BUILD_DIR)/spool/plan.o \
                                      $(BUILD_DIR)/spool/spool.o \
                                      $(BUILD_DIR)/record/record.o \
                                      $(BUILD_DIR)/record/journal.o \
                                      $(BUILD_DIR)/record/ledger.o \
                                      $(BUILD_DIR)/record/sync.o \
                                      $(BUILD_DIR)/state/state.o \
                                      $(BUILD_DIR)/trust/trust.o \
                                      $(BUILD_DIR)/log/log.o \
                                      $(BUILD_DIR)/wire/relay.o \
                                      $(BUILD_DIR)/sched/sched.o \
                                      $(LINK_OBJ) \
                                      $(BUILD_DIR)/chain/chain.o \
                                      $(BUILD_DIR)/chain/revocation.o \
                                      $(BUILD_DIR)/chain/manifest.o \
                                      $(BUILD_DIR)/chunk/reassembly.o \
                                      $(BUILD_DIR)/chunk/split.o \
                                      $(BUILD_DIR)/frame/freshness.o \
                                      $(BUILD_DIR)/local/peer.o \
                                      $(BUILD_DIR)/session/commitment.o \
                                      $(BUILD_DIR)/session/random.o \
                                      $(BUILD_DIR)/wire/seal.o \
                                      $(BUILD_DIR)/blob/blob.o \
                                      $(BUILD_DIR)/chain/authz.o \
                                      $(BUILD_DIR)/prekey/prekey.o \
                                      $(BUILD_DIR)/ratchet/ratchet.o \
                                      $(BUILD_DIR)/session/agree.o \
                                      $(BUILD_DIR)/session/session.o \
                                      $(BUILD_DIR)/spool/spool.o \
                                      $(BUILD_DIR)/persist/persist.o \
                                      $(BUILD_DIR)/claim/claim.o \
                                      $(BUILD_DIR)/record/store.o \
                                      $(BUILD_DIR)/catalog/catalog.o \
                                      $(if $(CLI_ON),$(BUILD_DIR)/cli/cli.o) \
                                      $(BUILD_DIR)/tree/tree.o \
                                      $(BUILD_DIR)/constant_time/constant_time.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# LINKS relay.o, WHICH IT DID NOT UNTIL THE ROUND TRIP EXISTED. Sealing and
# relaying were tested in separate binaries, so nothing anywhere asserted that a
# frame survives being relayed -- the one property `wire/relay.h` is built on.
# seal_test now spends the whole hop budget between build and open, which needs
# both halves in one process.
# AND commitment.o, WHICH IT DID NOT NEED WHILE THE COMMITMENT WAS AN
# ARGUMENT. `fzn_seal_open` and `fzn_seal_build` derive the frame's commitment
# themselves now -- it depends on the nonce, which the build path draws and the
# open path reads out of the frame, so no caller can hand one in -- and that
# makes session/commitment.o a link-time dependency of wire/seal.o rather than
# of its callers.
# THE OUTERMOST DECODER, over bytes that were never a frame. seal_test's
# object list without relay.o: this harness never forwards, it only
# decodes. Stubs stand in for the crypto, so it runs in every
# arrangement rather than only where Monocypher is present.
$(BUILD_DIR)/wire/test/seal_fuzz: $(BUILD_DIR)/wire/test/seal_fuzz.o \
                                   $(BUILD_DIR)/wire/seal.o \
                                   $(BUILD_DIR)/session/commitment.o \
                                   $(BUILD_DIR)/session/random.o \
                                   $(BUILD_DIR)/constant_time/constant_time.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/wire/test/seal_test: $(BUILD_DIR)/wire/test/seal_test.o \
                                   $(BUILD_DIR)/wire/seal.o $(BUILD_DIR)/wire/relay.o \
                                   $(BUILD_DIR)/session/commitment.o \
                                   $(BUILD_DIR)/session/random.o \
                                   $(BUILD_DIR)/constant_time/constant_time.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# seal_test's object list without relay.o: this file never forwards a frame,
# because the hop is the one span the generated harness deliberately does not
# reach and asserting it here would be a second copy of a case seal_test.c and
# golden_frame_test.c already carry. commitment.o and random.o are here for
# the reasons stated above them -- `fzn_seal_open` derives the frame's
# commitment itself, and seal.o references the nonce draw whether or not this
# binary calls the build path.
$(BUILD_DIR)/wire/test/tamper_test: $(BUILD_DIR)/wire/test/tamper_test.o \
                                     $(BUILD_DIR)/wire/seal.o \
                                     $(BUILD_DIR)/session/commitment.o \
                                     $(BUILD_DIR)/session/random.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Links the generated runtime for the frame views its runtime half needs;
# every other check in it is a static assert and needs no object at all.
$(BUILD_DIR)/wire/test/constants_test: $(BUILD_DIR)/wire/test/constants_test.o \
                                        $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/wire/test/generated_test: $(BUILD_DIR)/wire/test/generated_test.o \
                                        $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Links situ's output AND our reassembler, which is the only binary that
# does. It exists to compare the two implementations of one rule.
$(BUILD_DIR)/chunk/test/agreement_test.o: chunk/test/agreement_test.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iwire/generated -c $< -o $@

$(BUILD_DIR)/chunk/test/agreement_test: $(BUILD_DIR)/chunk/test/agreement_test.o \
                                         $(BUILD_DIR)/chunk/reassembly.o $(GEN_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Tests are built by this target and only by it, so a claim that a test
# passes or fails always goes through a rebuild. Re-running a stale binary
# after a plain build appears to pass either way.
# ctcheck runs first because it is about the library rather than the tests, and
# because a failure there is more interesting than any assertion below it.
test: codegencheck runtests

# The suite without the codegen gate, which exists for ONE caller.
#
# `coverage` builds this tree with `--coverage`, and that instrumentation
# adds counters to every basic block -- so `codegen_gate.py`, which reads a
# disassembly and pins the shape of the constant-time primitives and the
# wipe, cannot pass and never could. `make coverage` has therefore been
# failing for as long as the gate has existed, with the tripwire's own
# "read the disassembly and decide" message on the way out. Nobody could
# re-measure a coverage figure, which is why several in `project.md` named
# a total from before the binary grew.
#
# THE GATE IS NOT WEAKENED, and skipping it here is not a relaxation: its
# subject is the code this library SHIPS, and an instrumented build is not
# that code. Making it pass under `--coverage` would mean teaching it to
# accept a shape we never ship, which is the direction `evidence.md` warns
# about -- bending the world around a check rather than asking what the
# check can be right about. `test` still runs it first, which is where it
# belongs.
# THE COMPOSED SUITES RUN LAST, and this append is deliberately the final
# word on TEST_BINS rather than a line in the list above -- the subsystem and
# Monocypher blocks append after that list, so anything placed there would
# still have unit tests behind it.
#
# WHY THE ORDER IS LOAD-BEARING AT ALL. `runtests` stops at the first binary
# that fails, so the order decides which diagnostic a reader gets. sim/ walks
# the whole library through scenarios; a failure there says a session did not
# converge. The per-module suites say which function broke and on what input.
# When one defect fails both, the second is the one worth printing, and until
# now the first was printed instead.
#
# MEASURED, AND IT COST MORE THAN A WORSE MESSAGE. `sim/test/network_test`
# sat mid-list, ahead of record/, state/, trust/, log/, sched/ and link/.
# Sabotaging record/sync.c's plan clearing took it past any bound, so the
# twenty-two binaries behind it never ran -- including record/test/sync_test,
# which catches that same defect by name in under a second and had been
# written for it years' worth of commits earlier. The harness is bounded now
# (see plan_requests there), so that particular defect fails fast either way;
# the ordering is what stops the NEXT one hiding behind it.
#
# $(MONO_REAL) is sim/test/real_crypto_test and $(MONO_PROV) is
# sim/test/provision_test; both join here rather than in the Monocypher block
# above, so that "every per-module suite runs before every composed one" holds
# however this tree is configured. They expand to nothing when the bindings are
# not built.
TEST_BINS += $(BUILD_DIR)/sim/test/network_test $(MONO_REAL) $(MONO_PROV) \
             $(MONO_DISC)

# EVERY TEST BINARY GETS flog, ONCE, AND MAKE KNOWS ABOUT IT. sec 211.
#
# As more of the library logs, more objects reference flog, and naming its
# objects per rule does not scale: two logging modules in one rule would put
# `$(FLOG_OBJS)` on the link line TWICE, which is a multiple-definition error
# rather than a duplicate the linker ignores. That is what a per-module
# variable was heading for.
#
# A prerequisite of every test binary instead. GNU make's `$^` OMITS
# DUPLICATES -- which is the whole reason this works and the reason it is
# `$^` rather than `$+` in all 113 link recipes -- so flog appears exactly
# once on each command line whether or not a rule also named it.
#
# And it is a PREREQUISITE rather than an addition to the recipe, so a moved
# flog pin relinks the tests that use it. Appending to the recipe alone would
# have been the staleness sec 210 is about, introduced by the fix for it.
#
# Expands to nothing when flog is absent, which is the whole of that build.
$(TEST_BINS): $(FLOG_OBJS)

runtests: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "running $$t"; $$t || exit 1; done
	@# SAY WHEN THE MONOCYPHER BINDINGS WERE NOT BUILT, rather than leaving
	@# their absence to look like their success. Skipped, the three bindings
	@# are not compiled at all, and a run that never mentions them reads
	@# exactly like a run in which they passed. Same discipline as `analyze`
	@# and `ctcheck`, which skip loudly for the same reason.
	@#
	@# IT ASKS MONO_SKIP, NOT MONOCYPHER_DIR, and that distinction is what
	@# vendoring cost. The variable now defaults to the submodule, so an
	@# empty-variable test would say "built" for a clone whose monocypher/
	@# is an empty directory -- the notice reporting the bindings ran in the
	@# one case they could not have. MONO_SKIP is set by the same conditional
	@# that decides whether to compile them, so the notice and the build
	@# cannot disagree, and it carries the REASON because "not built" and
	@# "you have not run git submodule update --init" are different problems
	@# with different fixes.
	@#
	@# NO CHECK COUNT HERE, DELIBERATELY, AND IT USED TO SAY 43. The
	@# bindings carried 70 by then and carry more now; nobody noticed
	@# because a number in a comment is maintained by whoever remembers it
	@# exists. It was corrected once and would have drifted again -- the
	@# only figure that cannot is one taken at run time, and this target
	@# cannot take one for binaries it did not build. So the notice states
	@# what it can know: three bindings, not compiled. The count belongs to
	@# the gated run, which prints its own.
	@#
	@# The same trap then caught a REPORT about this comment, one commit
	@# later: a total measured correctly and quoted three commits after it
	@# was true. project.md sec 11 carries that incident, under the rule it
	@# produced -- a number is measured at the moment it is quoted, or it is
	@# not measured.
	@#
	@# Found by mutation: FZN_SECRET_KEY_LEN could be changed in either
	@# direction with the whole suite still green, because the module
	@# declaring it is dark in a default build.
	@if [ -n "$(MONO_SKIP)" ]; then \
		echo "test: the Monocypher bindings were NOT built, so their tests did"; \
		echo "test: not run -- $(MONO_SKIP)"; \
	fi
	@# AND WHICH SUBSYSTEMS ARE OFF, for the same reason: a subsystem that
	@# is absent and one that was never asked for look identical in a green
	@# run. The reason is carried, because "off" and "you have no POSIX" are
	@# different problems with different fixes.
	@if [ -n "$(PERSIST_FILE_SKIP)" ]; then \
		echo "test: the file-backed persist backend was NOT built, so its tests"; \
		echo "test: did not run -- $(PERSIST_FILE_SKIP)"; \
	fi
	@if [ -n "$(SPOOL_FILE_SKIP)" ]; then \
		echo "test: the file-backed spool backend was NOT built, so its tests"; \
		echo "test: did not run -- $(SPOOL_FILE_SKIP)"; \
	fi

CASES ?= 200000

FUZZ_BINS := $(BUILD_DIR)/chunk/test/reassembly_fuzz \
             $(BUILD_DIR)/spool/test/message_fuzz \
             $(BUILD_DIR)/chain/test/chain_fuzz \
             $(BUILD_DIR)/frame/test/freshness_fuzz \
             $(BUILD_DIR)/frame/test/receive_fuzz \
             $(BUILD_DIR)/chain/test/revocation_fuzz \
             $(BUILD_DIR)/chain/test/manifest_fuzz \
             $(BUILD_DIR)/chunk/test/roundtrip_fuzz \
             $(BUILD_DIR)/local/test/peer_fuzz \
             $(BUILD_DIR)/local/test/vocabulary_fuzz \
             $(BUILD_DIR)/record/test/record_fuzz \
             $(BUILD_DIR)/tree/test/tree_fuzz \
             $(BUILD_DIR)/wire/test/seal_fuzz \
             $(BUILD_DIR)/blob/test/blob_fuzz \
             $(BUILD_DIR)/prekey/test/prekey_fuzz \
             $(BUILD_DIR)/provision/test/provision_fuzz \
             $(BUILD_DIR)/record/test/sync_fuzz \
             $(BUILD_DIR)/disclose/test/disclose_fuzz \
             $(BUILD_DIR)/persist/test/persist_fuzz \
             $(BUILD_DIR)/wire/test/relay_fuzz \
             $(BUILD_DIR)/log/test/log_fuzz \
             $(BUILD_DIR)/spool/test/scrub_fuzz \
             $(BUILD_DIR)/ratchet/test/ratchet_fuzz \
             $(BUILD_DIR)/sched/test/sched_fuzz

fuzz: $(FUZZ_BINS)
	@for f in $(FUZZ_BINS); do echo "== $$f $(CASES)"; $$f $(CASES) || exit 1; done

# Not bare. A bare `.SECONDARY:` applies to every target matched by any
# pattern rule, silently including the object pattern above, and make does
# not rebuild a MISSING secondary when the thing depending on it already
# exists -- so adding a source would leave the build unchanged and every
# symbol in it undefined at link time. It exists to stop test objects being
# deleted as intermediates, so it names exactly those.
.SECONDARY: $(TEST_OBJS)

# The indentation, whitespace and ASCII gate. One tool, spread verbatim from
# ~/.claude/tool/style_gate.py; .style-gate.toml says which files here it
# applies to.
# TWO SECURITY PROPERTIES THE OPTIMISER COULD TAKE AWAY, each measured once by
# hand and then left in a comment. See tool/codegen_gate.py for what it does
# and does not claim -- it pins the shape each function compiles to so that a
# change stops the build, which is a tripwire rather than a proof. Skips loudly
# off x86-64 and without objdump; refuses if it cannot find a function, since
# that is indistinguishable from checking nothing.
#
# Named one per line rather than looped, because the pair is the point: a
# check added here should be a deliberate line somebody wrote.
codegencheck: $(BUILD_DIR)/constant_time/constant_time.o \
              $(BUILD_DIR)/session/commitment.o
	@# THE CONTROL, DERIVED FROM THE REAL SOURCE AND BUILT WITH THIS
	@# BUILD'S OWN CC AND FLAGS.
	@#
	@# Measured 2026-09-03 across eight cells: at clang -Os the ct check
	@# reports "shape unchanged" for an early-exit fzn_ct_memeq -- a mutant
	@# that preserves every result and destroys the only property
	@# constant_time/ exists for. -Os is this build's level and clang is
	@# what `fuzz` and `ctcheck` already use, so that is a green verdict
	@# meaning nothing on a supported toolchain.
	@#
	@# IT CANNOT BE DETECTED FROM THE OBJECT. codegen_gate.py skips for
	@# -O0, for a sanitizer build and off x86-64, all read from DWARF's
	@# producer string -- and clang records only its version there, with no
	@# flags at all, which that tool's own comment says. Nothing in a clang
	@# object says -Os.
	@#
	@# So the question is asked by experiment instead: compile a known-bad
	@# variant with the same CC and CFLAGS and see whether the gate rejects
	@# it. Rejected, the gate can discriminate here and its verdict on the
	@# real object means something. ACCEPTED, it cannot, and it says so and
	@# skips rather than reporting a pass. Same shape as `ctcheck`'s own
	@# positive control.
	@#
	@# DERIVED BY SUBSTITUTION RATHER THAN WRITTEN OUT, and that is the
	@# second version. The first was a hand-written early-exit memeq and it
	@# was REJECTED at clang -Os -- so it would have reported "this
	@# toolchain can discriminate" while the real mutant still passed. It
	@# differed from the real function in dropping `volatile uint8_t diff`,
	@# which is enough to change what clang emits. A control that is not
	@# the real function minus one line is a different program, and this
	@# one was a non-discriminating check inside the fix for a
	@# non-discriminating check.
	@#
	@# THE SUBSTITUTION IS ASSERTED TO MATCH EXACTLY ONE LINE, and that is
	@# stronger than checking the result differs. A pattern matching twice
	@# would build a control with two mutations, and a pattern matching
	@# nothing would build one identical to the real function -- which the
	@# gate would accept, correctly reporting that it cannot discriminate,
	@# but for a reason that is this recipe's fault rather than the
	@# compiler's. Naming the count tells those apart.
	@#
	@# PIPED TO THE COMPILER RATHER THAN WRITTEN OUT. BUILD_DIR defaults to
	@# `.` for the in-place build, so a generated .c lands in the source
	@# tree -- it did, in `tool/`, and `make style` refused it for its
	@# indentation. The gate catching that is the gate working; leaving a
	@# generated source where a person might read it as tracked is not
	@# something to fix by adding an exclusion.
	@mkdir -p $(BUILD_DIR)/tool
	@n=`grep -c 'diff |=' constant_time/constant_time.c`; \
	if [ "$$n" -ne 1 ]; then \
		echo "codegencheck: the control substitution matches $$n lines of" >&2; \
		echo "codegencheck: constant_time.c, wanted exactly 1 -- the control" >&2; \
		echo "codegencheck: it would build proves nothing." >&2; \
		exit 1; \
	fi
	@sed 's#^.*diff |=.*$$#        if (pa[i] != pb[i]) return 0;#' \
	  constant_time/constant_time.c \
	  | $(CC) $(FZN_PROBE_CPPFLAGS) $(CFLAGS) -Iconstant_time \
	    -x c - -c -o $(BUILD_DIR)/tool/ct_control.o
	python3 tool/codegen_gate.py ct $(BUILD_DIR)/constant_time/constant_time.o \
	                               $(BUILD_DIR)/tool/ct_control.o
	@# AND A CONTROL FOR THE WIPE CHECK, WHICH IS NOT BLIND ANYWHERE AND
	@# GETS ONE ANYWAY.
	@#
	@# Measured 2026-09-03 over the same eight cells that found the ct
	@# hole -- gcc and clang at -O1, -O2, -Os and -O3. All eight reject a
	@# derive_root missing one `fzn_wipe` call and accept the real one.
	@#
	@# THE ASYMMETRY IS THE INTERESTING PART AND IT IS STRUCTURAL. The ct
	@# check INFERS a property from instruction shape, and shape is a
	@# function of the toolchain -- which is how clang -Os came to accept
	@# a mutant. This one COUNTS CALLS TO A NAMED SYMBOL, and a call to an
	@# external function is not something an optimiser is free to reshape
	@# away: `fzn_wipe` lives in another translation unit, so without LTO
	@# there is nothing to inline. That is the general form worth
	@# remembering when a gate is written -- ask what the check is a
	@# function of, not just whether it passes.
	@#
	@# It is here because "measured robust in a session" and "re-measured
	@# every build" are different things, and this file has spent a day on
	@# the difference. It costs one compile.
	@n=`grep -c 'fzn_wipe(derived, sizeof(derived));' session/commitment.c`; \
	if [ "$$n" -ne 1 ]; then \
		echo "codegencheck: the wipe control deletes $$n lines of" >&2; \
		echo "codegencheck: commitment.c, wanted exactly 1." >&2; \
		exit 1; \
	fi
	@grep -v 'fzn_wipe(derived, sizeof(derived));' session/commitment.c \
	  | $(CC) $(FZN_PROBE_CPPFLAGS) $(CFLAGS) -Isession \
	    -x c - -c -o $(BUILD_DIR)/tool/wipe_control.o
	python3 tool/codegen_gate.py wipe $(BUILD_DIR)/session/commitment.o \
	                                 $(BUILD_DIR)/tool/wipe_control.o

# COVERAGE-GUIDED FUZZING, which is a different instrument from `fuzz`.
#
# `fuzz` runs the model-based harnesses: a PRNG generates chunk sequences and
# a model says what should have happened. That finds what the generator was
# written to reach. libFuzzer keeps inputs that reach new edges and mutates
# those, so it walks into states nobody described in advance.
#
# GUIDED_TIME is per harness and defaults low enough to be worth running
# before a commit. A real campaign is `make guided GUIDED_TIME=600`.
#
# The corpus is NOT committed. It is tens of thousands of bytes of machine-
# generated input whose value is local and perishable, and a crash worth
# keeping goes into the harness as a named byte string instead -- where it is
# reviewable and runs under plain `make test`.
#
# Skips loudly without a clang that has libFuzzer, on the same reasoning as
# `analyze` and `ctcheck`: an absent tool and a clean run are otherwise the
# same silence.
#
# First campaign 2026-08-26: 1.5M executions over chunk/reassembly.c under the
# address and undefined sanitizers, 209 of 400 edges, 292 corpus units, no
# crash. The local/ parsers were run the same way from a scratch harness:
# 15.3M executions, coverage 2 -> 82, no crash.
GUIDED_TIME ?= 60
GUIDED_DIR  ?= $(BUILD_DIR)/guided

guided:
	@if ! echo 'int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){(void)d;(void)s;return 0;}' \
	      | clang -fsanitize=fuzzer -x c - -o /dev/null 2>/dev/null; then \
		echo "guided: no clang with libFuzzer, so it was SKIPPED"; exit 0; \
	fi
	@# Named one per line rather than discovered, so that adding a harness
	@# here is a deliberate act and the sources each one needs are visible.
	@$(MAKE) --no-print-directory guided-one GUIDED_NAME=reassembly \
	        GUIDED_SRC="chunk/test/reassembly_guided.c chunk/reassembly.c \
	                    constant_time/constant_time.c"
	@$(MAKE) --no-print-directory guided-one GUIDED_NAME=chain \
	        GUIDED_SRC="chain/test/chain_guided.c chain/chain.c chain/revocation.c \
	                    chain/manifest.c constant_time/constant_time.c"
	@$(MAKE) --no-print-directory guided-one GUIDED_NAME=record \
	        GUIDED_SRC="record/test/record_guided.c record/record.c record/journal.c \
	                    state/state.c log/log.c constant_time/constant_time.c"
	@$(MAKE) --no-print-directory guided-one GUIDED_NAME=freshness \
	        GUIDED_SRC="frame/test/freshness_guided.c frame/freshness.c \
	                    constant_time/constant_time.c"

# The least coverage a guided run may report and still be believed. A harness
# that returns on its first line reports 1; the real ones report 112 to 209
# after ten seconds. Twenty is far below every real harness and far above the
# vacuous case, which is what a tripwire wants to be.
GUIDED_COV_MIN ?= 20

guided-one:
	@mkdir -p $(GUIDED_DIR)/$(GUIDED_NAME)
	@clang -O1 -g -fsanitize=fuzzer,address,undefined -DFZN_LIBFUZZER \
	       -o $(GUIDED_DIR)/$(GUIDED_NAME)/fuzz $(GUIDED_SRC)
	@echo "guided: $(GUIDED_NAME) for $(GUIDED_TIME)s"
	@# THE FUZZER'S EXIT STATUS IS READ, and until now it was thrown away.
	@#
	@# This line used to pipe the run into `grep -E "INITED|DONE|ERROR|SUMMARY"`,
	@# so the recipe's status was GREP's. libFuzzer exits non-zero when it finds
	@# a crash and prints "ERROR: libFuzzer: deadly signal" -- which grep matched,
	@# and so reported success. Measured: a harness that traps on the input "AB"
	@# produced a crash artifact, printed the error, and `make guided` exited 0.
	@#
	@# A coverage-guided fuzzer that cannot report a crash is the one instrument
	@# here whose entire purpose is finding them. The old comment on the line
	@# above -- "read the coverage, not the exit code" -- was an instruction to
	@# the person watching, standing in for a check nobody had written.
	@#
	@# Redirected to a file rather than piped, because `pipefail` is not in
	@# POSIX sh and make's shell is not guaranteed to have it.
	@# Paths below are relative BECAUSE OF THE `cd`. The first version of this
	@# kept the $(GUIDED_DIR)/$(GUIDED_NAME) prefix after changing into that
	@# directory, so every path resolved one level too deep, `cat` found no
	@# status file, and the exit-status test silently did nothing. A crashing
	@# harness was still caught -- by the coverage check below, which is a
	@# different check answering a different question. The check written for
	@# crashes had to be watched failing to fire to be found.
	@cd $(GUIDED_DIR)/$(GUIDED_NAME) && \
	    { ./fuzz . -max_total_time=$(GUIDED_TIME) -rss_limit_mb=2048 -max_len=4096 \
	        > run.log 2>&1; echo $$? > run.status; }; \
	    grep -E "INITED|DONE|ERROR|SUMMARY" run.log || true; \
	    rc=`cat run.status`; \
	    if [ "$$rc" -ne 0 ]; then \
	        echo "guided: $(GUIDED_NAME) FAILED -- the fuzzer exited $$rc."; \
	        echo "guided: a crash artifact is in $(GUIDED_DIR)/$(GUIDED_NAME)/."; \
	        exit 1; \
	    fi
	@# AND THE COVERAGE IS READ, not merely printed.
	@#
	@# libFuzzer reports `cov: N` on its INITED and DONE lines. The check is
	@# an ABSOLUTE FLOOR rather than growth, and the distinction matters: the
	@# corpus directory persists between runs, so a saturated corpus
	@# legitimately finds nothing new and a growth test would fail an honest
	@# re-run. What must never pass is a harness that reached NOTHING, and
	@# that is what a floor detects. Measured: a harness whose body is
	@# `return 0` reports cov 1; the four real harnesses report 112 to 209.
	@#
	@# A missing number is a failure too. A grep that matches nothing is not a
	@# check that passed -- which is the same mistake the piped `grep` above
	@# was making with the exit status.
	@d=`grep -o 'DONE *cov: [0-9]*' $(GUIDED_DIR)/$(GUIDED_NAME)/run.log | \
	     tail -1 | tr -dc '0-9'`; \
	if [ -z "$$d" ]; then \
		echo "guided: $(GUIDED_NAME) -- no DONE coverage line, so nothing was checked."; \
		echo "guided: the run did not finish, or libFuzzer changed its output."; \
		exit 1; \
	fi; \
	if [ "$$d" -lt "$(GUIDED_COV_MIN)" ]; then \
		echo "guided: $(GUIDED_NAME) reached cov $$d, below the floor of $(GUIDED_COV_MIN)."; \
		echo "guided: the harness is not reaching the code it is meant to drive."; \
		exit 1; \
	fi; \
	echo "guided: $(GUIDED_NAME) reached cov $$d"
	@# A CORPUS THAT DID NOT GROW MEANS THE HARNESS RETURNED EARLY, which is
	@# how the first version of this reported 61 million clean executions
	@# while every one of them bailed on its first line. The check is that
	@# the run kept more than the one unit libFuzzer starts with.
	@n=`ls $(GUIDED_DIR)/$(GUIDED_NAME) | grep -c '^[0-9a-f]\{40\}$$' || true`; \
	if [ "$$n" -lt 2 ]; then \
		echo "guided: $(GUIDED_NAME) kept $$n corpus unit(s) -- it is not reaching the code"; \
		echo "guided: a run that grows no corpus is not evidence of anything."; \
		exit 1; \
	fi; \
	echo "guided: $(GUIDED_NAME) kept $$n corpus units, so the search was real"

# IS THE CONSTANT-TIME COMPARISON ACTUALLY CONSTANT-TIME?
#
# `codegencheck` above counts branches in an object file, and
# tool/codegen_gate.py is explicit that this is "a tripwire rather than a
# proof". This asks the question directly: memcheck tracks definedness per
# bit and reports any conditional jump or memory address computed from data
# it considers undefined, so marking the two buffers undefined turns valgrind
# into a secret-dependence detector. Langley's ctgrind.
#
# IT RUNS THE BINARY TWICE ON PURPOSE. A memcheck that reports nothing and a
# memcheck that was never able to report anything look identical -- the build
# lost -DFZN_HAVE_VALGRIND, the binary was stale, valgrind ran something
# else. So the second run swaps in memcmp over the same poisoned buffers and
# this target FAILS IF THAT IS NOT REPORTED. The clean run means something
# only because the dirty one was seen.
#
# Not in `test`: valgrind is not on every machine, and it skips loudly rather
# than passing, since an absent tool and a clean one are otherwise the same
# silence.
CT_VG_BIN := $(BUILD_DIR)/constant_time/test/secret_flow_valgrind

ctcheck:
	@if ! command -v valgrind >/dev/null 2>&1; then \
		echo "ctcheck: no valgrind on PATH, so it was SKIPPED"; exit 0; \
	elif [ ! -f /usr/include/valgrind/memcheck.h ]; then \
		echo "ctcheck: valgrind headers absent, so it was SKIPPED"; exit 0; \
	else \
		mkdir -p $(dir $(CT_VG_BIN)) && \
		$(CC) $(CFLAGS) -DFZN_HAVE_VALGRIND -o $(CT_VG_BIN) \
		      constant_time/test/secret_flow_test.c constant_time/constant_time.c && \
		echo "ctcheck: fzn_ct_memeq, with both inputs marked secret" && \
		valgrind -q --error-exitcode=9 --track-origins=yes $(CT_VG_BIN) || \
			{ echo "ctcheck: FAILED -- control flow depended on secret data"; exit 1; }; \
		echo "ctcheck: positive control -- memcmp over the same secrets" && \
		if valgrind -q --error-exitcode=9 $(CT_VG_BIN) --leaky >/dev/null 2>&1; then \
			echo "ctcheck: FAILED -- memcmp over secret data was NOT reported."; \
			echo "ctcheck: the clean run above therefore proves nothing."; exit 1; \
		fi; \
		echo "ctcheck: reported, so the clean run above is evidence and not silence"; \
	fi

# STATIC ANALYSIS, from two tools that disagree about what to look for.
#
# Neither is in `test`, because both are slow and neither is a gate this
# project owns -- a new compiler release inventing a finding would break a
# build that changed nothing, which is the argument that keeps -Werror out
# too. Run deliberately, and read.
#
# Both skip loudly when absent rather than passing, since a missing analyser
# and a clean one produce the same silence otherwise.
#
# First run 2026-08-20: zero findings from either, over the library and the
# tests. Recorded in project.md as a result rather than a habit -- what makes
# it worth anything is that it had never been run at all.
analyze:
	@if $(CC) -fanalyzer -x c /dev/null -o /dev/null -c 2>/dev/null; then \
		echo "analyze: gcc -fanalyzer over the library and the tests"; \
		$(MAKE) --no-print-directory test BUILD_DIR=$(BUILD_DIR)-analyze \
		        CFLAGS="-Os -g -fanalyzer" 2>&1 | grep -E "Wanalyzer" || true; \
		rm -rf $(BUILD_DIR)-analyze; \
	else \
		echo "analyze: this compiler has no -fanalyzer, so it was SKIPPED"; \
	fi
	@if command -v cppcheck >/dev/null 2>&1; then \
		echo "analyze: cppcheck --check-level=exhaustive over the library"; \
		cppcheck --enable=warning,performance,portability \
		         --check-level=exhaustive --inline-suppr \
		         --suppress=missingIncludeSystem --quiet -I. $(SRCS) 2>&1 \
		         | grep -vE "normalCheckLevel" || true; \
	else \
		echo "analyze: no cppcheck on PATH, so it was SKIPPED"; \
	fi
	@echo "analyze: done -- read the output above; this target reports and does not gate"

# WHICH GUARDS IS ANYTHING ACTUALLY HOLDING TO ACCOUNT? Breaks one at a time
# and rebuilds through `make test`. See tool/sabotage.py, which carries the
# list and the reasoning; project.md sec 36 has what the first sweep found.
#
# DELIBERATELY NOT PART OF `make test`, and not because it is slow. It
# REWRITES TRACKED FILES IN PLACE and restores them afterwards, which is not
# something a routine gate should do in a tree more than one session works
# in. It refuses outright if the files it edits have uncommitted changes, so
# the worst case after a hard kill is `git checkout` on files that had
# nothing to lose.
#
# tool/sabotage.py exits 1 when it finds a guard nothing catches, and 2 when
# the run itself cannot be trusted -- a control that was not caught, a
# pattern that matched nothing, a restore that did not reproduce the
# original. The second is not a milder version of the first: it means the
# output above it says nothing at all.
#
# THROUGH THIS TARGET BOTH ARRIVE AS make's EXIT 2, because make reports any
# failed recipe that way, so the distinction survives in the printed text
# and not in $?. Read the last lines, or run the tool directly when a script
# needs to tell the two apart. This comment said otherwise until the
# difference was measured.
#
# `sync-clear-plan` USED TO HANG rather than fail, taking
# sim/test/network_test past any sensible bound, and this comment priced a
# full run at its timeout accordingly. a1af82d bounded the plan count that
# harness walks and the entry has failed fast since; measured 2026-09-03 at
# under ten seconds, two days after the fix and with the warning still here.
# A FULL SWEEP IS AFFORDABLE, AND THIS COMMENT SAID OTHERWISE FOR LONGER
# THAN IT WAS TRUE. It read "builds plus one `make test` each, and nothing
# budgets a timeout", which is accurate about the SHAPE and was taken as a
# reason not to run one -- so the table grew from the 42 entries sec 52 swept
# to 321 with no full run in between. Measured 2026-09-08: 321 entries in
# 40.6 minutes wall clock, about 7.6 seconds each, incremental builds doing
# most of the work.
#
# Run it with `make sabotage ARGS=--timeout\ 300` after landing a batch of
# entries, and record the verdict counts. See project.md sec 52 and sec 206.
#
# `make sabotage ARGS=--verify` is the read-only half: it checks that every
# entry still names exactly one site, builds nothing, and is what `make
# style` runs. An entry whose pattern has stopped matching tests nothing
# while sitting in a table that reads as coverage.
#
# `make sabotage ARGS=--list` prints the entries without running anything.
sabotage:
	@python3 tool/sabotage.py $(ARGS)

# EVERY GATE THIS PROJECT HAS, under the name thirteen of the seventeen
# private projects already use. Measured by collecting `.PHONY` across every
# sibling Makefile: `check` is there and it means the same thing everywhere
# -- hydra and beerssh spell it `style test`, fmake adds its version check,
# situ adds typecheck and lint. fuzznet had the gates and no entry point, so
# somebody arriving from another tree typed `make check` and got "No rule to
# make target".
#
# WHAT IS DELIBERATELY NOT IN IT. `schema` needs SITU_DIR and refuses
# without it, so it would make this target fail on a machine with no situ
# checkout -- it is a gate that runs when a second repository is present and
# says so when it is not. `fuzz` at its default 200000 cases and `coverage`
# and `analyze` are measurements rather than gates, and report without
# refusing. `sabotage` REWRITES TRACKED FILES, which nothing that reads as
# "check my work" should ever do.
#
# `test` already depends on `codegencheck`, so the constant-time and wipe
# tripwires are inside this without being named.
#
# `ctcheck` IS NAMED, AND JOINED THIS ON 2026-09-03. It was left out on the
# ground that valgrind is not on every machine -- which is an argument about
# `test`, the inner loop, and not about this target, which already tolerates
# a loud skip: `ctcheck` prints SKIPPED and exits 0 without valgrind or its
# headers, exactly as `analyze` does without cppcheck.
#
# What moved the decision is that it is a GATE and not a measurement. It
# refuses with exit 1 on a finding and carries its own positive control --
# it re-runs the same binary with `--leaky` and fails if valgrind does NOT
# report that one, so a clean first run is evidence rather than silence.
# That is the property `fuzz`, `coverage` and `analyze` lack and the reason
# they stay out.
#
# AND IT IS NOW THE ONLY PORTABLE WITNESS FOR THE PROPERTY. The codegen
# tripwire infers from instruction shape, and at clang -Os that shape does
# not distinguish `fzn_ct_memeq` from an early-exit version of it -- so
# since the control landed, the tripwire honestly SKIPS there. Without this
# line, `make check` on a clang box would verify the constant-time property
# not at all. valgrind observes the branch on secret data rather than
# inferring it, which is why it does not care which compiler emitted what.
# project.md sec 53 has the eight-cell matrix.
#
# It costs 1.8s here.
check: style test installcheck ctcheck sancheck qrcheck qttycheck

# THE SUITE AGAIN UNDER AddressSanitizer AND UBSan, on the holder's
# instruction 2026-09-04. What it costs is roughly the test time again; what
# it buys was measured the same day, before it was asked for: one real defect
# in one run -- a view into a stack buffer whose scope had ended, in a test
# that had passed `make check` a dozen times, `make fuzz` at 200000 cases per
# harness and three coverage runs, because the bytes were still there.
# project.md sec 86.
#
# `runtests` AND NOT `test`, WHICH IS THE WHOLE CARE IN THIS TARGET.
# `test` is `codegencheck runtests`, and `codegencheck` SKIPS a sanitizer
# build outright -- it reads the emitted shape of two security-critical
# functions, and instrumentation deliberately changes that shape. So a
# sanitized `test` would run the codegen gate, have it decline, and report a
# pass over a check that inspected nothing. Running `runtests` leaves
# `codegencheck` where it means something: on the plain build above.
#
# A SEPARATE BUILD_DIR because the header at the top of this file says so and
# says why: the objects are not interchangeable and mixing them produces a
# link nobody can explain. Derived from the caller's rather than hard-coded,
# so `make check BUILD_DIR=out` sanitizes into `out-san`; `.gitignore` covers
# both spellings.
#
# THE TREE IS KEPT, not removed. `coverage` deletes its own because it is a
# one-off measurement; this runs on every check, and rebuilding the whole
# suite under a sanitizer each time would make the gate cost what nobody
# would pay. `clean` removes it.
sancheck:
	@test -n "$(BUILD_DIR)" || { echo "BUILD_DIR is empty; refusing"; exit 1; }
	@case "$(BUILD_DIR)" in /*) echo "BUILD_DIR must be relative; refusing"; exit 1 ;; esac
	@echo "sancheck: the suite under AddressSanitizer and UBSan"
	@$(MAKE) --no-print-directory runtests BUILD_DIR=$(BUILD_DIR)-san SANITIZE=1

# STYLE BUILDS WHAT IT INSPECTS, since sec 231. The renderer sweep reads
# `nm` over $(SRCS)'s objects and the guard above refuses when one is
# missing -- correctly, since a sweep over a subset reports a pass over less
# than the build made. But `check` runs `style` FIRST, so on a fresh clone
# the documented entry point stopped at a message telling the reader to build
# something `check` was about to build anyway.
#
# Measured on a clone of this repository: `make check` failed at
# `constant_time/constant_time.o is missing` before compiling anything, under
# this Makefile AND under the one before sec 231 -- so it has been that way
# since the guard was added on 2026-09-04, and widening the guard did not
# cause it.
#
# The prerequisite costs nothing on a warm tree and costs `check` nothing at
# all, since `test` builds the same objects a moment later. What it removes is
# a first impression that reads as a broken makefile.
style: $(OBJS)
	@# THE GATE'S OWN CONTROL, AND IT RUNS BEFORE THE GATE'S VERDICT.
	@# `style_gate.py` is a detector whose failure mode is SILENCE: run
	@# over a conforming tree it prints the same sentence whether every
	@# rule is live or every rule has been deleted, so a pass is evidence
	@# only once something has shown it can fail. That suite arrived here
	@# in 83cf7ff and had no caller; a control nobody runs is a control
	@# that has stopped controlling.
	@#
	@# The ORDER is the point rather than the inclusion. Running it after
	@# the gate would let a gate that can no longer speak report "35 files
	@# conform" first, which is the sentence somebody quotes. Running it
	@# first means make stops before that sentence exists.
	@#
	@# About 8 seconds, stdlib only. THE TEST COUNT IS DELIBERATELY NOT
	@# WRITTEN HERE: this file is copied from ~/.claude/tool and another
	@# session synced two more controls into it within the hour, taking it
	@# from 101 to 103 while this comment was being drafted. A count in a
	@# comment beside a file somebody else keeps in sync is stale by
	@# construction. Measured 2026-09-05: it
	@# spawns one bounded subprocess per case with `timeout=120`, builds
	@# every fixture inside a `TemporaryDirectory` context manager, and
	@# left zero directories behind in /tmp -- counted, not assumed.
	@#
	@# IT HAD A HOLE, found by sabotaging it rather than by trusting it.
	@# Neutering `python_ascii_problems` so it reports nothing silenced the
	@# gate on a valid Python file whose em dash sits in a comment, and the
	@# whole suite still passed: C's tokeniser path had a fixture and
	@# Python's did not. Fixed at the source on the holder's instruction and
	@# taken back with `sync.py fuzznet`; project.md sec 112 has it.
	@#
	@# THE COMMENT STAYS BECAUSE THE NEXT HOLE WILL NOT ANNOUNCE ITSELF
	@# EITHER. A suite that has been sabotaged once is a suite with one
	@# known hole closed, not a suite without holes, and "the gate has a
	@# test suite" is the sentence somebody will quote instead.
	python3 tool/test_style_gate.py
	python3 tool/style_gate.py check
	@# THE SABOTAGE TABLE IS A LIST KEPT BY HAND, and it is the one list
	@# here whose staleness is invisible. `make sabotage` says so when it
	@# runs, and it rewrites tracked files, so it is deliberately outside
	@# `check` and gets run when somebody remembers -- which left
	@# `seal-open-clears-out` matching two sites, and therefore testing
	@# nothing, from 2026-09-01 to 2026-09-03. See project.md sec 52.
	@#
	@# `--verify` counts substrings. It opens no compiler and writes no
	@# byte, which is what makes it safe to put in a routine gate that
	@# `sabotage` itself can never be part of.
	python3 tool/sabotage.py --verify
	@# AND NO TWO ENUMERATORS SHARE A VALUE, which nothing else here would
	@# catch: a value clash is not a type error, so it compiles, passes every
	@# unit gate, and surfaces as one family being routed into another's
	@# handler. fuzzypickles paid for exactly that on 2026-09-04 and reported
	@# it; wire/bytes.h answers it for the object tags with a static-assert
	@# chain, and this answers it for the other 37. project.md sec 74.
	python3 tool/enum_gate.py
	@# AND NO LIBRARY SOURCE THROWS AWAY A STATUS IT WAS HANDED, which is
	@# sec 75's finding one step out: that seam cannot report a failure, and
	@# this is a failure reported and dropped. Zero today across 131
	@# status-returning functions, and a property nobody checks is one that
	@# stops being true quietly. project.md sec 76.
	python3 tool/status_gate.py
	@# EVERY .c IN THE TREE MUST BE IN A LIST -- the fourth instance of one
	@# pattern and the last that was not mechanically checked. HDRS against
	@# `install`, GEN_SRCS against `coverage`, TEST_BINS against .gitignore,
	@# and SRCS against the tree: each is a list kept by hand, and each guard
	@# is only as wide as the list it iterates. The first three are compared
	@# against another list. This one has no second list, so it is compared
	@# against the filesystem.
	@#
	@# It is what would have caught the Monocypher bindings, which were in the
	@# tree, built, linked and run, and in no list `make coverage` reads.
	@# `.claude/` IS PRUNED FROM EVERY SWEEP BELOW, along with the build
	@# directories. It holds tooling configuration rather than project
	@# content -- and, when more than one agent is working in this tree, git
	@# worktrees under `.claude/worktrees/`, each a full checkout. Without
	@# the prune every sweep here reports several hundred copies of the same
	@# files as unlisted, which is a gate that has stopped saying anything.
	@# TWO SOURCES ARE BUILT ONLY BY THEIR OWN TARGET and belong in no list
	@# a default build reads: `tool/consumer_check.c` needs an installed
	@# tree, and `qr/test/qr_quirc_check.c` needs a quirc checkout. Naming
	@# them here rather than widening the sweep keeps the gate exact -- a
	@# third one has to be added deliberately and says why.
	@known=" $(SRCS) $(TEST_SRCS) $(GEN_SRCS) $(MONO_SRCS) $(MONO_TSRC) \
	         $(FLOG_TSRC) tool/consumer_check.c qr/test/qr_quirc_check.c "; \
	unlisted=; n=0; \
	for c in `find . -name '*.c' -not -path './build/*' -not -path './san/*' \
	                 -not -path './*-coverage/*' -not -path './.claude/*' \
	                 $(VENDOR_PRUNE) | sed 's|^\./||' | sort`; do \
		n=$$((n + 1)); \
		case "$$known" in *" $$c "*) ;; *) unlisted="$$unlisted $$c" ;; esac; \
	done; \
	if [ "$$n" -eq 0 ]; then \
		echo "style: no C sources found, which cannot be right"; exit 1; \
	fi; \
	if [ -n "$$unlisted" ]; then \
		echo "style: C sources in the tree and in no list:$$unlisted"; \
		echo "style: nothing reading SRCS -- coverage, installcheck -- can see them."; \
		exit 1; \
	fi; \
	echo "style: $$n C sources, all named in a list"
	@# AND EVERY FUZZ HARNESS MUST BE IN FUZZ_BINS, a fifth hand-maintained
	@# list and the one still unchecked.
	@#
	@# vocabulary_fuzz.c was in TEST_SRCS and TEST_BINS, so `make test` ran
	@# it at the default case count, and absent from FUZZ_BINS, so `make
	@# fuzz CASES=2000000` never touched it. The deep campaign is the one
	@# place that omission costs anything, and nothing said so: the suite
	@# was green either way.
	@#
	@# `*_fuzz.c` is the convention every harness here follows, so the
	@# filesystem is asked directly rather than compared against another
	@# list somebody also maintains.
	@missing=; n=0; \
	listed=; \
	for b in $(FUZZ_BINS); do listed="$$listed $${b#$(BUILD_DIR)/}"; done; \
	for f in `find . -name '*_fuzz.c' -not -path './build/*' -not -path './san/*' \
	                 -not -path './*-coverage/*' -not -path './.claude/*' \
	                 $(VENDOR_PRUNE) | sed 's|^\./||' | sort`; do \
		n=$$((n + 1)); \
		bin=`echo "$$f" | sed 's/\.c$$//'`; \
		case " $$listed " in *" $$bin "*) ;; *) missing="$$missing $$bin" ;; esac; \
	done; \
	if [ "$$n" -eq 0 ]; then \
		echo "style: no fuzz harnesses found, which cannot be right"; exit 1; \
	fi; \
	if [ -n "$$missing" ]; then \
		echo "style: fuzz harnesses not in FUZZ_BINS:$$missing"; \
		echo "style: 'make fuzz' would never run them, whatever CASES said."; \
		exit 1; \
	fi; \
	echo "style: $$n fuzz harnesses, all in FUZZ_BINS"
	@# THE THIRD HAND-MAINTAINED LIST, and the third time one has drifted.
	@# .gitignore names each test binary rather than globbing them, for a
	@# stated reason: a pattern would also hide a source file added under
	@# that name by mistake. The cost is a line per test, and forgetting it
	@# leaves a build product in `git status` -- which matters here because
	@# the rule against blanket `git add` depends on that output being
	@# trustworthy. Noise trains people to stop reading it.
	@#
	@# HDRS versus `install` and GEN_SRCS versus `coverage` were the first
	@# two, and both were found by something breaking rather than by
	@# anybody comparing the lists. So this compares them.
	@#
	@# BUILD_DIR IS STRIPPED RATHER THAN SKIPPED ON. Both this check and the
	@# FUZZ_BINS one above used to refuse to run unless BUILD_DIR was the
	@# in-place default, on the reasoning that the paths would not match --
	@# but the prefix is incidental to what they compare, which is list
	@# membership. Stripping it makes them answer in every configuration,
	@# and a check that skips for anybody who habitually builds out of tree
	@# is a check those people do not have.
	@missing=; n=0; \
	for b in $(TEST_BINS); do \
		n=$$((n + 1)); \
		p=$${b#$(BUILD_DIR)/}; \
		grep -qx -- "/$$p" .gitignore || missing="$$missing $$p"; \
	done; \
	if [ "$$n" -eq 0 ]; then \
		echo "style: no test binaries to check, which cannot be right"; exit 1; \
	fi; \
	if [ -n "$$missing" ]; then \
		echo "style: test binaries missing from .gitignore:$$missing"; exit 1; \
	fi; \
	echo "style: $$n test binaries all named in .gitignore"
	@# THE CALLS QTTY BANS, BANNED HERE. project.md sec 158.
	@#
	@# `qtty` renders an unmodified Qt Widgets application on a character
	@# cell grid, and its design.md sec 7 names the four calls that make a
	@# layout unportable to one: `setContentsMargins`, `setSpacing`,
	@# `setFixedSize` and `setFixedWidth`. They hardcode pixels, and a cell
	@# is not a pixel.
	@#
	@# THAT PROJECT ENFORCES IT ON ITS OWN SHARED VIEW CODE AND CANNOT
	@# ENFORCE IT ON OURS. `gui/` exists so that every consumer shows an
	@# anchor the same way -- sec 140 -- and a widget here that a terminal
	@# cannot lay out is one a headless daemon cannot use, which is half
	@# the reason the widgets are Qt Widgets rather than QML.
	@#
	@# A GATE RATHER THAN A CONVENTION because the cost lands somewhere
	@# else: the call compiles, the desktop looks right, and the terminal
	@# is where it goes wrong -- so nothing on the machine writing it
	@# complains. sec 158 found a defect of exactly that shape by rendering
	@# rather than by reading, and this is the half that needs no qtty
	@# installed to run.
	@banned=; n=0; \
	for f in $(wildcard gui/*.cpp gui/*.h); do \
		n=$$((n + 1)); \
		if grep -nE 'set(ContentsMargins|Spacing|FixedSize|FixedWidth|FixedHeight)\(' \
		        "$$f" | grep -v 'qtty-allow:' | grep -q .; then \
			banned="$$banned $$f"; \
		fi; \
	done; \
	if [ "$$n" -eq 0 ]; then \
		echo "style: no gui sources to check for qtty portability"; \
	elif [ -n "$$banned" ]; then \
		echo "style: pixel geometry a character cell cannot honour, in:$$banned"; \
		echo "style: qtty design.md sec 7 bans these; sec 158 says why we do too."; \
		echo "style: a deliberate one carries a 'qtty-allow:' comment and a reason."; \
		exit 1; \
	else \
		echo "style: $$n gui source(s) free of pixel geometry qtty cannot honour"; \
	fi
	@# AND EVERY HEADER MUST BE IN HDRS, which is the sixth pairing and the
	@# one still open. installcheck already refuses when an HDRS entry is
	@# not exercised by the consumer check; nothing looked the other way,
	@# and a header in the tree that HDRS does not name is one `make
	@# install` never ships -- which surfaces as a consumer's include
	@# failing on a machine that is not this one.
	@#
	@# NO INSTALLED HEADER DECLARES A REALM, and this is a gate rather
	@# than a comment because the discipline it enforces cannot be
	@# expressed any other way.
	@#
	@# project.md sec 19: a realm is established by four different
	@# mechanisms and is a property of the authenticated relationship on
	@# the channel a message arrived over, computed per arrival. It is a
	@# verb, not a column. fuzzypickles settled that from inside their own
	@# tree, and settled it by quoting THIS library's rule back at it --
	@# chain.h's "capabilities are opaque ... a library that assumed a
	@# total order would be wrong for netcfgd on its first day". A realm
	@# enum is that same error one layer up: Registered and Unregistered
	@# are propositions about a chat product and mean nothing to a library
	@# reconfiguring a router.
	@#
	@# THE STRUCTURAL FORM IS THE POINT. "Computed per arrival, never
	@# stored" held by a comment lasts until the next session that reaches
	@# for the obvious field -- which is what this one nearly built. If
	@# the library offers nowhere to PUT a realm, the discipline is
	@# enforced by there being no field to store it in, which is the same
	@# move as the ratchet's unsafe advance having no spelling.
	@#
	@# IT MATCHES DECLARATIONS, NOT THE WORD. `realm` already appears in
	@# this tree meaning something else entirely -- "root A's realm", the
	@# scope of a root key, in revocation.h and two test files -- which is
	@# the fifth question sitting in the tree before anybody looked. A
	@# check on the word would fire on correct prose; this one fires on a
	@# type or a field.
	@#
	@# AND IT CARRIES ITS CONTROL, because a pattern that matches nothing
	@# and a tree that declares nothing look identical. The control is a
	@# declaration this gate must reject, classified before any header is
	@# read.
	@ctl='	fzn_realm_t realm;'; \
	if ! printf '%s\n' "$$ctl" | grep -qE 'fzn_realm|[^a-z_]realm[ \t]*(;|\[)'; then \
		echo "style: the realm pattern does not match its own control,"; \
		echo "style: so a clean result below would mean nothing."; \
		exit 2; \
	fi
	@found=`grep -nE 'fzn_realm|[^a-z_]realm[ \t]*(;|\[)' $(HDRS) 2>/dev/null`; \
	if [ -n "$$found" ]; then \
		echo "style: an installed header declares a realm:"; \
		echo "$$found" | sed 's/^/  /'; \
		echo "style: a realm is computed per arrival and never stored -- sec 19."; \
		exit 1; \
	fi; \
	echo "style: no installed header declares a realm, and the pattern was checked"

	@# ./installcheck/ IS EXCLUDED BECAUSE IT IS A COPY OF THIS LIST. It is
	@# installcheck's DESTDIR staging tree, and BUILD_DIR defaults to `.`,
	@# so it lands in the root. The target removes it at both ends -- but
	@# only on the paths it reaches, and an installcheck that FAILS leaves
	@# it behind, at which point `make style` reports all 28 installed
	@# headers as unlisted. That is a false finding in a gate, and it says
	@# nothing about the tree: every path it names is a copy of a file the
	@# walk has already accepted a line above. .gitignore has carried the
	@# same incident since it happened; the walk had not been told.
	@#
	@# MONO_HDRS IS NO LONGER UNIONED IN, and its absence is now doing
	@# work rather than merely being tidy. HDRS gained the binding headers
	@# only under `ifdef MONO_ON` until `make installcheck MONOCYPHER_DIR=`
	@# proved that wrong, and the union here is what kept this walk quiet
	@# about it -- the four headers were in the tree, absent from what
	@# `install` shipped, and named by the union anyway. Asking $(HDRS)
	@# alone means a re-conditionalising of that append fails here, with
	@# the message below saying exactly what would break.
	@#
	@# MONO_SRCS stays unioned into the C source check above, and the
	@# asymmetry is deliberate: those sources genuinely are not compiled
	@# without the submodule. Generated headers are situ's and tool/ is
	@# not installed, so both are excluded rather than listed.
	@# GUI_HDRS IS UNIONED IN RATHER THAN ADDED TO HDRS, the same asymmetry
	@# MONO_SRCS has above and for a sharper reason: HDRS is the C API, and
	@# `tool/consumer_check.c` includes every member of it while
	@# `installcheck`'s C++ arm parses every member without Qt's flags. A
	@# C++-only header that needs `QWidget` fails both. It is a real public
	@# header and it is installed below; it is not a C one. sec 140.
	@known=" $(HDRS) $(GUI_HDRS) "; missing=; n=0; \
	for h in `find . -name '*.h' -not -path './.git/*' -not -path './.claude/*' \
	                 -not -path './wire/generated/*' -not -path './tool/*' \
	                 -not -path './build/*' -not -path './san/*' \
	                 -not -path './installcheck/*' \
	                 -not -path './*-coverage/*' $(VENDOR_PRUNE) \
	                 | sed 's|^\./||' | sort`; do \
		n=$$((n + 1)); \
		case "$$known" in *" $$h "*) ;; *) missing="$$missing $$h" ;; esac; \
	done; \
	if [ "$$n" -eq 0 ]; then \
		echo "style: no headers found, which cannot be right"; exit 1; \
	fi; \
	if [ -n "$$missing" ]; then \
		echo "style: headers in the tree and not in HDRS:$$missing"; \
		echo "style: 'make install' would not ship them."; \
		exit 1; \
	fi; \
	echo "style: $$n headers, all named in HDRS"
	@# AND EVERY TEST SOURCE MUST PRODUCE A BINARY `make test` RUNS.
	@#
	@# TEST_SRCS is what gets compiled and dependency-tracked; TEST_BINS is
	@# what `test:` iterates. A source in the first and not the second
	@# builds cleanly and never runs -- and that is not hypothetical, it is
	@# what happened to local/test/vocabulary_fuzz.c one list over, which
	@# sat in TEST_SRCS and TEST_BINS but not FUZZ_BINS and so was never
	@# reached by the deep campaign. The same slip here costs a test that
	@# never runs at all, which is worse and just as quiet.
	@#
	@# The SRCS-against-the-tree check above does not cover it: a source in
	@# TEST_SRCS is in a list, which is all that one asks.
	@srcs=`for f in $(TEST_SRCS); do echo "$${f%.c}"; done | sort -u`; \
	bins=`for b in $(TEST_BINS); do echo "$${b#$(BUILD_DIR)/}"; done | sort -u`; \
	n=`echo "$$srcs" | grep -c .`; \
	missing=; \
	for t in $$srcs; do \
		case " `echo $$bins` " in *" $$t "*) ;; *) missing="$$missing $$t" ;; esac; \
	done; \
	if [ "$$n" -eq 0 ]; then \
		echo "style: no test sources found, which cannot be right"; exit 1; \
	fi; \
	if [ -n "$$missing" ]; then \
		echo "style: test sources that build but never run:$$missing"; \
		echo "style: they are in TEST_SRCS and not in TEST_BINS."; \
		exit 1; \
	fi; \
	echo "style: $$n test sources, all reached by 'make test'"
	@# EVERY ERROR RENDERER IS WALKED BY THE SWEEP, derived from the sources
	@# rather than from a list somebody keeps.
	@#
	@# WHAT IT COSTS TO GET WRONG, measured 2026-09-04: the library defined
	@# 26 `_err_str`/`_verdict_str` renderers and `wire/test/err_str_test.c`
	@# named 17. The nine missing were every enum that counts UP from OK,
	@# because the table had a hand-written direction column and the sixteen
	@# error enums in it all count DOWN -- so 33 arms had never rendered,
	@# including `fzn_spool_err_str`, which nothing in this tree calls at
	@# all. project.md sec 67.
	@#
	@# THE ROSTER IS THE TEST'S OWN `SUBJECTS[]` NAMES, so this creates no
	@# second list: the left side is what the compiler emitted, the right is
	@# what the sweep says it walks, and a renderer in one and not the other
	@# is named. Same shape as the TEST_SRCS check above and as
	@# `installcheck`'s symbol probe.
	@# EVERY OBJECT MUST BE THERE, WHICH THIS DID NOT CHECK. `nm` was run
	@# with `2>/dev/null`, so a source whose object had not been built was
	@# skipped in silence and its renderers were invisible -- and the guard
	@# below only catches the case where NONE exist. Measured 2026-09-04:
	@# adding `disclose/` and running `make style` before anything compiled
	@# it reported "27 error renderers, all walked", a true statement about
	@# the objects that happened to be present. `evidence.md`'s nastier
	@# variant: a check that inspected the wrong thing rather than nothing.
	@# OVER $(SRCS) SINCE sec 231, because the sweep below is. It was
	@# $(CORE_SRCS) while the sweep was, and widening one without the other
	@# would have reopened exactly what this guard closed -- for the 27
	@# sources that are in SRCS and not in CORE_SRCS.
	@for o in $(SRCS:%.c=$(BUILD_DIR)/%.o); do \
		if [ ! -e "$$o" ]; then \
			echo "style: $$o is missing, so the renderer sweep below would"; \
			echo "style: skip it silently and report a pass over less than"; \
			echo "style: what the build made. Build the objects first."; \
			exit 1; \
		fi; \
	done
	@# EVERY SUITE NAMES ITSELF IN ITS FAILURE LINES, because a suite that
	@# does not cannot be credited with what it catches: `tool/sabotage.py`
	@# reports one failure line per sabotage and cannot prefer a suite that
	@# does not say who it is. project.md sec 139 found one, sec 141 found a
	@# second, and sec 143 swept the rest -- this is what stops the next one
	@# arriving.
	@#
	@# ONLY LINES THAT PRINT are examined. A first version read every string
	@# literal and flagged a COMMENT in sign_monocypher_test.c that quotes
	@# the word, which is the detector reporting on prose rather than on
	@# output.
	@n=0; bad=; \
	for f in `git ls-files '*/test/*.c' '*/test/*.cpp'`; do \
		stem=`basename $$f | sed 's/\.[cp]*$$//'`; \
		n=$$((n + 1)); \
		if grep -E '(printf|fputs)' $$f | grep -oE '"[^"]*FAIL[^"]*"' \
		   | grep -qv "$$stem"; then \
			bad="$$bad $$f"; \
		fi; \
	done; \
	if [ "$$n" -eq 0 ]; then \
		echo "style: no test sources found, which cannot be right"; exit 1; \
	fi; \
	if [ -n "$$bad" ]; then \
		echo "style: suites whose failure lines name no file:$$bad"; \
		echo "style: a failure nobody can attribute is one the sabotage"; \
		echo "style: harness credits to whichever suite ran last."; \
		exit 1; \
	fi; \
	echo "style: $$n test sources, every failure line names its suite"
	@# OVER $(SRCS), NOT $(CORE_SRCS). The narrower list is the library
	@# only, so `fzn_cli_err_str` -- a real renderer with real arms -- sat
	@# outside the population this walks while having a row in the sweep.
	@# Deleting that row, or adding an arm with no row, was invisible here:
	@# "all walked" stayed true because the renderer was never in the set.
	@# Measured 2026-09-09: 39 over CORE_SRCS, 40 over SRCS, and the sweep
	@# has 40 rows. project.md sec 231.
	@#
	@# THE MISSING-OBJECT GUARD IS THE ONE ABOVE, WIDENED WITH THIS. A second
	@# copy was added here first, because the comment on that guard narrates
	@# the defect in the past tense -- "EVERY OBJECT MUST BE THERE, WHICH THIS
	@# DID NOT CHECK" -- and reads as a description of the present to anybody
	@# skimming for whether a check exists. It exists; it was pointed at the
	@# narrower list.
	have=`nm --defined-only $(SRCS:%.c=$(BUILD_DIR)/%.o) 2>/dev/null \
	       | awk '$$2 == "T" { print $$3 }' \
	       | grep -E '^fzn_[a-z_]+_str$$' | sort -u`; 	walked=`grep -oE '"fzn_[a-z_]+_str"' wire/test/err_str_test.c \
	        | tr -d '"' | sort -u`; 	n=`echo "$$have" | grep -c .`; 	w=`echo "$$walked" | grep -c .`; 	if [ "$$n" -eq 0 ]; then 		echo "style: the renderer probe matched no symbols, so it proves"; 		echo "style: nothing -- build the objects before running this."; 		exit 1; 	fi; 	missing=; \
	for r in $$have; do \
		case " `echo $$walked` " in *" $$r "*) ;; *) missing="$$missing $$r" ;; esac; \
	done; 	if [ -n "$$missing" ]; then 		echo "style: error renderers the sweep does not walk:" $$missing; 		echo "style: add a row to SUBJECTS[] in wire/test/err_str_test.c,"; 		echo "style: or its arms render text no test has ever read."; 		exit 1; 	fi; 	echo "style: $$n error renderers, all walked by err_str_test ($$w rows)"
	@# AND version/version.h MUST STILL SPELL WHAT VERSION SAYS, an eighth
	@# hand-maintained agreement. The header is a copy on purpose --
	@# version.h says why, and it is the reason constants_test.c gives about
	@# the field lengths: a generated header would put a build step between a
	@# consumer and a constant. What was missing there and here is anything
	@# to notice when a copy stops being one.
	@#
	@# The packing bound is checked too. At a minor or patch of 100 the
	@# arithmetic carries and 0.1.100 compares equal to 0.2.0 -- two releases
	@# indistinguishable, which is worse than either being wrong.
	@test -s VERSION || { echo "style: VERSION is missing or empty"; exit 1; }
	@v=`tr -d ' \t\n' < VERSION`; \
	h=version/version.h; \
	maj=`sed -n 's/^#define FZN_VERSION_MAJOR \([0-9][0-9]*\).*/\1/p' $$h`; \
	min=`sed -n 's/^#define FZN_VERSION_MINOR \([0-9][0-9]*\).*/\1/p' $$h`; \
	pat=`sed -n 's/^#define FZN_VERSION_PATCH \([0-9][0-9]*\).*/\1/p' $$h`; \
	str=`sed -n 's/^#define FZN_VERSION_STRING "\([^"]*\)".*/\1/p' $$h`; \
	if [ -z "$$maj" ] || [ -z "$$min" ] || [ -z "$$pat" ] || [ -z "$$str" ]; then \
		echo "style: could not read the version macros out of $$h."; \
		echo "style: a macro this could not find is not one it checked."; \
		exit 1; \
	fi; \
	if [ "$$maj.$$min.$$pat" != "$$v" ]; then \
		echo "style: $$h says $$maj.$$min.$$pat and VERSION says $$v"; \
		exit 1; \
	fi; \
	if [ "$$str" != "$$v" ]; then \
		echo "style: FZN_VERSION_STRING is \"$$str\" and VERSION says $$v"; \
		exit 1; \
	fi; \
	if [ "$$min" -gt 99 ] || [ "$$pat" -gt 99 ]; then \
		echo "style: $$v does not pack -- a minor or patch above 99 carries"; \
		echo "style: into the next field, so 0.1.100 would equal 0.2.0."; \
		exit 1; \
	fi; \
	echo "style: version/version.h and VERSION agree at $$v"

	@# AND project.md IS HELD TO THE TREE. `docs` is a mode of the same gate
	@# this target opens with, and fuzznet was the ONE private project of
	@# seventeen carrying the tool and never running it -- measured by
	@# grepping every sibling Makefile, sixteen run it.
	@#
	@# What it buys is the failure this document is most prone to. A heading
	@# that appears twice means whichever one you find, the other is the one
	@# with the answer; a named file that does not exist sends a reader
	@# looking for something that moved. Both are silent, both survive every
	@# other gate here, and project.md is 13000 lines and authoritative over
	@# the code.
	@#
	@# It found one on its first run: "What building it changed, 2026-08-28"
	@# was the heading of sec 13c's implementation notes AND of sec 15c's,
	@# two unrelated subjects, in a file that cites sections by name. The
	@# vendoring one is renamed; 13c's keeps the name its two citations use.
	python3 tool/style_gate.py docs
	@# EVERY SUBSYSTEM THIS LIBRARY LOGS UNDER IS ASSERTED BY A TEST.
	@# sec 211: a subsystem string is printed and never compared, so a
	@# misspelled one files a normal-looking line where nobody greps and no
	@# suite can fail on it. Refuses an empty sweep with its own exit code,
	@# because finding no emit sites means the detector stopped matching
	@# rather than that the tree is clean.
	python3 tool/log_gate.py

# Installs the commit-msg hook from tool/hooks/ into .git/hooks/. In the tree
# rather than only in .git so that it is reviewable, survives a clone, and can
# be diffed against its siblings in the other projects.
hooks:
	@install -m 0755 tool/hooks/commit-msg .git/hooks/commit-msg
	@echo "installed .git/hooks/commit-msg"
	@install -m 0755 tool/hooks/pre-push .git/hooks/pre-push
	@echo "installed .git/hooks/pre-push"

# Headers only. project.md sec 7 is explicit that this is not a system
# package and not a shared library -- a .so would put wire compatibility in
# the hands of whatever the distribution shipped, which is the failure a
# pinned submodule commit exists to prevent. DESTDIR is honoured because
# dh_auto_install calls it, and every private project honours it.
install: $(HDRS)
	@# The GUI headers ship only when they were built, which is the whole
	@# point of the option: a build without Qt installs no header that
	@# needs it. sec 140.
	@for h in $(HDRS) $(if $(GUI_ON),$(GUI_HDRS)); do \
		install -d $(DESTDIR)$(PREFIX)/include/fuzznet/`dirname $$h`; \
		install -m 0644 $$h $(DESTDIR)$(PREFIX)/include/fuzznet/$$h; \
	done
	@echo "installed `echo $(HDRS) $(if $(GUI_ON),$(GUI_HDRS)) | wc -w` header(s) under $(DESTDIR)$(PREFIX)/include/fuzznet"

# What do the suites never execute? Measured rather than assumed.
#
# Reports lines AND branches taken both ways, because the second is the
# honest number: 100% of lines is compatible with every decision in the
# library having only ever gone one way. It found two real gaps -- the
# malformed-argument guards of fzn_revocation_merge and fzn_split_at, each
# untested while its sibling function's was -- and one behaviour nobody had
# exercised, delegating a grant SHORTER than the chain allows.
#
# Instrumented objects go in their own BUILD_DIR: --coverage changes the
# objects, and mixing them with a plain build's is how a stale profile
# produces a number nobody can reproduce.
coverage:
	@test -n "$(BUILD_DIR)" || { echo "BUILD_DIR is empty; refusing"; exit 1; }
	@case "$(BUILD_DIR)" in /*) echo "BUILD_DIR must be relative; refusing"; exit 1 ;; esac
	@rm -rf $(BUILD_DIR)-coverage *.gcov
	@$(MAKE) --no-print-directory runtests BUILD_DIR=$(BUILD_DIR)-coverage \
	         CFLAGS="-Og -g --coverage" GEN_EXTRA="--coverage" >/dev/null
	@printf '%-30s %-14s %s\n' file lines "branches both ways"
	@unexercised=; \
	for c in $(SRCS); do \
		d=`dirname $$c`; \
		out=`gcov -b -o $(BUILD_DIR)-coverage/$$d $$c 2>/dev/null`; \
		l=`echo "$$out" | grep -m1 'Lines executed' | sed 's/.*://'`; \
		b=`echo "$$out" | grep -m1 'Taken at least once' | sed 's/.*://'`; \
		printf '%-30s %-14s %s\n' $$c "$$l" "$$b"; \
		case "$$l" in ""|0.00%*) unexercised="$$unexercised $$c" ;; esac; \
	done; \
	for c in $(GEN_SRCS); do \
		d=`dirname $$c`; \
		out=`gcov -b -o $(BUILD_DIR)-coverage/$$d $$c 2>/dev/null`; \
		l=`echo "$$out" | grep -m1 'Lines executed' | sed 's/.*://'`; \
		printf '%-30s %-14s %s\n' $$c "$$l" "(generated)"; \
		case "$$l" in ""|0.00%*) unexercised="$$unexercised $$c" ;; esac; \
	done; \
	rm -rf $(BUILD_DIR)-coverage *.gcov; \
	if [ -n "$$unexercised" ]; then \
		echo; \
		echo "coverage: NO TEST EXERCISES:$$unexercised"; \
		echo "coverage: a source linked into no test binary reports a blank"; \
		echo "coverage: line and exits 0, which is why this refuses instead."; \
		exit 1; \
	fi

# Refusing there rather than printing a blank is the point of the target
# beyond the numbers. Twice in one session a file reached the tree with
# nothing exercising it -- `fzn_peer_is_member`, added to answer a
# colleague's question rather than to fix a failing case, and
# `local/peer_linux.c`, believed untestable and not -- and both were found
# by a human reading the coverage table rather than by anything failing. A
# table nobody reads is a gate over an empty file list.

# Is the committed byte contract still what the schema says?
#
# project.md sec 7's reason for pinning a dependency is that this is a
# PROTOCOL: two hosts must agree about bytes, and a floating one is how they
# come to disagree silently. That reason applies hardest to the contract
# itself, so `wire/frame.situ.wire` and `.map` are committed and this target
# refuses when the schema has moved without them.
#
# SITU IS NOT A SUBMODULE, deliberately, and the distinction is what decides
# it: Monocypher is a submodule because it is LINKED -- its bytes end up in
# the binary. situ is a build-time tool. Vendoring it would make every clone
# carry a Python compiler and, worse, would push situc onto every consumer,
# since sec 7 has them compiling these sources into their own objects.
# fuzzypickles cross-compiles for Android; requiring situc there buys nothing
# at run time. Submodule what you link, not what you run at build time.
#
# So the schema's artifacts are committed and consumers need nothing extra.
# Checking them needs situc, which is why this is behind a variable and out
# of `make test`:
#
#   make schema SITU_DIR=../situ
#
# Without SITU_DIR it says what it would have checked rather than passing
# silently -- a target that no-ops when its tool is absent is a gate over an
# empty file list.
SITU_DIR ?=

# THE WIDGETS, RENDERED BY QTTY ONTO A CHARACTER CELL GRID. sec 158.
#
# NOT PART OF `make check`, on the same argument `make schema` uses: it needs
# a sibling checkout, and qtty is pre-alpha with the API movement its README
# promises. A gate that breaks for another tree's reasons is one people switch
# off, and the two guards that need nothing installed -- the format property
# in trust_view_test and the banned-call sweep in `make style` -- run in
# `check` where they belong.
#
# WHAT IT BUYS THAT THEY CANNOT. They assert what a widget HOLDS and what it
# does not CALL. This renders, and rendering is what found a trust view
# showing 63 hex digits of a 64-digit fingerprint at 80 columns while every
# text assertion passed.
#
# CHECKED AGAINST A COMMIT, NOT A WORKING TREE, which is `make schema`'s rule
# and its reason: comparing against $(QTTY_DIR) as it sits on disk makes the
# answer depend on whether anybody is mid-edit over there, and a session
# usually is. `git archive` touches nothing in their tree.
#
# QMAKE6 AND NOT QMAKE. Measured: qtty HEAD does not build under Qt 5 --
# `QPalette::Accent` is Qt 6.6 and later -- and the bare `qmake` on a Debian
# with both installed is Qt 5's. A first attempt here built for four minutes
# and failed on that, and a second failed again because qtty.pro is a subdirs
# project and the stale sub-Makefile from the first was still Qt 5's.
# DOES WHAT THIS ENCODES DECODE? sec 160.
#
# The only check that can answer it. `qr/test/qr_test.c` asserts shape --
# finders, timing, sizing, refusals -- and a QR code can satisfy every one of
# those and decode as nothing: the encoder was wrong in five separate ways
# during its first afternoon, and that suite would have passed four of them.
#
# QUIRC IS THE SECOND WITNESS, and it is an independent implementation rather
# than a second reading of this one -- `evidence.md`'s rule that a
# known-answer test generated by the code under test is one witness however
# many files it fills. It is vendored by fuzzypickles, which is why this takes
# a directory rather than a version.
#
# EVERY VERSION AND EVERY LEVEL, at each one's largest payload, because a
# per-version table error looks like nothing until the version that has it:
# the alignment coordinates were wrong for exactly version 14 and right for
# the other fourteen.
#
# PART OF `make check` SINCE sec 173, AND IT WAS NOT BEFORE.
#
# The reason it was excluded was written here and said "it needs a sibling
# checkout, and a gate that breaks for another tree's reasons is one people
# switch off". That reason EXPIRED when sec 169 vendored quirc, in the same
# session, and nobody noticed -- an exclusion outliving its own justification,
# which is the shape evidence.md calls a claim that outlived its subject.
#
# What it buys is the thing neither tree had. fuzzypickles proved its encoder
# against zbar and libqrencode once, recorded it, and then had to make the
# STANDING check use their own recogniser, because "a committed test cannot
# depend on a package that happens to be installed" -- so their gate is their
# encoder against their decoder, which they say plainly is not proof the
# symbol is readable by the rest of the world. Vendoring quirc removes exactly
# that constraint: an independent decoder that needs nothing installed can run
# every time.
#
# It SKIPS rather than fails when the vendored copy is missing, because that
# is an unfinished clone rather than a broken tree -- the three cases
# MONOCYPHER_DIR keeps apart, and the skip names the command. An override
# pointing at nothing is still an error: somebody asked for this by naming a
# path.
#
# The old comment, kept because it is still true of what it described: it needs a sibling
# checkout, and a gate that breaks for another tree's reasons is one people
# switch off.
#
# QUIRC IS VENDORED, AND THE DEFAULT IS THE VENDORED COPY. sec 169. It used to
# be reached at ../fuzzypickles/quirc, which had this library depending on its
# own CONSUMER: fuzzypickles vendors fuzznet, so the only independent witness
# the QR encoder has lived at a path that existed if you happened to have
# cloned a different project next door.
#
# The three cases are kept apart the way MONOCYPHER_DIR keeps them: empty is
# off, a missing vendored copy is an unfinished clone and names the command,
# and an OVERRIDE that points at nothing is an error rather than a skip --
# somebody asked for this by naming a path.
# QUIRC IS COMPILED SEPARATELY AND QUIETLY, which is not the same act as
# reducing a check's output. Built with this tree's flags it emitted 43
# warnings about code fuzznet does not own and will not change, and they
# buried the one line the target exists to print. Our own sources keep every
# flag; only the vendored translation units are compiled with -w.
QUIRC_VENDORED := quirc
QUIRC_DIR      ?= $(QUIRC_VENDORED)

# ONE SHELL, BECAUSE A SKIP MUST STOP THE TARGET. Written first as separate
# recipe lines with an `exit 0` in the skip, which does not skip anything:
# make gives each line its own shell, so the skip printed its notice and the
# next line then failed for the reason the skip had just excused. It reported
# SKIPPED and non-zero in one run -- both halves true and the pair meaningless,
# which is evidence.md's count-and-exit-code again.
qrcheck:
	@set -e; \
	if [ -z "$(QUIRC_DIR)" ]; then \
		echo "qrcheck: QUIRC_DIR is empty, so nothing DECODED what we encode."; \
		exit 1; \
	fi; \
	if [ ! -f "$(QUIRC_DIR)/lib/quirc.h" ]; then \
		if [ "$(QUIRC_DIR)" = "$(QUIRC_VENDORED)" ]; then \
			echo "qrcheck: SKIPPED -- the vendored $(QUIRC_VENDORED)/ is empty."; \
			echo "qrcheck: run 'git submodule update --init $(QUIRC_VENDORED)'."; \
			echo "qrcheck: nothing independent decoded what this tree encodes."; \
			exit 0; \
		fi; \
		echo "qrcheck: no quirc.h under $(QUIRC_DIR)/lib"; \
		exit 1; \
	fi; \
	scratch=$(BUILD_DIR)/.qrcheck; \
	case "$$scratch" in "" | "/" | "/*") \
		echo "qrcheck: refusing to work in '$$scratch'"; exit 1;; esac; \
	trap 'rm -rf "$$scratch"' EXIT INT TERM; \
	rm -rf "$$scratch"; mkdir -p "$$scratch"; \
	for u in quirc decode identify version_db; do \
		$(CC) $(GEN_CFLAGS) -w -I"$(QUIRC_DIR)/lib" -c \
		      "$(QUIRC_DIR)/lib/$$u.c" -o "$$scratch/$$u.o"; \
	done; \
	$(CC) $(CFLAGS) -I. -I"$(QUIRC_DIR)/lib" qr/test/qr_quirc_check.c qr/qr.c \
	      cli/qr_print.c "$$scratch"/quirc.o "$$scratch"/decode.o \
	      "$$scratch"/identify.o "$$scratch"/version_db.o \
	      -lm -o "$$scratch/qrcheck"; \
	"$$scratch/qrcheck"

#
# QTTY IS VENDORED TOO, and for a reason narrower than the dependency rule:
# nothing this library ships links it. sec 169. It is a test INSTRUMENT, and
# sec 158 and sec 159 recorded measurements taken THROUGH it -- so a live
# sibling meant those findings were measured against whatever that tree's HEAD
# happened to be, which is a method that cannot be re-run. The submodule pins
# it. A developer working on qtty itself points QTTY_DIR at their checkout.
QTTY_VENDORED := qtty
QTTY_DIR      ?= $(QTTY_VENDORED)

# THE RENDER SWEEP, AS PART OF `check` RATHER THAN ONLY ON REQUEST.
#
# `qtty` itself is strict: a developer who types it and cannot run it wants an
# error, not a shrug. This is the same work with the preconditions turned into
# SKIPS, so it rides with the widget suites -- `make GUI_ON=1 CLI_ON=1 check`
# renders every widget, and a plain `make check` says out loud that nothing
# did.
#
# It exists because the opt-in arrangement failed exactly as evidence.md says
# a check that runs only elsewhere fails. The target did not LINK for some
# time -- cli/provision_print.o was added to it without provision/provision.o
# -- and while it was unbuildable the sec 193 consolidation changed the wording
# of four widgets out from under its expectations. Nothing reported either,
# because nobody had reason to type the target. sec 205.
#
# A SKIP SAYS WHAT WAS NOT CHECKED. A silent one is a green line claiming
# coverage it never had, which is the whole failure above wearing a tidier
# face.
qttycheck:
	@if [ -z "$(GUI_ON)" ] || [ -z "$(CLI_ON)" ]; then \
		echo "qttycheck: SKIPPED -- the widgets are not built."; \
		echo "qttycheck: no widget was rendered on a character grid."; \
		echo "qttycheck: run 'make FZN_GUI=1 FZN_CLI=1 check' to include it."; \
		exit 0; \
	fi; \
	if [ -z "$(QTTY_DIR)" ] || [ ! -f "$(QTTY_DIR)/qtty.pro" ]; then \
		echo "qttycheck: SKIPPED -- no qtty under '$(QTTY_DIR)'."; \
		echo "qttycheck: run 'git submodule update --init $(QTTY_VENDORED)'."; \
		echo "qttycheck: no widget was rendered on a character grid."; \
		exit 0; \
	fi; \
	if ! command -v qmake6 >/dev/null 2>&1; then \
		echo "qttycheck: SKIPPED -- no qmake6, and qtty HEAD needs Qt 6."; \
		echo "qttycheck: no widget was rendered on a character grid."; \
		exit 0; \
	fi; \
	$(MAKE) --no-print-directory qtty

# THE OBJECTS THIS TARGET LINKS, AS A VARIABLE, SO THEY ARE ALSO
# PREREQUISITES. `qtty` had NONE AT ALL: it named twenty-eight objects on its
# link line and asked make for nothing, so on a freshly cleaned tree it failed
# in the linker naming a dozen files. It had never been seen to, because
# `check` runs `test` first and nobody had run this target alone after a
# `clean` -- which is the same shape as everything else in sec 219, a rule
# that is right only because of what ran before it.
#
# `build-and-commit.md`'s warning about `$^` is this one pointed the other
# way: there a header added to the prerequisites reaches the command line,
# here a command line has no prerequisites behind it. One variable is what
# keeps the two lists from being two lists.
#
# ONLY WHEN IT WILL ACTUALLY LINK. The recipe's first lines refuse without
# FZN_GUI and FZN_CLI, and building twenty-eight objects before printing that
# would be a slower way to say the same thing.
QTTY_RENDER_OBJS := $(BUILD_DIR)/cli/log_print.o $(BUILD_DIR)/qr/qr.o \
                    $(BUILD_DIR)/cli/manifest_print.o \
                    $(BUILD_DIR)/cli/ledger_print.o $(BUILD_DIR)/record/ledger.o \
                    $(BUILD_DIR)/cli/cli.o $(BUILD_DIR)/state/state.o \
                    $(BUILD_DIR)/cli/sync_print.o $(BUILD_DIR)/cli/journal_print.o \
                    $(BUILD_DIR)/cli/sweep_print.o $(BUILD_DIR)/cli/transfer_print.o \
                    $(BUILD_DIR)/cli/capability_print.o $(BUILD_DIR)/cli/state_print.o \
                    $(BUILD_DIR)/cli/revocation_print.o $(BUILD_DIR)/cli/authz_print.o \
                    $(BUILD_DIR)/cli/provision_print.o $(BUILD_DIR)/cli/link_print.o \
                    $(BUILD_DIR)/cli/peer_print.o $(BUILD_DIR)/local/peer.o \
                    $(BUILD_DIR)/provision/provision.o $(BUILD_DIR)/prekey/prekey.o \
                    $(BUILD_DIR)/local/vocabulary.o \
                    $(LINK_OBJ) $(BUILD_DIR)/sched/sched.o \
                    $(BUILD_DIR)/spool/spool.o $(BUILD_DIR)/spool/plan.o \
                    $(BUILD_DIR)/spool/transfer.o $(BUILD_DIR)/blob/blob.o \
                    $(BUILD_DIR)/trust/trust.o $(BUILD_DIR)/log/log.o \
                    $(BUILD_DIR)/record/journal.o $(BUILD_DIR)/record/record.o \
                    $(BUILD_DIR)/chain/authz.o $(BUILD_DIR)/chain/chain.o \
                    $(BUILD_DIR)/chain/revocation.o $(BUILD_DIR)/chain/manifest.o \
                    $(FLOG_OBJS) \
                    $(BUILD_DIR)/catalog/sweep.o $(BUILD_DIR)/catalog/catalog.o \
                    $(BUILD_DIR)/constant_time/constant_time.o

qtty: $(if $(and $(GUI_ON),$(CLI_ON)),$(QTTY_RENDER_OBJS))
	@if [ -z "$(QTTY_DIR)" ]; then \
		echo "qtty: QTTY_DIR is empty, so the widgets were NOT rendered."; \
		exit 1; \
	fi
	@test -f "$(QTTY_DIR)/qtty.pro" || { \
		if [ "$(QTTY_DIR)" = "$(QTTY_VENDORED)" ]; then \
			echo "qtty: the vendored $(QTTY_VENDORED)/ is empty."; \
			echo "qtty: run 'git submodule update --init $(QTTY_VENDORED)'."; \
		else \
			echo "qtty: no qtty.pro under $(QTTY_DIR)"; \
		fi; exit 1; }
	@command -v qmake6 >/dev/null 2>&1 || { \
		echo "qtty: no qmake6, and qtty HEAD does not build under Qt 5"; exit 1; }
	@test -n "$(GUI_ON)" || { \
		echo "qtty: the widgets are not built -- this needs FZN_GUI"; exit 1; }
	@# THE LOG VIEW RENDERS THROUGH cli/log_print SINCE sec 168, so this
	@# needs FZN_CLI as well -- and it links the OBJECT rather than
	@# compiling the .c here, because $(CXX) would mangle its symbols and
	@# they would not match the C-built log/log.o. Measured by the linker.
	@test -n "$(CLI_ON)" || { \
		echo "qtty: the log view needs FZN_CLI -- add CLI_ON=1"; exit 1; }
	@# ONE SHELL WITH A TRAP, BECAUSE A FAILURE HERE LEAVES A SOURCE TREE IN
	@# THE REPOSITORY. Measured the hard way: BUILD_DIR defaults to `.`, so
	@# the scratch is `./.qtty` -- and the first failing run of this target
	@# left 9.6 MB of qtty's sources in fuzznet's root, where `make style`
	@# duly walked them and reported 1070 convention violations in 321
	@# files. A recipe that cleans up only on the success path does not
	@# clean up, since failure is when there is something to clean up.
	@#
	@# `.qtty/` is in .gitignore as well, which is the backstop rather than
	@# the fix: it stops a leftover being committed and does nothing about
	@# the gate that reads the working tree.
	@# ONE SCRATCH PER RUN, NAMED BY PID. sec 208.
	@#
	@# It was `$(BUILD_DIR)/.qtty`, fixed -- and every run does `rm -rf` on
	@# it at the start AND again from its exit trap. So two concurrent runs
	@# destroy each other deterministically rather than racily: the second
	@# one's `rm -rf` deletes the first's unpacked tree mid-build, and the
	@# first's trap deletes the second's. The failure surfaces as
	@# "their library would not build", which blames qtty for a collision
	@# in this file.
	@#
	@# It became reachable when sec 205 put this sweep into `make check`:
	@# these trees have more than one session, and two of them running
	@# `make check` is the ordinary case rather than an exotic one.
	@#
	@# The `.qtty-` PREFIX is kept because sec 205's style-gate prune
	@# depends on it -- a scratch left behind by a killed run is still
	@# pruned, and a random name would have defeated that.
	@set -e; \
	scratch=$(BUILD_DIR)/.qtty-$$$$; \
	case "$$scratch" in "" | "/" | "/*" | "$(BUILD_DIR)/.qtty-") \
		echo "qtty: refusing to work in '$$scratch'"; exit 1;; esac; \
	trap 'rm -rf "$$scratch"' EXIT INT TERM; \
	rm -rf "$$scratch"; mkdir -p "$$scratch"; \
	if git -C "$(QTTY_DIR)" rev-parse --git-dir >/dev/null 2>&1; then \
		git -C "$(QTTY_DIR)" archive HEAD | tar -x -C "$$scratch"; \
		echo "qtty: against qtty `git -C $(QTTY_DIR) rev-parse --short HEAD`"; \
	else \
		echo "qtty: $(QTTY_DIR) is not a git checkout, so nothing can be pinned"; \
		exit 1; \
	fi; \
	( cd "$$scratch" && qmake6 qtty.pro >/dev/null 2>&1 && \
	  $(MAKE) -j4 >qtty-build.log 2>&1 ) || { \
		echo "qtty: their library would not build; the log goes with the scratch"; \
		exit 1; }; \
	test -f "$$scratch/lib/libqtty.a" || { \
		echo "qtty: the build reported success and produced no libqtty.a"; exit 1; }; \
	qflags=; qobjs=; \
	if [ -n "$(QUIRC_DIR)" ]; then \
		test -f "$(QUIRC_DIR)/lib/quirc.h" || { \
			echo "qtty: no quirc.h under $(QUIRC_DIR)/lib"; exit 1; }; \
		mkdir -p "$$scratch/quirc"; \
		for f in quirc decode identify version_db; do \
			$(CC) $(GEN_CFLAGS) -w -I"$(QUIRC_DIR)/lib" -c \
			      "$(QUIRC_DIR)/lib/$$f.c" -o "$$scratch/quirc/$$f.o"; \
		done; \
		qflags="-DFZN_HAVE_QUIRC -I$(QUIRC_DIR)/lib"; \
		qobjs="$$scratch/quirc/quirc.o $$scratch/quirc/decode.o \
		       $$scratch/quirc/identify.o $$scratch/quirc/version_db.o -lm"; \
		echo "qtty: with quirc, so the render is DECODED as well as shaped"; \
	else \
		echo "qtty: QUIRC_DIR unset -- the render is checked for SHAPE only."; \
		echo "qtty: add QUIRC_DIR=../fuzzypickles/quirc to decode it too."; \
	fi; \
	$(CXX) $(CXXFLAGS_BUILD) $(CXXFLAGS_WARN) $(QT_CFLAGS) $$qflags -I"$$scratch/include" \
	       gui/test/qtty_render_test.cpp gui/trust_view.cpp gui/log_view.cpp \
	       gui/qr_view.cpp gui/authz_view.cpp gui/capability_view.cpp \
	       gui/sweep_view.cpp gui/revocation_view.cpp gui/journal_view.cpp \
	       gui/sync_view.cpp gui/transfer_view.cpp gui/state_view.cpp \
	       gui/config_view.cpp gui/link_view.cpp gui/peer_view.cpp \
	       gui/manifest_view.cpp gui/ledger_view.cpp gui/sched_view.cpp \
	       gui/provision_view.cpp \
	       $(QTTY_RENDER_OBJS) \
	       "$$scratch/lib/libqtty.a" $$qobjs $(QT_LIBS) -o "$$scratch/render_test"; \
	"$$scratch/render_test"

schema:
	@if [ -z "$(SITU_DIR)" ]; then \
		echo "schema: SITU_DIR unset, so the committed contract was NOT checked."; \
		echo "schema: run 'make schema SITU_DIR=../situ' to verify it."; \
		exit 1; \
	fi
	@test -x "$(SITU_DIR)/bin/situc" || { echo "schema: no situc at $(SITU_DIR)/bin"; exit 1; }
	@# CHECKED AGAINST A COMMIT, NOT AGAINST A WORKING TREE.
	@#
	@# Everything below compares this repository's committed artifacts with
	@# what situ produces. Comparing against $(SITU_DIR) as it sits on disk
	@# makes that answer depend on whether anybody is mid-edit over there --
	@# and a session usually is.
	@#
	@# Both failure directions happened here within a minute. The target
	@# refused, naming our vendored runtime as drifted; our copy turned out
	@# identical to situ's HEAD, and the difference was an uncommitted
	@# change in their working tree. Re-vendoring "to fix the drift" then
	@# took that work in progress and stamped it with a commit hash that
	@# does not contain it -- a provenance banner that was a lie, and a
	@# check that would afterwards have passed. The dangerous direction is
	@# the pass, not the failure.
	@#
	@# So HEAD is extracted read-only with `git archive`, which touches
	@# nothing in their tree -- no worktree, no stash, no checkout, all of
	@# which would disturb a session working there. The commit is printed,
	@# because "matches situ" is not a claim and "matches situ at cd0cb01"
	@# is.
	@rm -rf $(BUILD_DIR)/.situ-head && mkdir -p $(BUILD_DIR)/.situ-head
	@if git -C "$(SITU_DIR)" rev-parse --git-dir >/dev/null 2>&1; then \
		git -C "$(SITU_DIR)" archive HEAD | tar -x -C $(BUILD_DIR)/.situ-head; \
		echo "schema: against situ `git -C $(SITU_DIR) rev-parse --short HEAD`"; \
	else \
		echo "schema: $(SITU_DIR) is not a git checkout, so nothing can be pinned"; \
		rm -rf $(BUILD_DIR)/.situ-head; exit 1; \
	fi
	@$(BUILD_DIR)/.situ-head/bin/situc wire --check wire/frame.situ
	@$(BUILD_DIR)/.situ-head/bin/situc map wire/frame.situ > $(BUILD_DIR)/.frame.map.new
	@if ! cmp -s $(BUILD_DIR)/.frame.map.new wire/frame.situ.map; then \
		echo "schema: wire/frame.situ.map is stale -- the schema moved without it"; \
		rm -f $(BUILD_DIR)/.frame.map.new; exit 1; \
	fi
	@rm -f $(BUILD_DIR)/.frame.map.new
	@# The generated C and the vendored runtime, same argument as the
	@# contract: committed so consumers need no situc, checked so they
	@# cannot quietly diverge from the schema that produced them.
	@rm -rf $(BUILD_DIR)/.gen.new && mkdir -p $(BUILD_DIR)/.gen.new
	@$(BUILD_DIR)/.situ-head/bin/situc build --target c --layer relate \
	         --out $(BUILD_DIR)/.gen.new wire/frame.situ >/dev/null 2>&1
	@# AND THE TAMPER HARNESS, on exactly the same argument. It is
	@# `wire/test/tamper_test.c`'s statement of which bytes the tag reaches,
	@# and a harness that could drift from the schema is worth less than the
	@# hand-written cases it supplements: it would keep flipping the bytes
	@# the layout used to have and keep reporting SITU_OK.
	@#
	@# `--out` IS NOT DECORATION HERE. `situc gen-tamper` writes
	@# `frame_tamper.h` into the CURRENT DIRECTORY by default rather than to
	@# stdout, so a run of it from a repository root drops a header in the
	@# root -- which is how this was first met. Naming the scratch directory
	@# keeps every byte situc writes inside $(BUILD_DIR), which is already
	@# gitignored and already removed below, so a situc that fails halfway
	@# leaves a partial file there for the comparison to refuse and never a
	@# half-written header in wire/.
	@$(BUILD_DIR)/.situ-head/bin/situc gen-tamper wire/frame.situ \
	         --out $(BUILD_DIR)/.gen.new >/dev/null 2>&1 || { \
		echo "schema: situc gen-tamper failed"; \
		rm -rf $(BUILD_DIR)/.gen.new $(BUILD_DIR)/.situ-head; exit 1; }
	@for f in frame.c frame.h frame_relate.c frame_relate.h frame_tamper.h; do \
		cmp -s $(BUILD_DIR)/.gen.new/$$f wire/generated/$$f || { \
			echo "schema: wire/generated/$$f is stale"; \
			rm -rf $(BUILD_DIR)/.gen.new $(BUILD_DIR)/.situ-head; exit 1; }; \
	done
	@for f in situ.h situ.c; do \
		tail -n +2 wire/generated/$$f | sed '1,/^ \*\//d' > $(BUILD_DIR)/.gen.new/$$f.body; \
		cmp -s $(BUILD_DIR)/.gen.new/$$f.body $(BUILD_DIR)/.situ-head/runtime/c/$$f || { \
			echo "schema: wire/generated/$$f has drifted from situ's runtime"; \
			rm -rf $(BUILD_DIR)/.gen.new $(BUILD_DIR)/.situ-head; exit 1; }; \
	done
	@rm -rf $(BUILD_DIR)/.gen.new
	@rm -rf $(BUILD_DIR)/.situ-head
	@echo "schema: contract, map, generated C, tamper harness and vendored runtime all match"

# Does a consumer outside this tree still work? Nothing else asks.
#
# project.md sec 10 step 5 makes netcfgd's agent the first real consumer and
# sec 7 says how it takes this library: a submodule, sources compiled into
# its own objects, no archive. Every suite here builds from inside the tree,
# which is the one arrangement a consumer never has. Two silent failures
# follow from that and this target is what catches them -- a header added to
# a module and not to HDRS, which is hand-maintained and read back by
# nothing; and a relative include between modules that resolves in the
# source layout and not in the installed one.
#
# The staging directory is created here and removed here. It is guarded
# rather than trusted: an unset BUILD_DIR would make the rm below something
# else entirely, which is the failure `build-and-commit.md` names.
# Depends on the OBJECTS as well as the sources now, because the symbol probe
# below reads them. Naming them as prerequisites is what makes the probe's
# subject exist; the explicit absence check inside is the backstop for anyone
# who runs the recipe another way.
installcheck: $(HDRS) $(SRCS) $(OBJS) tool/consumer_check.c
	@test -n "$(BUILD_DIR)" || { echo "BUILD_DIR is empty; refusing"; exit 1; }
	@# Every installed header must be one the consumer actually includes.
	@# Without this the target's guarantee narrows silently as modules are
	@# added: it can only catch a break in a header somebody remembered to
	@# include, and `session/commitment.h` and `local/peer.h` were both
	@# installed and unchecked for several commits.
	@# AN #include LINE, NOT A MENTION. This asked `grep -q "$$h"` for the
	@# header's NAME anywhere in the file, and a name in a COMMENT satisfied
	@# that as loudly as a real include -- so the gate could report a header
	@# checked while nothing compiled it. The dead-`#ifdef` form of the same
	@# vacuity has already bitten once here and was fixed by hand, which is
	@# the argument for closing the prose form before it does.
	@#
	@# Measured before tightening rather than after: all 40 entries already
	@# match the stricter pattern, so this refuses nothing that passes today.
	@# The optional `fuzznet/` is what makes one pattern cover both forms the
	@# file carries -- `<fuzznet/chain/chain.h>` installed and
	@# `"chain/chain.h"` from the source tree.
	@#
	@# It still cannot tell a live include from one in a branch this
	@# arrangement does not compile; only asking the compiler for its
	@# dependency list would, and that is a bigger change than the gap
	@# currently justifies. persist_file.h and spool_file.h are the two
	@# conditional includes, and the Makefile turns their define on in the
	@# same place it adds them to HDRS, so the two cannot disagree.
	@missing=; \
	for h in $(HDRS); do \
		grep -qE "^[ \t]*#[ \t]*include[ \t]*[<\"](fuzznet/)?$$h[\">]" \
		     tool/consumer_check.c || missing="$$missing $$h"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "installcheck: installed but not included by the consumer:$$missing"; \
		echo "installcheck: the check would pass whatever those headers did."; \
		exit 1; \
	fi
	@case "$(BUILD_DIR)" in /*) echo "BUILD_DIR must be relative; refusing"; exit 1 ;; esac
	@rm -rf $(BUILD_DIR)/installcheck
	@$(MAKE) --no-print-directory install DESTDIR=$(BUILD_DIR)/installcheck PREFIX=/usr >/dev/null
	@# FIRST, THE ARRANGEMENT A CONSUMER ACTUALLY HAS: the core sources, the
	@# installed headers, and Monocypher nowhere on the command line. This
	@# arm is the one that can fail if a core source ever grows an include
	@# of a primitive, and it is deliberately first because the two arms
	@# below cannot: they hand the compiler Monocypher, so a core source
	@# that included it would compile there and be found by nobody.
	@echo "installcheck: the core alone, with no Monocypher anywhere"
	@# NO SUBSYSTEM DEFINES ON THIS ARM. It compiles CORE_SRCS, which is
	@# frozen before any subsystem can append to it -- so claiming a
	@# subsystem here would promise a symbol this arm does not link, which
	@# is what it did for one build until the linker said so. The core arm
	@# is about the core.
	@$(CC) $(CFLAGS) -DFZN_CONSUMER_INSTALLED \
	       -I$(BUILD_DIR)/installcheck/usr/include \
	       -o $(BUILD_DIR)/installcheck/consumer_core \
	       -Iwire/generated tool/consumer_check.c $(CORE_SRCS) $(GEN_SRCS)
	@$(BUILD_DIR)/installcheck/consumer_core
	@# THAT ARM'S REAL FORCE IS THE LINK, and it is worth saying which
	@# failure it is. A core source that INCLUDED <monocypher.h> would not
	@# compile, there being no include path; one that CALLED a primitive
	@# through a declaration of its own would compile and fail to link. Both
	@# are hard failures of the arm above, so there is nothing left for a
	@# symbol probe to add on that side -- a linked binary has no undefined
	@# crypto symbol to find, because it could not have linked.
	@#
	@# WHAT THE LINK CANNOT SEE is a core source that DEFINES a primitive --
	@# a copy of BLAKE2b pasted into the tree links perfectly and gives a
	@# consumer the second implementation sec 15c exists to prevent. So the
	@# probe asks the object files for definitions, not the binary for
	@# references.
	@#
	@# AND IT CARRIES ITS CONTROL, because an empty answer otherwise means
	@# only that the pattern was wrong. The same pattern is run against a
	@# translation unit known to define these -- the vendored monocypher.o --
	@# and must find some. Without that this is evidence.md's probe that
	@# could not have succeeded, reported as a clean result.
	@if [ -n "$(MONO_ON)" ]; then \
		if [ ! -f $(BUILD_DIR)/monocypher.o ]; then \
			echo "installcheck: monocypher.o absent, so the control cannot run."; \
			exit 1; \
		fi; \
		ctl=`nm --defined-only $(BUILD_DIR)/monocypher.o 2>/dev/null \
		     | grep -Ec '$(CRYPTO_SYMS)'`; \
		if [ "$$ctl" = "0" ]; then \
			echo "installcheck: the crypto-symbol pattern matches nothing in"; \
			echo "installcheck: monocypher.o -- the probe below proves nothing."; \
			exit 1; \
		fi; \
		echo "installcheck: symbol probe verified against monocypher.o ($$ctl symbols)"; \
	fi
	@# AND THE OBJECTS MUST BE THERE TO ASK. nm over a path that does not
	@# exist prints a diagnostic and nothing else, which greps to empty and
	@# reads exactly like a clean core -- the vacuous pass one more time, in
	@# the check written to stop one. This target does not depend on the
	@# objects, so a probe run before a build would have found nothing every
	@# time; the count is what makes the difference visible.
	@absent=; for o in $(CORE_SRCS:%.c=$(BUILD_DIR)/%.o) $(GEN_OBJS); do \
		[ -f "$$o" ] || absent="$$absent $$o"; \
	done; \
	if [ -n "$$absent" ]; then \
		echo "installcheck: cannot probe -- objects absent:$$absent"; \
		echo "installcheck: run 'make' first; an unbuilt probe finds nothing."; \
		exit 1; \
	fi
	@defined=`nm --defined-only $(CORE_SRCS:%.c=$(BUILD_DIR)/%.o) $(GEN_OBJS) 2>/dev/null \
	          | grep -E '$(CRYPTO_SYMS)'`; \
	if [ -n "$$defined" ]; then \
		echo "installcheck: a core object DEFINES a crypto primitive:"; \
		echo "$$defined" | sed 's/^/  /'; \
		exit 1; \
	fi
	@echo "installcheck: against the installed headers"
	@$(CC) $(CFLAGS) $(if $(PERSIST_FILE_ON),-DFZN_PERSIST_FILE_ON) $(if $(SPOOL_FILE_ON),-DFZN_SPOOL_FILE_ON) $(if $(CLAIM_FILE_ON),-DFZN_CLAIM_FILE_ON) $(if $(RECORD_STORE_FILE_ON),-DFZN_RECORD_STORE_FILE_ON) $(if $(CLI_ON),-DFZN_CLI_ON) -DFZN_CONSUMER_INSTALLED \
	       -I$(BUILD_DIR)/installcheck/usr/include \
	       -o $(BUILD_DIR)/installcheck/consumer_installed \
	       -Iwire/generated $(MONO_CONSUMER) tool/consumer_check.c $(SRCS) $(GEN_SRCS)
	@$(BUILD_DIR)/installcheck/consumer_installed
	@echo "installcheck: against the source tree, from another directory"
	@cd $(BUILD_DIR)/installcheck && $(CC) $(CFLAGS) \
	       $(if $(PERSIST_FILE_ON),-DFZN_PERSIST_FILE_ON) $(if $(SPOOL_FILE_ON),-DFZN_SPOOL_FILE_ON) $(if $(CLAIM_FILE_ON),-DFZN_CLAIM_FILE_ON) $(if $(RECORD_STORE_FILE_ON),-DFZN_RECORD_STORE_FILE_ON) $(if $(CLI_ON),-DFZN_CLI_ON) -I$(CURDIR) \
	       -I$(CURDIR)/wire/generated \
	       -o consumer_source $(CURDIR)/tool/consumer_check.c \
	       $(patsubst %,$(CURDIR)/%,$(SRCS)) \
	       $(patsubst %,$(CURDIR)/%,$(GEN_SRCS)) $(MONO_CONSUMER)
	@$(BUILD_DIR)/installcheck/consumer_source
	@# THE FOREIGN BUILD, DRIVEN BY `make manifest` AND NOTHING ELSE. This
	@# arm exists to make the manifest load-bearing: it reads the emitted
	@# lines, builds a command line from them, and compiles the same
	@# consumer. A manifest that omits a source fails to link here rather
	@# than failing in somebody else's tree a week later, which is the
	@# whole difference between a generated list and a transcribed one.
	@#
	@# NO MONOCYPHER ON THIS LINE, deliberately. README promises a consumer
	@# compiling the core gets it nowhere on the command line, and the
	@# manifest's `source` lines are that core -- so this arm is also the
	@# proof that following the manifest cannot silently pull a primitive
	@# in. The bindings are emitted under `binding` and not compiled here,
	@# which is what the split means.
	@echo "installcheck: against the manifest a foreign build would read"
	@$(MAKE) --no-print-directory manifest > $(BUILD_DIR)/installcheck/manifest.txt
	@srcs=; incs=; \
	while read -r key val; do \
		case "$$key" in \
		source|generated) srcs="$$srcs $(CURDIR)/$$val" ;; \
		include) incs="$$incs -I$(CURDIR)/$$val" ;; \
		esac; \
	done < $(BUILD_DIR)/installcheck/manifest.txt; \
	test -n "$$srcs" || { \
		echo "installcheck: the manifest named no sources"; exit 1; \
	}; \
	cd $(BUILD_DIR)/installcheck && $(CC) $(CFLAGS) $$incs \
	       -o consumer_manifest $(CURDIR)/tool/consumer_check.c $$srcs
	@$(BUILD_DIR)/installcheck/consumer_manifest
	@# THE HEADERS MUST PARSE AS C++, AND THE LIST IS DERIVED FROM HDRS
	@# rather than written out, so it cannot fall behind the way a second
	@# hand-maintained list would. Three headers used `_Static_assert`,
	@# which C++ does not have, and no consumer had ever been C++ -- so the
	@# defect was found by the first Qt widget instead of by a gate. This
	@# arm is what stops that arriving again. sec 140.
	@if [ "$(FZN_PROBE_CXX)" = yes ]; then \
		mkdir -p $(BUILD_DIR)/installcheck; \
		: > $(BUILD_DIR)/installcheck/cxx_headers.cpp; \
		for h in $(HDRS); do \
			echo "#include \"$(CURDIR)/$$h\"" \
			        >> $(BUILD_DIR)/installcheck/cxx_headers.cpp; \
		done; \
		n=`grep -c include $(BUILD_DIR)/installcheck/cxx_headers.cpp`; \
		test "$$n" -gt 0 || { \
			echo "installcheck: the C++ arm was handed no headers, so"; \
			echo "installcheck: passing it would prove nothing."; exit 1; }; \
		echo "int main(void) { return 0; }" \
		        >> $(BUILD_DIR)/installcheck/cxx_headers.cpp; \
		$(if $(CXX),$(CXX),c++) -x c++ -std=c++17 -Wall -Wextra -I$(CURDIR) \
		       -I$(CURDIR)/wire/generated -Imonocypher/src \
		       $(if $(PERSIST_FILE_ON),-DFZN_PERSIST_FILE_ON) \
		       $(if $(SPOOL_FILE_ON),-DFZN_SPOOL_FILE_ON) \
		       $(if $(CLAIM_FILE_ON),-DFZN_CLAIM_FILE_ON) \
		       $(if $(RECORD_STORE_FILE_ON),-DFZN_RECORD_STORE_FILE_ON) \
		       $(if $(CLI_ON),-DFZN_CLI_ON) \
		       -c $(BUILD_DIR)/installcheck/cxx_headers.cpp \
		       -o $(BUILD_DIR)/installcheck/cxx_headers.o \
		|| { echo "installcheck: the public headers do not parse as C++;"; \
		     echo "installcheck: a C++ consumer cannot include them."; exit 1; }; \
		echo "installcheck: $$n public headers parse as C++"; \
	else \
		echo "installcheck: no C++ compiler, so the C++ header arm was skipped"; \
	fi
	@rm -rf $(BUILD_DIR)/installcheck
	@echo "installcheck: all four arrangements build and run"

# WHAT A FOREIGN BUILD SYSTEM NEEDS, emitted rather than transcribed.
#
# README says a consumer compiles CORE_SRCS, and that sentence is the whole
# integration contract -- but a consumer whose build is not make has to COPY
# the list into its own files. fuzzypickles vendors this tree as a source
# subdirectory under a CMake parent, which is the arrangement `installcheck`
# already compiles; what it does not have is a way to learn the list without
# reading this file and writing it down somewhere else.
#
# A COPIED LIST IS THE FAILURE THIS TREE KEEPS CLOSING. `constants_test.c`
# exists because four modules restate a length the schema also defines;
# `installcheck` exists because HDRS is hand-maintained and nothing read it
# back. A consumer's transcription of CORE_SRCS is the same shape one tree
# further out, and it goes stale silently every time a module is added --
# which happened six times in one day on 2026-09-01.
#
# The format is one `key value` per line so that anything can read it:
# CMake's file(STRINGS), a shell loop, or a person. Sources are relative to
# this directory, which is the only root a vendoring consumer has.
#
# IT IS NOT A CHECKED-IN FILE. Generating it on demand is what stops it
# becoming the stale copy it exists to prevent, and `installcheck` compiles
# a consumer from nothing but this output, so a manifest that omits a source
# fails to link rather than being believed.
manifest:
	@echo "# fuzznet build manifest -- generated by \`make manifest\`"
	@# THE VERSION COMES FROM THE HEADER, not from a Makefile variable that
	@# would be a second place to change it. version/version.h is where
	@# `fzn_version_string` reads it from too.
	@printf 'version %s.%s.%s\n' \
	  `sed -n 's/^#define FZN_VERSION_MAJOR *//p' version/version.h` \
	  `sed -n 's/^#define FZN_VERSION_MINOR *//p' version/version.h` \
	  `sed -n 's/^#define FZN_VERSION_PATCH *//p' version/version.h`
	@for c in $(CORE_SRCS); do echo "source $$c"; done
	@for c in $(GEN_SRCS); do echo "generated $$c"; done
	@# AND THE HEADERS, because some of them are code.
	@#
	@# A header carrying `static inline` bodies is compiled into every
	@# consumer's translation unit, which makes it more exposed than a `.c`
	@# rather than less -- and record/record.h holds eleven such bodies, every
	@# accessor of the richest format here. The sabotage census read this
	@# target for its population and this target named no header, so that file
	@# had never been sabotaged while a coverage figure was printed over 92 of
	@# 93 sources. project.md sec 234.
	@#
	@# Emitted whole rather than filtered to the ones with bodies: which
	@# headers are code is a question about their contents, and the reader
	@# already has to open them to answer it.
	@for h in $(HDRS); do echo "header $$h"; done
	@echo "include ."
	@echo "include wire/generated"
	@# WHAT IS OPTIONAL IS NAMED SEPARATELY AND CARRIES ITS OWN DEFINE.
	@#
	@# The first draft emitted bare `define` lines from this build's own
	@# configuration while `source` held CORE_SRCS -- which excludes the
	@# file backends -- so it described an arrangement that does not link:
	@# the define switches a consumer's block on and the source that
	@# satisfies it was never named. The manifest arm caught it, which is
	@# the argument for the arm.
	@#
	@# CORE_SRCS EXCLUDES BOTH ON PURPOSE, and installcheck's own core arm
	@# says so in as many words -- "no subsystem defines on this arm". A
	@# binding needs the consumer's Monocypher; a backend needs its define.
	@# Neither is something a consumer should acquire by following a list,
	@# so each is named with what it costs and taken deliberately.
	@for c in $(MONO_SRCS); do echo "binding $$c"; done
	@$(if $(PERSIST_FILE_ON),echo "backend persist/persist_file.c FZN_PERSIST_FILE_ON";)
	@$(if $(CLAIM_FILE_ON),echo "backend claim/claim_file.c FZN_CLAIM_FILE_ON";)
	@$(if $(RECORD_STORE_FILE_ON),echo "backend record/store_file.c FZN_RECORD_STORE_FILE_ON";)
	@# ONE LINE PER SOURCE, as `binding` and `backend` already are. These two
	@# were a hand-written literal naming `cli/cli.c` and a bare directory
	@# `gui/`, and the first had drifted: CLI_SRCS holds sixteen files, so a
	@# consumer following this output built the parser and none of the
	@# fifteen printers. Nothing read these lines back -- they were the only
	@# kind in this target no gate checked -- which is how a list that said
	@# one where the tree has sixteen went unnoticed. The sabotage census
	@# reads them now. project.md sec 225.
	@$(if $(CLI_ON),for c in $(CLI_SRCS); do echo "subsystem $$c FZN_CLI_ON"; done;)
	@$(if $(GUI_ON),for c in $(GUI_SRCS); do \
		echo "subsystem $$c FZN_GUI_ON against $(FZN_PROBE_QT)"; done;)
	@$(if $(SPOOL_FILE_ON),echo "backend spool/spool_file.c FZN_SPOOL_FILE_ON";)

# Named targets only, and it lists them. No rm -rf of a directory and no
# wildcard sweep: a clean target is the one thing everybody runs without
# reading, and an unset variable in an `rm -rf $(VAR)` is how one eats
# something it should not.
# WHAT THE MONOCYPHER BINDING BUILT IS NAMED UNCONDITIONALLY, because the
# build that made those files and the one running `clean` need not agree
# about whether the binding was on.
#
# OBJS, TEST_OBJS and TEST_BINS gain the Monocypher half only inside the
# `ifdef MONO_ON` above, so `make test MONOCYPHER_DIR=...` followed by a plain
# `make clean` left thirteen objects and three binaries in the tree and
# printed "fuzznet: clean". That is build-and-commit.md's warning in its other
# direction: a clean target that removes LESS than was built, and says so as
# loudly as one that removed everything. It survives the vendored default,
# which only moves the case: `make clean MONOCYPHER_DIR=` is now the way to
# reach it.
#
# Named rather than globbed, per the same rule. MONO_SRCS and MONO_TSRC are
# already outside the conditional for the style check, so the names are here
# to be had; monocypher.o is the vendored upstream source and is spelled out.
MONO_CLEAN := $(MONO_SRCS:%.c=$(BUILD_DIR)/%.o) $(MONO_SRCS:%.c=$(BUILD_DIR)/%.d) \
              $(MONO_TSRC:%.c=$(BUILD_DIR)/%.o) $(MONO_TSRC:%.c=$(BUILD_DIR)/%.d) \
              $(MONO_TSRC:%.c=$(BUILD_DIR)/%) \
              $(BUILD_DIR)/monocypher.o $(BUILD_DIR)/monocypher.d

clean:
	@# THE SANITIZER TREE, which `sancheck` keeps between runs so that an
	@# incremental build is possible and the gate costs the test time rather
	@# than a full rebuild. Removed here by directory rather than by named
	@# file, which `build-and-commit.md` permits for exactly this shape -- a
	@# tree the build created and owns -- and only after checking the path
	@# is non-empty and relative, because an unset variable in an `rm -rf`
	@# is how a clean target eats something it should not.
	@test -n "$(BUILD_DIR)" || { echo "BUILD_DIR is empty; refusing"; exit 1; }
	@case "$(BUILD_DIR)" in /*) echo "BUILD_DIR must be relative; refusing"; exit 1 ;; esac
	@if [ -d "$(BUILD_DIR)-san" ]; then \
		echo "removing $(BUILD_DIR)-san"; \
		rm -rf "$(BUILD_DIR)-san"; \
	fi
	@# THE CODEGEN CONTROLS, which `ctcheck` compiles from a sed of a real
	@# source into $(BUILD_DIR)/tool/ and which were in no list here. They
	@# have no `.d`: both are built from stdin with $(FZN_PROBE_CPPFLAGS),
	@# which filters -MMD out for the reason the probe rules give.
	@for f in $(OBJS) $(TEST_OBJS) $(DEPS) $(TEST_BINS) $(MONO_CLEAN) \
	          $(FLOG_CLEAN) $(GUI_CLEAN) $(BUILD_DIR)/tool/ct_control.o \
	          $(BUILD_DIR)/tool/wipe_control.o; do \
		if [ -e "$$f" ]; then echo "removing $$f"; rm -f "$$f"; fi; \
	done
	@# CLEAN CHECKS ITS OWN WORK, which is the only way "quietly removed
	@# nothing" and "removed everything" stop looking alike. Only for the
	@# in-place default: an out-of-tree BUILD_DIR leaves the tree with no
	@# artifacts to find whether it worked or not.
	@#
	@# THE VENDORED TREE IS PRUNED, and here that matters twice over. This
	@# build never writes into it -- monocypher.o is kept under $(BUILD_DIR),
	@# which is fuzzypickles' refinement and keeps the checkout clean -- but
	@# somebody who ran the submodule's OWN makefile would leave objects
	@# there, and without the prune `clean` would fail naming files it must
	@# not remove. build-and-commit.md forbids a `find .` from the root that
	@# walks a vendored tree, and the check is the one place here that still
	@# does one.
	@if [ "$(BUILD_DIR)" = "." ]; then \
		left=`find . \( -name '*.o' -o -name '*.d' -o -name '*.gcno' \
		                 -o -name '*.gcda' \) -not -path './.git/*' \
		                 -not -path './.claude/*' $(VENDOR_PRUNE) | sort`; \
		if [ -n "$$left" ]; then \
			echo "clean: build artifacts survived:"; \
			echo "$$left" | sed 's/^/  /'; \
			echo "clean: something the build produces is in no list clean reads."; \
			exit 1; \
		fi; \
	fi
	@echo "fuzznet: clean"

-include $(DEPS)
