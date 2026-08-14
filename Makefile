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

BUILD_DIR ?= .
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
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
           -Wstrict-prototypes -Wvla
CPPFLAGS += -MMD -MP

SRCS      := constant_time/constant_time.c \
             chain/chain.c chain/revocation.c frame/freshness.c \
             chunk/reassembly.c \
             chunk/split.c
OBJS      := $(SRCS:%.c=$(BUILD_DIR)/%.o)
HDRS      := constant_time/constant_time.h \
             chain/chain.h chain/revocation.h frame/freshness.h \
             chunk/reassembly.h \
             chunk/split.h

TEST_SRCS := chain/tests/chain_test.c chain/tests/revocation_test.c \
             frame/tests/freshness_test.c \
             chunk/tests/reassembly_test.c chunk/tests/split_test.c \
             chunk/tests/reassembly_fuzz.c chain/tests/chain_fuzz.c \
             frame/tests/freshness_fuzz.c chain/tests/revocation_fuzz.c \
             chunk/tests/roundtrip_fuzz.c
TEST_OBJS := $(TEST_SRCS:%.c=$(BUILD_DIR)/%.o)
TEST_BINS := $(BUILD_DIR)/chain/tests/chain_test \
             $(BUILD_DIR)/chain/tests/revocation_test \
             $(BUILD_DIR)/frame/tests/freshness_test \
             $(BUILD_DIR)/chunk/tests/reassembly_test \
             $(BUILD_DIR)/chunk/tests/split_test \
             $(BUILD_DIR)/chunk/tests/reassembly_fuzz \
             $(BUILD_DIR)/chain/tests/chain_fuzz \
             $(BUILD_DIR)/frame/tests/freshness_fuzz \
             $(BUILD_DIR)/chain/tests/revocation_fuzz \
             $(BUILD_DIR)/chunk/tests/roundtrip_fuzz

# The Monocypher binding, built only when MONOCYPHER_DIR names a checkout.
#
# project.md sec 7 says a submodule and sec 10 has not reached that step, so
# there is nothing vendored here to build against and adding a dependency is
# not a thing to do in passing. During bring-up sec 7 blesses exactly this
# shape -- a sibling directory behind a variable, not a second build path:
#
#   make test MONOCYPHER_DIR=../fuzzypickles/monocypher
#
# Without it the library builds and every test above still runs, which is
# the property chain.h's signer vtable exists to give. With it, one more
# binary runs a real Ed25519 round trip, because a seam that has only ever
# had a stub behind it is a seam nobody has checked.
MONOCYPHER_DIR ?=

ifneq ($(MONOCYPHER_DIR),)
MONO_OBJS  := $(BUILD_DIR)/chain/sign_monocypher.o $(BUILD_DIR)/monocypher.o
MONO_TSRC  := chain/tests/sign_monocypher_test.c
MONO_TOBJ  := $(MONO_TSRC:%.c=$(BUILD_DIR)/%.o)
MONO_BIN   := $(BUILD_DIR)/chain/tests/sign_monocypher_test
OBJS       += $(MONO_OBJS)
TEST_OBJS  += $(MONO_TOBJ)
TEST_BINS  += $(MONO_BIN)
HDRS       += chain/sign_monocypher.h
CPPFLAGS   += -I$(MONOCYPHER_DIR)/src

# Vendored, so it is compiled with its own terms rather than ours.
# code-style.md exempts vendored sources from our rules, and -Wconversion
# against somebody else's crypto is noise nobody will read, which is how a
# warning that matters gets missed.
$(BUILD_DIR)/monocypher.o: $(MONOCYPHER_DIR)/src/monocypher.c
	@mkdir -p $(dir $@)
	$(CC) -Os -g -c $< -o $@

$(MONO_BIN): $(MONO_TOBJ) $(MONO_OBJS) $(BUILD_DIR)/chain/chain.o \
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
DEPS := $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)

.PHONY: all test fuzz installcheck style hooks clean install

# The default build does NOT build tests -- build-and-commit.md, and the
# discipline it buys is paid for by the dependency rules above being right.
all: $(OBJS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/chain/tests/chain_test: $(BUILD_DIR)/chain/tests/chain_test.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/frame/tests/freshness_test: $(BUILD_DIR)/frame/tests/freshness_test.o \
                                         $(BUILD_DIR)/frame/freshness.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chunk/tests/reassembly_test: $(BUILD_DIR)/chunk/tests/reassembly_test.o \
                                          $(BUILD_DIR)/chunk/reassembly.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Links BOTH halves on purpose: this binary is what holds the splitter and
# the reassembler to the same contract.
$(BUILD_DIR)/chunk/tests/split_test: $(BUILD_DIR)/chunk/tests/split_test.o \
                                     $(BUILD_DIR)/chunk/split.o \
                                     $(BUILD_DIR)/chunk/reassembly.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chain/tests/revocation_test: $(BUILD_DIR)/chain/tests/revocation_test.o \
                                          $(BUILD_DIR)/chain/revocation.o \
                                          $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# The fuzz harness. It runs a FIXED number of cases from a seeded generator
# -- argv[1] or its own default -- so `make test` terminates and a failing
# case is reproducible from the source alone. `make fuzz CASES=n` runs a
# longer campaign without editing anything.
$(BUILD_DIR)/chunk/tests/reassembly_fuzz: $(BUILD_DIR)/chunk/tests/reassembly_fuzz.o \
                                          $(BUILD_DIR)/chunk/reassembly.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chain/tests/chain_fuzz: $(BUILD_DIR)/chain/tests/chain_fuzz.o \
                                     $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/frame/tests/freshness_fuzz: $(BUILD_DIR)/frame/tests/freshness_fuzz.o \
                                         $(BUILD_DIR)/frame/freshness.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/chain/tests/revocation_fuzz: $(BUILD_DIR)/chain/tests/revocation_fuzz.o \
                                          $(BUILD_DIR)/chain/revocation.o \
                                          $(BUILD_DIR)/chain/chain.o \
                                     $(BUILD_DIR)/constant_time/constant_time.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Links both halves, like split_test: this binary is what holds the
# splitter and the reassembler to the same contract over permutations.
$(BUILD_DIR)/chunk/tests/roundtrip_fuzz: $(BUILD_DIR)/chunk/tests/roundtrip_fuzz.o \
                                         $(BUILD_DIR)/chunk/split.o \
                                         $(BUILD_DIR)/chunk/reassembly.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@

# Tests are built by this target and only by it, so a claim that a test
# passes or fails always goes through a rebuild. Re-running a stale binary
# after a plain build appears to pass either way.
test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "running $$t"; $$t || exit 1; done

CASES ?= 200000

FUZZ_BINS := $(BUILD_DIR)/chunk/tests/reassembly_fuzz \
             $(BUILD_DIR)/chain/tests/chain_fuzz \
             $(BUILD_DIR)/frame/tests/freshness_fuzz \
             $(BUILD_DIR)/chain/tests/revocation_fuzz \
             $(BUILD_DIR)/chunk/tests/roundtrip_fuzz

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
# ~/.claude/tools/style_gate.py; .style-gate.toml says which files here it
# applies to.
style:
	python3 tools/style_gate.py check

# Installs the commit-msg hook from tools/hooks/ into .git/hooks/. In the tree
# rather than only in .git so that it is reviewable, survives a clone, and can
# be diffed against its siblings in the other projects.
hooks:
	@install -m 0755 tools/hooks/commit-msg .git/hooks/commit-msg
	@echo "installed .git/hooks/commit-msg"

# Headers only. project.md sec 7 is explicit that this is not a system
# package and not a shared library -- a .so would put wire compatibility in
# the hands of whatever the distribution shipped, which is the failure a
# pinned submodule commit exists to prevent. DESTDIR is honoured because
# dh_auto_install calls it, and every private project honours it.
install: $(HDRS)
	@for h in $(HDRS); do \
		install -d $(DESTDIR)$(PREFIX)/include/fuzznet/`dirname $$h`; \
		install -m 0644 $$h $(DESTDIR)$(PREFIX)/include/fuzznet/$$h; \
	done
	@echo "installed `echo $(HDRS) | wc -w` header(s) under $(DESTDIR)$(PREFIX)/include/fuzznet"

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
installcheck: $(HDRS) $(SRCS) tools/consumer_check.c
	@test -n "$(BUILD_DIR)" || { echo "BUILD_DIR is empty; refusing"; exit 1; }
	@case "$(BUILD_DIR)" in /*) echo "BUILD_DIR must be relative; refusing"; exit 1 ;; esac
	@rm -rf $(BUILD_DIR)/installcheck
	@$(MAKE) --no-print-directory install DESTDIR=$(BUILD_DIR)/installcheck PREFIX=/usr >/dev/null
	@echo "installcheck: against the installed headers"
	@$(CC) $(CFLAGS) -DFZN_CONSUMER_INSTALLED \
	       -I$(BUILD_DIR)/installcheck/usr/include \
	       -o $(BUILD_DIR)/installcheck/consumer_installed \
	       tools/consumer_check.c $(SRCS)
	@$(BUILD_DIR)/installcheck/consumer_installed
	@echo "installcheck: against the source tree, from another directory"
	@cd $(BUILD_DIR)/installcheck && $(CC) $(CFLAGS) -I$(CURDIR) \
	       -o consumer_source $(CURDIR)/tools/consumer_check.c \
	       $(patsubst %,$(CURDIR)/%,$(SRCS))
	@$(BUILD_DIR)/installcheck/consumer_source
	@rm -rf $(BUILD_DIR)/installcheck
	@echo "installcheck: both arrangements build and run"

# Named targets only, and it lists them. No rm -rf of a directory and no
# wildcard sweep: a clean target is the one thing everybody runs without
# reading, and an unset variable in an `rm -rf $(VAR)` is how one eats
# something it should not.
clean:
	@for f in $(OBJS) $(TEST_OBJS) $(DEPS) $(TEST_BINS); do \
		if [ -e "$$f" ]; then echo "removing $$f"; rm -f "$$f"; fi; \
	done
	@echo "fuzznet: clean"

-include $(DEPS)
