# fuzznet -- the shared authenticated datagram protocol.
#
# No sources yet: project.md sec 9 puts a `situ` evaluation before anything is
# hand-written, so a build rule now would be a rule for code whose shape is
# still an open question. What exists today is the gate and the hooks, which
# are the two things every private project has from its first commit.

BUILD_DIR ?= .

.PHONY: all style hooks clean

all:
	@echo "fuzznet: nothing to build yet -- see project.md sec 9 for the order"

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

# Deletes named targets only, and lists them. There is nothing to remove yet,
# and this says so rather than sweeping a directory -- a clean target is the
# one thing everybody runs without reading.
clean:
	@echo "fuzznet: nothing built, so nothing to remove"
