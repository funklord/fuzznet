#!/usr/bin/env python3
"""Two strangers become contacts by a card: `make livecheck`, sec 619.

Three stores over loopback, each a user of one machine with an address:
A asks, B is asked, C asks and is turned away.

    a  B shows its card (`get card bob`); A adds B by it (`add contact bob
       FZC1:...`), which sends B a request in a sealed box; B lists one
       request, from A's root, with A's card's name
    b  B approves it (`grant request ROOT alice`); B's round pairs A's host
       and offers B's, which is A's answer; A writes a line to B and it is
       delivered, and B files it under A's root
    c  C asks too; B rejects it (`remove request ROOT`) and lists none
    d  A asks where it is seen (`fetch address`); B, its one peer, says
       127.0.0.1 (sec 621)
    e  A's `list link` shows its link to B measured -- a latency, requests
       answered, bytes received (sec 631)
    f  A writes an app stream at three levels; B is given nothing until A
       grants it level 1, and then that level of each record (sec 632)
    g  A adds a fix, `add location`, and lists it exact; B, granted level
       1, fetches it and lists it on the 0.01 degree grid, marked coarse --
       never A's exact position (sec 676)
    g2 granted level 0, B lists A's next fix exact; level 2, on the 0.1
       degree grid; revoked, B is given no fix after (sec 766)
    h  A puts a sticker pack and sends B a line carrying a sticker's
       reference; B's node wants the pack and fetches it from A, which
       granted it to B as the line went out, and B comes to list its
       stickers (sec 682); fetched is not saved, until B keeps it with `add
       sticker REF` (sec 683)
    h2 A puts a file and sends it to B as an attachment (`add message bob
       out ID attach ROOT NAME`), the line's text fuzznet's reference; B
       holds nothing until it asks, then fetches by the whole reference
       from A, which granted it as the line went out, and exports A's bytes
       (sec 794)

`--skew S` runs A S seconds ahead and B S behind, by faketime (sec 767):
the asker and the asked 2S apart.

Against a daemon that drops every box, phase a lists no request; against
one whose approval does not hand over to the contact round, phase b
delivers nothing.

BOUNDED FROM INSIDE as live_rejoin.py is, whose daemon handling this reuses:
one deadline, each daemon in its own process group, and every daemon
checked gone.

Exit 0 on a pass, 1 on a failure.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_rejoin import ROUND_DONE_RE, command, daemon, expect  # noqa: E402
from live_trim import ask, failed  # noqa: E402
import live_trim  # noqa: E402

# EVERY WAIT GROWS WITH THE LOSS, sec 767, as journey 4's scripts' do (sec
# 756): a contact request's box and a round's asks are sent again each
# round, and at 20 per cent a wait sized for no loss ended before the
# round that would have carried them.
LOSS = int(os.environ.get("FZN_FAULT_LOSS", "0") or 0)


def within(base):
	"""A wait of `base` seconds at no loss, six more a point of loss."""
	return base + 6.0 * LOSS


# A ROUND, 60 s: a lost request box is sent again the round after.
ROUND_S = 60.0


def a_round_more(base):
	"""`within(base)`, and under any loss a round more."""
	return within(base) + (ROUND_S + 5.0 if LOSS else 0.0)


live_trim.DEADLINE = time.monotonic() + 360.0 + 40.0 * LOSS

KEPT_RE = re.compile(r"a contact request from ([0-9a-f]{16}), waiting")
# DELIVERED, OR SETTLED (sec 767): an offer whose answer was lost is made
# again, and B, holding the line already, answers SETTLED -- held by every
# device of B's -- which is more than delivered, not less.
OFFERED_RE = re.compile(r"line\(s\) offered to 127\.0\.0\.1: "
                        r"(1 delivered|0 delivered, 1 settled)")
# A ROUND'S OWN END, after its fetches and log pass: "history pass" comes
# before them (sec 637).
ROUND_END_RE = ROUND_DONE_RE
LINE = "51" * 16
LINE2 = "52" * 16
LINE3 = "53" * 16
PREKEY_HOST = slice(4, 68)


def requests(sock, who):
	"""`who`'s waiting requests, as [(root, name)]."""
	reply = ask(sock, "list request")
	words = reply.split()
	if len(words) < 2 or words[0] != "ok":
		raise failed("%s: list request answered %r" % (who, reply))
	return [tuple(w.split(",")[:2]) for w in words[2:]]


def main(argv):
	skew = 0
	if len(argv) == 4 and argv[2] == "--skew" and argv[3].isdigit():
		skew = int(argv[3])
	elif len(argv) != 2:
		print("usage: live_pairing.py PATH_TO_FUZZNETD [--skew S]", file=sys.stderr)
		return 2
	skews = {}
	if skew:
		if not shutil.which("faketime"):
			print("livecheck: pairing SKIPPED -- --skew needs faketime on PATH")
			return 0
		skews = {"a": "+%ds" % skew, "b": "-%ds" % skew}
		print("livecheck: setup: A runs %d s ahead and B %d s behind" % (skew, skew))

	class run:
		pass

	run.fuzznetd = os.path.abspath(argv[1])
	run.started = []
	base = 8000 + (os.getpid() % 500) * 4
	port = {"a": str(base), "b": str(base + 1), "c": str(base + 2)}
	with tempfile.TemporaryDirectory(prefix="fzn-live.") as scratch, \
	     tempfile.TemporaryDirectory(prefix="fzs.", dir="/tmp") as sock_dir:
		run.scratch = scratch
		dirs = {k: os.path.join(scratch, k) for k in port}
		socks = {k: os.path.join(sock_dir, k) for k in port}
		started = {}

		def up(who, tag):
			started[who] = daemon(run, tag, dirs[who], socks[who], fake=skews.get(who),
			                      extra=["--udp-port=" + port[who]])
			return started[who]

		def down(who):
			started.pop(who).stop()

		try:
			keys = {}
			for who in port:
				os.mkdir(dirs[who])
				command(run, ["--fuzznet-dir=" + dirs[who], "--new-root"], skews.get(who))
				keys[who] = command(run, ["--fuzznet-dir=" + dirs[who], "--prekey"],
				                    skews.get(who))[PREKEY_HOST]
			for who in port:
				up(who, who + "1")
				expect(socks[who], who, "set setting host net/address 127.0.0.1 " + port[who],
				       "ok")

			# NOBODY TO ASK YET, said so (sec 653): A has no contact or sibling.
			got = ask(socks["a"], "fetch address").strip()
			if not got.startswith("ok 0 no "):
				raise failed("setup: A's fetch address with nobody to ask answered %r" % got)

			# a: A asks B by B's card.
			card = ask(socks["b"], "get card bob")
			if not card.startswith("ok FZC1:"):
				raise failed("a: get card answered %r" % card)
			card = card.split(" ", 1)[1].strip()
			got = ask(socks["a"], "add contact bob " + card)
			if got.strip() != "ok " + keys["b"]:
				raise failed("a: add contact by card answered %r" % got)
			started["b"].wait_for(KEPT_RE, "B keeping A's request", a_round_more(30.0))
			held = requests(socks["b"], "b")
			if held != [(keys["a"], "-")]:
				raise failed("a: B's requests are %r, not A's alone" % (held,))
			print("livecheck: a: A asked B by B's card, and B holds A's request")

			# b: B approves; the round pairs them; a line goes.
			# A ROOT THAT ASKED NOTHING is an error, a word the reply
			# vocabulary has (sec 646): it said `absent`, which none read.
			nobody = "00" * 31 + "07"
			expect(socks["b"], "b", "remove request " + nobody,
			       "error no request from that root")
			expect(socks["b"], "b", "grant request %s nobody" % nobody,
			       "error no request from that root")
			expect(socks["b"], "b", "grant request %s alice" % keys["a"], "ok")
			if requests(socks["b"], "b"):
				raise failed("b: B's request was still listed once approved")
			for who in ("b", "a"):
				down(who)
				d = up(who, who + "2")
				d.wait_for(ROUND_END_RE, "%s's round" % who.upper())
			expect(socks["a"], "a", "add message bob out %s hello%%20bob" % LINE, "ok")
			try:
				started["a"].wait_for(OFFERED_RE, "A's delivery to B", within(30.0))
			except failed:
				# A ROUND MORE at each, the pairing taking one to settle; and
				# under loss, more (sec 767).
				for extra in range(1 + LOSS // 5):
					for who in ("b", "a"):
						down(who)
						d = up(who, "%s3-%d" % (who, extra))
						d.wait_for(ROUND_END_RE, "%s's round" % who.upper(), within(30.0))
					try:
						started["a"].wait_for(OFFERED_RE, "A's delivery to B", within(30.0))
						break
					except failed:
						if extra == LOSS // 5:
							raise
			reply = ask(socks["b"], "list message " + keys["a"])
			if LINE not in reply or "hello%20bob" not in reply:
				raise failed("b: B holds %r under A's root" % reply)
			print("livecheck: b: approved, the two paired by the round, and A's line "
			      "delivered to B under A's root")

			# c: C asks; B turns it away.
			got = ask(socks["c"], "add contact bob " + card)
			if not got.startswith("ok "):
				raise failed("c: C's add contact answered %r" % got)
			deadline = time.monotonic() + a_round_more(20.0)
			while time.monotonic() < deadline:
				held = requests(socks["b"], "b")
				if held:
					break
				time.sleep(0.2)
			if held != [(keys["c"], "-")]:
				raise failed("c: B's requests are %r, not C's alone" % (held,))
			expect(socks["b"], "b", "remove request " + keys["c"], "ok")
			if requests(socks["b"], "b"):
				raise failed("c: a rejected request was still listed")
			print("livecheck: c: C asked too, and B turned it away")

			# d: where A is seen, asked of the contact it now has (sec 621).
			# HOW MANY IT WILL ASK, sec 653: B at least.
			got = ask(socks["a"], "fetch address").split()
			if len(got) != 2 or got[0] != "ok" or not got[1].isdigit() or got[1] == "0":
				raise failed("d: A's fetch address answered %r, not a count of hosts" % got)
			# ASKED AGAIN when nothing came within 10 s, three asks at most
			# (sec 767): one ask and its resends are lost together at 20 per
			# cent now and then, and a user asks again.
			deadline = time.monotonic() + within(20.0)
			again = time.monotonic() + 10.0
			asks = 1
			seen = []
			while time.monotonic() < deadline:
				seen = ask(socks["a"], "get address").split()
				if len(seen) >= 3 and seen[1] != "0":
					break
				if time.monotonic() > again and asks < 3:
					ask(socks["a"], "fetch address")
					asks += 1
					again = time.monotonic() + 10.0
				time.sleep(0.2)
			if len(seen) != 4 or seen[:3] != ["ok", "1", "1"] \
			   or not seen[3].startswith(keys["b"][:16] + ",127.0.0.1,"):
				raise failed("d: A's get address answered %r" % (seen,))
			print("livecheck: d: B told A it sees A at 127.0.0.1")

			# e: the link to B measured at A, sec 631.
			links = ask(socks["a"], "list link").split()
			to_b = [l.split(",") for l in links[3:] if l.startswith("127.0.0.1:%s," % port["b"])]
			if len(links) < 3 or links[0] != "ok" or len(to_b) != 1 or to_b[0][1] == "-" \
			   or int(to_b[0][3]) == 0 or int(to_b[0][6]) == 0 or int(to_b[0][8]) == 0:
				raise failed("e: A's list link answered %r, without B measured" % (links,))
			# PAGED, sec 777: the same links from FROM 0, and from 1 one fewer --
			# by address, since their counters move between asks.
			page = ask(socks["a"], "list link 0").split()
			later = ask(socks["a"], "list link 1").split()
			def hosts(rows):
				return [r.split(",")[0] for r in rows]
			if page[:1] != ["ok"] or page[3] != "0" or hosts(page[4:]) != hosts(links[3:]) \
			   or later[3] != "1" or hosts(later[4:]) != hosts(links[4:]):
				raise failed("e: A's list link 0 and 1 answered %r and %r, not %r paged"
				             % (page, later, links))
			if not ask(socks["a"], "list link x").startswith("malformed "):
				raise failed("e: list link x was not malformed")
			print("livecheck: e: A measured its link to B: %s ms, %s of %s asked answered"
			      % (to_b[0][1], to_b[0][6], to_b[0][5]))

			# f: an app stream, sec 632. A writes two records at three levels;
			# B, not granted, is given nothing; granted level 1, B holds A's
			# records at that level alone.
			for rec in ("aa01 bb01 cc01", "aa02 bb02 cc02"):
				got = ask(socks["a"], "add stream location " + rec)
				if not got.startswith("ok "):
					raise failed("f: add stream answered %r" % got)

			def held_at_b():
				reply = ask(socks["b"], "list stream location").split()
				if not reply or reply[0] != "ok":
					raise failed("f: B's list stream answered %r" % reply)
				return [r for r in reply[1:] if r.startswith(keys["a"][:16] + ",")]

			def fetch_once():
				before = started["b"].log().count("stream fetch:")
				expect(socks["b"], "b", "fetch stream location alice", "ok")
				deadline = time.monotonic() + within(20.0)
				while time.monotonic() < deadline \
				      and started["b"].log().count("stream fetch:") == before:
					time.sleep(0.2)

			# FETCHED AGAIN UNTIL `held` IS TRUE, sec 767: at 20 per cent a
			# fetch's answer and its resends are lost together now and then
			# ("1 host(s) asked, 0 record(s) taken"), and a user fetches
			# again. With nothing to wait for -- a grant not yet given, one
			# revoked -- it fetches as often as it would have tried, so an
			# absence is shown by as many answers as a presence.
			def fetched(held=None):
				tries = 1 + LOSS // 5
				for i in range(tries if held is None else 3 * tries):
					fetch_once()
					if held is not None and held():
						return

			fetched()
			if held_at_b():
				raise failed("f: B, not granted, holds %r" % held_at_b())
			# WHAT B MAY READ, as A answers it (sec 645): nothing, then level 1.
			expect(socks["a"], "a", "get stream location bob", "ok none")
			expect(socks["a"], "a", "grant stream location bob 1", "ok")
			expect(socks["a"], "a", "get stream location bob", "ok 1")
			time.sleep(2.5)
			fetched(lambda: len(held_at_b()) == 2)
			got = held_at_b()
			if [r.split(",", 1)[1].split(",", 2)[0] + "," + r.rsplit(",", 1)[1] for r in got] \
			   != ["1,bb01", "2,bb02"]:
				raise failed("f: B holds %r of A's stream, not level 1 of both records" % got)
			print("livecheck: f: B was given nothing of A's stream until granted, then level 1")

			# g: a fix, sec 676, the third record of A's `location` stream: A
			# lists it as given, B at the level it was granted. The two app
			# records before it are no fixes, and neither side lists them.
			# LOCATION ON, sec 774: a supplied fix is kept only so, as the
			# sampler's; gpsd aimed at a port where nothing listens.
			for key, value in (("location/gpsd", "127.0.0.1 1"), ("location/enabled", "on")):
				expect(socks["a"], "a", "set setting host %s %s" % (key, value), "ok")
			got = ask(socks["a"], "add location 59.3293230 18.0685810 alt 31 bearing 90 "
			                      "acc 5 9 vacc 20 at 1792600000")
			if got != "ok 3":
				raise failed("g: add location answered %r" % got)
			reply = ask(socks["a"], "list location").split()
			rows = [r.split(",") for r in reply[1:]]
			if reply[:1] != ["ok"] or len(rows) != 1 or rows[0][1] != "3" \
			   or rows[0][3:] != ["59.3293230", "18.0685810", "1792600000", "31", "90", "5", "9",
			                      "20", "0"]:
				raise failed("g: A lists %r, not its fix exact" % reply)
			time.sleep(2.5)
			fetched(lambda: any(r.startswith(keys["a"][:16] + ",")
			                    for r in ask(socks["b"], "list location").split()[1:]))
			reply = ask(socks["b"], "list location").split()
			rows = [r.split(",") for r in reply[1:] if r.startswith(keys["a"][:16] + ",")]
			if len(rows) != 1 or rows[0][3:6] != ["59.3300000", "18.0700000", "1792600000"] \
			   or rows[0][-1] != "1":
				raise failed("g: B lists %r of A's fixes, not one on the coarse grid" % reply)
			print("livecheck: g: A's fix listed exact at A, and on the 0.01 degree grid at B")

			# g2: EACH LEVEL, AND THE GRANT REVOKED (sec 766, sec 689's journey
			# 5). A record held is not fetched again, so each level is shown
			# with a fix of its own: level 0, exact; level 2, the 0.1 degree
			# grid; revoked, the next fix never reaches B.
			def b_fix(seq):
				reply = ask(socks["b"], "list location").split()
				return [r.split(",") for r in reply[1:]
				        if r.startswith(keys["a"][:16] + ",") and r.split(",")[1] == seq]

			def add_fix(seq, held=True):
				got = ask(socks["a"], "add location 59.3293230 18.0685810 acc 5 5 at 1792600%03d"
				                      % seq)
				if got != "ok %d" % seq:
					raise failed("g2: add location answered %r, not record %d" % (got, seq))
				time.sleep(2.5)
				fetched((lambda: b_fix(str(seq))) if held else None)
				return b_fix(str(seq))

			expect(socks["a"], "a", "grant stream location bob 0", "ok")
			rows = add_fix(4)
			if len(rows) != 1 or rows[0][3:5] != ["59.3293230", "18.0685810"] or rows[0][-1] != "0":
				raise failed("g2: granted level 0, B lists %r of record 4, not it exact" % rows)
			expect(socks["a"], "a", "grant stream location bob 2", "ok")
			rows = add_fix(5)
			if len(rows) != 1 or rows[0][3:5] != ["59.3000000", "18.1000000"] or rows[0][-1] != "1":
				raise failed("g2: granted level 2, B lists %r of record 5, not it on the 0.1 "
				             "degree grid" % rows)
			expect(socks["a"], "a", "revoke stream location bob", "ok")
			expect(socks["a"], "a", "get stream location bob", "ok none")
			rows = add_fix(6, held=False)
			if rows:
				raise failed("g2: revoked, B still holds A's record 6: %r" % rows)
			print("livecheck: g2: B listed A's fixes exact at level 0, on the 0.1 degree grid at "
			      "level 2, and was given none once revoked")

			# h: a sticker, sec 682. A's pack, its reference sent as a line's
			# text (escaped, as every text is), and B fetching the pack it
			# names from A, who granted it as the line went out.
			packdir = os.path.join(run.scratch, "pack")
			os.makedirs(os.path.join(packdir, "art"))
			art = os.urandom(3000)
			with open(os.path.join(packdir, "art", "wave.png"), "wb") as f:
				f.write(art)
			spec = os.path.join(packdir, "cats.spec")
			with open(spec, "w") as f:
				f.write("name cats\nsticker 1 static\ndescription a cat waving\n"
				        "inline png 128 128 art/wave.png\n")
			got = ask(socks["a"], "put sticker " + spec).split()
			if len(got) != 2 or got[0] != "ok":
				raise failed("h: put sticker answered %r" % got)
			ref = ask(socks["a"], "get sticker %s 1" % got[1])
			if not ref.startswith("ok fzn:sticker/"):
				raise failed("h: get sticker answered %r" % ref)
			ref = ref[3:]
			fields = ref.split("/")
			whole = fields[1] + fields[2] + "%016x" % int(fields[3])
			if not ask(socks["b"], "list sticker " + whole).startswith("error"):
				raise failed("h: B held A's pack before any line named it")
			expect(socks["a"], "a", "add message bob out %s %s"
			       % (LINE2, ref.replace("%", "%25").replace(" ", "%20")), "ok")
			until = time.monotonic() + 150.0
			while not ask(socks["b"], "list sticker " + whole).startswith("ok 1 0 "):
				if time.monotonic() > until:
					raise failed("h: B never fetched the pack its line names: %r, B's "
					             "messages %r" % (ask(socks["b"], "list sticker " + whole),
					                              ask(socks["b"], "list message "
					                                  + keys["a"])[:300]))
				time.sleep(2.0)
			out = os.path.join(run.scratch, "wave.out")
			if ask(socks["b"], "get sticker %s 1 inline %s" % (whole, out)) != "ok 4 128 128":
				raise failed("h: B could not draw the sticker it fetched")
			with open(out, "rb") as f:
				if f.read() != art:
					raise failed("h: the sticker B drew is not A's art")
			# RECEIVING IS NOT SAVING; keeping is B's act, sec 683.
			if ask(socks["b"], "list sticker") != "ok 0 0":
				raise failed("h: a pack fetched for a line was saved unasked")
			if not ask(socks["b"], "add sticker " + "00" * 64 + "%016x" % 100) \
			       .startswith("error that pack is not here"):
				raise failed("h: a pack not here was kept")
			got = ask(socks["b"], "add sticker " + whole).split()
			if len(got) < 2 or got[0] != "ok" or got[1] != fields[1]:
				raise failed("h: add sticker answered %r" % got)
			listed = ask(socks["b"], "list sticker").split()
			if listed[:3] != ["ok", "1", "0"] or not listed[3].startswith(fields[1] + ",") \
			   or ",cats,1," not in listed[3]:
				raise failed("h: B's collection is %r after keeping the pack" % listed)
			print("livecheck: h: a line carrying a sticker made B fetch A's pack, granted as "
			      "it went out, and draw it; fetched was not saved until B kept it")

			# h2: a file sent as an attachment, sec 794. Its reference is
			# fuzznet's, written from the file A holds; B is not made to fetch
			# it, and fetches it by the reference once it asks.
			payload = os.path.join(run.scratch, "holiday")
			sent = os.urandom(5000)
			with open(payload, "wb") as f:
				f.write(sent)
			put = ask(socks["a"], "put file " + payload).split()
			if len(put) < 2 or put[0] != "ok":
				raise failed("h2: put file answered %r" % put)
			root = put[1][:64]
			expect(socks["a"], "a", "add message bob out %s attach %s holiday%%20photo.jpg"
			       % (LINE3, root), "ok")
			until = time.monotonic() + 120.0
			attached = None
			while attached is None:
				listing = ask(socks["b"], "list message " + keys["a"])
				at = listing.find("fzn:file/" + root + "/")
				if at >= 0:
					attached = listing[at:].split(",")[0].split(" ")[0]
					break
				if time.monotonic() > until:
					raise failed("h2: B never filed the attachment's line: %r" % listing[:300])
				time.sleep(2.0)
			text = attached.replace("%20", " ")
			head, name = text.split(" ", 1)
			fields = head.split("/")
			if name != "holiday photo.jpg" or len(fields) != 4 or int(fields[3]) != len(sent):
				raise failed("h2: the line's reference reads %r" % text)
			if root in ask(socks["b"], "list file"):
				raise failed("h2: B fetched an attachment nobody asked for")
			expect(socks["b"], "b", "fetch file %s%s%016x" % (fields[1], fields[2],
			                                                 int(fields[3])), "ok")
			until = time.monotonic() + 120.0
			while ask(socks["b"], "get file %s check" % root).strip() != "ok intact":
				if time.monotonic() > until:
					raise failed("h2: B never fetched the attachment: %r"
					             % ask(socks["b"], "get file " + root))
				time.sleep(2.0)
			out = os.path.join(run.scratch, "holiday.out")
			expect(socks["b"], "b", "get file %s%s%016x %s" % (fields[1], fields[2],
			                                                  int(fields[3]), out), "ok")
			with open(out, "rb") as f:
				if f.read() != sent:
					raise failed("h2: the file B exported is not the file A attached")
			print("livecheck: h2: A attached a file, its reference written by fuzznet; B "
			      "fetched it by that reference only when asked, and holds A's bytes")
		except failed as e:
			print("livecheck: FAILED -- %s" % e)
			return 1
		except subprocess.TimeoutExpired as e:
			print("livecheck: FAILED -- a command passed its deadline: %s" % e)
			return 1
		finally:
			for d in started.values():
				d.stop()
			for pid in run.started:
				if os.path.exists("/proc/%d" % pid):
					try:
						with open("/proc/%d/cmdline" % pid, "rb") as f:
							alive = run.fuzznetd.encode() in f.read()
						# STILL OUR CHILD, sec 741: a reaped daemon's pid, handed to
						# another run's daemon of the same binary, is not this run's.
						with open("/proc/%d/stat" % pid) as f:
							alive = alive and int(f.read().rsplit(")", 1)[1].split()[1]) == os.getpid()
					except OSError:
						alive = False
					if alive:
						print("livecheck: FAILED -- daemon %d outlived its phase" % pid)
						return 1
	print("livecheck: two strangers became contacts by a card, and a third was turned away")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
