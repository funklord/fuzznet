#!/usr/bin/env python3
"""The original test sticker set, fuzznet sec 1277: written, not drawn by
hand, so its art is reproducible and its phrases reviewable in one place.

The holder, 2026-11-18: "ship an original sticker set ... This is just for
testing but later we want to ensure we don't include or market low quality
stickers". So the pack is named as a test fixture, and is not one to ship.
And its phrases are "expanded to be as complete as possible", the search
while typing (sec 1272) being what they are for.

One character, Pip -- a round teal creature of fuzznet's own -- in twelve
moods, each a Lottie animation of plain shapes (no images, no fonts), 512 by
512, two seconds at 30 frames. Writes `sticker/fixture/test-set/` beside
this tree's root: `test-set.spec` and `art/NN-name.json`, a fixed set of
names, overwritten each run, nothing else touched.

    python3 tool/sticker_test_set.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "sticker", "fixture", "test-set")
W = H = 512
FRAMES = 60

TEAL = [0.16, 0.62, 0.62, 1]
TEAL_DARK = [0.09, 0.42, 0.43, 1]
WHITE = [1, 1, 1, 1]
INK = [0.12, 0.13, 0.16, 1]
PINK = [0.95, 0.45, 0.55, 1]
RED = [0.88, 0.2, 0.3, 1]
BLUE = [0.35, 0.6, 0.95, 1]
GOLD = [0.98, 0.78, 0.25, 1]
GREY = [0.55, 0.57, 0.6, 1]


def still(v):
	return {"a": 0, "k": v}


def moving(*keys):
	"""Keyframes (frame, value), eased in and out, the last held."""
	out = []
	for i, (t, v) in enumerate(keys):
		k = {"t": t, "s": v if isinstance(v, list) else [v]}
		if i + 1 < len(keys):
			n = len(k["s"])
			k["i"] = {"x": [0.4] * n, "y": [1] * n}
			k["o"] = {"x": [0.6] * n, "y": [0] * n}
		out.append(k)
	return {"a": 1, "k": out}


def transform(p=(0, 0), s=(100, 100), r=0, o=100, a=(0, 0)):
	def v(x):
		return x if isinstance(x, dict) else still(list(x) if isinstance(x, tuple) else x)
	return {"ty": "tr", "p": v(p), "a": v(a), "s": v(s), "r": v(r), "o": v(o)}


def fill(c):
	return {"ty": "fl", "c": still(c), "o": still(100), "r": 1}


def stroke(c, w):
	return {"ty": "st", "c": still(c), "o": still(100), "w": still(w), "lc": 2, "lj": 2}


def ellipse(w, h, at=(0, 0)):
	return {"ty": "el", "p": still(list(at)), "s": still([w, h])}


def rect(w, h, at=(0, 0), round_=0):
	return {"ty": "rc", "p": still(list(at)), "s": still([w, h]), "r": still(round_)}


def path(points, closed=False, curve=None):
	"""Straight segments through `points`, or a curve with tangents `curve`
	(one in and one out per point)."""
	n = len(points)
	ins = [[0, 0]] * n if not curve else [list(c[0]) for c in curve]
	outs = [[0, 0]] * n if not curve else [list(c[1]) for c in curve]
	return {"ty": "sh", "ks": still({"i": ins, "o": outs, "v": [list(p) for p in points], "c": closed})}


def group(items, **tr):
	return {"ty": "gr", "it": list(items) + [transform(**tr)]}


def layer(name, shapes, **tr):
	ks = transform(**tr)
	ks.pop("ty")
	return {"ty": 4, "nm": name, "ip": 0, "op": FRAMES, "st": 0, "sr": 1, "ks": ks, "shapes": shapes, "ao": 0,
	        "bm": 0, "ddd": 0}


def body(bob=True, squash=False):
	"""Pip: a round body with a lighter belly, breathing or bouncing."""
	s = moving((0, [100, 100]), (30, [104, 96] if squash else [102, 102]), (60, [100, 100])) if bob else None
	return layer("body", [
		group([ellipse(150, 120, (0, 70)), fill([0.55, 0.85, 0.83, 1])]),
		group([ellipse(330, 310), fill(TEAL)]),
	], p=(256, 290), **({"s": s} if s else {}))


def eyes(kind="open", dy=0):
	if kind == "closed":
		lid = [path([(-25, 0), (0, 10), (25, 0)], curve=[((0, 0), (8, 8)), ((-10, 0), (10, 0)), ((-8, 8), (0, 0))]),
		       stroke(INK, 9)]
		return layer("eyes", [group(lid, p=(-55, 0)), group(lid, p=(55, 0))], p=(256, 250 + dy))
	if kind == "happy":
		arc = [path([(-25, 8), (0, -12), (25, 8)], curve=[((0, 0), (8, -10)), ((-12, 0), (12, 0)), ((-8, -10), (0, 0))]),
		       stroke(INK, 9)]
		return layer("eyes", [group(arc, p=(-55, 0)), group(arc, p=(55, 0))], p=(256, 250 + dy))
	one = [group([ellipse(20, 24, (4, 2)), fill(INK)]), group([ellipse(46, 52), fill(WHITE)])]
	blink = moving((0, [100, 100]), (40, [100, 100]), (44, [100, 10]), (48, [100, 100]), (60, [100, 100]))
	return layer("eyes", [group(one, p=(-55, 0)), group(one, p=(55, 0))], p=(256, 250 + dy), s=blink)


def mouth(kind):
	shapes = {
		"smile": [path([(-40, 0), (0, 28), (40, 0)], curve=[((0, 0), (10, 20)), ((-25, 0), (25, 0)), ((-10, 20), (0, 0))]),
		          stroke(INK, 9)],
		"open": [ellipse(56, 44), fill([0.45, 0.12, 0.2, 1])],
		"flat": [path([(-30, 0), (30, 0)]), stroke(INK, 9)],
		"sad": [path([(-35, 14), (0, -6), (35, 14)], curve=[((0, 0), (10, -14)), ((-20, 0), (20, 0)), ((-10, -14), (0, 0))]),
		        stroke(INK, 9)],
		"o": [ellipse(26, 30), fill([0.45, 0.12, 0.2, 1])],
		"grin": [path([(-50, -5), (50, -5), (0, 40)], closed=True,
		              curve=[((0, 0), (0, 0)), ((0, 0), (0, 30)), ((40, 0), (-40, 0))]), fill([0.45, 0.12, 0.2, 1])],
	}[kind]
	return layer("mouth", [group(shapes)], p=(256, 320))


def cheeks():
	return layer("cheeks", [group([ellipse(40, 22, (-95, 0)), fill(PINK)]), group([ellipse(40, 22, (95, 0)), fill(PINK)])],
	             p=(256, 300), o=70)


def hand(at, rotate=None, lift=None):
	tr = {"p": lift or at, "a": (0, 40)}
	if rotate:
		tr["r"] = rotate
	return layer("hand", [group([ellipse(56, 56, (0, -10)), fill(TEAL_DARK)])], **tr)


def heart(at, size=1.0, beat=True):
	s = moving((0, [100 * size] * 2), (15, [115 * size] * 2), (30, [100 * size] * 2), (45, [115 * size] * 2),
	           (60, [100 * size] * 2)) if beat else (100 * size, 100 * size)
	return layer("heart", [
		group([ellipse(60, 60, (-22, -10)), fill(RED)]),
		group([ellipse(60, 60, (22, -10)), fill(RED)]),
		group([rect(62, 62, (0, 12)), fill(RED)], r=45, p=(0, 12), a=(0, 12)),
	], p=at, s=s)


def zeds():
	z = [path([(-15, -15), (15, -15), (-15, 15), (15, 15)]), stroke(GREY, 8)]
	return layer("z", [group(z, p=(0, 0)), group(z, p=(40, -50), s=(70, 70))],
	             p=moving((0, [380, 150]), (60, [400, 110])), o=moving((0, 100), (50, 100), (60, 0)))


def drop(at):
	return layer("drop", [group([path([(0, -28), (18, 6), (0, 22), (-18, 6)], closed=True,
	                                   curve=[((0, 0), (8, 10)), ((0, -10), (0, 10)), ((10, 0), (-10, 0)), ((0, 10), (0, -10))]),
	                              fill(BLUE)])],
	             p=moving((0, list(at)), (60, [at[0], at[1] + 40])))


def clock():
	return layer("clock", [
		group([path([(0, 0), (0, -38)]), stroke(INK, 7)], r=moving((0, 0), (60, 360))),
		group([path([(0, 0), (26, 0)]), stroke(INK, 7)]),
		group([ellipse(110, 110), fill(WHITE), stroke(INK, 7)]),
	], p=(395, 140))


def confetti():
	bits = []
	for i, (x, c) in enumerate(zip((-180, -110, -40, 30, 100, 170), (GOLD, PINK, BLUE, GOLD, RED, BLUE))):
		bits.append(group([rect(18, 30), fill(c)], p=moving((0, [x, -40 - 30 * (i % 3)]), (60, [x + 10, 260])),
		                  r=moving((0, 0), (60, 270 if i % 2 else -270))))
	return layer("confetti", bits, p=(256, 60))


def dots():
	return layer("dots", [group([ellipse(22, 22, (-36, 0)), fill(GREY)]), group([ellipse(22, 22, (0, 0)), fill(GREY)]),
	                      group([ellipse(22, 22, (36, 0)), fill(GREY)])],
	             p=(390, 130), o=moving((0, 30), (30, 100), (60, 30)))


def bang():
	return layer("bang", [group([rect(16, 60, (0, -20), 8), fill(GOLD)]), group([ellipse(18, 18, (0, 30)), fill(GOLD)])],
	             p=(400, 140), s=moving((0, [100, 100]), (10, [130, 130]), (20, [100, 100]), (60, [100, 100])))


def check():
	return layer("check", [group([path([(-30, 0), (-8, 24), (34, -26)]), stroke([0.2, 0.7, 0.35, 1], 16)])],
	             p=(400, 140), s=moving((0, [0, 0]), (15, [110, 110]), (25, [100, 100]), (60, [100, 100])))


def anim(name, layers):
	# Lottie draws its first layer on top: the art lists front to back.
	return {"v": "5.7.4", "fr": 30, "ip": 0, "op": FRAMES, "w": W, "h": H, "nm": name, "ddd": 0, "assets": [],
	        "layers": [dict(l, ind=i + 1) for i, l in enumerate(layers)]}


WAVE = moving((0, -20), (15, 25), (30, -20), (45, 25), (60, -20))

STICKERS = [
	("hello", "Pip waving hello",
	 [eyes(), mouth("smile"), cheeks(), hand((400, 260), rotate=WAVE), body()],
	 ["hello", "hi", "hey", "hiya", "hey there", "hi there", "hello there", "howdy", "yo", "greetings",
	  "good morning", "morning", "good afternoon", "good evening", "nice to meet you", "long time no see",
	  "how are you", "how are you doing", "how's it going", "what's up", "sup", "wave", "waving", "hallo",
	  "hej", "hola", "ciao", "bonjour"]),
	("ok", "Pip nodding with a tick, OK",
	 [check(), eyes("happy"), mouth("smile"), body(squash=True)],
	 ["ok", "okay", "k", "kk", "sure", "sure thing", "yes", "yep", "yeah", "yup", "alright", "all right",
	  "sounds good", "got it", "understood", "will do", "no problem", "no worries", "agreed", "deal",
	  "of course", "fine", "that works", "works for me", "perfect", "done", "roger", "noted", "absolutely",
	  "definitely", "for sure", "you got it", "consider it done", "makes sense"]),
	("thanks", "Pip bowing in thanks, a little heart above",
	 [heart((256, 110), 0.6), eyes("closed", dy=10), mouth("smile"), cheeks(), body(squash=True)],
	 ["thanks", "thank you", "thank you so much", "thanks so much", "thanks a lot", "many thanks", "thx", "ty",
	  "tysm", "much appreciated", "appreciate it", "i appreciate it", "i appreciate you", "cheers", "grateful",
	  "so grateful", "you're the best", "you are the best", "you're a star", "that's kind of you", "so kind",
	  "you shouldn't have", "thanks for everything", "thanks for your help", "thanks for coming", "tack"]),
	("sorry", "Pip looking sorry, a tear falling",
	 [drop((340, 250)), eyes("closed"), mouth("sad"), body(bob=False)],
	 ["sorry", "i'm sorry", "so sorry", "really sorry", "my bad", "my mistake", "oops", "apologies",
	  "my apologies", "forgive me", "please forgive me", "i didn't mean it", "i didn't mean to", "sorry about that",
	  "sorry for the delay", "sorry i'm late", "sorry for the late reply", "excuse me", "pardon", "whoops",
	  "that was my fault", "feel bad", "i feel bad", "ugh sorry", "förlåt"]),
	("on-my-way", "Pip running, on the way",
	 [eyes(dy=-5), mouth("open"), body(squash=True),
	  layer("dust", [group([ellipse(40, 26, (-150, 150)), fill(GREY)]), group([ellipse(26, 18, (-195, 135)), fill(GREY)])],
	        p=(256, 256), o=moving((0, 80), (60, 0)))],
	 ["on my way", "omw", "coming", "i'm coming", "coming now", "be right there", "be there soon",
	  "be there in five", "be there in 5", "be there in ten minutes", "almost there", "nearly there", "on the way",
	  "leaving now", "just left", "heading out", "heading over", "running late", "i'm late", "hurry", "hurrying",
	  "in a hurry", "rushing", "two minutes", "five minutes", "i'll be right there", "wait for me",
	  "i'll be there in five minutes", "see you soon", "eta"]),
	("see-you", "Pip waving goodbye",
	 [eyes("happy"), mouth("smile"), hand((110, 260), rotate=WAVE), body()],
	 ["see you", "see ya", "see you later", "see you soon", "see you tomorrow", "see you tonight",
	  "see you there", "see you around", "see you next week", "later", "laters", "catch you later",
	  "talk later", "talk to you later", "ttyl", "bye", "bye bye", "goodbye", "good bye", "take care", "farewell",
	  "until next time", "so long", "cya", "gotta go", "got to go", "have to go", "have a good one",
	  "have a nice day", "have a great day", "hej då", "adios"]),
	("good-night", "Pip asleep, Z after Z",
	 [zeds(), eyes("closed"), mouth("o"), body(squash=True)],
	 ["good night", "goodnight", "night", "nighty night", "night night", "gn", "sleep well", "sleep tight",
	  "sweet dreams", "going to bed", "off to bed", "bedtime", "time for bed", "sleepy", "so sleepy", "tired",
	  "so tired", "exhausted", "zzz", "nap", "napping", "taking a nap", "rest well", "god natt", "sov gott"]),
	("laughing", "Pip laughing out loud",
	 [eyes("happy"), mouth("grin"), cheeks(), body(squash=True)],
	 ["haha", "hahaha", "lol", "lmao", "rofl", "hehe", "heh", "that's funny", "so funny", "hilarious",
	  "laughing", "can't stop laughing", "i'm dying", "dying", "dead", "too funny", "good one", "you're funny",
	  "that's hilarious", "lol that's great", "made my day", "cracking up", "lmfao", "xd", "ha"]),
	("love", "Pip hugging a big heart",
	 [heart((256, 340), 1.3), eyes("happy"), cheeks(), body(bob=False)],
	 ["love", "love you", "i love you", "love you too", "love it", "i love it", "love this", "so much love",
	  "lots of love", "xoxo", "xo", "hugs", "big hug", "sending hugs", "sending love", "miss you", "i miss you",
	  "missing you", "you're sweet", "so sweet", "adorable", "aww", "awww", "heart", "<3", "kisses", "kiss",
	  "darling", "sweetheart", "my love", "jag älskar dig"]),
	("waiting", "Pip waiting beside a ticking clock",
	 [clock(), eyes(), mouth("flat"), body()],
	 ["waiting", "still waiting", "i'm waiting", "waiting for you", "where are you", "where r u", "hurry up",
	  "any update", "any news", "well", "so", "hello?", "anyone there", "you there", "are you there",
	  "how long", "how much longer", "taking forever", "still here", "tick tock", "time", "what time",
	  "what time is it", "when", "when are you coming", "soon?", "ready?", "are you ready", "patience"]),
	("congratulations", "Pip cheering under falling confetti",
	 [confetti(), eyes("happy"), mouth("open"), cheeks(), body(squash=True)],
	 ["congratulations", "congrats", "congrats!", "well done", "great job", "good job", "nice job", "amazing",
	  "awesome", "brilliant", "fantastic", "you did it", "we did it", "proud of you", "so proud of you",
	  "hooray", "hurray", "yay", "woohoo", "woo", "celebrate", "let's celebrate", "party", "happy birthday",
	  "happy new year", "cheers to that", "bravo", "nailed it", "you rock", "grattis", "grattis på födelsedagen"]),
	("thinking", "Pip thinking it over",
	 [dots(), eyes(), mouth("flat"), hand((330, 350), rotate=moving((0, 10), (30, -5), (60, 10))), body(bob=False)],
	 ["hmm", "hmmm", "let me think", "thinking", "i'm thinking", "let me see", "not sure", "i'm not sure",
	  "maybe", "perhaps", "i wonder", "wondering", "good question", "no idea", "dunno", "i don't know", "idk",
	  "who knows", "we'll see", "possibly", "could be", "depends", "it depends", "hard to say", "thinking about it",
	  "let me get back to you", "give me a minute", "one sec", "one moment", "what do you think", "really?",
	  "are you sure", "wait what", "huh"]),
]


def check_phrases():
	for slug, desc, _, phrases in STICKERS:
		# WHAT A LENGTH BYTE SAYS, sec 1278: 255 phrases of 255 bytes, and a
		# description of 255.
		if len(phrases) > 255 or len(set(phrases)) != len(phrases):
			sys.exit("%s: more than 255 phrases, or one twice" % slug)
		for p in phrases:
			if not p or len(p.encode()) > 255 or "\n" in p:
				sys.exit("%s: phrase %r is empty, past 255 bytes or broken" % (slug, p))
		if len(desc.encode()) > 255:
			sys.exit("%s: description past 255 bytes" % slug)


def main():
	check_phrases()
	os.makedirs(os.path.join(OUT, "art"), exist_ok=True)
	spec = ["# THE ORIGINAL TEST SET, fuzznet sec 1277: written by tool/sticker_test_set.py,",
	        "# not by hand. A fixture for the path and the search while typing -- not a",
	        "# set to ship or market (the holder, 2026-11-18).",
	        "name fuzznet test set (not for release)", ""]
	for i, (slug, desc, layers, phrases) in enumerate(STICKERS, 1):
		art = "art/%02d-%s.json" % (i, slug)
		with open(os.path.join(OUT, art), "w") as f:
			json.dump(anim(slug, layers), f, separators=(",", ":"))
			f.write("\n")
		spec.append("sticker animated")
		spec.append("description " + desc)
		spec.extend("keyword " + p for p in phrases)
		spec.append("main lottie 512 512 " + art)
		spec.append("")
	with open(os.path.join(OUT, "test-set.spec"), "w") as f:
		f.write("\n".join(spec))
	print("sticker_test_set: %d stickers, %d phrases, in %s"
	      % (len(STICKERS), sum(len(s[3]) for s in STICKERS), os.path.relpath(OUT, ROOT)))


if __name__ == "__main__":
	main()
