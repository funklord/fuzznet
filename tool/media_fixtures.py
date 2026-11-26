#!/usr/bin/env python3
"""Write media/test/fixture/: small files whose tags media/test/tags_test.c
reads back, project.md sec 1447.

WRITTEN BY OTHER HANDS than the reader they test: ffmpeg for the MP3s,
the Ogg Vorbis and Opus files, the M4As, and the FLAC's audio, mutagen
for an ID3v2.3 tag, metaflac for the Vorbis comments, Pillow for the
JPEG and its EXIF, jhead for an EXIF thumbnail. A reader agreeing with
what those wrote is evidence; one agreeing with bytes this tree built
for itself would be a reader checked against its own reading. Run again
after changing it; it writes only media/test/fixture/ and a scratch
directory it removes.

NOT BYTE FOR BYTE AGAIN: an Ogg stream's serial is drawn at random, so
song.ogg and memo.opus differ at each run, and jhead stamps
photo_thumb.jpg; keep the committed ones unless they are meant to
change.

BOUNDED: thirteen files, each from one tool run with a timeout; nothing loops.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "media", "test", "fixture")
TIMEOUT_S = 60


def run(*argv):
	subprocess.run(argv, check=True, timeout=TIMEOUT_S, stdout=subprocess.DEVNULL,
	               stderr=subprocess.DEVNULL)


def main():
	import mutagen.id3 as id3
	from PIL import Image

	os.makedirs(OUT, exist_ok=True)
	with tempfile.TemporaryDirectory(prefix="fzn-media.") as scratch:
		tone = ["-f", "lavfi", "-i", "sine=frequency=440:duration=0.25:sample_rate=8000"]

		# ID3v2.4, as ffmpeg writes it: UTF-8 text, the recording time.
		run("ffmpeg", "-y", "-loglevel", "error", *tone, "-ac", "1", "-b:a", "8k",
		    "-metadata", "title=Night Drive", "-metadata", "artist=Svalbard Echo",
		    "-metadata", "album=Polar Lights", "-metadata", "album_artist=Various",
		    "-metadata", "genre=Synthwave", "-metadata", "track=3/12",
		    "-metadata", "disc=1/2", "-metadata", "date=2019",
		    "-id3v2_version", "4", os.path.join(OUT, "v24.mp3"))

		# ID3v2.3, as mutagen writes it: a plain u32 frame size, UTF-16 text
		# with a byte order mark, TYER, and a name past Latin-1.
		bare = os.path.join(scratch, "bare.mp3")
		run("ffmpeg", "-y", "-loglevel", "error", *tone, "-ac", "1", "-b:a", "8k",
		    "-write_id3v2", "0", bare)
		tags = id3.ID3()
		tags.add(id3.TIT2(encoding=1, text="Förlåt — 夜"))
		tags.add(id3.TPE1(encoding=0, text="Björk"))
		# Long enough, in UTF-16, that its size passes 127: below that a plain
		# u32 and a synchsafe size are the same bytes, and a reader taking
		# one for the other would pass.
		tags.add(id3.TALB(encoding=1, text="Homogenic (Deluxe Edition, Remastered in 2024, with the Bonus Tracks and Live Recordings)"))
		tags.add(id3.TRCK(encoding=0, text="7"))
		tags.add(id3.TYER(encoding=0, text="1997"))
		tags.add(id3.TLEN(encoding=0, text="250"))
		tags.save(bare, v2_version=3)
		shutil.copy(bare, os.path.join(OUT, "v23.mp3"))

		# FLAC, its tags by metaflac: case as people write it, the track
		# and its total apart, and a picture block before the comments.
		flac = os.path.join(OUT, "song.flac")
		run("ffmpeg", "-y", "-loglevel", "error", *tone, "-ac", "1", "-sample_fmt", "s16",
		    "-map_metadata", "-1", flac)
		cover = os.path.join(scratch, "cover.png")
		Image.new("RGB", (4, 4), (200, 30, 30)).save(cover)
		run("metaflac", "--remove-all-tags", "--import-picture-from=" + cover,
		    "--set-tag=Title=Waltz for Debby", "--set-tag=ARTIST=Bill Evans",
		    "--set-tag=album=Sunday at the Village Vanguard", "--set-tag=TRACKNUMBER=2",
		    "--set-tag=TRACKTOTAL=6", "--set-tag=DATE=1961-06-25", flac)

		# Ogg Vorbis and Ogg Opus, ffmpeg's: the comments in the stream's
		# second packet, after the identification header.
		run("ffmpeg", "-y", "-loglevel", "error", *tone, "-ac", "1", "-c:a", "libvorbis",
		    "-metadata", "title=Snow on the Fjord", "-metadata", "artist=Kvist",
		    "-metadata", "album=Vinter", "-metadata", "track=4", "-metadata", "date=2021",
		    os.path.join(OUT, "song.ogg"))
		run("ffmpeg", "-y", "-loglevel", "error", *tone, "-ac", "1", "-c:a", "libopus",
		    "-metadata", "title=Voice memo", "-metadata", "artist=Anna",
		    os.path.join(OUT, "memo.opus"))

		# AN MP3 OF NO TAG AND NO XING HEADER, a constant bitrate: its length
		# is its bytes over the bitrate (sec 1456).
		run("ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i",
		    "sine=frequency=440:duration=1:sample_rate=44100", "-ac", "1", "-b:a", "64k",
		    "-write_xing", "0", "-write_id3v2", "0", "-id3v2_version", "0",
		    os.path.join(OUT, "cbr.mp3"))

		# MP4 audio, ffmpeg's: the movie box after the media as it writes it
		# by default, and before it with +faststart -- the reader must find
		# it either way, by the boxes' sizes.
		for name, flags in (("song.m4a", []), ("song_fast.m4a", ["-movflags", "+faststart"])):
			run("ffmpeg", "-y", "-loglevel", "error", *tone, "-ac", "1", "-c:a", "aac", "-b:a", "16k",
			    "-metadata", "title=Midnight Sun", "-metadata", "artist=Lumo",
			    "-metadata", "album_artist=Various", "-metadata", "album=Arctic Nights",
			    "-metadata", "track=2/9", "-metadata", "disc=1/1", "-metadata", "date=2018",
			    "-metadata", "genre=Ambient", *flags, os.path.join(OUT, name))

		# A JPEG with EXIF from Pillow: big-endian ("MM"), as many cameras
		# write it, a maker and a model that repeats it, both dates, an
		# orientation, and where it was taken -- Kiruna, north and east.
		img = Image.new("RGB", (16, 12), (40, 120, 200))
		exif = Image.Exif()
		exif.endian = ">"
		exif[0x010F] = "Canon"
		exif[0x0110] = "Canon EOS 5D Mark IV"
		exif[0x0112] = 6
		exif[0x0132] = "2024:01:02 03:04:05"
		sub = exif.get_ifd(0x8769)
		sub[0x9003] = "2023:07:14 21:45:30"
		sub[0xA002] = 4000
		sub[0xA003] = 3000
		gps = exif.get_ifd(0x8825)
		gps[1] = "N"
		gps[2] = (67.0, 51.0, 21.6)
		gps[3] = "E"
		gps[4] = (20.0, 13.0, 30.0)
		img.save(os.path.join(OUT, "photo.jpg"), exif=exif, quality=50)

		# Little-endian ("II"), as Pillow and most phones write it: south and
		# west, the file's time alone, a maker and no model.
		img = Image.new("RGB", (8, 8), (90, 90, 90))
		exif = Image.Exif()
		exif[0x010F] = "OnePlus  "
		exif[0x0132] = "2025:12:31 23:59:58"
		gps = exif.get_ifd(0x8825)
		gps[1] = "S"
		gps[2] = (33.0, 51.0, 54.0)
		gps[3] = "W"
		gps[4] = (70.0, 39.0, 0.0)
		img.save(os.path.join(OUT, "photo_le.jpg"), exif=exif, quality=50)

		# A THUMBNAIL IN EXIF, by jhead: a minimal EXIF header, then its
		# thumbnail generated (through ImageMagick), and jhead's own copy of
		# it extracted beside, for the reader to be compared against.
		img = Image.new("RGB", (640, 480), (40, 120, 200))
		for x in range(0, 640, 40):
			for y in range(480):
				img.putpixel((x, y), (250, 250, 0))
		thumbed = os.path.join(OUT, "photo_thumb.jpg")
		img.save(thumbed, quality=60)
		run("jhead", "-mkexif", thumbed)
		run("jhead", "-rgt", thumbed)
		run("jhead", "-st", os.path.join(OUT, "photo_thumb.thumb"), thumbed)

		# And one with no EXIF at all, for its frame's size.
		Image.new("RGB", (17, 9), (0, 0, 0)).save(os.path.join(OUT, "plain.jpg"), quality=50)
	return 0


if __name__ == "__main__":
	sys.exit(main())
