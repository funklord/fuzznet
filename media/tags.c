/* What a file says of itself: media/tags.h, project.md sec 1447. */
#include "tags.h"

#include "../wire/generated/exif.h"
#include "../wire/generated/flac.h"
#include "../wire/generated/id3.h"
#include "../wire/generated/mp4.h"
#include "../wire/generated/mpeg.h"
#include "../wire/generated/ogg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A FILE'S BYTES GONE FROM MEMORY before it is given back: what a library
 * holds is somebody's, and a freed buffer is read by the next to take it.
 * Through a volatile pointer, so the stores are not dropped as dead. */
static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n--)
		*v++ = 0;
}

/* ---- the values ----------------------------------------------------------- */

/* THE CATALOGUE'S NAMES, sec 1447's table: string constants, so a tag's
 * name is compared by pointer as readily as by text. */
static const char N_TITLE[] = "title", N_ARTIST[] = "artist", N_ALBUM[] = "album",
                  N_ALBUM_ARTIST[] = "album_artist", N_GENRE[] = "genre",
                  N_COMPOSER[] = "composer", N_TRACK[] = "track", N_DISC[] = "disc",
                  N_YEAR[] = "year", N_DURATION[] = "duration", N_TAKEN[] = "taken",
                  N_CAMERA[] = "camera", N_WIDTH[] = "width", N_HEIGHT[] = "height",
                  N_PLACE[] = "place", N_ORIENTATION[] = "orientation";

const fzn_media_tag_t *fzn_media_tag_find(const fzn_media_tags_t *tags, const char *name)
{
	size_t i;

	for (i = 0; tags && name && i < tags->count; i++)
		if (strcmp(tags->tags[i].name, name) == 0)
			return &tags->tags[i];
	return NULL;
}

/* The length of the UTF-8 character at `s` (at most `left` bytes): 1 to 4,
 * or 0 where the bytes are not one -- an overlong form, a surrogate, past
 * U+10FFFF, or cut short. */
static size_t utf8_char(const uint8_t *s, size_t left)
{
	uint32_t c;
	size_t n, i;

	if (!left)
		return 0;
	if (s[0] < 0x80u)
		return 1;
	if ((s[0] & 0xE0u) == 0xC0u)
		n = 2, c = s[0] & 0x1Fu;
	else if ((s[0] & 0xF0u) == 0xE0u)
		n = 3, c = s[0] & 0x0Fu;
	else if ((s[0] & 0xF8u) == 0xF0u)
		n = 4, c = s[0] & 0x07u;
	else
		return 0;
	if (n > left)
		return 0;
	for (i = 1; i < n; i++) {
		if ((s[i] & 0xC0u) != 0x80u)
			return 0;
		c = (c << 6) | (s[i] & 0x3Fu);
	}
	if ((n == 2 && c < 0x80u) || (n == 3 && c < 0x800u) || (n == 4 && c < 0x10000u) || c > 0x10FFFFu
	    || (c >= 0xD800u && c <= 0xDFFFu))
		return 0;
	return n;
}

/* `u` (a code point) onto `out` as UTF-8, if it fits: the bytes written. */
static size_t utf8_put(uint32_t u, uint8_t *out, size_t room)
{
	if (u < 0x80u && room >= 1) {
		out[0] = (uint8_t)u;
		return 1;
	}
	if (u < 0x800u && room >= 2) {
		out[0] = (uint8_t)(0xC0u | (u >> 6));
		out[1] = (uint8_t)(0x80u | (u & 0x3Fu));
		return 2;
	}
	if (u < 0x10000u && room >= 3) {
		out[0] = (uint8_t)(0xE0u | (u >> 12));
		out[1] = (uint8_t)(0x80u | ((u >> 6) & 0x3Fu));
		out[2] = (uint8_t)(0x80u | (u & 0x3Fu));
		return 3;
	}
	if (u <= 0x10FFFFu && u >= 0x10000u && room >= 4) {
		out[0] = (uint8_t)(0xF0u | (u >> 18));
		out[1] = (uint8_t)(0x80u | ((u >> 12) & 0x3Fu));
		out[2] = (uint8_t)(0x80u | ((u >> 6) & 0x3Fu));
		out[3] = (uint8_t)(0x80u | (u & 0x3Fu));
		return 4;
	}
	return 0;
}

/* `name` = `text` (UTF-8, `len` bytes) taken into `out` unless the name is
 * there already: a control character becomes a space, a byte that is not
 * UTF-8 ends the value, the ends are trimmed, and it is cut at a
 * character's edge to fit. Nothing is taken that comes to nothing. */
static void put(fzn_media_tags_t *out, const char *name, const uint8_t *text, size_t len)
{
	fzn_media_tag_t *t;
	size_t at = 0, n = 0, c;

	if (out->count >= FZN_MEDIA_TAGS_MAX || fzn_media_tag_find(out, name))
		return;
	t = &out->tags[out->count];
	while (at < len && text[at]) {
		c = utf8_char(text + at, len - at);
		if (!c || n + c > FZN_MEDIA_TAG_VALUE_MAX)
			break;
		if (c == 1 && (text[at] < 0x20u || text[at] == 0x7Fu))
			t->value[n] = ' ';
		else
			memcpy(t->value + n, text + at, c);
		n += c;
		at += c;
	}
	while (n && t->value[n - 1] == ' ')
		n--;
	at = 0;
	while (at < n && t->value[at] == ' ')
		at++;
	if (at == n)
		return;
	memmove(t->value, t->value + at, n - at);
	t->value_len = n - at;
	t->value[t->value_len] = '\0';
	t->name = name;
	out->count++;
}

static void put_text(fzn_media_tags_t *out, const char *name, const char *text)
{
	put(out, name, (const uint8_t *)text, strlen(text));
}

/* ---- JPEG and EXIF, media/exif.situ ----------------------------------------- */

#define TIFF_ASCII 2u
#define TIFF_SHORT 3u
#define TIFF_LONG 4u
#define TIFF_RATIONAL 5u

struct tiff {
	situ_msg_t msg; /* the TIFF, offsets counted from its first byte */
	const uint8_t *base;
	uint32_t len;
	uint16_t order;
};

/* A directory at `off`: its view, or 0. */
static int tiff_ifd(const struct tiff *t, uint32_t off, situ_view_t *ifd)
{
	uint32_t need = 0;

	return off >= 8u && off < t->len
	       && fzn_exif_ifd_required(t->base + off, t->len - off, &need, t->order) == SITU_OK
	       && fzn_exif_ifd_view(&t->msg, off, need, ifd) == SITU_OK
	       && fzn_exif_ifd_validate(*ifd, t->order) == SITU_OK;
}

/* An entry's value bytes, where its type and count put them: in the
 * entry's last four bytes when they fit, else at the offset those name.
 * NULL where they lie outside the TIFF. */
static const uint8_t *tiff_value(const struct tiff *t, situ_view_t entry, uint32_t size)
{
	uint32_t at = 0;

	if (size <= 4u)
		return entry.base + 8;
	if (fzn_exif_ifd_entry_value_long_get(entry, &at, t->order) != SITU_OK || at > t->len
	    || size > t->len - at)
		return NULL;
	return t->base + at;
}

/* An ASCII entry's text: its bytes up to the first NUL, or none. */
static size_t tiff_ascii(const struct tiff *t, situ_view_t entry, const uint8_t **text)
{
	uint32_t count = fzn_exif_ifd_entry_count_get(entry, t->order);
	const uint8_t *v;
	size_t n = 0;

	if (fzn_exif_ifd_entry_type_get(entry, t->order) != TIFF_ASCII || !count || count > 4096u
	    || !(v = tiff_value(t, entry, count)))
		return 0;
	while (n < count && v[n])
		n++;
	*text = v;
	return n;
}

/* A SHORT or LONG entry's first value, or 0. */
static int tiff_number(const struct tiff *t, situ_view_t entry, uint32_t *out)
{
	uint16_t s = 0;
	uint16_t type = fzn_exif_ifd_entry_type_get(entry, t->order);

	if (!fzn_exif_ifd_entry_count_get(entry, t->order))
		return 0;
	if (type == TIFF_SHORT && fzn_exif_ifd_entry_value_shorts_get(entry, 0, &s, t->order) == SITU_OK) {
		*out = s;
		return 1;
	}
	return type == TIFF_LONG && fzn_exif_ifd_entry_value_long_get(entry, out, t->order) == SITU_OK;
}

/* A GPS coordinate, three RATIONALs of degrees, minutes and seconds, in
 * degrees: 0 where it does not read or is no coordinate. */
static int tiff_degrees(const struct tiff *t, situ_view_t entry, double *out)
{
	uint32_t at = 0, i;
	double part[3];

	if (fzn_exif_ifd_entry_type_get(entry, t->order) != TIFF_RATIONAL
	    || fzn_exif_ifd_entry_count_get(entry, t->order) != 3u
	    || fzn_exif_ifd_entry_value_long_get(entry, &at, t->order) != SITU_OK || at > t->len
	    || t->len - at < 24u)
		return 0;
	for (i = 0; i < 3u; i++) {
		situ_view_t r;
		uint32_t num, den;

		if (fzn_exif_rational_view(&t->msg, at + 8u * i, &r) != SITU_OK)
			return 0;
		num = fzn_exif_rational_numerator_get(r, t->order);
		den = fzn_exif_rational_denominator_get(r, t->order);
		if (!den)
			return 0;
		part[i] = (double)num / (double)den;
	}
	*out = part[0] + part[1] / 60.0 + part[2] / 3600.0;
	return *out <= 180.0;
}

/* EXIF's "YYYY:MM:DD HH:MM:SS" as "YYYY-MM-DDTHH:MM:SS"; 0 for anything
 * else, a camera's blank "    :  :     :  :  " among it. */
static int exif_date(const uint8_t *text, size_t len, char out[20])
{
	static const char shape[] = "dddd:dd:dd dd:dd:dd";
	size_t i;

	if (len < 19u)
		return 0;
	for (i = 0; i < 19u; i++) {
		if (shape[i] == 'd' ? (text[i] < '0' || text[i] > '9') : text[i] != (uint8_t)shape[i])
			return 0;
		out[i] = (char)text[i];
	}
	out[4] = out[7] = '-';
	out[10] = 'T';
	out[19] = '\0';
	return memcmp(out, "0000", 4) != 0;
}

#define TAG_MAKE 0x010Fu
#define TAG_MODEL 0x0110u
#define TAG_ORIENTATION 0x0112u
#define TAG_DATETIME 0x0132u
#define TAG_EXIF_IFD 0x8769u
#define TAG_GPS_IFD 0x8825u
#define TAG_DATETIME_ORIGINAL 0x9003u
#define TAG_PIXEL_X 0xA002u
#define TAG_PIXEL_Y 0xA003u
#define TAG_GPS_LAT_REF 0x0001u
#define TAG_GPS_LAT 0x0002u
#define TAG_GPS_LON_REF 0x0003u
#define TAG_GPS_LON 0x0004u

/* The facts of a TIFF directory a catalogue keeps, from EXIF's APP1. */
static void exif_read(const uint8_t *tiff_bytes, uint32_t len, fzn_media_tags_t *out)
{
	struct tiff t;
	situ_view_t head, ifd0, sub, e;
	const uint8_t *make = NULL, *model = NULL, *text;
	size_t make_len = 0, model_len = 0, n;
	uint32_t exif_at = 0, gps_at = 0, i, count, v;
	char taken[20] = "", when[20] = "", place[48];
	int lat_ok = 0, lon_ok = 0;
	double lat = 0.0, lon = 0.0;
	char south = 0, west = 0;

	t.base = tiff_bytes;
	t.len = len;
	situ_msg_init(&t.msg, (uint8_t *)(uintptr_t)tiff_bytes, len);
	if (fzn_exif_tiff_header_view(&t.msg, 0, &head) != SITU_OK
	    || fzn_exif_tiff_header_validate(head) != SITU_OK)
		return;
	t.order = fzn_exif_tiff_header_byte_order_get(head);
	if (!tiff_ifd(&t, fzn_exif_tiff_header_ifd_offset_get(head), &ifd0))
		return;
	count = fzn_exif_ifd_entries_count(ifd0, t.order);
	for (i = 0; i < count; i++) {
		if (fzn_exif_ifd_entries_at(ifd0, i, &e, t.order) != SITU_OK)
			continue;
		switch (fzn_exif_ifd_entry_tag_get(e, t.order)) {
		case TAG_MAKE:
			make_len = tiff_ascii(&t, e, &make);
			break;
		case TAG_MODEL:
			model_len = tiff_ascii(&t, e, &model);
			break;
		case TAG_ORIENTATION:
			if (tiff_number(&t, e, &v) && v >= 1u && v <= 8u) {
				char o[2] = { (char)('0' + v), '\0' };
				put_text(out, N_ORIENTATION, o);
			}
			break;
		case TAG_DATETIME:
			if ((n = tiff_ascii(&t, e, &text)) != 0)
				(void)exif_date(text, n, when);
			break;
		case TAG_EXIF_IFD:
			(void)tiff_number(&t, e, &exif_at);
			break;
		case TAG_GPS_IFD:
			(void)tiff_number(&t, e, &gps_at);
			break;
		default:
			break;
		}
	}
	/* THE EXIF DIRECTORY: when the picture was taken, and its size. */
	if (exif_at && tiff_ifd(&t, exif_at, &sub)) {
		count = fzn_exif_ifd_entries_count(sub, t.order);
		for (i = 0; i < count; i++) {
			if (fzn_exif_ifd_entries_at(sub, i, &e, t.order) != SITU_OK)
				continue;
			switch (fzn_exif_ifd_entry_tag_get(e, t.order)) {
			case TAG_DATETIME_ORIGINAL:
				if ((n = tiff_ascii(&t, e, &text)) != 0)
					(void)exif_date(text, n, taken);
				break;
			case TAG_PIXEL_X:
			case TAG_PIXEL_Y:
				if (tiff_number(&t, e, &v) && v) {
					char num[12];
					(void)snprintf(num, sizeof(num), "%u", (unsigned)v);
					put_text(out, fzn_exif_ifd_entry_tag_get(e, t.order) == TAG_PIXEL_X ? N_WIDTH : N_HEIGHT,
					         num);
				}
				break;
			default:
				break;
			}
		}
	}
	/* THE GPS DIRECTORY: where. */
	if (gps_at && tiff_ifd(&t, gps_at, &sub)) {
		count = fzn_exif_ifd_entries_count(sub, t.order);
		for (i = 0; i < count; i++) {
			if (fzn_exif_ifd_entries_at(sub, i, &e, t.order) != SITU_OK)
				continue;
			switch (fzn_exif_ifd_entry_tag_get(e, t.order)) {
			case TAG_GPS_LAT_REF:
				if (tiff_ascii(&t, e, &text))
					south = text[0] == 'S';
				break;
			case TAG_GPS_LON_REF:
				if (tiff_ascii(&t, e, &text))
					west = text[0] == 'W';
				break;
			case TAG_GPS_LAT:
				lat_ok = tiff_degrees(&t, e, &lat) && lat <= 90.0;
				break;
			case TAG_GPS_LON:
				lon_ok = tiff_degrees(&t, e, &lon);
				break;
			default:
				break;
			}
		}
		if (lat_ok && lon_ok) {
			(void)snprintf(place, sizeof(place), "%.7f,%.7f", south ? -lat : lat, west ? -lon : lon);
			put_text(out, N_PLACE, place);
		}
	}
	if (taken[0] || when[0])
		put_text(out, N_TAKEN, taken[0] ? taken : when);
	/* THE CAMERA, its maker's name once: "Canon" and "Canon EOS 5D" are
	 * "Canon EOS 5D", and a model alone is itself. */
	while (make_len && make[make_len - 1] == ' ')
		make_len--;
	if (model_len) {
		char camera[2u * 128u + 2u];

		if (!make_len || make_len > 128u || model_len > 128u
		    || (model_len >= make_len && memcmp(model, make, make_len) == 0))
			put(out, N_CAMERA, model, model_len);
		else {
			memcpy(camera, make, make_len);
			camera[make_len] = ' ';
			memcpy(camera + make_len + 1u, model, model_len);
			put(out, N_CAMERA, (const uint8_t *)camera, make_len + 1u + model_len);
		}
	} else if (make_len) {
		put(out, N_CAMERA, make, make_len);
	}
}

/* THE CAMERA'S OWN THUMBNAIL, sec 1455: IFD0's next directory, IFD1, names
 * a JPEG by its offset (0x0201) and length (0x0202), counted from the TIFF
 * header. Where it lies wholly within the APP1 segment: 1 with its place in
 * `tiff_bytes`. */
static int exif_thumbnail(const uint8_t *tiff_bytes, uint32_t len, uint32_t *at, uint32_t *n)
{
	struct tiff t;
	situ_view_t head, ifd0, ifd1, e;
	uint32_t i, count, offset = 0, length = 0, v;

	t.base = tiff_bytes;
	t.len = len;
	situ_msg_init(&t.msg, (uint8_t *)(uintptr_t)tiff_bytes, len);
	if (fzn_exif_tiff_header_view(&t.msg, 0, &head) != SITU_OK || fzn_exif_tiff_header_validate(head) != SITU_OK)
		return 0;
	t.order = (uint16_t)fzn_exif_tiff_header_byte_order_get(head);
	if (!tiff_ifd(&t, fzn_exif_tiff_header_ifd_offset_get(head), &ifd0)
	    || !tiff_ifd(&t, fzn_exif_ifd_next_get(ifd0, t.order), &ifd1))
		return 0;
	count = fzn_exif_ifd_entries_count(ifd1, t.order);
	for (i = 0; i < count; i++) {
		if (fzn_exif_ifd_entries_at(ifd1, i, &e, t.order) != SITU_OK || !tiff_number(&t, e, &v))
			continue;
		if (fzn_exif_ifd_entry_tag_get(e, t.order) == 0x0201u)
			offset = v;
		else if (fzn_exif_ifd_entry_tag_get(e, t.order) == 0x0202u)
			length = v;
	}
	if (!offset || length < 4u || offset > len || length > len - offset || tiff_bytes[offset] != 0xFFu
	    || tiff_bytes[offset + 1u] != 0xD8u)
		return 0;
	*at = offset;
	*n = length;
	return 1;
}

int fzn_media_exif_thumbnail(const uint8_t *head, size_t len, size_t *offset, size_t *thumb_len)
{
	situ_msg_t msg;
	uint32_t at = 2, have = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len, need;

	if (!head || len < 4u || head[0] != 0xFFu || head[1] != 0xD8u || !offset || !thumb_len)
		return 0;
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)head, have);
	while (at + 4u <= have) {
		situ_view_t seg, v;
		situ_msg_t app;
		uint32_t body_len, t_at = 0, t_n = 0;
		const uint8_t *body;

		if (head[at] == 0xFFu && head[at + 1u] == 0xFFu) {
			at++;
			continue;
		}
		need = 0;
		if (fzn_exif_jpeg_segment_required(head + at, have - at, &need) != SITU_OK
		    || fzn_exif_jpeg_segment_view(&msg, at, need, &seg) != SITU_OK
		    || fzn_exif_jpeg_segment_validate(seg) != SITU_OK || fzn_exif_jpeg_segment_marker_get(seg) == 0xDAu)
			return 0;
		body = fzn_exif_jpeg_segment_body_ptr(seg);
		body_len = fzn_exif_jpeg_segment_body_len(seg);
		situ_msg_init(&app, (uint8_t *)(uintptr_t)body, body_len);
		if (fzn_exif_jpeg_segment_marker_get(seg) == 0xE1u && body_len > 6u + 8u
		    && fzn_exif_exif_app1_view(&app, 0, &v) == SITU_OK && fzn_exif_exif_app1_validate(v) == SITU_OK
		    && exif_thumbnail(body + 6, body_len - 6u, &t_at, &t_n)) {
			*offset = (size_t)(body + 6 + t_at - head);
			*thumb_len = t_n;
			return 1;
		}
		at += need;
	}
	return 0;
}

/* B.1.1.3: from after SOI, segment by segment to the scan. */
static void jpeg_read(const uint8_t *b, size_t len, fzn_media_tags_t *out)
{
	situ_msg_t msg;
	uint32_t at = 2, have = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len, need;
	char num[12];

	out->format = FZN_MEDIA_JPEG;
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)b, have);
	while (at + 4u <= have) {
		situ_view_t seg;
		uint8_t marker;
		const uint8_t *body;
		uint32_t body_len;

		/* B.1.1.2: any number of fill bytes may stand before a marker. */
		if (b[at] == 0xFFu && b[at + 1u] == 0xFFu) {
			at++;
			continue;
		}
		need = 0;
		if (fzn_exif_jpeg_segment_required(b + at, have - at, &need) != SITU_OK
		    || fzn_exif_jpeg_segment_view(&msg, at, need, &seg) != SITU_OK
		    || fzn_exif_jpeg_segment_validate(seg) != SITU_OK)
			return;
		marker = fzn_exif_jpeg_segment_marker_get(seg);
		body = fzn_exif_jpeg_segment_body_ptr(seg);
		body_len = fzn_exif_jpeg_segment_body_len(seg);
		if (marker == 0xDAu) /* SOS: the scan, and nothing more to read */
			return;
		if (marker == 0xE1u && body_len > 6u + 8u) {
			situ_msg_t app;
			situ_view_t v;

			situ_msg_init(&app, (uint8_t *)(uintptr_t)body, body_len);
			if (fzn_exif_exif_app1_view(&app, 0, &v) == SITU_OK && fzn_exif_exif_app1_validate(v) == SITU_OK)
				exif_read(body + 6, body_len - 6u, out);
		} else if (marker >= 0xC0u && marker <= 0xCFu && marker != 0xC4u && marker != 0xC8u
		           && marker != 0xCCu) {
			situ_view_t frame;

			if (fzn_exif_jpeg_frame_view(&msg, at + 4u, &frame) == SITU_OK
			    && fzn_exif_jpeg_frame_validate(frame) == SITU_OK && fzn_exif_jpeg_frame_height_get(frame)) {
				(void)snprintf(num, sizeof(num), "%u", (unsigned)fzn_exif_jpeg_frame_width_get(frame));
				put_text(out, N_WIDTH, num);
				(void)snprintf(num, sizeof(num), "%u", (unsigned)fzn_exif_jpeg_frame_height_get(frame));
				put_text(out, N_HEIGHT, num);
			}
		}
		at += need;
	}
}

/* ---- ID3v2, media/id3.situ -------------------------------------------------- */

/* A text frame's text, in its encoding, onto `out` as UTF-8: its first
 * value, v2.4 separating several by NUL. */
static void id3_text(const uint8_t *content, uint32_t len, const char *name, fzn_media_tags_t *out)
{
	situ_msg_t msg;
	situ_view_t v;
	uint8_t utf8[FZN_MEDIA_TAG_VALUE_MAX + 4u];
	const uint8_t *s;
	size_t n = 0, i = 0, room = FZN_MEDIA_TAG_VALUE_MAX;
	uint32_t s_len;
	int big = 1;

	situ_msg_init(&msg, (uint8_t *)(uintptr_t)content, len);
	if (!len || fzn_id3_id3_text_view(&msg, 0, len, &v) != SITU_OK || fzn_id3_id3_text_validate(v) != SITU_OK)
		return;
	s = fzn_id3_id3_text_text_ptr(v);
	s_len = fzn_id3_id3_text_text_len(v);
	switch (fzn_id3_id3_text_encoding_get(v)) {
	case FZN_ID3_ID3_ENCODING_UTF_8:
		put(out, name, s, s_len);
		return;
	case FZN_ID3_ID3_ENCODING_ISO_8859_1:
		for (i = 0; i < s_len && s[i]; i++) {
			size_t c = utf8_put(s[i], utf8 + n, room - n);
			if (!c)
				break;
			n += c;
		}
		put(out, name, utf8, n);
		return;
	case FZN_ID3_ID3_ENCODING_UTF_16:
		/* A byte order mark opens it; without one, big-endian. */
		if (s_len >= 2u && s[0] == 0xFFu && s[1] == 0xFEu)
			big = 0, i = 2;
		else if (s_len >= 2u && s[0] == 0xFEu && s[1] == 0xFFu)
			i = 2;
		break;
	case FZN_ID3_ID3_ENCODING_UTF_16_BE:
	default:
		break;
	}
	for (; i + 1u < s_len; i += 2) {
		uint32_t u = big ? (uint32_t)s[i] << 8 | s[i + 1u] : (uint32_t)s[i + 1u] << 8 | s[i];
		size_t c;

		if (!u)
			break;
		if (u >= 0xD800u && u <= 0xDBFFu && i + 3u < s_len) {
			uint32_t lo = big ? (uint32_t)s[i + 2u] << 8 | s[i + 3u] : (uint32_t)s[i + 3u] << 8 | s[i + 2u];
			if (lo < 0xDC00u || lo > 0xDFFFu)
				break;
			u = 0x10000u + ((u - 0xD800u) << 10) + (lo - 0xDC00u);
			i += 2;
		} else if (u >= 0xD800u && u <= 0xDFFFu) {
			break;
		}
		if (!(c = utf8_put(u, utf8 + n, room - n)))
			break;
		n += c;
	}
	put(out, name, utf8, n);
}

/* The frames a catalogue reads, by identifier: v2.3 and v2.4 share them
 * but the year, which v2.4 calls the recording time. */
static const char *id3_name(const uint8_t id[4])
{
	static const struct {
		char id[5];
		const char *name;
	} map[] = {
		{ "TIT2", N_TITLE },  { "TPE1", N_ARTIST }, { "TALB", N_ALBUM },        { "TPE2", N_ALBUM_ARTIST },
		{ "TCON", N_GENRE },  { "TCOM", N_COMPOSER }, { "TRCK", N_TRACK },      { "TPOS", N_DISC },
		{ "TDRC", N_YEAR },   { "TYER", N_YEAR },     { "TLEN", N_DURATION },
	};
	size_t i;

	for (i = 0; i < sizeof(map) / sizeof(map[0]); i++)
		if (memcmp(id, map[i].id, 4) == 0)
			return map[i].name;
	return NULL;
}

static void id3_read(const uint8_t *b, size_t len, fzn_media_tags_t *out)
{
	situ_msg_t msg;
	situ_view_t h;
	uint32_t have = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len, end, at = 10, need;
	uint8_t major;

	situ_msg_init(&msg, (uint8_t *)(uintptr_t)b, have);
	if (fzn_id3_id3_header_view(&msg, 0, &h) != SITU_OK || fzn_id3_id3_header_validate(h) != SITU_OK)
		return;
	out->format = FZN_MEDIA_ID3;
	/* A WHOLE TAG UNSYNCHRONISED is a tag whose every frame needs undoing
	 * first; a catalogue reads it as saying nothing. */
	if (fzn_id3_id3_header_unsynchronisation_get(h))
		return;
	major = fzn_id3_id3_header_major_get(h);
	end = 10u + ((uint32_t)fzn_id3_id3_header_size_0_get(h) << 21 | (uint32_t)fzn_id3_id3_header_size_1_get(h) << 14
	             | (uint32_t)fzn_id3_id3_header_size_2_get(h) << 7 | fzn_id3_id3_header_size_3_get(h));
	if (end > have)
		end = have;
	if (fzn_id3_id3_header_extended_header_get(h)) {
		situ_view_t x;

		need = 0;
		if (major == 3u) {
			if (fzn_id3_id3v23_extended_required(b + at, end - at, &need) != SITU_OK
			    || fzn_id3_id3v23_extended_view(&msg, at, need, &x) != SITU_OK
			    || fzn_id3_id3v23_extended_validate(x) != SITU_OK)
				return;
		} else if (fzn_id3_id3v24_extended_required(b + at, end - at, &need) != SITU_OK
		           || fzn_id3_id3v24_extended_view(&msg, at, need, &x) != SITU_OK
		           || fzn_id3_id3v24_extended_validate(x) != SITU_OK) {
			return;
		}
		at += need;
	}
	/* FRAME BY FRAME, to the padding (a zero byte where an identifier
	 * would start) or the tag's end. */
	while (at + 10u <= end && b[at]) {
		situ_view_t f;
		const uint8_t *id, *content;
		uint32_t content_len;
		uint16_t flags;
		const char *name;

		need = 0;
		if (major == 3u) {
			if (fzn_id3_id3v23_frame_required(b + at, end - at, &need) != SITU_OK
			    || fzn_id3_id3v23_frame_view(&msg, at, need, &f) != SITU_OK
			    || fzn_id3_id3v23_frame_validate(f) != SITU_OK)
				return;
			id = fzn_id3_id3v23_frame_identifier_ptr(f);
			flags = fzn_id3_id3v23_frame_flags_get(f);
			content = fzn_id3_id3v23_frame_content_ptr(f);
			content_len = fzn_id3_id3v23_frame_content_len(f);
			/* v2.3 3.3.1: compressed (0x80) or encrypted (0x40) is not
			 * text; a group byte (0x20) stands before the content. */
			if (flags & 0x00C0u)
				content_len = 0;
			else if ((flags & 0x0020u) && content_len) {
				content++;
				content_len--;
			}
		} else {
			if (fzn_id3_id3v24_frame_required(b + at, end - at, &need) != SITU_OK
			    || fzn_id3_id3v24_frame_view(&msg, at, need, &f) != SITU_OK
			    || fzn_id3_id3v24_frame_validate(f) != SITU_OK)
				return;
			id = fzn_id3_id3v24_frame_identifier_ptr(f);
			flags = fzn_id3_id3v24_frame_flags_get(f);
			content = fzn_id3_id3v24_frame_content_ptr(f);
			content_len = fzn_id3_id3v24_frame_content_len(f);
			/* v2.4 4.1.2: compressed (0x08), encrypted (0x04) or
			 * unsynchronised (0x02) is not plain text; a group byte
			 * (0x40) and a four-byte length (0x01) stand before it. */
			if (flags & 0x000Eu)
				content_len = 0;
			if ((flags & 0x0040u) && content_len) {
				content++;
				content_len--;
			}
			if ((flags & 0x0001u) && content_len >= 4u) {
				content += 4;
				content_len -= 4u;
			}
		}
		if (content_len && (name = id3_name(id)) != NULL) {
			if (name == N_DURATION) {
				/* TLEN: milliseconds, in digits. */
				fzn_media_tags_t one;
				size_t k;

				memset(&one, 0, sizeof(one));
				id3_text(content, content_len, N_DURATION, &one);
				for (k = 0; one.count && k < one.tags[0].value_len; k++)
					if (one.tags[0].value[k] < '0' || one.tags[0].value[k] > '9')
						break;
				if (one.count && k == one.tags[0].value_len && k <= 12u)
					put(out, N_DURATION, (const uint8_t *)one.tags[0].value, k);
			} else {
				id3_text(content, content_len, name, out);
			}
		}
		at += need;
	}
}

/* ---- FLAC, media/flac.situ -------------------------------------------------- */

/* `key`, `n` bytes, is `upper` compared without case. */
static int key_is(const uint8_t *key, size_t n, const char *upper)
{
	size_t k;

	if (strlen(upper) != n)
		return 0;
	for (k = 0; k < n; k++) {
		uint8_t c = key[k];
		if (c >= 'a' && c <= 'z')
			c = (uint8_t)(c - 'a' + 'A');
		if (c != (uint8_t)upper[k])
			return 0;
	}
	return 1;
}

/* The Vorbis comment names a catalogue reads, compared without case. */
static const char *vorbis_name(const uint8_t *key, size_t n)
{
	static const struct {
		const char *key;
		const char *name;
	} map[] = {
		{ "TITLE", N_TITLE },         { "ARTIST", N_ARTIST }, { "ALBUM", N_ALBUM },
		{ "ALBUMARTIST", N_ALBUM_ARTIST }, { "ALBUM ARTIST", N_ALBUM_ARTIST }, { "GENRE", N_GENRE },
		{ "COMPOSER", N_COMPOSER },   { "TRACKNUMBER", N_TRACK }, { "DISCNUMBER", N_DISC },
		{ "DATE", N_YEAR },
	};
	size_t i;

	for (i = 0; i < sizeof(map) / sizeof(map[0]); i++)
		if (key_is(key, n, map[i].key))
			return map[i].name;
	return NULL;
}

/* A comment block's `NAME=value`s. A track number and its total, which
 * Vorbis keeps apart, become ID3's "N/M". */
static void vorbis_read(const uint8_t *b, uint32_t len, fzn_media_tags_t *out)
{
	situ_msg_t msg;
	situ_view_t h;
	uint32_t at, need = 0, count, i;
	const uint8_t *track = NULL, *track_total = NULL, *disc = NULL, *disc_total = NULL;
	size_t track_len = 0, track_total_len = 0, disc_len = 0, disc_total_len = 0;

	situ_msg_init(&msg, (uint8_t *)(uintptr_t)b, len);
	if (fzn_flac_vorbis_comment_head_required(b, len, &need) != SITU_OK
	    || fzn_flac_vorbis_comment_head_view(&msg, 0, need, &h) != SITU_OK
	    || fzn_flac_vorbis_comment_head_validate(h) != SITU_OK)
		return;
	count = fzn_flac_vorbis_comment_head_count_get(h);
	at = need;
	for (i = 0; i < count && at < len; i++) {
		situ_view_t c;
		const uint8_t *text, *eq;
		uint32_t text_len;
		const char *name;

		need = 0;
		if (fzn_flac_vorbis_comment_required(b + at, len - at, &need) != SITU_OK
		    || fzn_flac_vorbis_comment_view(&msg, at, need, &c) != SITU_OK
		    || fzn_flac_vorbis_comment_validate(c) != SITU_OK)
			break;
		at += need;
		text = fzn_flac_vorbis_comment_text_ptr(c);
		text_len = fzn_flac_vorbis_comment_text_len(c);
		if (!(eq = memchr(text, '=', text_len)))
			continue;
		if (key_is(text, (size_t)(eq - text), "TRACKTOTAL") || key_is(text, (size_t)(eq - text), "TOTALTRACKS")) {
			track_total = eq + 1;
			track_total_len = text_len - (size_t)(eq + 1 - text);
			continue;
		}
		if (key_is(text, (size_t)(eq - text), "DISCTOTAL") || key_is(text, (size_t)(eq - text), "TOTALDISCS")) {
			disc_total = eq + 1;
			disc_total_len = text_len - (size_t)(eq + 1 - text);
			continue;
		}
		if (!(name = vorbis_name(text, (size_t)(eq - text))))
			continue;
		if (name == N_TRACK && !track) {
			track = eq + 1;
			track_len = text_len - (size_t)(eq + 1 - text);
		} else if (name == N_DISC && !disc) {
			disc = eq + 1;
			disc_len = text_len - (size_t)(eq + 1 - text);
		} else {
			put(out, name, eq + 1, text_len - (size_t)(eq + 1 - text));
		}
	}
	{
		const uint8_t *part[2][2] = { { track, track_total }, { disc, disc_total } };
		const size_t part_len[2][2] = { { track_len, track_total_len }, { disc_len, disc_total_len } };
		const char *names[2] = { N_TRACK, N_DISC };
		size_t p;

		for (p = 0; p < 2u; p++) {
			char both[2u * 16u + 2u];

			if (!part[p][0] || !part_len[p][0])
				continue;
			if (part[p][1] && part_len[p][1] && part_len[p][0] <= 16u && part_len[p][1] <= 16u
			    && !memchr(part[p][0], '/', part_len[p][0])) {
				memcpy(both, part[p][0], part_len[p][0]);
				both[part_len[p][0]] = '/';
				memcpy(both + part_len[p][0] + 1u, part[p][1], part_len[p][1]);
				put(out, names[p], (const uint8_t *)both, part_len[p][0] + 1u + part_len[p][1]);
			} else {
				put(out, names[p], part[p][0], part_len[p][0]);
			}
		}
	}
}

static void flac_read(const uint8_t *b, size_t len, fzn_media_tags_t *out)
{
	situ_msg_t msg;
	situ_view_t v;
	uint32_t have = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len, at = 4;

	situ_msg_init(&msg, (uint8_t *)(uintptr_t)b, have);
	if (fzn_flac_flac_marker_view(&msg, 0, &v) != SITU_OK || fzn_flac_flac_marker_validate(v) != SITU_OK)
		return;
	out->format = FZN_MEDIA_FLAC;
	while (at + 4u <= have) {
		situ_view_t head;
		uint32_t body, body_len;
		uint8_t type, last;

		if (fzn_flac_flac_block_header_view(&msg, at, &head) != SITU_OK
		    || fzn_flac_flac_block_header_validate(head) != SITU_OK)
			return;
		type = fzn_flac_flac_block_header_type_get(head);
		last = fzn_flac_flac_block_header_last_get(head);
		body = at + 4u;
		body_len = fzn_flac_flac_block_header_length_get(head);
		/* A BLOCK NOT GIVEN WHOLE ends the reading: what follows it is
		 * past the head. */
		if (body_len > have - body)
			return;
		if (type == 0u) {
			situ_view_t si;

			if (body_len == 34u && fzn_flac_flac_streaminfo_view(&msg, body, &si) == SITU_OK
			    && fzn_flac_flac_streaminfo_validate(si) == SITU_OK) {
				uint32_t rate = fzn_flac_flac_streaminfo_sample_rate_get(si);
				uint64_t samples = fzn_flac_flac_streaminfo_samples_get(si);

				if (rate && samples) {
					char ms[24];
					(void)snprintf(ms, sizeof(ms), "%llu",
					               (unsigned long long)(samples * 1000u / rate));
					put_text(out, N_DURATION, ms);
				}
			}
		} else if (type == 4u) {
			vorbis_read(b + body, body_len, out);
		}
		if (last)
			return;
		at = body + body_len;
	}
}

/* ---- Ogg, media/ogg.situ, sec 1451 ------------------------------------------ */

/* WHAT A STREAM'S LAST PAGE NEEDS to say its length (sec 1456): which
 * stream, what its granule counts, and what it skips at the start. */
struct ogg_info {
	uint32_t serial;
	uint32_t rate;     /* granules a second, 0 where the head said none */
	uint32_t pre_skip; /* granules not heard, Opus's */
};

/* The identification packet's `n` bytes at `p`: the rate and the skip. */
static void ogg_identify(const uint8_t *p, size_t n, struct ogg_info *info)
{
	situ_msg_t m;
	situ_view_t v;

	situ_msg_init(&m, (uint8_t *)(uintptr_t)p, (uint32_t)n);
	if (fzn_ogg_vorbis_id_packet_view(&m, 0, &v) == SITU_OK && fzn_ogg_vorbis_id_packet_validate(v) == SITU_OK)
		info->rate = fzn_ogg_vorbis_id_packet_rate_get(v);
	else if (fzn_ogg_opus_head_packet_view(&m, 0, &v) == SITU_OK && fzn_ogg_opus_head_packet_validate(v) == SITU_OK) {
		info->rate = 48000u;
		info->pre_skip = fzn_ogg_opus_head_packet_pre_skip_get(v);
	}
}

/* The first logical stream's second packet -- its comments, Vorbis's or
 * Opus's -- joined across the pages it runs over, and read. A packet goes
 * on while a lacing value is 255; pages of another stream are passed over.
 * `info`, where given, takes the stream and its first packet's rate. */
static void ogg_read_info(const uint8_t *b, size_t len, fzn_media_tags_t *out, struct ogg_info *info)
{
	situ_msg_t msg;
	uint32_t have = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len, at = 0, serial = 0;
	uint8_t *packet;
	size_t packet_len = 0, packets = 0;
	int first = 1, done = 0;

	if (!(packet = malloc(len)))
		return;
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)b, have);
	out->format = FZN_MEDIA_OGG;
	while (!done && at + 27u <= have) {
		situ_view_t page;
		uint32_t need = 0, body, i, segments;
		const uint8_t *lacing;

		if (fzn_ogg_ogg_page_required(b + at, have - at, &need) != SITU_OK
		    || fzn_ogg_ogg_page_view(&msg, at, need, &page) != SITU_OK
		    || fzn_ogg_ogg_page_validate(page) != SITU_OK)
			break;
		if (first) {
			serial = fzn_ogg_ogg_page_serial_get(page);
			if (info)
				info->serial = serial;
		}
		first = 0;
		segments = fzn_ogg_ogg_page_segments_get(page);
		lacing = fzn_ogg_ogg_page_lacing_ptr(page);
		body = at + need;
		if (fzn_ogg_ogg_page_serial_get(page) != serial) {
			for (i = 0; i < segments; i++)
				body += lacing[i];
			at = body;
			continue;
		}
		for (i = 0; i < segments && !done; i++) {
			/* A PAGE CUT SHORT: what of the packet is here is read. */
			uint32_t take = lacing[i] <= have - body ? lacing[i] : have - body;

			/* THE FIRST PACKET'S HEAD, which says what a granule counts:
			 * it fits in its first segment. */
			if (packets == 0u && info && i == 0u && !info->rate)
				ogg_identify(b + body, take, info);
			if (packets == 1u) {
				memcpy(packet + packet_len, b + body, take);
				packet_len += take;
			}
			body += take;
			if (take < lacing[i])
				done = 1;
			else if (lacing[i] < 255u && ++packets == 2u)
				done = 1;
		}
		if (body > have)
			break;
		at = body;
	}
	if (packet_len >= 8u) {
		situ_msg_t pm;
		situ_view_t v;

		situ_msg_init(&pm, packet, (uint32_t)packet_len);
		if (fzn_ogg_vorbis_comment_packet_view(&pm, 0, &v) == SITU_OK
		    && fzn_ogg_vorbis_comment_packet_validate(v) == SITU_OK)
			vorbis_read(packet + 7, (uint32_t)packet_len - 7u, out);
		else if (fzn_ogg_opus_tags_packet_view(&pm, 0, &v) == SITU_OK
		         && fzn_ogg_opus_tags_packet_validate(v) == SITU_OK)
			vorbis_read(packet + 8, (uint32_t)packet_len - 8u, out);
	}
	wipe(packet, packet_len);
	free(packet);
}

static void ogg_read(const uint8_t *b, size_t len, fzn_media_tags_t *out)
{
	ogg_read_info(b, len, out, NULL);
}

/* THE LENGTH FROM THE LAST PAGE, sec 1456: `tail`, the file's last bytes,
 * searched from its end for a page of the stream, the first whose granule
 * is set (a page ending no packet says -1). Its granule less the skip, over
 * the rate. */
static void ogg_length(const uint8_t *tail, size_t len, const struct ogg_info *info, fzn_media_tags_t *out)
{
	situ_msg_t msg;
	size_t i;

	if (!info->rate || len < 27u)
		return;
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)tail, (uint32_t)len);
	for (i = len - 27u + 1u; i-- > 0;) {
		situ_view_t page;
		uint32_t need = 0;
		uint64_t granule;
		char ms[24];

		if (memcmp(tail + i, "OggS", 4) != 0
		    || fzn_ogg_ogg_page_required(tail + i, (uint32_t)(len - i), &need) != SITU_OK
		    || fzn_ogg_ogg_page_view(&msg, (uint32_t)i, need, &page) != SITU_OK
		    || fzn_ogg_ogg_page_validate(page) != SITU_OK || fzn_ogg_ogg_page_serial_get(page) != info->serial)
			continue;
		granule = fzn_ogg_ogg_page_granule_get(page);
		if (granule == UINT64_MAX)
			continue;
		if (granule <= info->pre_skip || granule - info->pre_skip > UINT64_MAX / 1000u)
			return;
		(void)snprintf(ms, sizeof(ms), "%llu", (unsigned long long)((granule - info->pre_skip) * 1000u / info->rate));
		put_text(out, N_DURATION, ms);
		return;
	}
}

/* ---- by what the file is ---------------------------------------------------- */

/* ---- MP4, media/mp4.situ, sec 1452 ------------------------------------------ */

/* THE WALK'S BOUNDS: boxes read in all, and the item list's bytes. A file
 * whose boxes would take more is read as far as they go. */
#define MP4_READS_MAX 256u
/* An Ogg stream's last page lies within its last 64 KiB: a page is at most
 * 27 + 255 + 255 * 255 bytes. */
#define OGG_TAIL (64u * 1024u + 512u)
#define MP4_ILST_MAX (256u * 1024u)

struct mp4 {
	fzn_media_read_t read;
	void *ctx;
	uint64_t file_len;
	unsigned reads;
};

/* The box at `at`, within `end`: its size, its header's length and its
 * type. 0 where it does not read or overruns `end`. */
static int mp4_box(struct mp4 *m, uint64_t at, uint64_t end, uint64_t *size, uint32_t *head, uint8_t type[4])
{
	uint8_t b[16];
	situ_msg_t msg;
	situ_view_t v;
	size_t got;
	uint32_t s32;

	if (at + 8u > end || m->reads >= MP4_READS_MAX)
		return 0;
	m->reads++;
	got = m->read(m->ctx, at, b, end - at < sizeof(b) ? (size_t)(end - at) : sizeof(b));
	situ_msg_init(&msg, b, (uint32_t)got);
	if (got < 8u || fzn_mp4_box_view(&msg, 0, &v) != SITU_OK || fzn_mp4_box_validate(v) != SITU_OK)
		return 0;
	memcpy(type, fzn_mp4_box_type_ptr(v), 4);
	s32 = fzn_mp4_box_size_get(v);
	*head = 8u;
	if (s32 == 1u) {
		if (got < 16u || fzn_mp4_box_large_view(&msg, 8, &v) != SITU_OK)
			return 0;
		*size = fzn_mp4_box_large_size_get(v);
		*head = 16u;
	} else {
		*size = s32 ? s32 : end - at;
	}
	return *size >= *head && *size <= end - at;
}

/* The first child of type `want` among the boxes in [at, end): its place
 * and size. */
static int mp4_find(struct mp4 *m, uint64_t at, uint64_t end, const char *want, uint64_t *where, uint64_t *size,
                    uint32_t *head)
{
	uint8_t type[4];

	while (mp4_box(m, at, end, size, head, type)) {
		if (memcmp(type, want, 4) == 0) {
			*where = at;
			return 1;
		}
		at += *size;
	}
	return 0;
}

/* An item list's items, `b` its `len` bytes after the ilst header. */
static void mp4_items(const uint8_t *b, uint32_t len, fzn_media_tags_t *out)
{
	static const struct {
		char type[5];
		const char *name;
	} map[] = {
		{ "\xa9nam", N_TITLE },  { "\xa9" "ART", N_ARTIST },   { "\xa9" "alb", N_ALBUM }, { "aART", N_ALBUM_ARTIST },
		{ "\xa9gen", N_GENRE },  { "\xa9wrt", N_COMPOSER }, { "\xa9" "day", N_YEAR },  { "trkn", N_TRACK },
		{ "disk", N_DISC },
	};
	situ_msg_t msg;
	uint32_t at = 0, i;

	situ_msg_init(&msg, (uint8_t *)(uintptr_t)b, len);
	while (at + 8u <= len) {
		situ_view_t item, data;
		uint32_t size, need = 0;

		if (fzn_mp4_box_view(&msg, at, &item) != SITU_OK)
			return;
		size = fzn_mp4_box_size_get(item);
		if (size < 8u || size > len - at)
			return;
		for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
			if (memcmp(fzn_mp4_box_type_ptr(item), map[i].type, 4) != 0)
				continue;
			/* ITS FIRST `data`, straight after the item's header. */
			if (fzn_mp4_item_data_required(b + at + 8, size - 8u, &need) != SITU_OK
			    || fzn_mp4_item_data_view(&msg, at + 8u, need, &data) != SITU_OK
			    || fzn_mp4_item_data_validate(data) != SITU_OK)
				break;
			if (map[i].name == N_TRACK || map[i].name == N_DISC) {
				situ_msg_t pm;
				situ_view_t pair;
				char nm[16];
				uint16_t number, total;

				situ_msg_init(&pm, fzn_mp4_item_data_value_ptr(data), fzn_mp4_item_data_value_len(data));
				if (fzn_mp4_item_pair_view(&pm, 0, &pair) != SITU_OK || fzn_mp4_item_pair_validate(pair) != SITU_OK
				    || !(number = fzn_mp4_item_pair_number_get(pair)))
					break;
				total = fzn_mp4_item_pair_total_get(pair);
				if (total)
					(void)snprintf(nm, sizeof(nm), "%u/%u", (unsigned)number, (unsigned)total);
				else
					(void)snprintf(nm, sizeof(nm), "%u", (unsigned)number);
				put_text(out, map[i].name, nm);
			} else if (fzn_mp4_item_data_kind_get(data) == 1u) {
				put(out, map[i].name, fzn_mp4_item_data_value_ptr(data), fzn_mp4_item_data_value_len(data));
			}
			break;
		}
		at += size;
	}
}

/* ISO 14496-12: the movie box found by the sizes, wherever it stands; its
 * header's length; and its item list. */
static void mp4_read(struct mp4 *m, fzn_media_tags_t *out)
{
	uint64_t moov, moov_size, at, size, udta, udta_size, meta, meta_size, ilst, ilst_size;
	uint32_t head, h2, h3, h4;
	uint8_t b[40];

	out->format = FZN_MEDIA_MP4;
	if (!mp4_find(m, 0, m->file_len, "moov", &moov, &moov_size, &head))
		return;
	/* THE LENGTH, from the movie header: its duration over its time scale. */
	if (mp4_find(m, moov + head, moov + moov_size, "mvhd", &at, &size, &h2) && size >= h2 + 4u + 16u) {
		size_t got = m->read(m->ctx, at + h2, b, size - h2 < sizeof(b) ? (size_t)(size - h2) : sizeof(b));
		situ_msg_t msg;
		situ_view_t fb, v;
		uint64_t duration = 0;
		uint32_t scale = 0;

		situ_msg_init(&msg, b, (uint32_t)got);
		if (fzn_mp4_full_box_view(&msg, 0, &fb) == SITU_OK) {
			if (fzn_mp4_full_box_version_get(fb) == 1u && fzn_mp4_mvhd_v1_view(&msg, 4, &v) == SITU_OK) {
				duration = fzn_mp4_mvhd_v1_duration_get(v);
				scale = fzn_mp4_mvhd_v1_timescale_get(v);
			} else if (fzn_mp4_full_box_version_get(fb) == 0u && fzn_mp4_mvhd_v0_view(&msg, 4, &v) == SITU_OK) {
				duration = fzn_mp4_mvhd_v0_duration_get(v);
				scale = fzn_mp4_mvhd_v0_timescale_get(v);
			}
		}
		if (scale && duration && duration != UINT64_MAX && duration != UINT32_MAX && duration < UINT64_MAX / 1000u) {
			char ms[24];
			(void)snprintf(ms, sizeof(ms), "%llu", (unsigned long long)(duration * 1000u / scale));
			put_text(out, N_DURATION, ms);
		}
	}
	/* THE ITEMS: moov/udta/meta/ilst, `meta` a full box -- or, as some
	 * writers have it, a plain one, its first child straight after. */
	if (!mp4_find(m, moov + head, moov + moov_size, "udta", &udta, &udta_size, &h2)
	    || !mp4_find(m, udta + h2, udta + udta_size, "meta", &meta, &meta_size, &h3))
		return;
	at = meta + h3;
	if (m->read(m->ctx, at, b, 8) == 8u && memcmp(b + 4, "hdlr", 4) != 0)
		at += 4u;
	if (!mp4_find(m, at, meta + meta_size, "ilst", &ilst, &ilst_size, &h4) || ilst_size - h4 > MP4_ILST_MAX)
		return;
	{
		uint8_t *items = malloc((size_t)(ilst_size - h4) + 1u);
		size_t got;

		if (!items)
			return;
		got = m->read(m->ctx, ilst + h4, items, (size_t)(ilst_size - h4));
		mp4_items(items, (uint32_t)got, out);
		wipe(items, got);
		free(items);
	}
}

/* ---- an MP3's length, media/mpeg.situ, sec 1456 ------------------------------ */

/* 2.4.2.3's tables, by version (3 MPEG-1, 2 MPEG-2, 0 MPEG-2.5) and layer
 * (3 I, 2 II, 1 III): kbit/s by the bitrate index, Hz by the rate index. */
static uint32_t mpeg_kbps(unsigned version, unsigned layer, unsigned index)
{
	static const uint16_t v1[3][15] = {
		{ 0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },   /* I */
		{ 0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384 },      /* II */
		{ 0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320 },       /* III */
	};
	static const uint16_t v2[2][15] = {
		{ 0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256 },      /* I */
		{ 0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160 },           /* II, III */
	};

	if (index > 14u || layer < 1u || layer > 3u)
		return 0;
	return version == 3u ? v1[3u - layer][index] : v2[layer == 3u ? 0 : 1][index];
}

static uint32_t mpeg_hz(unsigned version, unsigned index)
{
	static const uint32_t v1[3] = { 44100u, 48000u, 32000u };

	if (index > 2u || version == 1u)
		return 0;
	return v1[index] / (version == 3u ? 1u : version == 2u ? 2u : 4u);
}

/* THE LENGTH OF AN MP3 from its first frame (sec 1456): a Xing or Info
 * header's frame count where the encoder wrote one, the frames over the
 * rate; else, a constant bitrate, the audio's bytes over the bitrate. The
 * frame is sought in the 4 KiB from `at`, where the tag ends. */
static void mp3_length(fzn_media_read_t read, void *ctx, uint64_t file_len, uint64_t at, fzn_media_tags_t *out)
{
	uint8_t b[4096];
	situ_msg_t msg;
	size_t got, i;
	char ms[24];

	if (at >= file_len || fzn_media_tag_find(out, N_DURATION))
		return;
	got = read(ctx, at, b, file_len - at < sizeof(b) ? (size_t)(file_len - at) : sizeof(b));
	situ_msg_init(&msg, b, (uint32_t)got);
	for (i = 0; i + 4u <= got; i++) {
		situ_view_t h, x, fr;
		unsigned version, layer, mono;
		uint32_t kbps, hz, spf, side;
		uint64_t length;

		if (b[i] != 0xFFu || (b[i + 1u] & 0xE0u) != 0xE0u || fzn_mpeg_mpeg_header_view(&msg, (uint32_t)i, &h) != SITU_OK
		    || fzn_mpeg_mpeg_header_validate(h) != SITU_OK)
			continue;
		version = fzn_mpeg_mpeg_header_version_get(h);
		layer = fzn_mpeg_mpeg_header_layer_get(h);
		kbps = mpeg_kbps(version, layer, fzn_mpeg_mpeg_header_bitrate_get(h));
		hz = mpeg_hz(version, fzn_mpeg_mpeg_header_rate_get(h));
		if (!kbps || !hz)
			continue;
		mono = fzn_mpeg_mpeg_header_mode_get(h) == 3u;
		spf = layer == 3u ? 384u : layer == 2u || version == 3u ? 1152u : 576u;
		side = version == 3u ? (mono ? 17u : 32u) : (mono ? 9u : 17u);
		/* XING OR INFO, after the side information. */
		if (layer == 1u && i + 4u + side + 12u <= got
		    && fzn_mpeg_xing_header_view(&msg, (uint32_t)(i + 4u + side), &x) == SITU_OK
		    && (!memcmp(b + i + 4u + side, "Xing", 4) || !memcmp(b + i + 4u + side, "Info", 4))
		    && (fzn_mpeg_xing_header_flags_get(x) & 1u)
		    && fzn_mpeg_xing_frames_view(&msg, (uint32_t)(i + 4u + side + 8u), &fr) == SITU_OK
		    && fzn_mpeg_xing_frames_validate(fr) == SITU_OK) {
			length = (uint64_t)fzn_mpeg_xing_frames_frames_get(fr) * spf * 1000u / hz;
		} else {
			/* A CONSTANT BITRATE: kbit/s is bits a millisecond. */
			length = (file_len - at - i) * 8u / kbps;
		}
		if (length) {
			(void)snprintf(ms, sizeof(ms), "%llu", (unsigned long long)length);
			put_text(out, N_DURATION, ms);
		}
		return;
	}
}

/* ---- a file read by ranges ------------------------------------------------- */

size_t fzn_media_tags_read_file(fzn_media_read_t read, void *ctx, uint64_t file_len, fzn_media_tags_t *out)
{
	uint8_t *head;
	size_t want, got;

	if (!out)
		return 0;
	memset(out, 0, sizeof(*out));
	if (!read || file_len < 4u)
		return 0;
	want = file_len < FZN_MEDIA_TAGS_HEAD ? (size_t)file_len : FZN_MEDIA_TAGS_HEAD;
	if (!(head = malloc(want)))
		return 0;
	got = read(ctx, 0, head, want);
	/* AN MP4 opens with its file type box, and is walked by its sizes. */
	if (got >= 12u && memcmp(head + 4, "ftyp", 4) == 0) {
		struct mp4 m = { read, ctx, file_len, 0 };
		mp4_read(&m, out);
	} else if (got >= 4u && memcmp(head, "OggS", 4) == 0) {
		/* OGG'S LENGTH is at its end, sec 1456: the last 64 KiB read for it. */
		struct ogg_info info = { 0, 0, 0 };
		size_t tail_len = file_len < OGG_TAIL ? (size_t)file_len : OGG_TAIL;
		uint8_t *tail;

		ogg_read_info(head, got, out, &info);
		if (info.rate && (tail = malloc(tail_len)) != NULL) {
			size_t n = read(ctx, file_len - tail_len, tail, tail_len);
			ogg_length(tail, n, &info, out);
			wipe(tail, n);
			free(tail);
		}
	} else {
		(void)fzn_media_tags_read(head, got, out);
		/* AN MP3, its tag first or none, sec 1456: its length from its
		 * first frame, where the tag said none. */
		if (out->format == FZN_MEDIA_ID3 && got >= 10u) {
			const uint64_t tag = 10u + ((uint64_t)(head[6] & 0x7Fu) << 21 | (uint64_t)(head[7] & 0x7Fu) << 14
			                            | (uint64_t)(head[8] & 0x7Fu) << 7 | (head[9] & 0x7Fu))
			                     + ((head[5] & 0x10u) ? 10u : 0u);
			mp3_length(read, ctx, file_len, tag, out);
		} else if (out->format == FZN_MEDIA_UNKNOWN && head[0] == 0xFFu && (head[1] & 0xE0u) == 0xE0u) {
			out->format = FZN_MEDIA_MP3;
			mp3_length(read, ctx, file_len, 0, out);
		}
	}
	wipe(head, got);
	free(head);
	return out->count;
}

size_t fzn_media_tags_read(const uint8_t *head, size_t len, fzn_media_tags_t *out)
{
	if (!out)
		return 0;
	memset(out, 0, sizeof(*out));
	if (!head || len < 4u)
		return 0;
	if (head[0] == 0xFFu && head[1] == 0xD8u && head[2] == 0xFFu)
		jpeg_read(head, len, out);
	else if (memcmp(head, "ID3", 3) == 0)
		id3_read(head, len, out);
	else if (memcmp(head, "fLaC", 4) == 0)
		flac_read(head, len, out);
	else if (memcmp(head, "OggS", 4) == 0)
		ogg_read(head, len, out);
	return out->count;
}
