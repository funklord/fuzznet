/*
 * A tune's tempo, key and loudness: media/analysis.h, project.md sec 1457.
 * snurra's detector (its src/beats.cpp at analysis 5) in C, its constants
 * and their measurements kept as snurra recorded them.
 */
#include "analysis.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define WINDOW 1024 /* frames an analysis looks at */
#define HOP 512     /* and how far the next one is */
#define SLOWEST 70.0
#define FASTEST 180.0
#define LIKELIEST 120.0  /* the prior's centre, BPM */
#define PRIOR_WIDTH 0.9  /* in octaves, one standard deviation */
/* A fold's peak over its mean, for a beat to count. snurra measured on made
 * signals: beats 17 to 24; white noise 1.4, a steady tone 2.4, hits at
 * random times 3.3 -- the best of many periods and phases searched, so
 * chance alone climbs above 1. */
#define CLEAR 6.0
/* Onset strength a beat line, on average, for a beat to count. Measured:
 * made drums 1640 to 1770; a steady tone through AAC 6.3, MP3 4.8, Opus
 * 0.7; white noise 7. */
#define AUDIBLE 50.0
/* At half the tempo, the weaker of a beat's two lines under this share of
 * the stronger: the strong ones are the beat. */
#define ALTERNATING 0.5
/* The correlation with a key's profile under which no key is given: noise
 * 0.27, a kick with a click 0.33, a bare 55 Hz kick 0.40. */
#define KEY_FIT 0.45
#define KEY_WINDOW 8192 /* 5.9 Hz a bin at 48 kHz */
#define RATE ((double)FZN_MEDIA_ANALYSIS_RATE)

typedef struct {
	float re, im;
} cplx;

typedef struct {
	float *v;
	size_t n, cap;
} floats;

typedef struct {
	double *v;
	size_t n, cap;
} doubles;

static int floats_put(floats *f, float x)
{
	if (f->n == f->cap) {
		size_t cap = f->cap ? f->cap * 2u : 4096u;
		float *more = realloc(f->v, cap * sizeof(*more));

		if (!more)
			return 0;
		f->v = more;
		f->cap = cap;
	}
	f->v[f->n++] = x;
	return 1;
}

static int doubles_put(doubles *d, double x)
{
	if (d->n == d->cap) {
		size_t cap = d->cap ? d->cap * 2u : 1024u;
		double *more = realloc(d->v, cap * sizeof(*more));

		if (!more)
			return 0;
		d->v = more;
		d->cap = cap;
	}
	d->v[d->n++] = x;
	return 1;
}

static float magnitude(cplx c)
{
	return sqrtf(c.re * c.re + c.im * c.im);
}

/* In place, radix 2; `n` a power of two. */
static void fft(cplx *data, size_t n)
{
	size_t i, j, length, k;

	for (i = 1, j = 0; i < n; ++i) {
		size_t bit = n >> 1;

		for (; j & bit; bit >>= 1)
			j ^= bit;
		j ^= bit;
		if (i < j) {
			cplx t = data[i];
			data[i] = data[j];
			data[j] = t;
		}
	}
	for (length = 2; length <= n; length <<= 1) {
		const double angle = -2.0 * M_PI / (double)length;
		const cplx step = { (float)cos(angle), (float)sin(angle) };

		for (i = 0; i < n; i += length) {
			cplx turn = { 1.0f, 0.0f };

			for (k = 0; k < length / 2u; ++k) {
				const cplx even = data[i + k], b = data[i + k + length / 2u];
				const cplx odd = { b.re * turn.re - b.im * turn.im, b.re * turn.im + b.im * turn.re };
				const cplx next = { turn.re * step.re - turn.im * step.im, turn.re * step.im + turn.im * step.re };

				data[i + k].re = even.re + odd.re;
				data[i + k].im = even.im + odd.im;
				data[i + k + length / 2u].re = even.re - odd.re;
				data[i + k + length / 2u].im = even.im - odd.im;
				turn = next;
			}
		}
	}
}

/* ---- loudness, ITU-R BS.1770-4 --------------------------------------------- */

struct biquad {
	double b0, b1, b2, a1, a2;
	double z1[2], z2[2];
};

static double biquad_run(struct biquad *q, int channel, double x)
{
	const double y = q->b0 * x + q->z1[channel];

	q->z1[channel] = q->b1 * x - q->a1 * y + q->z2[channel];
	q->z2[channel] = q->b2 * x - q->a2 * y;
	return y;
}

/* Each channel K-weighted -- a high shelf of about +4 dB above 1.5 kHz,
 * then a high-pass at 38 Hz -- designed at the rate from their analogue
 * prototypes, which at 48 kHz gives the standard's own coefficients. */
static void loudness_design(struct biquad *shelf, struct biquad *high_pass)
{
	{
		const double f0 = 1681.974450955533, gain_db = 3.999843853973347, q = 0.7071752369554196;
		const double k = tan(M_PI * f0 / RATE), vh = pow(10.0, gain_db / 20.0);
		const double vb = pow(vh, 0.4996667741545416), a0 = 1.0 + k / q + k * k;

		shelf->b0 = (vh + vb * k / q + k * k) / a0;
		shelf->b1 = 2.0 * (k * k - vh) / a0;
		shelf->b2 = (vh - vb * k / q + k * k) / a0;
		shelf->a1 = 2.0 * (k * k - 1.0) / a0;
		shelf->a2 = (1.0 - k / q + k * k) / a0;
	}
	{
		const double f0 = 38.13547087602444, q = 0.5003270373238773;
		const double k = tan(M_PI * f0 / RATE), a0 = 1.0 + k / q + k * k;

		high_pass->b0 = 1.0;
		high_pass->b1 = -2.0;
		high_pass->b2 = 1.0;
		high_pass->a1 = 2.0 * (k * k - 1.0) / a0;
		high_pass->a2 = (1.0 - k / q + k * k) / a0;
	}
}

/* ---- the chromagram ------------------------------------------------------- */

#define CHROMA_EVERY 4 /* at 48 kHz every fourth frame, after a low pass at 3 kHz */
#define CHROMA_SIZE (KEY_WINDOW / CHROMA_EVERY)

struct section {
	float b0, b1, b2, a1, a2, z1, z2;
};

static float section_run(struct section *s, float x)
{
	const float y = s->b0 * x + s->z1;

	s->z1 = s->b1 * x - s->a1 * y + s->z2;
	s->z2 = s->b2 * x - s->a2 * y;
	return y;
}

struct fzn_media_analysis {
	/* the onsets */
	float window[WINDOW];
	float mono[WINDOW]; /* the frames not yet looked at, from the window's start */
	size_t mono_n;
	cplx spectrum[WINDOW];
	float previous[WINDOW / 2 + 1], previous_linear[WINDOW / 2 + 1];
	int first;
	floats flux, body;
	/* the key */
	float chroma_window[CHROMA_SIZE];
	float chroma_block[CHROMA_SIZE];
	size_t chroma_n;
	int chroma_skipped;
	cplx chroma_spectrum[CHROMA_SIZE];
	struct section low[2];
	int bin_k[CHROMA_SIZE / 2];
	int bin_note[CHROMA_SIZE / 2];
	size_t bins;
	double notes[12];
	/* the loudness */
	struct biquad shelf, high_pass;
	int in_step;
	double sum;
	doubles tenths;
	double peak;
	size_t frames;
	int short_of_memory;
};

fzn_media_analysis_t *fzn_media_analysis_open(void)
{
	fzn_media_analysis_t *a = calloc(1, sizeof(*a));
	const double kept_rate = RATE / CHROMA_EVERY;
	int i, k;

	if (!a)
		return NULL;
	a->first = 1;
	for (i = 0; i < WINDOW; ++i)
		a->window[i] = (float)(0.5 - 0.5 * cos(2.0 * M_PI * i / WINDOW));
	for (i = 0; i < CHROMA_SIZE; ++i)
		a->chroma_window[i] = (float)(0.5 - 0.5 * cos(2.0 * M_PI * i / CHROMA_SIZE));
	for (k = 1; k < CHROMA_SIZE / 2; ++k) {
		const double hz = (double)k * kept_rate / CHROMA_SIZE;
		long midi;

		/* G2 to C7: a kick's 40 to 60 Hz, leaking into C2's bins, made a
		 * bare drum loop read as Db minor. */
		if (hz < 98.0 || hz > 2093.0)
			continue;
		midi = lround(69.0 + 12.0 * log2(hz / 440.0));
		a->bin_k[a->bins] = k;
		a->bin_note[a->bins++] = (int)(midi % 12);
	}
	/* A fourth-order Butterworth, two sections, at 3 kHz: what would fold
	 * onto the notes, from 9.9 kHz up, is 40 dB down. */
	for (i = 0; i < 2; i++) {
		const double q = 1.0 / (2.0 * cos((i ? 3.0 : 1.0) * M_PI / 8.0));
		const double w = 2.0 * M_PI * 3000.0 / RATE, alpha = sin(w) / (2.0 * q), a0 = 1.0 + alpha;

		a->low[i].b0 = (float)((1.0 - cos(w)) / 2.0 / a0);
		a->low[i].b1 = (float)((1.0 - cos(w)) / a0);
		a->low[i].b2 = (float)((1.0 - cos(w)) / 2.0 / a0);
		a->low[i].a1 = (float)(-2.0 * cos(w) / a0);
		a->low[i].a2 = (float)((1.0 - alpha) / a0);
	}
	loudness_design(&a->shelf, &a->high_pass);
	return a;
}

void fzn_media_analysis_free(fzn_media_analysis_t *a)
{
	if (!a)
		return;
	free(a->flux.v);
	free(a->body.v);
	free(a->tenths.v);
	free(a);
}

/* A frame into the chromagram: blocks of KEY_WINDOW frames end to end, each
 * bin counted to the note nearest it, a block weighed by its own loudest
 * note -- so a loud chorus does not outvote a quiet verse -- and silence
 * left out. */
static void chroma_add(fzn_media_analysis_t *a, float frame)
{
	double block[12] = { 0 }, loudest = 0;
	size_t i;
	int note;

	frame = section_run(&a->low[0], frame);
	frame = section_run(&a->low[1], frame);
	if (++a->chroma_skipped < CHROMA_EVERY)
		return;
	a->chroma_skipped = 0;
	a->chroma_block[a->chroma_n++] = frame;
	if (a->chroma_n < CHROMA_SIZE)
		return;
	for (i = 0; i < CHROMA_SIZE; ++i) {
		a->chroma_spectrum[i].re = a->chroma_block[i] * a->chroma_window[i];
		a->chroma_spectrum[i].im = 0.0f;
	}
	a->chroma_n = 0;
	fft(a->chroma_spectrum, CHROMA_SIZE);
	for (i = 0; i < a->bins; ++i)
		block[a->bin_note[i]] += magnitude(a->chroma_spectrum[a->bin_k[i]]);
	for (note = 0; note < 12; ++note)
		if (block[note] > loudest)
			loudest = block[note];
	if (loudest < 1e-3 * CHROMA_SIZE / KEY_WINDOW)
		return; /* silence, or near it */
	for (note = 0; note < 12; ++note)
		a->notes[note] += block[note] / loudest;
}

static int loudness_add(fzn_media_analysis_t *a, float left, float right)
{
	const int step = (int)(FZN_MEDIA_ANALYSIS_RATE / 10u);
	double l, r;

	if (fabs(left) > a->peak)
		a->peak = fabs(left);
	if (fabs(right) > a->peak)
		a->peak = fabs(right);
	l = biquad_run(&a->high_pass, 0, biquad_run(&a->shelf, 0, (double)left));
	r = biquad_run(&a->high_pass, 1, biquad_run(&a->shelf, 1, (double)right));
	a->sum += l * l + r * r;
	if (++a->in_step == step) {
		if (!doubles_put(&a->tenths, a->sum / step))
			return 0;
		a->sum = 0;
		a->in_step = 0;
	}
	return 1;
}

/* One window of mono frames looked at: the summed rise of each bin's log
 * magnitude (`flux`, where onsets are, quiet ones too), and of the plain
 * magnitude below 4 kHz (`body`, which of them are strong -- in log
 * magnitude a quiet hat rises nearly as far as a kick). */
static int onset_window(fzn_media_analysis_t *a)
{
	const int body_bins = (int)(4000.0 * WINDOW / RATE);
	float rise = 0.0f, body_rise = 0.0f;
	int i, k;

	for (i = 0; i < WINDOW; ++i) {
		a->spectrum[i].re = a->mono[i] * a->window[i];
		a->spectrum[i].im = 0.0f;
	}
	fft(a->spectrum, WINDOW);
	for (k = 1; k <= WINDOW / 2; ++k) {
		const float linear = magnitude(a->spectrum[k]);
		const float m = log1pf(100.0f * linear);

		if (!a->first) {
			if (m > a->previous[k])
				rise += m - a->previous[k];
			if (k < body_bins && linear > a->previous_linear[k])
				body_rise += linear - a->previous_linear[k];
		}
		a->previous[k] = m;
		a->previous_linear[k] = linear;
	}
	a->first = 0;
	return floats_put(&a->flux, rise) && floats_put(&a->body, body_rise);
}

int fzn_media_analysis_add(fzn_media_analysis_t *a, const float *stereo, size_t frames)
{
	size_t i;

	if (!a || a->short_of_memory)
		return 0;
	for (i = 0; i < frames; ++i) {
		const float left = stereo[2u * i], right = stereo[2u * i + 1u];
		const float m = 0.5f * (left + right);

		chroma_add(a, m);
		if (!loudness_add(a, left, right))
			goto short_of_memory;
		a->mono[a->mono_n++] = m;
		if (a->mono_n == WINDOW) {
			if (!onset_window(a))
				goto short_of_memory;
			memmove(a->mono, a->mono + HOP, (WINDOW - HOP) * sizeof(a->mono[0]));
			a->mono_n = WINDOW - HOP;
		}
		a->frames++;
	}
	return 1;
short_of_memory:
	a->short_of_memory = 1;
	return 0;
}

/* ---- the grid ------------------------------------------------------------- */

/* Less the local mean (a third of a second each side), never below zero:
 * what stands out. */
static float *standing_out(const floats *flux)
{
	enum { AROUND = 16 };
	float *strength = calloc(flux->n ? flux->n : 1u, sizeof(*strength));
	double *prefix = calloc(flux->n + 1u, sizeof(*prefix));
	size_t i;

	if (!strength || !prefix) {
		free(strength);
		free(prefix);
		return NULL;
	}
	for (i = 0; i < flux->n; ++i)
		prefix[i + 1] = prefix[i] + flux->v[i];
	for (i = 0; i < flux->n; ++i) {
		const size_t low = i >= AROUND ? i - AROUND : 0;
		const size_t high = i + AROUND + 1 < flux->n ? i + AROUND + 1 : flux->n;
		const double mean = (prefix[high] - prefix[low]) / (double)(high - low);
		const double d = (double)flux->v[i] - mean;

		strength[i] = (float)(d > 0.0 ? d : 0.0);
	}
	free(prefix);
	return strength;
}

struct onsets {
	const float *all, *body;
	size_t n;
};

/* Every onset folded at `period` hops into bins a tenth of a hop wide,
 * smoothed over about a hop: the best phase in hops, its height, and the
 * fold's mean. */
struct fold {
	double phase, peak, mean;
};

static struct fold fold(const float *strength, size_t n, double period)
{
	int bins = (int)ceil(period / 0.1), reach, b, d, top = 0;
	double *histogram, *smooth, total = 0, left, right, curve, shift;
	struct fold best = { 0, 0, 0 };
	size_t i;

	if (bins < 8)
		bins = 8;
	histogram = calloc((size_t)bins, sizeof(*histogram));
	smooth = calloc((size_t)bins, sizeof(*smooth));
	if (!histogram || !smooth) {
		free(histogram);
		free(smooth);
		return best;
	}
	for (i = 0; i < n; ++i) {
		double place;
		int at;

		if (strength[i] <= 0.0f)
			continue;
		place = fmod((double)i, period) / period * bins;
		at = (int)place < bins - 1 ? (int)place : bins - 1;
		histogram[at] += strength[i];
	}
	/* A triangle a hop either side, round the circle. */
	reach = (int)lround(bins / period);
	if (reach < 1)
		reach = 1;
	for (b = 0; b < bins; ++b)
		for (d = -reach; d <= reach; ++d)
			smooth[b] += histogram[((b + d) % bins + bins) % bins] * (double)(reach + 1 - abs(d));
	for (b = 0; b < bins; ++b) {
		total += smooth[b];
		if (smooth[b] > smooth[top])
			top = b;
	}
	best.peak = smooth[top];
	best.mean = total / bins;
	/* Between bins, by the parabola through the top and its neighbours. */
	left = smooth[(top + bins - 1) % bins];
	right = smooth[(top + 1) % bins];
	curve = left - 2.0 * best.peak + right;
	shift = curve < 0.0 ? 0.5 * (left - right) / curve : 0.0;
	best.phase = (top + 0.5 + shift) / bins * period;
	free(histogram);
	free(smooth);
	return best;
}

/* The fold's height at a given phase, smoothed as above. */
static struct fold fold_at(const float *strength, size_t n, double period, double phase)
{
	struct fold at = { phase, 0, 0 };
	double total = 0;
	size_t i;

	for (i = 0; i < n; ++i) {
		double distance = fabs(fmod((double)i - phase, period));

		total += strength[i];
		if (period - distance < distance)
			distance = period - distance;
		if (distance <= 1.0)
			at.peak += strength[i] * (1.0 - distance);
	}
	at.mean = total;
	return at;
}

/* The finest period within `span` of `period` whose fold stands highest,
 * three passes each finer. */
static double refine(const float *strength, size_t n, double period, double span, struct fold *chosen,
                     const volatile int *stop)
{
	enum { STEPS = 80 };
	int pass, i;

	*chosen = fold(strength, n, period);
	for (pass = 0; pass < 3; ++pass) {
		const double from = period - span;

		for (i = 0; i <= STEPS; ++i) {
			const double candidate = from + 2.0 * span * i / STEPS;
			struct fold tried;

			if (stop && *stop)
				return 0;
			tried = fold(strength, n, candidate);
			if (tried.peak > chosen->peak) {
				*chosen = tried;
				period = candidate;
			}
		}
		span = 4.0 * span / STEPS;
		*chosen = fold(strength, n, period);
	}
	return period;
}

static double per_cycle(const struct onsets *o, double at)
{
	const struct fold folded = fold_at(o->body, o->n, at, fold(o->body, o->n, at).phase);

	return folded.peak / ((double)o->n / at);
}

struct grid {
	double period, first, confidence; /* in frames; period 0: none */
};

/* The grid one run of onsets holds, at one tempo and phase; none, with its
 * confidence, where it is not clear. 0 when stopped. */
static int grid_of(const struct onsets *o, struct grid *g, const volatile int *stop)
{
	const double hops_a_second = RATE / HOP;
	const int shortest = (int)floor(hops_a_second * 60.0 / FASTEST);
	const int longest = (int)ceil(hops_a_second * 60.0 / SLOWEST);
	const float *strength = o->all;
	double best_lag = 0, best_score = 0, period, per_beat, correlation[256];
	struct fold chosen;
	int lag;

	memset(g, 0, sizeof(*g));
	if (o->n < (size_t)longest * 8u || longest + 2 > (int)(sizeof(correlation) / sizeof(correlation[0])))
		return 1; /* fewer than eight beats: no tempo to speak of */
	/* The tempo, roughly: the autocorrelation's best lag, weighted toward
	 * LIKELIEST so that a tempo wins over its double or half. */
	for (lag = shortest - 1; lag <= longest + 1; ++lag) {
		double sum = 0;
		size_t i;

		for (i = 0; i + (size_t)lag < o->n; ++i)
			sum += (double)strength[i] * strength[i + (size_t)lag];
		correlation[lag] = sum / (double)(o->n - (size_t)lag);
	}
	for (lag = shortest; lag <= longest; ++lag) {
		const double left = correlation[lag - 1], here = correlation[lag], right = correlation[lag + 1];
		double curve, exact, octaves, score;

		if (here < left || here < right)
			continue;
		curve = left - 2.0 * here + right;
		exact = lag + (curve < 0.0 ? 0.5 * (left - right) / curve : 0.0);
		octaves = log2(60.0 * hops_a_second / exact / LIKELIEST) / PRIOR_WIDTH;
		score = here * exp(-0.5 * octaves * octaves);
		if (score > best_score) {
			best_score = score;
			best_lag = exact;
		}
	}
	if (best_lag <= 0.0)
		return 1;
	/* Then exactly: the period, within 2 % of it, whose fold of the whole
	 * tune stands highest -- finer each pass, so that over hundreds of
	 * beats the grid does not drift off them. */
	if (!(period = refine(strength, o->n, best_lag, 0.02 * best_lag, &chosen, stop)))
		return 0;
	/* A beat or a dotted one: the autocorrelation can take a pulse every
	 * beat and a half for the beat (snurra measured 88 for 132, 92 for 138
	 * against Mixxx). Folded at two thirds of the period, a true beat puts a
	 * kick on its line every cycle; so the stronger a cycle, in the body, is
	 * the beat. */
	if (60.0 * hops_a_second / (2.0 * period / 3.0) <= FASTEST
	    && per_cycle(o, 2.0 * period / 3.0) > per_cycle(o, period)) {
		const double faster = 2.0 * period / 3.0;

		if (!(period = refine(strength, o->n, faster, 0.005 * faster, &chosen, stop)))
			return 0;
	}
	/* A tempo or its half: folded at twice the period, are the beat's two
	 * lines equal, or one strong and one weak? */
	if (60.0 * hops_a_second / (2.0 * period) >= SLOWEST) {
		const struct fold slow = fold(strength, o->n, 2.0 * period);
		const double other = fmod(slow.phase + period, 2.0 * period);
		const double one = fold_at(o->body, o->n, 2.0 * period, slow.phase).peak;
		const double two = fold_at(o->body, o->n, 2.0 * period, other).peak;
		const double weaker = one < two ? one : two, stronger = one < two ? two : one;

		if (stronger > 0.0 && weaker / stronger < ALTERNATING) {
			period = 2.0 * period;
			chosen = slow;
		}
	}
	g->confidence = chosen.mean > 0.0 ? chosen.peak / chosen.mean : 0.0;
	/* And loud enough to be a beat: a codec's frames ripple a steady tone
	 * at their own period, which a fold finds as clearly as a drum -- but
	 * faintly. */
	per_beat = fold_at(strength, o->n, period, chosen.phase).peak / ((double)o->n / period);
	if (g->confidence < CLEAR || per_beat < AUDIBLE)
		return 1;
	g->period = period * HOP;
	g->first = fmod(chosen.phase * HOP + WINDOW / 2.0, g->period);
	return 1;
}

static int by_double(const void *x, const void *y)
{
	const double a = *(const double *)x, b = *(const double *)y;

	return a < b ? -1 : a > b;
}

/* A DJ set is one tempo with its phase moving at each track's join: the
 * whole of it folded smears to nothing (snurra measured a 42 minute set at
 * confidence 3.7 where each minute stood at 7.6 to 10.9). So a long tune
 * whose whole is not clear is judged a minute at a time, at up to twelve
 * places across it, and where half of those minutes -- three at least --
 * agree on the tempo within 1 %, the grid is that tempo, the middle of
 * theirs, in the phase of the first of them. */
static int find_grid(const struct onsets *o, struct grid *g, const volatile int *stop)
{
	enum { LONG_MINUTES = 8, PLACES = 12 };
	const size_t minute = (size_t)(RATE / HOP * 60.0);
	struct grid found[PLACES];
	size_t from_of[PLACES], clear = 0, looked = 0, step, from, i, agreeing = 0, first_agreeing = PLACES;
	double periods[PLACES], confidences[PLACES], middle;

	if (!grid_of(o, g, stop))
		return 0;
	if (g->period > 0.0 || o->n < minute * LONG_MINUTES)
		return 1;
	step = (o->n - minute) / (PLACES - 1);
	if (step < minute)
		step = minute;
	for (from = 0; from + minute <= o->n && looked < PLACES; from += step) {
		struct onsets part = { o->all + from, o->body + from, minute };
		struct grid pg;

		++looked;
		if (!grid_of(&part, &pg, stop))
			return 0;
		if (pg.period > 0.0) {
			from_of[clear] = from;
			found[clear++] = pg;
		}
	}
	if (clear < 3u || clear * 2u < looked)
		return 1;
	for (i = 0; i < clear; i++)
		periods[i] = found[i].period;
	qsort(periods, clear, sizeof(periods[0]), by_double);
	middle = periods[clear / 2u];
	for (i = 0; i < clear; i++)
		if (fabs(found[i].period / middle - 1.0) <= 0.01) {
			if (first_agreeing == PLACES)
				first_agreeing = i;
			confidences[agreeing++] = found[i].confidence;
		}
	if (agreeing < 3u || agreeing * 2u < looked)
		return 1;
	qsort(confidences, agreeing, sizeof(confidences[0]), by_double);
	g->period = middle;
	g->confidence = confidences[agreeing / 2u];
	g->first = fmod((double)from_of[first_agreeing] * HOP + found[first_agreeing].first, middle);
	return 1;
}

/* The key whose profile the notes match best: Krumhansl and Kessler's
 * probe-tone ratings correlated with the notes at all 24 rotations. None
 * where the best fit is weak, since a key shown is a key mixed by. */
static int key_of(const double notes[12], double *fit)
{
	static const double MAJOR[12] = { 6.35, 2.23, 3.48, 2.33, 4.38, 4.09, 2.52, 5.19, 2.39, 3.66, 2.29, 2.88 };
	static const double MINOR[12] = { 6.33, 2.68, 3.52, 5.38, 2.60, 3.53, 2.54, 4.75, 3.98, 2.69, 3.34, 3.17 };
	int best = -1, key, i;

	*fit = 0;
	for (key = 0; key < 24; ++key) {
		const double *profile = key < 12 ? MAJOR : MINOR;
		double profile_mean = 0, heard_mean = 0, both = 0, profile_spread = 0, heard_spread = 0, r;

		for (i = 0; i < 12; ++i) {
			profile_mean += profile[i] / 12.0;
			heard_mean += notes[i] / 12.0;
		}
		for (i = 0; i < 12; ++i) {
			const double p = profile[i] - profile_mean, h = notes[(i + key % 12) % 12] - heard_mean;

			both += p * h;
			profile_spread += p * p;
			heard_spread += h * h;
		}
		r = heard_spread > 0.0 ? both / sqrt(profile_spread * heard_spread) : 0.0;
		if (r > *fit) {
			*fit = r;
			best = key;
		}
	}
	return *fit >= KEY_FIT ? best : -1;
}

/* Integrated as EBU R128 says: 400 ms blocks a tenth apart, those over -70
 * LUFS, then of those the ones within 10 LU of their mean, averaged as
 * energy. 0 where no block is over the absolute gate. */
static int integrated(const doubles *tenths, double *out)
{
	const double absolute = pow(10.0, (-70.0 + 0.691) / 10.0);
	double total = 0, relative;
	size_t count = 0, i;

	for (i = 3; i < tenths->n; ++i) {
		const double block = (tenths->v[i - 3] + tenths->v[i - 2] + tenths->v[i - 1] + tenths->v[i]) / 4.0;

		if (block > absolute) {
			total += block;
			++count;
		}
	}
	if (!count)
		return 0;
	relative = total / (double)count * pow(10.0, -1.0);
	total = 0;
	count = 0;
	for (i = 3; i < tenths->n; ++i) {
		const double block = (tenths->v[i - 3] + tenths->v[i - 2] + tenths->v[i - 1] + tenths->v[i]) / 4.0;

		if (block > absolute && block > relative) {
			total += block;
			++count;
		}
	}
	*out = -0.691 + 10.0 * log10(total / (double)count);
	return 1;
}

int fzn_media_analysis_finish(fzn_media_analysis_t *a, fzn_media_sound_t *out, const volatile int *stop)
{
	float *all = NULL, *body = NULL;
	struct grid g;
	int ok = 0;

	if (!out) {
		fzn_media_analysis_free(a);
		return 0;
	}
	memset(out, 0, sizeof(*out));
	out->key = -1;
	if (!a)
		return 0;
	out->seconds = (double)a->frames / RATE;
	out->key = key_of(a->notes, &out->key_fit);
	out->loudness_known = integrated(&a->tenths, &out->loudness);
	out->peak = a->peak;
	if ((all = standing_out(&a->flux)) != NULL && (body = standing_out(&a->body)) != NULL) {
		struct onsets o = { all, body, a->flux.n };

		if (find_grid(&o, &g, stop)) {
			ok = 1;
			out->confidence = g.confidence;
			if (g.period > 0.0) {
				out->bpm = 60.0 * RATE / g.period;
				out->first = g.first / RATE;
			}
		}
	}
	free(all);
	free(body);
	fzn_media_analysis_free(a);
	return ok;
}

/* ---- keys by name ---------------------------------------------------------- */

static const char *const NOTES[12] = { "C", "Db", "D", "Eb", "E", "F", "Gb", "G", "Ab", "A", "Bb", "B" };

/* A major key's place on the Camelot wheel: C is 8, each fifth up one
 * more; a minor key's is its relative major's, three semitones up. */
static int camelot_number(int key)
{
	const int major = key < 12 ? key : (key + 3) % 12;

	return (major * 7 + 7) % 12 + 1;
}

size_t fzn_media_key_name(int key, char *out, size_t cap)
{
	char text[16];
	size_t n = 0;
	int c;

	if (key < 0 || key > 23 || !out || !cap)
		return 0;
	c = camelot_number(key);
	if (c >= 10)
		text[n++] = '1';
	text[n++] = (char)('0' + c % 10);
	text[n++] = key < 12 ? 'B' : 'A';
	text[n++] = ' ';
	memcpy(text + n, NOTES[key % 12], strlen(NOTES[key % 12]));
	n += strlen(NOTES[key % 12]);
	if (key >= 12)
		text[n++] = 'm';
	if (n + 1u > cap)
		return 0;
	memcpy(out, text, n);
	out[n] = '\0';
	return n;
}

int fzn_media_key_order(int key)
{
	if (key < 0 || key > 23)
		return 1000;
	return camelot_number(key) * 2 + (key < 12 ? 1 : 0);
}

int fzn_media_key_parse(const char *name, size_t len)
{
	int number = 0, key;
	size_t i = 0;

	while (i < len && i < 2u && name[i] >= '0' && name[i] <= '9')
		number = number * 10 + (name[i++] - '0');
	if (!i || number < 1 || number > 12 || i >= len || (name[i] != 'A' && name[i] != 'B'))
		return -1;
	for (key = 0; key < 24; key++)
		if (camelot_number(key) == number && (key < 12) == (name[i] == 'B'))
			return key;
	return -1;
}
