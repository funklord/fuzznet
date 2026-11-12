/*
 * THE METRIC LAYER'S TABLE, project.md sec 1034 and 1055: every measured value
 * a host keeps -- a link's latency and loss, a family's bytes, a call's round
 * trip -- named, estimated, counted and listed once, rather than in a table of
 * each subsystem's own (sec 631's `link/`, sec 685's meter).
 *
 * A VALUE IS NAMED, a path of words the schema's keys are made of
 * (`link/127.0.0.1:7000/latency`), so a listing and a logging rule select by
 * prefix (sec 1053's `metric/log/NAME`).
 *
 * ITS ESTIMATE BEGINS AT A PRIOR and every sample moves it one part in
 * 2^FZN_METRIC_SMOOTH_SHIFT -- `link/`'s estimator (sec 202), integer, slow
 * enough that one late sample does not condemn a path and fast enough that a
 * path gone is not chosen for a minute. A value with no observation says so,
 * since a prior is no measurement.
 *
 * THE TABLE IS THE CALLER'S, of any size (sec 704): `fzn_metrics_use` moves it
 * onto larger room, and a full one refuses a new name rather than forgetting an
 * old one, whose measurements would go with it.
 */
#ifndef FZN_NODE_METRIC_H
#define FZN_NODE_METRIC_H

#include <stddef.h>
#include <stdint.h>

#define FZN_METRIC_NAME_MAX 96u
#define FZN_METRIC_SMOOTH_SHIFT 3u
#define FZN_METRIC_OWN 16u
/* A COUNT'S WINDOW, sec 1057: its rate is what the last whole window carried,
 * a second at a time, as the meter's rows' are (sec 685). */
#define FZN_METRIC_WINDOW_MS 5000u

typedef struct fzn_metric {
	char name[FZN_METRIC_NAME_MAX + 1u];
	uint64_t estimate;     /* smoothed; the prior until observed */
	uint64_t prior;
	uint64_t observations;
	uint64_t last_ms;      /* when last observed; 0 never */
	/* A COUNT, sec 1057, where a value is an amount added rather than a sample
	 * estimated -- bytes, requests: its total, and the last whole window's rate
	 * a second. */
	uint64_t total, rate;
	uint64_t window_start_ms, window_sum;
	int used;
} fzn_metric_t;

typedef struct fzn_metrics {
	fzn_metric_t *rows;
	size_t cap, n;
	fzn_metric_t own[FZN_METRIC_OWN];
} fzn_metrics_t;

void fzn_metrics_init(fzn_metrics_t *m);

/* LARGER ROOM OF THE CALLER'S, `rows` of `cap`, which must outlive `m`, what is
 * held copied over: 1, or 0 for room smaller than what is held. */
int fzn_metrics_use(fzn_metrics_t *m, fzn_metric_t *rows, size_t cap);

/* `name`'S ROW, found, or added beginning at `prior`: NULL for a name out of
 * shape -- empty, longer than FZN_METRIC_NAME_MAX, or not printable without a
 * space or comma -- or a full table. */
fzn_metric_t *fzn_metrics_open(fzn_metrics_t *m, const char *name, uint64_t prior);

/* `name`'s row, or NULL. */
const fzn_metric_t *fzn_metrics_get(const fzn_metrics_t *m, const char *name);

/* A SAMPLE of `name` at `now_ms`: its estimate moved toward it, counted. 0 when
 * there is no such row. */
int fzn_metrics_observe(fzn_metrics_t *m, const char *name, uint64_t sample, uint64_t now_ms);

/* AN AMOUNT ADDED to `name`'s count at `now_ms`, sec 1057: its total grown, and
 * its rate a second the last whole FZN_METRIC_WINDOW_MS's once that window ends.
 * 0 when there is no such row. */
int fzn_metrics_count(fzn_metrics_t *m, const char *name, uint64_t amount, uint64_t now_ms);

/* THE ROWS NAMED UNDER `prefix` ("" for all), in the order they were added, from
 * the `from`th of them, at most `max`, each handed to `row`: how many were, and
 * into `*next` where the next page begins -- `*next` past the last when no more. */
size_t fzn_metrics_page(const fzn_metrics_t *m, const char *prefix, size_t from, size_t max,
                        void (*row)(void *ctx, const fzn_metric_t *r), void *ctx, size_t *next);

#endif /* FZN_NODE_METRIC_H */
