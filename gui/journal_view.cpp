#include "journal_view.h"

extern "C" {
#include "../constant_time/constant_time.h"
}

#include <QFormLayout>
#include <QLabel>

#include <stdint.h>
#include <string.h>

fzn_journal_view::fzn_journal_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), full_(false), state_label_(new QLabel(this)),
          pending_(new QLabel(this)), capacity_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Stream"), state_label_);
	form->addRow(QStringLiteral("Applying"), pending_);
	form->addRow(QStringLiteral("Table"), capacity_);

	state_label_->setWordWrap(true);
	pending_->setWordWrap(true);
	capacity_->setWordWrap(true);

	show_stream(nullptr, nullptr, 0);
}

void fzn_journal_view::show_stream(const fzn_journal_t *journal,
                                   const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	const fzn_journal_entry_t *row = NULL;
	uint64_t next = 0;
	uint64_t pending = 0;
	size_t i;

	state_ = NOTHING;
	full_ = false;

	if (!journal || !issuer) {
		state_label_->setText(QStringLiteral("no journal"));
		pending_->setText(QStringLiteral("--"));
		capacity_->setText(QStringLiteral("--"));
		return;
	}

	/* THE SCANNABILITY RULE, OPEN-CODED. `record/journal.c` keeps it
	 * private as `usable()`; sec 186 reports that rather than exposing a
	 * fourth copy unilaterally. Walking `used` past the array is the read
	 * this stops. */
	if (journal->used > journal->capacity || (journal->used > 0u && !journal->entries)) {
		state_ = UNREADABLE;
		state_label_->setText(QStringLiteral("the journal cannot be read -- it "
		                                     "counts more streams than it holds"));
		pending_->setText(QStringLiteral("--"));
		capacity_->setText(QStringLiteral("--"));
		return;
	}

	/* THE TABLE'S OWN STATE, SHOWN WHATEVER THE STREAM SAYS. A full
	 * journal refuses every issuer it has not met, and no single row
	 * reveals it. */
	full_ = journal->used >= journal->capacity;
	capacity_->setText(full_ ? QStringLiteral("%1 of %2 streams -- FULL, so a peer "
	                                          "this host has not met is being refused")
	                                   .arg((qulonglong)journal->used)
	                                   .arg((qulonglong)journal->capacity)
	                         : QStringLiteral("%1 of %2 streams")
	                                   .arg((qulonglong)journal->used)
	                                   .arg((qulonglong)journal->capacity));

	for (i = 0; i < journal->used; i++) {
		if (journal->entries[i].stream != stream)
			continue;
		if (!fzn_ct_memeq(journal->entries[i].issuer, issuer, FZN_PUBKEY_LEN))
			continue;
		row = &journal->entries[i];
		break;
	}

	if (!row) {
		/* NOT LISTENING. `fzn_journal_next` would answer 1 here, which
		 * is the same answer a followed and silent stream gives. */
		state_ = UNTRACKED;
		state_label_->setText(QStringLiteral("not followed -- nothing from this "
		                                     "peer would be admitted"));
		pending_->setText(QStringLiteral("--"));
		return;
	}

	next = fzn_journal_next(journal, issuer, stream);
	pending = fzn_journal_pending(journal, issuer, stream);

	if (next == UINT64_MAX) {
		/* RUN OUT, NOT WANTING A HUGE NUMBER. */
		state_ = EXHAUSTED;
		state_label_->setText(QStringLiteral("exhausted -- this stream has no next "
		                                     "sequence and takes no more records"));
	} else if (next <= 1u) {
		state_ = FRESH;
		state_label_->setText(QStringLiteral("followed, and nothing received yet"));
	} else {
		state_ = TRACKING;
		state_label_->setText(QStringLiteral("received to %1; wants %2 next")
		                              .arg((qulonglong)(next - 1u))
		                              .arg((qulonglong)next));
	}

	pending_->setText(pending == 0u
	                          ? QStringLiteral("settled")
	                          : QStringLiteral("%1 received and not yet applied")
	                                    .arg((qulonglong)pending));
}

fzn_journal_view::state fzn_journal_view::shown_state() const
{
	return state_;
}

QString fzn_journal_view::state_text() const
{
	return state_label_->text();
}

QString fzn_journal_view::pending_text() const
{
	return pending_->text();
}

bool fzn_journal_view::full() const
{
	return full_;
}

QString fzn_journal_view::capacity_text() const
{
	return capacity_->text();
}
