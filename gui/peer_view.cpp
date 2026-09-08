#include "peer_view.h"

#include <QFormLayout>
#include <QLabel>

/*
 * THREE WORDS, SHARING NO PREFIX. See the header: every affordance a toolkit
 * offers for membership is two-valued, so the verdict is text and the suite
 * asserts the three are pairwise distinct. They are also deliberately not
 * "yes"/"no"/"maybe" -- "maybe" reads as a hedge about the answer, and this
 * is a definite statement that the evidence could not be obtained.
 */
static QString word_for(fzn_peer_verdict_t verdict)
{
	switch (verdict) {
	case FZN_PEER_MEMBER:
		return QStringLiteral("admitted");
	case FZN_PEER_NOT_MEMBER:
		return QStringLiteral("denied");
	case FZN_PEER_UNKNOWN:
		break;
	}

	/* THE DEFAULT IS THE DENYING ONE, and it is reached for an enum value
	 * this build does not know as well as for UNKNOWN. A widget that fell
	 * through to "admitted" on a value added later would grant on the
	 * strength of not recognising it. */
	return QStringLiteral("cannot tell");
}

fzn_peer_view::fzn_peer_view(QWidget *parent)
        : QWidget(parent), verdict_(FZN_PEER_UNKNOWN), named_(false),
          summary_(new QLabel(this)), verdict_label_(new QLabel(this)),
          groups_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Request"), summary_);
	form->addRow(QStringLiteral("Answer"), verdict_label_);
	form->addRow(QStringLiteral("Groups"), groups_);

	summary_->setWordWrap(true);
	groups_->setWordWrap(true);

	show_peer(nullptr, nullptr, 0u, nullptr, 0u);
}

void fzn_peer_view::show_peer(const fzn_peer_t *peer, const uint8_t *verb, size_t verb_len,
                              const fzn_verb_rule_t *rules, size_t rule_count)
{
	char line[FZN_PEER_PRINT_MAX];
	fzn_peer_verdict_t verdict = FZN_PEER_UNKNOWN;
	int named = 0;
	size_t len = 0u;

	verdict_ = FZN_PEER_UNKNOWN;
	named_ = false;

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193. */
	if (fzn_peer_print(peer, verb, verb_len, rules, rule_count, line, sizeof(line), &len,
	                   &verdict, &named) != 0) {
		summary_->setText(QStringLiteral("nothing to report"));
		verdict_label_->setText(word_for(FZN_PEER_UNKNOWN));
		groups_->setText(QStringLiteral("not known"));
		return;
	}

	summary_->setText(QString::fromLatin1(line));
	verdict_label_->setText(word_for(verdict));
	verdict_ = verdict;
	named_ = named ? true : false;

	if (!peer) {
		groups_->setText(QStringLiteral("not known -- no peer"));
		return;
	}

	if (!peer->groups_known) {
		/* WORDS, NOT AN EMPTY WIDGET. An unreadable list and a
		 * genuinely empty one both draw as nothing unless something is
		 * put here on purpose, and peer.h's whole subject is that they
		 * are different. `group_count` is not read: peer.h documents it
		 * as meaningless when the list is unknown. */
		groups_->setText(QStringLiteral(
		        "could not be read -- this is not the same as belonging to none"));
		return;
	}

	if (!peer->group_count) {
		groups_->setText(QStringLiteral("none -- read, and empty"));
		return;
	}

	{
		QString text;
		size_t i;
		size_t shown = peer->group_count;

		/* A struct whose count exceeds its array was not filled by this
		 * library. `fzn_peer_group_verdict` answers UNKNOWN for it
		 * rather than scanning, so the widget must not scan either --
		 * reading past the array can only invent memberships. */
		if (shown > FZN_PEER_MAX_GROUPS) {
			groups_->setText(QStringLiteral(
			        "not known -- the group count exceeds the list it indexes"));
			return;
		}

		for (i = 0u; i < shown; i++) {
			if (i)
				text += QStringLiteral(", ");
			text += QString::number(peer->groups[i]);
		}
		groups_->setText(text);
	}
}

fzn_peer_verdict_t fzn_peer_view::shown_verdict() const
{
	return verdict_;
}

bool fzn_peer_view::named() const
{
	return named_;
}

QString fzn_peer_view::summary_text() const
{
	return summary_->text();
}

QString fzn_peer_view::verdict_text() const
{
	return verdict_label_->text();
}

QString fzn_peer_view::groups_text() const
{
	return groups_->text();
}
