#include "authz_view.h"

extern "C" {
#include "../trust/trust.h"
}

#include <QFormLayout>
#include <QLabel>

#include <string.h>

/* The three origins a request can arrive over, with the words a user reads.
 * FZN_ORIGIN_NONE is not among them: it is the unset value, reaches nothing
 * by construction, and a row saying so would be a row about a mistake rather
 * than about a transport. */
struct origin_row {
	fzn_origin_t origin;
	const char *label;
};

static const struct origin_row ORIGINS[] = {
	{ FZN_ORIGIN_SAME_USER, "same user" },
	{ FZN_ORIGIN_LOCAL, "local" },
	{ FZN_ORIGIN_REMOTE, "remote" },
};

fzn_authz_view::fzn_authz_view(QWidget *parent)
        : QWidget(parent), requirement_(new QLabel(this)), origins_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Requires"), requirement_);
	form->addRow(QStringLiteral("Reachable from"), origins_);
	requirement_->setWordWrap(true);
	origins_->setWordWrap(true);

	show_policy(nullptr);
}

void fzn_authz_view::show_policy(const fzn_authz_policy_t *policy)
{
	QStringList reaching;
	size_t i;

	if (policy)
		policy_ = *policy;
	else
		memset(&policy_, 0, sizeof(policy_));

	if (!policy_.spelled) {
		/* NOBODY HAS SAID. Not "denied", which is what it does -- what
		 * it IS, is unconfigured, and the two want different actions
		 * from whoever is reading. */
		requirement_->setText(QStringLiteral("no policy has been spelled"));
		origins_->setText(QStringLiteral("nothing"));
		return;
	}

	if (!policy_.guarded) {
		/* ITS OWN WORDS, because a policy that has drifted to unguarded
		 * is what somebody is looking for when they read this. */
		requirement_->setText(QStringLiteral("no capability -- unguarded"));
	} else {
		char text[FZN_TRUST_FINGERPRINT_LEN];

		/* THE SAME SPELLING OF THIRTY-TWO BYTES THE ANCHOR USES.
		 * `trust_view` exists because a fingerprint compared against a
		 * differently-formatted copy of itself cannot be compared, and
		 * a capability id is the same length and the same problem. */
		if (fzn_trust_fingerprint(policy_.capability.b, text, sizeof(text)) ==
		    FZN_TRUST_OK)
			requirement_->setText(QStringLiteral("capability ") +
			                      QString::fromLatin1(text));
		else
			requirement_->setText(QStringLiteral("a capability this widget "
			                                     "could not format"));
	}

	for (i = 0; i < sizeof(ORIGINS) / sizeof(ORIGINS[0]); i++) {
		/* THE LIBRARY'S ANSWER, not a test of the bitmask. */
		if (fzn_authz_origin_permitted(policy_, ORIGINS[i].origin))
			reaching += QString::fromUtf8(ORIGINS[i].label);
	}
	origins_->setText(reaching.isEmpty() ? QStringLiteral("nothing")
	                                     : reaching.join(QStringLiteral(", ")));
}

bool fzn_authz_view::is_spelled() const
{
	return policy_.spelled != 0;
}

QString fzn_authz_view::requirement_text() const
{
	return requirement_->text();
}

QString fzn_authz_view::origins_text() const
{
	return origins_->text();
}

bool fzn_authz_view::shows_origin_permitted(fzn_origin_t origin) const
{
	size_t i;

	for (i = 0; i < sizeof(ORIGINS) / sizeof(ORIGINS[0]); i++) {
		if (ORIGINS[i].origin != origin)
			continue;
		/* READ OUT OF THE TEXT, so this answers what is on the screen
		 * rather than what the library would say if asked again --
		 * which is the whole thing the suite is comparing. */
		return origins_->text().contains(QString::fromUtf8(ORIGINS[i].label));
	}

	return false;
}
