#include "authz_view.h"

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
        : QWidget(parent), state_label_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Policy"), state_label_);
	state_label_->setWordWrap(true);

	show_policy(nullptr);
}

void fzn_authz_view::show_policy(const fzn_authz_policy_t *policy)
{
	char line[FZN_AUTHZ_PRINT_MAX];
	fzn_authz_line_t said = FZN_AUTHZ_LINE_UNSPELLED;
	size_t len = 0;

	if (policy)
		policy_ = *policy;
	else
		memset(&policy_, 0, sizeof(policy_));

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193. */
	if (fzn_authz_print(policy, line, sizeof(line), &len, &said) != FZN_CHAIN_OK) {
		state_label_->setText(QStringLiteral("no policy has been spelled"));
		return;
	}

	{
		QString text = QString::fromLatin1(line);

		while (text.endsWith(QLatin1Char('\n')))
			text.chop(1);
		state_label_->setText(text);
	}
}

bool fzn_authz_view::is_spelled() const
{
	return policy_.spelled != 0;
}

QString fzn_authz_view::state_text() const
{
	return state_label_->text();
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
		return state_label_->text().contains(QString::fromUtf8(ORIGINS[i].label));
	}

	return false;
}
