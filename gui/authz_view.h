/*
 * What a kind of request requires, so every consumer shows a policy alike.
 *
 * project.md sec 165. sec 139 asked for the objects every consuming software
 * needs and named permissions among them; `chain/authz.h` is the model, and
 * this is a way of looking at one of its policies.
 *
 * IT RENDERS THE LIBRARY'S ANSWERS AND COMPUTES NONE.
 *
 * That is the same rule `gui/config_view.h` follows about validation and
 * `gui/trust_view.h` about deciding, and it bites hardest here. Whether an
 * origin may reach a kind is `fzn_authz_origin_permitted`'s answer, and a
 * widget that tested `policy.origins` against `FZN_ORIGIN_BIT` itself would
 * be a second implementation of the reachability rule -- readable, obvious,
 * and free to disagree with the one that actually gates requests. So every
 * row here is a call, and the suite asserts the two agree for every policy
 * and origin it can build.
 *
 * AN UNSPELLED POLICY IS SHOWN AS UNSPELLED, NOT AS DENYING. `authz.h` calls
 * `spelled` "the field the whole design rests on": it is what makes a zeroed
 * policy distinguishable from a deliberate one. Both deny, so a view that
 * rendered the verdict alone would show a policy nobody wrote and a policy
 * somebody wrote to refuse everything in exactly the same words -- and the
 * first is a configuration fault somebody has to be able to find.
 *
 * GUARDED AND UNGUARDED ARE ALSO DIFFERENT WORDS here, for the reason
 * `fzn_authz_verdict_t` keeps GRANTED_BY_CHAIN and GRANTED_UNGUARDED apart:
 * a policy that has drifted to unguarded is a thing somebody has to be able
 * to find, and it cannot be found if the screen says "allowed" for both.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_AUTHZ_VIEW_H
#define FZN_GUI_AUTHZ_VIEW_H

extern "C" {
#include "../chain/authz.h"
}

#include <QString>
#include <QWidget>

class QLabel;

class fzn_authz_view : public QWidget {
public:
	explicit fzn_authz_view(QWidget *parent = nullptr);

	/*
	 * Show one policy.
	 *
	 * A null pointer shows the unspelled state, which is what a zeroed
	 * `fzn_authz_policy_t` is and what a consumer that forgot to spell one
	 * has.
	 */
	void show_policy(const fzn_authz_policy_t *policy);

	/* Whether this policy has been spelled at all, and what the widget says
	 * about it. A test reads these; a consumer auditing its policies wants
	 * the first. */
	bool is_spelled() const;
	QString requirement_text() const;

	/* Which origins the widget shows as reaching this kind, as the text a
	 * user reads. Empty when none do. */
	QString origins_text() const;

	/* What the widget says about `origin`, which is `fzn_authz_origin_
	 * permitted`'s answer and not this widget's opinion of it. */
	bool shows_origin_permitted(fzn_origin_t origin) const;

private:
	fzn_authz_policy_t policy_;
	QLabel *requirement_;
	QLabel *origins_;
};

#endif /* FZN_GUI_AUTHZ_VIEW_H */
