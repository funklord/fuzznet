/*
 * The configuration form, so that every consumer asks for the same settings.
 *
 * project.md sec 164. sec 137 built `cli/cli.h` on the holder's observation
 * that "every consuming software will probably require the exact same
 * interface"; this is that interface with a dialog on it rather than a
 * command line, and it edits the same `fzn_cli_t` the parser fills.
 *
 * IT DOES NOT VALIDATE. THE PARSER DOES.
 *
 * That is the whole design and it is worth stating before anything else. A
 * form that checked its own fields would be a second opinion about what a
 * legal service number is, and the two would drift -- the CLI refusing what
 * the dialog accepted, on the same machine, for the same daemon. So
 * `fzn_config_view::apply` composes the very option strings a command line
 * would carry -- `--fuzznet-service=7` -- and hands each to `fzn_cli_arg`.
 *
 * What that buys is not tidiness. It is that the two front doors CANNOT
 * disagree: there is one validator and the dialog is a way of typing at it.
 * When `chain/service.h` changes what a product may be, both change together
 * because there is only one of them.
 *
 * AND THE ERROR SHOWN IS THE PARSER'S. `fzn_cli_err_str`'s words, for
 * `trust_view`'s reason: a widget that worded its own would give a user two
 * spellings of one refusal, and somebody comparing a dialog against a log
 * would be comparing them rather than the fault.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. The form does not tell
 * anybody it changed; a consumer reads it when it is ready -- when a dialog
 * is accepted, typically -- which is the same shape `fzn_cli_arg` has, where
 * a caller drives and the library answers.
 */

#ifndef FZN_GUI_CONFIG_VIEW_H
#define FZN_GUI_CONFIG_VIEW_H

extern "C" {
#include "../cli/cli.h"
}

#include <QString>
#include <QWidget>

class QComboBox;
class QLabel;
class QLineEdit;

class fzn_config_view : public QWidget {
public:
	explicit fzn_config_view(QWidget *parent = nullptr);

	/*
	 * Put `cli`'s values in the fields. A null pointer shows the unset
	 * state, which is what `fzn_cli_init` leaves and is not the same as a
	 * form full of zeroes: an unset service is blank here, because zero is
	 * a value `chain/service.h` refuses and showing it would invite
	 * somebody to send it.
	 */
	void show_config(const fzn_cli_t *cli);

	/*
	 * Read the fields back into `cli`, through the parser.
	 *
	 * Returns FZN_CLI_OK when every field was accepted, and otherwise the
	 * first refusal -- with `cli` left as `fzn_cli_init` leaves it, since a
	 * half-applied configuration is worse than none. `message_text` then
	 * says which option and why, in the parser's words.
	 *
	 * A BLANK FIELD IS NOT AN ERROR. It means unset, and the option is
	 * simply not offered -- exactly as leaving it off a command line does.
	 */
	fzn_cli_err_t apply(fzn_cli_t *cli);

	/* What the form is saying about the last `apply`: empty when it
	 * succeeded, and the option and the parser's reason when it did not. */
	QString message_text() const;

	/* The fields, as text, so a test can drive the form without a screen
	 * and a consumer can pre-fill one. */
	void set_field_text(const QString &option, const QString &value);
	QString field_text(const QString &option) const;

private:
	QLineEdit *dir_;
	QLineEdit *store_;
	QLineEdit *service_;
	QLineEdit *product_;
	QComboBox *owner_;
	QLabel *message_;
};

#endif /* FZN_GUI_CONFIG_VIEW_H */
