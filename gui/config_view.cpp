#include "config_view.h"

#include <QComboBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QVBoxLayout>

/* The options this form offers, in the order the usage text lists them, so a
 * user reading `--help` and a user reading the dialog meet them the same way.
 *
 * ONE TABLE, WALKED BY BOTH `apply` AND THE FIELD ACCESSORS. A second list
 * would be a second thing to keep in step with the parser. */
struct field {
	const char *option; /* the spelling a command line uses */
	const char *label;
};

static const struct field FIELDS[] = {
	{ "--fuzznet-dir", "Identity directory" },
	{ "--fuzznet-store", "Record store" },
	{ "--fuzznet-service", "Service number" },
	{ "--fuzznet-product", "Product number" },
};

fzn_config_view::fzn_config_view(QWidget *parent)
        : QWidget(parent), dir_(new QLineEdit(this)), store_(new QLineEdit(this)),
          service_(new QLineEdit(this)), product_(new QLineEdit(this)),
          owner_(new QComboBox(this)), message_(new QLabel(this))
{
	QVBoxLayout *outer = new QVBoxLayout(this);
	QFormLayout *form = new QFormLayout();

	form->addRow(QString::fromUtf8(FIELDS[0].label), dir_);
	form->addRow(QString::fromUtf8(FIELDS[1].label), store_);
	form->addRow(QString::fromUtf8(FIELDS[2].label), service_);
	form->addRow(QString::fromUtf8(FIELDS[3].label), product_);

	/* THE OWNER IS A CHOICE OF THREE AND IS SPELLED AS ONE. A free-text
	 * field would let a user type something the parser refuses, for no
	 * benefit: the three values are the whole vocabulary and a list cannot
	 * be mistyped. The strings are the parser's own -- `auto`, `yes`,
	 * `no` -- so what the form sends is what a command line would. */
	owner_->addItem(QStringLiteral("auto"));
	owner_->addItem(QStringLiteral("yes"));
	owner_->addItem(QStringLiteral("no"));
	form->addRow(QStringLiteral("Become owner"), owner_);

	outer->addLayout(form);
	outer->addWidget(message_);

	message_->setWordWrap(true);
	show_config(nullptr);
}

/* The line edit behind an option, or null for one this form does not carry. */
static QLineEdit *edit_for(const QString &option, QLineEdit *dir, QLineEdit *store,
                           QLineEdit *service, QLineEdit *product)
{
	if (option == QLatin1String("--fuzznet-dir"))
		return dir;
	if (option == QLatin1String("--fuzznet-store"))
		return store;
	if (option == QLatin1String("--fuzznet-service"))
		return service;
	if (option == QLatin1String("--fuzznet-product"))
		return product;
	return nullptr;
}

void fzn_config_view::show_config(const fzn_cli_t *cli)
{
	fzn_cli_t unset;

	message_->clear();
	if (!cli) {
		fzn_cli_init(&unset);
		cli = &unset;
	}

	dir_->setText(cli->dir ? QString::fromUtf8(cli->dir) : QString());
	store_->setText(cli->store ? QString::fromUtf8(cli->store) : QString());

	/* UNSET IS BLANK, NOT ZERO. `fzn_cli_init` leaves these at the values
	 * `chain/service.h` refuses, so printing them would put a number in
	 * front of somebody that the library exists to reject. */
	service_->setText(cli->service == FZN_SERVICE_NONE
	                          ? QString()
	                          : QString::number(cli->service));
	product_->setText(cli->product == FZN_PRODUCT_NONE
	                          ? QString()
	                          : QString::number(cli->product));
	owner_->setCurrentIndex(cli->owner == FZN_CLI_OWNER_YES  ? 1
	                        : cli->owner == FZN_CLI_OWNER_NO ? 2
	                                                         : 0);
}

fzn_cli_err_t fzn_config_view::apply(fzn_cli_t *cli)
{
	size_t i;

	if (!cli)
		return FZN_CLI_ERR_MALFORMED;

	fzn_cli_init(cli);
	message_->clear();

	for (i = 0; i < sizeof(FIELDS) / sizeof(FIELDS[0]); i++) {
		const QString option = QString::fromUtf8(FIELDS[i].option);
		const QString value = field_text(option);
		QByteArray arg;
		int claimed = 0;
		fzn_cli_err_t err;

		/* A BLANK FIELD IS AN OPTION NOT GIVEN, which is what leaving
		 * it off a command line does. */
		if (value.isEmpty())
			continue;

		arg = (option + QLatin1Char('=') + value).toUtf8();
		err = fzn_cli_arg(cli, arg.constData(), &claimed);
		if (err != FZN_CLI_OK) {
			/* THE PARSER'S WORDS, and the option named beside them
			 * so a user knows which row to look at. */
			message_ ->setText(option + QStringLiteral(": ") +
			                   QString::fromUtf8(fzn_cli_err_str(err)));
			fzn_cli_init(cli);
			return err;
		}
	}

	{
		const QByteArray arg =
		        (QStringLiteral("--fuzznet-owner=") + owner_->currentText()).toUtf8();
		int claimed = 0;
		fzn_cli_err_t err = fzn_cli_arg(cli, arg.constData(), &claimed);

		if (err != FZN_CLI_OK) {
			message_->setText(QStringLiteral("--fuzznet-owner: ") +
			                  QString::fromUtf8(fzn_cli_err_str(err)));
			fzn_cli_init(cli);
			return err;
		}
	}

	return FZN_CLI_OK;
}

QString fzn_config_view::message_text() const
{
	return message_->text();
}

void fzn_config_view::set_field_text(const QString &option, const QString &value)
{
	QLineEdit *edit = edit_for(option, dir_, store_, service_, product_);

	if (edit)
		edit->setText(value);
	else if (option == QLatin1String("--fuzznet-owner"))
		owner_->setCurrentText(value);
}

QString fzn_config_view::field_text(const QString &option) const
{
	QLineEdit *edit = edit_for(option, dir_, store_, service_, product_);

	if (edit)
		return edit->text();
	if (option == QLatin1String("--fuzznet-owner"))
		return owner_->currentText();
	return QString();
}
