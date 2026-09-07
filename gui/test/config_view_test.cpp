/* Tests for gui/config_view.cpp.
 *
 * THE CASE THIS FILE EXISTS FOR is that the form and the command line accept
 * exactly the same things. Not similar things: the same. A dialog with its
 * own idea of a legal service number is a second validator, and the two drift
 * -- the CLI refusing what the form accepted, on one machine, for one daemon.
 *
 * So the central case does not assert a list of good and bad values at all.
 * It drives BOTH front doors with the same inputs and requires them to agree,
 * which is a relationship rather than a pair of values and survives
 * `chain/service.h` changing its mind.
 */

#include "../config_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL config_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* What the command line says about one option and value. */
static fzn_cli_err_t by_command_line(const char *option, const char *value)
{
	fzn_cli_t cli;
	char arg[256];
	int claimed = 0;

	fzn_cli_init(&cli);
	snprintf(arg, sizeof(arg), "%s=%s", option, value);
	return fzn_cli_arg(&cli, arg, &claimed);
}

/* What the form says about the same one. */
static fzn_cli_err_t by_form(fzn_config_view &view, const char *option, const char *value)
{
	fzn_cli_t cli;

	view.show_config(nullptr);
	view.set_field_text(QString::fromUtf8(option), QString::fromUtf8(value));
	return view.apply(&cli);
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_config_view view;
	fzn_cli_t cli;

	/* THE CENTRAL CASE. Every value, through both doors, and they must
	 * agree -- including about which refusal it is. */
	{
		static const struct {
			const char *option;
			const char *value;
		} CASES[] = {
			{ "--fuzznet-service", "1" },
			{ "--fuzznet-service", "7" },
			{ "--fuzznet-service", "0" },
			{ "--fuzznet-service", "-1" },
			{ "--fuzznet-service", "notanumber" },
			{ "--fuzznet-service", "4294967296" },
			{ "--fuzznet-product", "1" },
			{ "--fuzznet-product", "65534" },
			{ "--fuzznet-product", "65535" },
			{ "--fuzznet-product", "0" },
			{ "--fuzznet-product", "99999" },
			{ "--fuzznet-dir", "/var/lib/thing" },
			{ "--fuzznet-store", "/var/lib/thing/records" },
		};
		size_t i;
		int agreed = 1;

		for (i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++) {
			fzn_cli_err_t line = by_command_line(CASES[i].option, CASES[i].value);
			fzn_cli_err_t form = by_form(view, CASES[i].option, CASES[i].value);

			if (line != form) {
				char msg[256];

				snprintf(msg, sizeof(msg),
				         "%s=%s: the command line says \"%s\" and the form "
				         "says \"%s\"",
				         CASES[i].option, CASES[i].value,
				         fzn_cli_err_str(line), fzn_cli_err_str(form));
				check_at(0, __LINE__, msg);
				agreed = 0;
			}
		}
		CHECK(agreed, "the form and the command line disagree about a value");
		/* AND THE SWEEP MUST HAVE COVERED BOTH ANSWERS, or agreement is
		 * cheap: a form that refused everything would agree with a
		 * command line on the refusals alone. */
		{
			int accepted = 0;
			int refused = 0;

			for (i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++) {
				if (by_command_line(CASES[i].option, CASES[i].value) ==
				    FZN_CLI_OK)
					accepted++;
				else
					refused++;
			}
			CHECK(accepted > 0 && refused > 0,
			      "the sweep is all one answer, so agreeing about it proves "
			      "nothing");
		}
	}

	/* A BLANK FIELD IS AN OPTION NOT GIVEN, exactly as leaving it off a
	 * command line is -- not a zero, which is a value the library refuses. */
	view.show_config(nullptr);
	CHECK(view.apply(&cli) == FZN_CLI_OK, "an empty form was refused");
	CHECK(cli.service == FZN_SERVICE_NONE && cli.product == FZN_PRODUCT_NONE,
	      "an empty form invented values");
	CHECK(cli.dir == NULL && cli.store == NULL, "an empty form invented paths");

	/* UNSET SHOWS BLANK, not the number the library refuses. */
	{
		fzn_cli_t unset;

		fzn_cli_init(&unset);
		view.show_config(&unset);
		CHECK(view.field_text(QStringLiteral("--fuzznet-service")).isEmpty(),
		      "an unset service is shown as a number, and the number is one the "
		      "library refuses");
		CHECK(view.field_text(QStringLiteral("--fuzznet-product")).isEmpty(),
		      "an unset product is shown as a number");
	}

	/* A REFUSAL LEAVES NOTHING HALF-APPLIED, and says which option in the
	 * parser's own words. */
	{
		view.show_config(nullptr);
		view.set_field_text(QStringLiteral("--fuzznet-dir"), QStringLiteral("/tmp/x"));
		view.set_field_text(QStringLiteral("--fuzznet-service"), QStringLiteral("0"));
		CHECK(view.apply(&cli) != FZN_CLI_OK, "a refused value was accepted");
		CHECK(cli.dir == NULL,
		      "a refused apply left an earlier field applied, so the caller has "
		      "half a configuration");
		CHECK(view.message_text().contains(QLatin1String("--fuzznet-service")),
		      "the message does not name the option that was refused");
		CHECK(view.message_text().contains(
		              QString::fromUtf8(fzn_cli_err_str(FZN_CLI_ERR_VALUE))),
		      "the message is not the parser's own wording");
	}

	/* A ROUND TRIP. What the form shows, the form reads back. */
	{
		fzn_cli_t out;

		view.show_config(nullptr);
		view.set_field_text(QStringLiteral("--fuzznet-service"), QStringLiteral("9"));
		view.set_field_text(QStringLiteral("--fuzznet-product"), QStringLiteral("42"));
		view.set_field_text(QStringLiteral("--fuzznet-owner"), QStringLiteral("no"));
		CHECK(view.apply(&out) == FZN_CLI_OK, "a good form was refused");
		CHECK(out.service == 9u && out.product == 42u,
		      "the form did not read its own fields back");
		CHECK(out.owner == FZN_CLI_OWNER_NO, "the owner choice did not survive");

		view.show_config(&out);
		CHECK(view.field_text(QStringLiteral("--fuzznet-service")) ==
		              QStringLiteral("9"),
		      "showing a configuration did not put it in the fields");
		CHECK(view.field_text(QStringLiteral("--fuzznet-owner")) ==
		              QStringLiteral("no"),
		      "showing a configuration did not set the owner choice");
	}

	/* THE OWNER IS A LIST, so a value the parser refuses cannot be typed.
	 * Every entry must be one the parser takes -- which is the same
	 * agreement as above, asserted over the vocabulary rather than over
	 * values. */
	{
		static const char *const OWNERS[] = { "auto", "yes", "no" };
		size_t i;

		for (i = 0; i < 3u; i++) {
			view.show_config(nullptr);
			view.set_field_text(QStringLiteral("--fuzznet-owner"),
			                    QString::fromUtf8(OWNERS[i]));
			CHECK(view.apply(&cli) == FZN_CLI_OK,
			      "an entry the form offers is one the parser refuses");
		}
	}

	CHECK(view.apply(NULL) == FZN_CLI_ERR_MALFORMED, "a null destination was accepted");

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("config_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
