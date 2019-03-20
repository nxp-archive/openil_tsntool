// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018-2019 NXP
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>


#include "readinput.h"
#include "cmd.h"
#include "main.h"
#include "tsn/genl_tsn.h"

//#define UNUSED __attribute__((__unused__))

#define SHOW_NO_OUTPUT 0x00
#define SHOW_OUTPUT    0x01
#define SHOW_RAW       0x02
#define SHOW_RAW_ONLY  0x04
#define PROMPT			"tsntool> "

int VERBOSE_CONDITION = 0;

extern struct cli_cmd cli_commands[];

#define TSNTOOL_VERSION "V0.1"

const char *cli_version =
"tsntool " TSNTOOL_VERSION "\n"
"Copyright 2018 NXP\n";

int cli_quit;
static int show_raw;

static const char *commands_help =
"tsn Commands:\n"
" command line:\n";

int multiline;

void signal_handler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
	case SIGABRT:
		multiline = 0;
		rl_line_buffer[0] = '\0';
		rl_end = rl_point = 0;
		rl_reset_line_state();
		fprintf(stdout, "\n");
		rl_redisplay();
		break;
	default:
		exit(EXIT_FAILURE);
		break;
	}
}

void cli_cmd_list(void);

static void usage(void)
{
	fprintf(stderr, "%s\n", cli_version);
	fprintf(stderr,
		"\n"
		"Usage:\n"
		"  tsntool -h\n"
		"  tsntool -v\n"
		"  tsntool                      interactive mode\n"
		"\n"
		"Options:\n"
		"  -h                           help (show this usage text)\n"
		"  -v                           shown version information\n"
		"\n%s",
		commands_help);

	cli_cmd_list();
}

void print_version(void)
{
	fprintf(stdout, "tsntool, version %s\n", TSNTOOL_VERSION);
	fprintf(stdout, "compile time: %s, %s\n", __DATE__, __TIME__);
}


void cli_cmd_list(void)
{
	struct cli_cmd *cmd;

	cmd = cli_commands;
	while (cmd->cmd) {
		printf("      %-12s\t%s\n", cmd->cmd, cmd->help);
		cmd++;
	}
}

static int request(int argc, char *argv[])
{
	struct cli_cmd *cmd, *match = NULL;
	int count;
	int ret	= 0;
	int number = 0, cmdnumber;

	count = 0;
	cmd = cli_commands;
	while (cmd->cmd) {
		if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) == 0) {
			match = cmd;
			count++;
			cmdnumber = number;
		}
		cmd++;
		number++;
	}

	if (count > 1) {
		/* found two parameter in the cli_commands */
		printf("Ambiguous command '%s'; possible commands:", argv[0]);
		cmd = cli_commands;
		while (cmd->cmd) {
			if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) ==
			    0) {
				printf(" %s", cmd->cmd);
			}
			cmd++;
		}
		printf("\n");
		ret = -1;
	} else if (count == 0) {
		/* Maybe it is one line command */
		usage();
	} else {
		/* = 1 in the commands cli_commands */
		ret = match->handler(argc, &argv[0], cmdnumber);
	}

	return ret;
}

static void cli_interactive(void)
{
	const int max_args = MAX_ARG_LEN;
	char *cmd, *argv[max_args], *pos;
	int argc;

	setlinebuf(stdout);
	printf("\nInteractive mode\n\n");
	using_history();
	//stifle_history(1000);

	initialize_readline();

	do {
		cmd = readline(PROMPT);
		if (!cmd)
			break;
		if (*cmd)
			add_history(cmd);
		argc = 0;
		pos = cmd;
		for (;;) {
			while (*pos == ' ')
				pos++;
			if (*pos == '\0')
				break;
			argv[argc] = pos;
			argc++;
			if (argc == max_args)
				break;
			while (*pos != '\0' && *pos != ' ')
				pos++;
			if (*pos == ' ')
				*pos++ = '\0';
		}
		printf("\n");
		if (argc)
			request(argc, argv);
		free(cmd);
	} while (!cli_quit);
}

int main(int argc, char *argv[])
{
	struct sigaction action;
	int interactive;
	int c;
	int raw = 0;
	int ret = 0;
	int run = 0;
	sigset_t block_mask;

	/* signal handling */
	sigfillset(&block_mask);
	action.sa_handler = signal_handler;
	action.sa_mask = block_mask;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGQUIT, &action, NULL);
	sigaction(SIGABRT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);

	for (;;) {
		c = getopt(argc, argv, "hrv");
		if (c < 0 || run)
			break;
		switch (c) {
		case 'h':
			usage();
			return 0;
		case 'v':
			printf("%s\n", cli_version);
			return 0;
		case 'r':
			if (raw) {
				usage();
				return -1;
			}
			raw = SHOW_RAW;
			break;
		default:
			run = 1;
			break;
		}
	}

	show_raw = raw;

	interactive = argc == optind;

	ret = genl_tsn_init();
	if (ret < 0) {
		loge("generic netlink init failure.\n");
		return -1;
	}

	tsn_echo_test("test netlink", 1);

	if (interactive) {
		printf("%s\n\n", cli_version);

		cli_interactive();
	} else
		ret = request(argc - 1, &argv[1]);

	genl_tsn_close();
	return 0;
}
