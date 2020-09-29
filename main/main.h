// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018-2019 NXP
 */

#ifndef _FELIX_MAIN_H_
#define _FELIX_MAIN_H_

extern const char *cli_version;
extern int cli_quit;
void print_version(void);
void cli_cmd_list(void);

extern int VERBOSE_CONDITION;

#define _log(file, fmt, ...) do { \
	if (VERBOSE_CONDITION) { \
		fprintf(file, "%s@%d: " fmt "\n", \
		__func__, __LINE__, ##__VA_ARGS__); \
	} else { \
		fprintf(file, fmt "\n", ##__VA_ARGS__); \
	} \
} while (0)

#define logc(file, condition, ...) do { \
	if (condition) { \
		_log(file, __VA_ARGS__); \
	} \
} while (0)

#define loge(...) _log(stderr, __VA_ARGS__)
#define logi(...) _log(stdout, __VA_ARGS__)
#define logv(...) logc(stdout, VERBOSE_CONDITION, __VA_ARGS__)

#define SWITCH_NUMBER 1
#define SWITCH_PORTS_NUMBER 5
#define MAX_ARG_LEN 30

extern char some_msg[4096];
#define UNUSED __attribute__((__unused__))
#define INSTRUCTION(output, format, args...) {snprintf(some_msg, 4095, format, ##args); fprintf(output, "\n  %s", some_msg); }
#define ERROR(function, format, args...) {snprintf(some_msg, 4095, format, ##args); fprintf(stderr, "%s: %s\n", function, some_msg); }
enum {
	OPT_TYPE_SWITCH,
	OPT_TYPE_TSN
};

#endif
