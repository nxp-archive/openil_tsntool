// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018-2019 NXP
 */

#ifndef _CLI_CMD_H_
#define _CLI_CMD_H_
#include <getopt.h>
#include "main.h"

struct cli_cmd {
	const char *cmd;
	int (*handler)(int argc, char *argv[], int number);
	const char *help;
	struct option long_options[MAX_ARG_LEN];
};

extern struct cli_cmd cli_commands[];

int cli_cmd_help(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_version(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_quit(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_verbose(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_cmd_qbv_set(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_qbv_get(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_qci_sfi_set(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_qci_sfi_get(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_qci_sfi_counters_get(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_streamid_set(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_streamid_get(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_qci_sgi_set(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_qci_sgi_get(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_qci_fmi_set(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_qci_fmi_get(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_cbs_set(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_cbs_get(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_tsd_set(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_tsd_get(UNUSED int argc, UNUSED char *argv[], UNUSED int number);
int cli_cmd_qbu_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_cmd_qbu_get_status(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_sendip(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_regtool(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_ptptool(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_cmd_ct_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_cmd_cbgen_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_cmd_cbrec_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_cmd_cbstatus_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
int cli_cmd_dscp_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber);
#endif
