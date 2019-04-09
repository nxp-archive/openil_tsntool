// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018-2019 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <linux/pci.h>

#include "tsn/genl_tsn.h"
#include "fill.h"
#include "readinput.h"
#include "cmd.h"


#define PRINT_ERROR \
	do { \
		fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \
				__LINE__, __FILE__, errno, strerror(errno)); return 0; \
	} while (0)

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

extern int VERBOSE_CONDITION;

char qbventry_example[] = "#NUMBER GATE_VLAUE TIME_LONG\n \
						   \r#t0  00001111b       500\n \
						   \r#t1  11110000b       1000\n";
char sglentry_example[] = "#'NUMBER' 'GATE_VLAUE' 'IPV' 'TIME_LONG' 'OCTET_MAX'\n \
					  \r#t0  0b  1   500     2000\n \
					  \r#t1  1b	3	1000	1580\n";

struct cli_cmd cli_commands[] = {
	{ "help", cli_cmd_help, "show funciton",
		{
			{0, 0, 0, 0}
		}
	},
	{ "version", cli_cmd_version, "show version ",
		{
			{0, 0, 0, 0}
		}
	},
	{ "verbose", cli_cmd_verbose, "debug on/off",
		{
			{0, 0, 0, 0}
		}
	},
	{ "quit", cli_cmd_quit, "quit ",
		{
			{0, 0, 0, 0}
		}
	},
	{ "qbvset", cli_cmd_qbv_set, "set time gate scheduling config for <ifname>",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd' },
			{"entryfile", 1, 0, 'f'},
			{"maxsdu", 1, 0, 'm'},
			{"configchange", 0, 0, 'c'},
			{"basetime", 1, 0, 'b'},
			{"enable", 0, 0, 'e'},
			{"disable", 0, 0, 'q'},
			{"cycletime", 1, 0, 'y'},
			{"cycletimeext", 1, 0, 'x'},
			{"initgate", 1, 0, 'i'},
			{0, 0, 0, 0}
		}
	},
	{ "qbvget", cli_cmd_qbv_get, "<ifname> : get time scheduling entrys for <ifname>",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0}
		}
	},
	{ "cbstreamidset", cli_cmd_streamid_set, "set stream identify table",
		{
			{"help", 0, 0, 'h'},
			{"enable", 0, 0, 'e'},
			{"disable", 0, 0, 'q'},
			{"index", 1, 0, 'i'},
			{"streamhandle", 1, 0, 's'},
			{"infacoutport", 1, 0, 'u'},
			{"outfacoutport", 1, 0, 'v'},
			{"infacinport", 1, 0, 'w'},
			{"outfacinport", 1, 0, 'x'},
			{"nullstreamid", 0, 0, 'n'},
			{"sourcemacvid", 0, 0, 'f'},
			{"destmacvid", 0, 0, 't'},
			{"ipstreamid", 0, 0, 'p'},
			{"nulldmac", 1, 0, 'm'},
			{"nulltagged", 1, 0, 'g'},
			{"nullvid", 1, 0, 'l'},
			{"sourcemac", 1, 0, 'a'},
			{"sourcetagged", 1, 0, 'b'},
			{"sourcevid", 1, 0, 'c'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0}
		}
	},
	{ "cbstreamidget", cli_cmd_streamid_get, "get stream identify table and counters",
		{
			{"help", 0, 0, 'h'},
			{"index", 1, 0, 'i'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0}
		}
	},
	{ "qcisfiset", cli_cmd_qci_sfi_set, "set stream filter instance ",
		{
			{"help", 0, 0, 'h'},
			{"enable", 0, 0, 'e'},
			{"disable", 0, 0, 'q'},
			{"index", 1, 0, 'i'},
			{"streamhandle", 1, 0, 's'},
			{"priority", 1, 0, 'p'},
			{"gateid", 1, 0, 'g'},
			{"maxsdu", 1, 0, 'u'},
			{"flowmeterid", 1, 0, 'f'},
			{"oversizeenable", 0, 0, 'o'},
			{"oversize", 0, 0, 'v'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0}
		}
	},
	{ "qcisfiget", cli_cmd_qci_sfi_get, "get stream filter instance ",
		{
			{"help", 0, 0, 'h'},
			{"index", 1, 0, 'i'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0}
		}
	},
	{ "qcisgiset", cli_cmd_qci_sgi_set, "set stream gate instance ",
		{
			{"help", 0, 0, 'h'},
			{"enable", 0, 0, 'e'},
			{"disable", 0, 0, 'q'},
			{"index", 1, 0, 'i'},
			{"configchange", 0, 0, 'c'},
			{"enblkinvrx", 0, 0, 'v'},
			{"blkinvrx", 0, 0, 'r'},
			{"enblkoctex", 0, 0, 'o'},
			{"blkoctex", 0, 0, 'x'},
			{"initgate", 1, 0, 't'},
			{"cycletime", 1, 0, 'y'},
			{"cycletimeext", 1, 0, 'a'},
			{"basetime", 1, 0, 'b'},
			{"initipv", 1, 0, 'p'},
			{"gatelistfile", 1, 0, 'f'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0}
		}
	},
	{ "qcisgiget", cli_cmd_qci_sgi_get, "get stream gate instance ",
		{
			{"help", 0, 0, 'h'},
			{"index", 1, 0, 'i'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0}
		}
	},
	{ "qcisficounterget", cli_cmd_qci_sfi_counters_get, "get stream filter counters",
		{
			{0, 0, 0, 0}
		}
	},
	{ "qcifmiset", cli_cmd_qci_fmi_set, "set flow metering instance",
		{
			{"help", 0, 0, 'h'},
			{"index", 1, 0, 'i'},
			{"disable", 0, 0, 'q'},
			{"cir", 1, 0, 'c'},
			{"cbs", 1, 0, 'b'},
			{"eir", 1, 0, 'e'},
			{"ebs", 1, 0, 's'},
			{"cf", 0, 0, 'f'},
			{"cm", 0, 0, 'm'},
			{"dropyellow", 0, 0, 'y'},
			{"markred_enable", 0, 0, 'a'},
			{"markred", 0, 0, 'k'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0}
		}
	},
	{ "qcifmiget", cli_cmd_qci_fmi_get, "get flow metering instance",
		{
			{"help", 0, 0, 'h'},
			{"index", 1, 0, 'i'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0}
		}
	},
	{ "cbsset", cli_cmd_cbs_set, "set TCs credit-based shaper configure",
		{
			{"help", 0, 0, 'h'},
			{"tc", 1, 0, 't'},
			{"percentage", 1, 0, 'p'},
			{"all", 1, 0, 'a'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0},
		}
	},
	{ "cbsget", cli_cmd_cbs_get, "get TCs credit-based shaper status",
		{
			{"help", 0, 0, 'h'},
			{"tc", 1, 0, 't'},
			{"device", 1, 0, 'd' },
			{0, 0, 0, 0},
		}
	},
	{ "qbuset", cli_cmd_qbu_set, "set one 8-bits vector showing the preemptable traffic class",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd'},
			{"preemptable", 1, 0, 'p'},
			{0, 0, 0, 0},
		}
	},
	{ "qbugetstatus", cli_cmd_qbu_get_status, "get qbu preemption setings",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd'},
			{0, 0, 0, 0},
		}
	},
	{ "tsdset", cli_cmd_tsd_set, "set tsd configure",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd'},
			{"enable", 0, 0, 'e'},
			{"disable", 0, 0, 'q'},
			{"period", 1, 0, 'p'},
			{"frame_num", 1, 0, 'n'},
			{"immediate", 0, 0, 'i'},
		}
	},
	{"tsdget", cli_cmd_tsd_get, "get tsd configure",
			{
				{"help", 0, 0, 'h'},
				{"device", 1, 0, 'd'},
			}
	},
	{ "ctset", cli_cmd_ct_set, "set cut through queue status",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd'},
			{"queue_stat", 1, 0, 'q'},
		}
	},
	{ "cbgen", cli_cmd_cbgen_set, "set sequence generate configure",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd'},
			{"index", 1, 0, 'i'},
			{"iport_mask", 1, 0, 'p'},
			{"split_mask", 1, 0, 's'},
			{"seq_len", 1, 0, 'l'},
			{"seq_num", 1, 0, 'n'},
		}
	},
	{ "cbrec", cli_cmd_cbrec_set, "set sequence recover configure",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd'},
			{"index", 1, 0, 'i'},
			{"seq_len", 1, 0, 'l'},
			{"his_len", 1, 0, 's'},
			{"rtag_pop_en", 0, 0, 'r'},
		}
	},
	{ "cbget", cli_cmd_cbstatus_get, "get 802.1CB config status",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd'},
			{"index", 1, 0, 'i'},
		}
	},
	{ "pcpmap", cli_cmd_pcpmap_set, "set queues map to PCP tag",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd'},
			{"enable", 0, 0, 'e'},
		}
	},

	{ "dscpset", cli_cmd_dscp_set, "set DSCP to queues and dpl",
		{
			{"help", 0, 0, 'h'},
			{"device", 1, 0, 'd'},
			{"disable", 0, 0, 'u'},
			{"index", 1, 0, 'i'},
			{"cos", 1, 0, 'c'},
			{"dpl", 1, 0, 'p'},
		}
	},




	{ "sendpkt", cli_sendip, "send ptp broadcast packet every 5 second",
		{
			{"help", 0, 0, 'h'},
			{"loopcount", 1, 0, 'c'},
			{"timeint", 1, 0, 't'},
			{"length", 1, 0, 'l'},
			{"smac", 1, 0, 's'},
			{"device", 1, 0, 'd'},
		}
	},
	{ "regtool", cli_regtool, "register read/write of bar0 of PFs",
		{
			{"help", 0, 0, 'h'},
		}
	},
	{ "ptptool", cli_ptptool, "ptp timer set tool",
		{
			{"help", 0, 0, 'h'},
		}
	},
	{ NULL, NULL, NULL, { {0, 0, 0, 0} } }
};

int cli_cmd_verbose(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	if (!VERBOSE_CONDITION)
		VERBOSE_CONDITION = 1;
	else
		VERBOSE_CONDITION = 0;

	printf("Debug: %s\n", VERBOSE_CONDITION?"ON":"OFF");

	return 0;
}

int cli_cmd_help(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	cli_cmd_list();
	return 0;
}

int cli_cmd_version(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	printf("%s\n\n", cli_version);
	print_version();
	return 0;
}

int cli_cmd_quit(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	cli_quit = 1;
	return 0;
}


#define HEX_OCT(str) \
	(((*str) == '0' && ((*(str + 1)) == 'x' || (*(str + 1)) == 'X')) ? 16:10)


static inline int is_hex_oct(char *str)
{
	char *opt = str;

	if ((*str) == '0' && ((*(str + 1)) == 'x' || (*(str + 1)) == 'X')) {
		str += 2;
		while (*str != '\0') {

			if ((*str <= '9' && *str >= '0')
					|| (*str >= 'a' && *str <= 'f')
					|| (*str >= 'A' && *str <= 'F')) {
				str++;
				continue;
			} else {
				loge("warning:parameter '%s' is not right Hex expression\n", opt);
				return -1;
			}
		}
		return 16;
	}

	while (*str != '\0') {
		if (*str <= '9' && *str >= '0' || *str == '.') {
			str++;
			continue;
		} else {
			loge("warning: parameter '%s' is not right Decimal expression\n", opt);
			return -1;
		}
	}

	return 10;
}

uint64_t get_seconds_time(char *optbuf)
{
	uint64_t basetime, basetimel, basetimeh;
	char *pt;
	char bufs[32];

	pt = strrchr(optarg, '.');
	if (pt) {
		basetimel = strtoul(pt + 1, NULL, 10);
		strncpy(bufs, optbuf, pt - optbuf);

		basetimeh = strtoul(bufs, NULL, 10);
		while (basetimel && basetimel < 1000000000)
			basetimel *= 10;

		while (basetimel > 1000000000)
			basetimel /= 10;

		basetime = basetimeh * 1000000000 + basetimel;
	} else {
		basetime = strtoul(optbuf, NULL, 10);
	}

	return basetime;
}

static void cmd_qbvset_help(void)
{
	printf(" qbvset\n \
			--device <ifname>\n \
			--entryfile <filename>\n \
			--basetime <value> \n\
			--cycletime <value>\n  \
			--cycleextend <value>\n \
			--enable | --disable\n \
			--maxsdu <value>\n \
			--initgate <value>\n \
			--configchange\n \
			--configchangetime <value>\n \
			--help\n\n");
}

int cli_cmd_qbv_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int config_fd;
	int device = 0;
	struct stat config_stat;
	char *config = NULL, *config_m =  NULL;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];
	int ret;
	uint32_t maxsdu = 0;
	uint8_t configchange = 0;
	uint64_t basetime = 0;
	uint32_t cycletime = 0;
	uint32_t cycletimeext = 0;
	uint8_t enable = 0;
	uint8_t disable = 0;
	uint8_t initgate = 0;

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:f:hm:cb:eqy:x:", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'f':
			if (access(optarg, R_OK) != 0) {
				ERROR("setqbv", "There isn't a local file (%s).", strerror(errno));
				return -1;
			}
			config_fd = open(optarg, O_RDONLY);
			if (config_fd == -1) {
				ERROR("setqbv", "unable to open a local file (%s).", strerror(errno));
				return -1;
			}

			if (fstat(config_fd, &config_stat) != 0) {
				ERROR("setqbv", "fstat failed (%s).", strerror(errno));
				close(config_fd);
				return -1;
			}

			config_m = (char *) mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
			if (config_m == MAP_FAILED) {
				ERROR("setqbv", "mmapping of a local qbv config file failed (%s).", strerror(errno));
				close(config_fd);
				return -1;
			}

			/* make a copy of the file */
			config = strdup(config_m);

			munmap(config_m, config_stat.st_size);
			close(config_fd);

			//logv("entries setting:\n%s\n", config);

			break;
		case 'm':
			ret = is_hex_oct(optarg);
			if (ret < 0) {
				if (config != NULL)
					free(config);
				loge("maxsdu parameter error.\n");
				return -1;
			}
			maxsdu = strtoul(optarg, NULL, ret);
			break;
		case 'b':
			ret = is_hex_oct(optarg);
			if (ret < 0) {
				if (config != NULL)
					free(config);
				loge("basetime parameter error.\n");
				return -1;
			}
			if (ret == 16) {
				basetime = strtoul(optarg, NULL, ret);
			} else {
				basetime = get_seconds_time(optarg);
			}

			break;
		case 'y':
			ret = is_hex_oct(optarg);
			if (ret < 0) {
				if (config != NULL)
					free(config);
				loge("cycletime parameter error.\n");
				return -1;
			}
			cycletime = strtoul(optarg, NULL, ret);

			break;
		case 'x':
			ret = is_hex_oct(optarg);
			if (ret < 0) {
				if (config != NULL)
					free(config);
				loge("cycletimeext parameter error.\n");
				return -1;
			}
			cycletimeext = strtoul(optarg, NULL, ret);

			break;
		case 'c':
			configchange = 1;
			break;
		case 'e':
			enable = 1;
			break;
		case 'q':
			disable = 1;
			break;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0) {
				if (config != NULL)
					free(config);
				loge("initgate parameter error.\n");
				return -1;
			}
			initgate = (uint8_t)strtoul(optarg, NULL, ret);
			break;
		case 'h':
			cmd_qbvset_help();
			return 0;
		default:
			cmd_qbvset_help();
			return -1;
		}
	}

	if (enable && disable) {
		loge("--disable and --enable can't config together.\n");
		return -1;
	}

	/* if disable not set, gate list must insert */
	if (config == NULL && !disable) {
		config = readinput(qbventry_example, NULL, stdout);
		if (config == NULL) {
			ERROR("setqbv", "read entries failed.");
			return -1;
		}
	}

	if (!device) {
		loge("You must input --device <ifname>\n");
		if (config)
			free(config);
		return -1;
	}

	if (fill_qbv_set(portname, config, disable ? 0:1,
				configchange, basetime,
				cycletime, cycletimeext, maxsdu, initgate) != 0) {
		if (config)
			free(config);
		return -1;
	}

	if (config)
		free(config);

	return 0;
}

static void cmd_qbvget_help(void)
{
	printf(" qbvget --device <ifname> --help\n\n");
}

int cli_cmd_qbv_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int device = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_qbvget_help();
			return 0;
		default:
			cmd_qbvget_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		fill_qbv_get(NULL);
	} else {
		fill_qbv_get(portname);
	}

	return 0;
}

static void cmd_qcisfiset_help(void)
{
	printf(" qcisfiset\n \
			--device <ifname>\n \
			--enable | --disable\n \
			--maxsdu <value> \n \
			--flowmeterid <value>\n \
			--index <value>\n \
			--streamhandle <value> \n \
			--priority <value> \n \
			--gateid <value> \n \
			--oversizeenable \n \
			--oversize \n \
			--help\n\n");
}

int cli_cmd_qci_sfi_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint8_t enable = 0, disable = 0;
	uint32_t index = 0;
	int32_t streamhandle = -1;
	int8_t priority = -1;
	uint32_t gateid = 0;
	uint16_t maxsdu = 0;
	int32_t flowmeterid = -1;
	uint8_t osenable = 0;
	uint8_t oversize = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:eqi:s:p:g:u:f:ovh", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_qcisfiset_help();
			return 0;
		case 'e':
			enable = 1;
			break;
		case 'q':
			disable = 1;
			break;
		/* index */
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		/* streamhandle */
		case 's':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			streamhandle = (int32_t)strtol(optarg, NULL, ret);
			break;
		/* priority */
		case 'p':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			priority = (int8_t)strtol(optarg, NULL, ret);
			break;
		/* gateid */
		case 'g':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			gateid = (uint32_t)strtol(optarg, NULL, ret);
			break;
		/* maxsdu */
		case 'u':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			maxsdu = (uint16_t)strtoul(optarg, NULL, ret);
			break;
		/* flowmeterid*/
		case 'f':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			flowmeterid = (int32_t)strtol(optarg, NULL, ret);
			break;
		/* oversizeenable */
		case 'o':
			osenable = 1;
			break;
		/* oversize */
		case 'v':
			oversize = 1;
			break;
		default:
			cmd_qcisfiset_help();
			return -1;
		}
	}

	if (!device) {
		loge("You must input --device <ifname>\n");
		return -1;
	}

	if (enable && disable) {
		loge("You can't input enable disable same time");
		return -1;
	}

	if (!osenable && (oversize == 1)) {
		loge("oversize can't be set without osenable set (oversizeenable)");
		return -1;
	}

	return fill_qci_sfi_set(portname, index, enable ? 1:(disable ? 0:1),
			streamhandle, priority, gateid, maxsdu, flowmeterid, osenable, oversize);
}

static void cmd_qcisfiget_help(void)
{
	printf(" qcisfiget\n \
			--device <ifname>\n \
			--index <value>\n \
			--help\n\n");
}

int cli_cmd_qci_sfi_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	int32_t sfid = -1;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:i:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_qcisfiget_help();
			return 0;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			sfid = strtoul(optarg, NULL, ret);
			break;
		default:
			cmd_qcisfiget_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		fill_qci_sfi_get(NULL, -1);
	} else {
		fill_qci_sfi_get(portname, sfid);
	}

	return 0;
}

int cli_cmd_qci_sfi_counters_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	return 0;
}

void cmd_cbstreamidset_help(void)
{
	printf(" cbstreamidset\n \
			--enable | --disable \n \
			--index <value>\n \
			--device <string>\n \
			--streamhandle <value>\n \
			--infacoutport <value>\n \
			--outfacoutport <value>\n \
			--infacinport <value>\n \
			--outfacinport <value>\n \
			--nullstreamid | --sourcemacvid | --destmacvid | --ipstreamid\n \
			--nulldmac <value>\n \
			--nulltagged <value>\n \
			--nullvid <value>\n \
			--sourcemac <value>\n \
			--sourcetagged <value>\n \
			--sourcevid <value>\n \
			--help\n\n");
}

int cli_cmd_streamid_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint8_t enable = 0, disable = 0;
	uint32_t index = 0;
	int32_t streamhandle = -1;
	uint32_t infacoutport = 0, outfacoutport = 0, infacinport = 0, outfacinport = 0;
	uint8_t streamidtype = 0, typeflag = 0;
	uint64_t mac = 0;
	uint8_t tagged = 0;
	uint16_t vid = 0;
	struct tsn_cb_streamid streamid;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];
	char smac[6];
	int i;

	memset(&streamid, 0, sizeof(struct tsn_cb_streamid));

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:eqi:s:u:v:w:x:nftpm:g:l:h",
			 long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_cbstreamidset_help();
			return 0;
		case 'e':
			enable = 1;
			break;
		case 'q':
			disable = 1;
			break;
		/* streamid index */
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		/* streamhandle */
		case 's':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			streamhandle = (int32_t)strtol(optarg, NULL, ret);
			break;
		/* infacoutport */
		case 'u':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			infacoutport = strtol(optarg, NULL, ret);
			break;
		/* outfacoutport */
		case 'v':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			outfacoutport = strtoul(optarg, NULL, ret);
			break;
		/* infacoutport */
		case 'w':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			infacinport = strtol(optarg, NULL, ret);
			break;
		/* outfacoutport */
		case 'x':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			outfacinport = strtoul(optarg, NULL, ret);
			break;
		/* nullstreamid */
		case 'n':
			streamidtype = STREAMID_NULL;
			typeflag++;
			break;
		case 'f':
			streamidtype = STREAMID_SMAC_VLAN;
			typeflag++;
			break;
		case 't':
			streamidtype = STREAMID_DMAC_VLAN;
			typeflag++;
			break;
		case 'p':
			streamidtype = STREAMID_IP;
			typeflag++;
			break;
		/* destination mac */
		case 'm':
			ret = is_hex_oct(optarg);
			if (ret == 16) {
				mac = strtoull(optarg, NULL, ret);
			} else {
				char temp[25];
				strcpy(temp, optarg);
				sscanf(temp, "%2hx:%2hx:%2hx:%2hx:%2hx:%2hx",
						&smac[0], &smac[1], &smac[2], &smac[3], &smac[4], &smac[5]);
				mac = 0;
				for (i = 0; i < 6; i++)
					mac = (mac << 8) + smac[i];
			}
			break;
		/* tagged */
		case 'g':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			tagged = strtoul(optarg, NULL, ret);
			break;
		/* vid */
		case 'l':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			vid = strtoul(optarg, NULL, ret);
			break;
		/* source mac */
		case 'a':
			ret = is_hex_oct(optarg);
			if (ret == 16) {
				mac = strtoull(optarg, NULL, ret);
			} else {
				char temp[25];
				strcpy(temp, optarg);
				sscanf(temp, "%2hx:%2hx:%2hx:%2hx:%2hx:%2hx",
						&smac[0], &smac[1], &smac[2], &smac[3], &smac[4], &smac[5]);
				mac = 0;
				for (i = 0; i < 6; i++)
					mac = (mac << 8) + smac[i];
			}
			break;
		/* tagged */
		case 'b':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			tagged = strtoul(optarg, NULL, ret);
			break;
		/* vid */
		case 'c':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			vid = strtoul(optarg, NULL, ret);
			break;
		default:
			cmd_cbstreamidset_help();
			return -1;
		}
	}

	if (!device) {
		loge("You must input --device <ifname>\n");
		return -1;
	}

	if (enable && disable) {
		loge("You can't input enable disable same time");
		return -1;
	}

	switch (streamidtype) {
	case STREAMID_NULL:
			streamid.para.nid.dmac = mac;
			streamid.para.nid.tagged = tagged;
			streamid.para.nid.vid = vid;
			break;
	case STREAMID_SMAC_VLAN:
			streamid.para.sid.smac = mac;
			streamid.para.sid.tagged = tagged;
			streamid.para.sid.vid = vid;
			break;
	case STREAMID_DMAC_VLAN:

	case STREAMID_IP:
	default:
		loge("Type do not supported!");
		if (enable)
			return -1;
	}

	streamid.handle = streamhandle;
	streamid.ifac_oport = infacoutport;
	streamid.ofac_oport = outfacoutport;
	streamid.ifac_iport = infacinport;
	streamid.ofac_iport = outfacinport;
	streamid.type = streamidtype;

	return fill_cb_streamid_set(portname, index, enable ? 1:(disable ? 0:1), &streamid);
}

void cmd_cbstreamidget_help(void)
{
	printf(" cbstreamidget\n \
			--device <ifname>\n \
			--index <value>\n \
			--help\n\n");
}

int cli_cmd_streamid_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	int32_t index = -1;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:i:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_cbstreamidget_help();
			return 0;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = (int32_t)strtol(optarg, NULL, ret);
			break;
		default:
			cmd_cbstreamidget_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		fill_cbstreamid_get(NULL, -1);
	} else {
		fill_cbstreamid_get(portname, (int32_t)index);
	}

	return 0;
}

void cmd_qcisgiset_help(void)
{
	printf(" qcisgiset\n \
			--device <ifname>\n \
			--index <value>\n \
			--enable | --disable\n \
			--configchange\n \
			--enblkinvrx\n \
			--blkinvrx\n \
			--initgate\n \
			--initipv\n \
			--cycletime\n \
			--cycletimeext\n \
			--basetime\n \
			--gatelistfile\n \
			--help\n\n");
}

int cli_cmd_qci_sgi_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	struct stat config_stat;
	int config_fd;
	char *listtable = NULL, *config_m;
	bool enable = 0, disable = 0;
	bool configchange = 0, blkinvrx_en = 0, blkinvrx = 0, blkoctex_en = 0, blkoctex = 0;
	bool initgate = 0;
	int8_t initipv = -1;
	uint32_t cycletime = 0, cycletimeext = 0;
	uint64_t basetime = 0;
	uint32_t index = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:eqi:cvroxt:y:a:b:p:f:h",
			 long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_qcisgiset_help();
			return 0;
		case 'e':
			enable = 1;
			break;
		case 'q':
			disable = 1;
			break;
		/* stream gate index */
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		case 'c':
			configchange = 1;
			break;
		case 'v':
			blkinvrx_en = 1;
			break;
		case 'r':
			blkinvrx = 1;
			break;
		case 'o':
			blkoctex_en = 1;
			break;
		case 'x':
			blkoctex = 1;
			break;
		case 't':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			initgate = strtoul(optarg, NULL, ret) ? 1:0;
			break;
		case 'y':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			cycletime = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		case 'a':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			cycletimeext = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		case 'b':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;

			if (ret == 16) {
				basetime = strtoul(optarg, NULL, ret);
			} else {
				basetime = get_seconds_time(optarg);
			}

			break;
		case 'p':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			initipv = (int8_t)strtol(optarg, NULL, ret);
			break;
		case 'f':
			if (access(optarg, R_OK) != 0) {
				ERROR("setqcisgi", "There isn't a local file (%s).", strerror(errno));
				return -1;
			}
			config_fd = open(optarg, O_RDONLY);
			if (config_fd == -1) {
				ERROR("setqcisgi", "unable to open a local file (%s).", strerror(errno));
				return -1;
			}

			if (fstat(config_fd, &config_stat) != 0) {
				ERROR("setqcisgi", "fstat failed (%s).", strerror(errno));
				close(config_fd);
				return -1;
			}

			config_m = (char *) mmap(NULL, config_stat.st_size, PROT_READ, MAP_PRIVATE, config_fd, 0);
			if (config_m == MAP_FAILED) {
				ERROR("setqcisgi", "mmapping of a local qbv config file failed (%s).", strerror(errno));
				close(config_fd);
				return -1;
			}

			/* make a copy of the file */
			listtable = strdup(config_m);

			munmap(config_m, config_stat.st_size);
			close(config_fd);

			//logv("entries setting:\n%s\n", listtable);
			break;
		default:
			cmd_qcisgiset_help();
			break;
		}
	}

	if (enable && disable) {
		loge("--disable and --enable can't config together.\n");
		return -1;
	}

	/* if disable not set, gate list must insert */
	if (listtable == NULL && !disable) {
		char ch;

		printf("No --gatelistfile, Do you want to edit list file(Y/N)N? ");
		ch = getchar();
		printf("\n Gate list length would be 0.\n\n", ch);
		if ((ch == 'Y') || (ch == 'y')) {
			listtable = readinput(sglentry_example, NULL, stdout);
			if (listtable == NULL) {
				ERROR("setqcisgi", "read entries failed.");
				return -1;
			}
		}
	}

	if (!device) {
		loge("You must input --device <ifname>\n");
		if (listtable != NULL)
			free(listtable);
		return -1;
	}

	if (!fill_qci_sgi_set(portname, index, disable ? 0:1, listtable,
				configchange, blkinvrx_en, blkinvrx, blkoctex_en, blkoctex,
				initgate, initipv, basetime, cycletime, cycletimeext))
		goto err;

	if (listtable != NULL)
		free(listtable);

	return 0;

err:
	if (listtable != NULL)
		free(listtable);

	return -1;
}

void cmd_qcisgiget_help(void)
{
	printf("qcisgiget\n \
			--device <ifname>\n \
			--index <value>\n \
			--help\n\n");
}

int cli_cmd_qci_sgi_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint32_t index = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:i:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_qcisgiget_help();
			return 0;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		default:
			cmd_qcisgiget_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
	} else {
		fill_qci_sgi_status_get(portname, index);
	}

	return 0;
}


void cmd_qcifmiset_help(void)
{
	printf("qcifmiset\n \
			--device <ifname>\n \
			--index <value>\n \
			--disable\n \
			--cir <value>\n \
			--cbs <value>\n \
			--eir <value>\n \
			--ebs <value>\n \
			--cf\n \
			--cm\n \
			--dropyellow\n \
			--markred_enable\n \
			--markred\n \
			--help\n\n");
}

int cli_cmd_qci_fmi_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint32_t index = 0;
	uint32_t cir = 0, cbs = 0, eir = 0, ebs = 0;
	uint32_t cirflag = 0, cbsflag = 0, eirflag = 0, ebsflag = 0;
	bool cf = 0, cm = 0, dropyellow = 0, markred_en = 0, markred = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];
	bool disable = 0;

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:qi:c:b:e:s:fmyakh",
			 long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_qcifmiset_help();
			return 0;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = strtoul(optarg, NULL, ret);
			break;
		case 'q':
			disable = 1;
			break;
		case 'c':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			cir = strtoul(optarg, NULL, ret);
			cirflag = 1;
			break;
		case 'b':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			cbs = strtoul(optarg, NULL, ret);
			cbsflag = 1;
			break;
		case 'e':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			eir = strtoul(optarg, NULL, ret);
			eirflag = 1;
			break;
		case 's':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			ebs = strtoul(optarg, NULL, ret);
			ebsflag = 1;
			break;
		case 'f':
			cf = 1;
			break;
		case 'm':
			cm = 1;
			break;
		case 'y':
			dropyellow = 1;
			break;
		case 'a':
			markred_en = 1;
			break;
		case 'k':
			markred = 1;
			break;
		default:
			cmd_qcifmiset_help();
			return -1;
		}
	}

	if (!device) {
		loge("No --device not supported\n");
		return -1;
	} else
		return fill_qci_fmi_set(portname, index, disable ? 0:1,
				cirflag ? cir:0xffffffff, cbsflag ? cbs:0xffffffff,
				eirflag ? eir:0xffffffff, ebsflag ? ebs:0xffffffff,
				cf, cm, dropyellow, markred_en, markred);
}

void cmd_qcifmiget_help(void)
{
	printf("qcifmiget\n \
			--device <ifname>\n \
			--index <value>\n \
			--help\n\n");
}

int cli_cmd_qci_fmi_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint32_t index = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:i:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_qcifmiget_help();
			return 0;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = strtoul(optarg, NULL, ret);
			break;
		default:
			cmd_qcifmiget_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
	} else {
		fill_qci_fmi_get(portname, index);
	}

	return 0;
}

void cmd_cbs_set_help(void)
{
	printf("cbsset\n \
			--device <ifname>\n \
			--tc <value>\n \
			--percentage <value>\n \
			--all <tc-percent:tc-percent...>\n \
			--help\n\n");
}

static int get_tc_percent(char **s, uint8_t *tc, uint8_t *p)
{
	char sbuf[16];
	char *end, *begin = *s;
	int len;
	int ret;
	*s = NULL;
	end = strchr(begin, '-');
	if (!end)
		return -1;
	len = end - begin;
	memcpy(sbuf, begin, len);
	sbuf[len] = '\0';
	ret = is_hex_oct(sbuf);
	if (ret < 0)
		return -1;
	*tc = (uint8_t)strtoul(sbuf, NULL, ret);

	begin = end + 1;
	end = strchr(begin, ':');

	if (!end) {
		len = strlen(begin);
	} else {
		len = end - begin;
	}

	memcpy(sbuf, begin, len);
	sbuf[len] = '\0';
	ret = is_hex_oct(sbuf);
	if (ret < 0)
		return -1;
	*p = (uint8_t)strtoul(sbuf, NULL, ret);
	*s = end ? NULL : end + 1;
	*s = **s == '\0' ? NULL : *s;
	return 0;

}

int cli_cmd_cbs_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	bool opt_t = 0, opt_p = 0;
	char *optarg_a = NULL;
	uint8_t tc = 0;
	uint8_t percentage = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:t:p:a:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_cbs_set_help();
			return 0;
		case 't':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			tc = (uint8_t)strtoul(optarg, NULL, ret);
			opt_t = 1;
			break;
		case 'p':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			percentage = (uint8_t)strtoul(optarg, NULL, ret);
			opt_p = 1;
			break;
		case 'a':
			optarg_a = optarg;
			break;

		default:
			cmd_cbs_set_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
		return -1;
	}

	if (opt_t ^ opt_p) {
		loge("Please specify the tc and percentage concurrently\n");
		return -1;

	}

	if (opt_t == 0 && opt_t == 0 && optarg_a == NULL) {
		loge("Please specify parameters by -t or -a\n");
		return -1;

	}

	if (opt_t | opt_p)
		fill_cbs_set(portname, tc, percentage);

	while (optarg_a) {
		if (get_tc_percent(&optarg_a, &tc, &percentage) < 0) {
			loge("Please check the parameter of -a\n");
			return -1;
		}
		fill_cbs_set(portname, tc, percentage);
	}

	return 0;
}

void cmd_cbs_get_help(void)
{
	printf("cbsget\n \
			--device <ifname>\n \
			--tc <value>\n \
			--help\n\n");
}

int cli_cmd_cbs_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint8_t tc = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:i:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_cbs_get_help();
			return 0;
		case 't':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			tc = (uint8_t)strtoul(optarg, NULL, ret);
			break;
		default:
			cmd_cbs_get_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
	} else {
		fill_cbs_get(portname, tc);
	}

	return 0;
}

void cmd_tsd_set_help(void)
{
	printf("tsdset\n \
			--device <ifname>\n \
			--period <value>\n \
			--enable \n \
			--disable \n \
			--frame_num <value>\n \
			--immediate \n \
			--help\n\n");
}
int cli_cmd_tsd_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	bool enable = TRUE;
	uint32_t period = 0, frame_num = 0;
	bool imme = FALSE;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:p:f:ieqh", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_tsd_set_help();
			return 0;
		case 'p':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			period = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		case 'n':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			frame_num = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		case 'e':
			enable = TRUE;
			break;
		case 'i':
			imme = TRUE;
			break;
		case 'q':
			enable = FALSE;
			break;

		default:
			cmd_tsd_set_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
		return -1;
	}

	if (enable && period == 0) {
		loge("The period must greater than 0\n");
		return -1;
	}

	fill_tsd_set(portname, enable, period, frame_num, imme);
	return 0;
}


void cmd_tsd_get_help(void)
{
	printf("tsdget\n \
			--device <ifname>\n \
			--help\n\n");
}

int cli_cmd_tsd_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_tsd_get_help();
			return 0;
		default:
			cmd_tsd_get_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
	} else {
		fill_tsd_get(portname);
	}

	return 0;
}

void cmd_qbuset_help(void)
{
	printf("cbsqueueget\n \
			--device <ifname>\n \
			--preemptable <value>\n \
			--help\n\n");
}

int cli_cmd_qbu_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint8_t preemptable = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:p:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_qbuset_help();
			return 0;
		case 'p':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			preemptable = (uint8_t)strtoul(optarg, NULL, ret);
			break;
		default:
			cmd_qbuset_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
	} else {
		fill_qbu_set(portname, preemptable);
	}

	return 0;
}

void cmd_qbugetstatus_help(void)
{
	printf("cbsqueueget\n \
			--device <ifname>\n \
			--preemptable <value>\n \
			--help\n\n");
}

int cli_cmd_qbu_get_status(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int device = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:p:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_qbugetstatus_help();
			return 0;
		default:
			cmd_qbugetstatus_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
	} else {
		fill_qbu_get_status(portname);
	}

	return 0;
}

void cmd_sendip_help(void)
{
	printf("sendpkt\n \
			--device <ifname>\n \
			--length <value>\n \
			--timeint <value>\n \
			--loopcount <value> \n \
			--smac <mac addr> \n \
			--help\n\n");

}

int cli_sendip(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int device = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];
	char smac[10];
	unsigned char mac[6];
	unsigned int length = 0;
	unsigned int timeint = 0;
	unsigned int loopcount = 1;

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:l:t:c:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'l':
			length = strtoul(optarg, NULL, 0);
			break;
		case 't':
			timeint = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			loopcount = strtoul(optarg, NULL, 0);
			break;
		case 's':
			strcpy(smac, optarg);
			logv("source mac is %s\n", smac);
			sscanf(smac, "%d:%d:%d:%d:%d:%d", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
			break;
		case 'h':
			cmd_sendip_help();
			return 0;
		default:
			cmd_sendip_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
	}

	pid_t pid = fork();
	int stat = 0;

	switch (pid) {
	case -1:
		perror("fork failed");
		return 0;
	case 0:
		printf("\n");
		char str[10];

		sprintf(str, "%d", length);
		printf("length is %d\n", length);
		execlp("./sendpkt", "./sendpkt", " -i ", portname, " -l ", str, " -m ", smac, (char *)0);
		printf("sendpkt error\n");
		exit(0);
	default:
		//pid = wait(&stat);
		printf("Sendip SEND LEN length:%d PID = %d\n", length, pid);
		if (WIFEXITED(stat))
			printf("Child exited with code %d\n", WEXITSTATUS(stat));
		else
			printf("Child still running\n");
		printf("Parent, sendip running\n");
		break;
	}
	return 0;
}

int cli_regtool(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int fd;
	void *map_base, *virt_addr;
	uint32_t read_result, writeval;
	char filename[100];
	off_t target;
	int access_type = 'w';
	int pf_num = 0;

	if (argc < 3) {
		// pcimem /sys/bus/pci/devices/0001\:00\:07.0/resource0 0x100 w 0x00
		// // argv[0]  [1]                                         [2]   [3] [4]
		fprintf(stderr, "\nUsage:\t%s { pf number } { offset } [ data ]\n"
				"\tpf number: pf number for the pci resource to act on\n"
				"\toffset  : offset into pci memory region to act upon\n"
				"\tdata    : data to be written\n\n",
				argv[0]);
		return 0;
	}

	pf_num = strtoul(argv[1], 0, 0);
	if (pf_num > 6) {
		fprintf(stderr, "pf number to big\n");
		return 0;
	}
	sprintf(filename, "/sys/bus/pci/devices/0000:00:00.%d/resource0", pf_num);
	target = strtoul(argv[2], 0, 0);

	fd = open(filename, O_RDWR | O_SYNC);
	if (fd  == -1) {
		printf("%s\n", filename);
		PRINT_ERROR;
	}
	fflush(stdout);

	/* Map one page */
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (target & ~MAP_MASK));
	if (map_base == (void *) -1) {
		printf("PCI Memory mapped ERROR.\n");
		PRINT_ERROR;
		close(fd);
		return 1;
	}

	printf("mmap(%d, %ld, 0x%x, 0x%x, %d, 0x%x)\n", 0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (int) (target & ~MAP_MASK));
	fflush(stdout);

	virt_addr = map_base + (target & MAP_MASK);
	printf("PCI Memory mapped access 0x %08X.\n", (uint32_t) virt_addr);
	switch (access_type) {
	case 'b':
		read_result = *((uint8_t *) virt_addr);
		break;
	case 'h':
		read_result = *((uint16_t *) virt_addr);
		break;
	case 'w':
		read_result = *((uint32_t *) virt_addr);
		printf("READ Value at offset 0x%X (%p): 0x%X\n", (int) target, virt_addr, read_result);
		break;
	default:
		fprintf(stderr, "Illegal data type '%c'.\n", access_type);
		return -1;
	}
	fflush(stdout);

	if (argc > 3) {
		writeval = strtoul(argv[3], 0, 0);
		switch (access_type) {
		case 'b':
			*((uint8_t *) virt_addr) = writeval;
			read_result = *((uint8_t *) virt_addr);
			break;
		case 'h':
			*((uint16_t *) virt_addr) = writeval;
			read_result = *((uint16_t *) virt_addr);
			break;
		case 'w':
			*((uint32_t *) virt_addr) = writeval;
			read_result = *((uint32_t *) virt_addr);
		break;
		}
		printf("Written 0x%X; readback 0x%X\n", writeval, read_result);
		fflush(stdout);
	}

	if (munmap(map_base, MAP_SIZE) == -1)
		PRINT_ERROR;
	close(fd);
	return 0;
}

int cli_ptptool(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	return testptp(argc, argv);
}

void cmd_ctset_help(void)
{
	printf("cut through set\n \
			--device <ifname>\n \
			--queue_stat <value>\n \
			--help\n\n");
}

int cli_cmd_ct_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint8_t queue_stat = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:h:q", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_ctset_help();
			return 0;
		case 'q':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			queue_stat = (uint8_t)strtoul(optarg, NULL, ret);
			break;
		default:
			cmd_ctset_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with ct capability */
		loge("No --device not supported\n");
	} else {
		fill_ct_set(portname, queue_stat);
	}

	return 0;
}

void cmd_cbgenset_help(void)
{
	printf("802.1cb generate set\n \
			--device <ifname>\n \
			--index <value>\n \
			--iport_mask <value>\n \
			--split_mask <value>\n \
			--seq_len <value>\n \
			--seq_num <value>\n \
			--help\n\n");
}

int cli_cmd_cbgen_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint32_t index = 0;
	uint8_t iport_mask = 0;
	uint8_t split_mask = 0;
	uint8_t seq_len = 0;
	uint32_t seq_num = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:h:i:p:s:l:n", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_cbgenset_help();
			return 0;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		case 'p':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				 return -1;
			iport_mask = (uint8_t)strtoul(optarg, NULL, ret);
			break;
		case 's':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				 return -1;
			split_mask = (uint8_t)strtoul(optarg, NULL, ret);
			break;
		case 'l':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				 return -1;
			seq_len = (uint8_t)strtoul(optarg, NULL, ret);
			break;
		case 'n':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				 return -1;
			seq_num = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		default:
			cmd_cbgenset_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with ct capability */
		loge("No --device not supported\n");
	} else {
		fill_cbgen_set(portname, index, iport_mask,
			       split_mask, seq_len, seq_num);
	}

	return 0;
}

void cmd_cbrecset_help(void)
{
	printf("802.1cb recover set\n \
			--device <ifname>\n \
			--index <value>\n \
			--seq_len <value>\n \
			--his_len <value>\n \
			--rtag_pop_en\n \
			--help\n\n");
}

int cli_cmd_cbrec_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	uint32_t index = 0;
	uint8_t seq_len = 0;
	uint8_t his_len = 0;
	bool rtag_pop_en = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:h:i:l:s:r", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_cbrecset_help();
			return 0;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		case 'l':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				 return -1;
			seq_len = (uint8_t)strtoul(optarg, NULL, ret);
			break;
		case 's':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				 return -1;
			his_len = (uint8_t)strtoul(optarg, NULL, ret);
			break;
		case 'r':
			rtag_pop_en = 1;
			break;
		default:
			cmd_cbrecset_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with ct capability */
		loge("No --device not supported\n");
	} else {
		fill_cbrec_set(portname, index, seq_len,
			       his_len, rtag_pop_en);
	}

	return 0;
}

void cmd_cbget_help(void)
{
	printf("802.1cb status get\n \
			--device <ifname>\n \
			--index <value>\n \
			--help\n\n");
}

int cli_cmd_cbstatus_get(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c, index, ret;
	int device = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:i:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = strtoul(optarg, NULL, ret);
			break;
		case 'h':
			cmd_cbget_help();
			return 0;
		default:
			cmd_cbget_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with qbv capability */
		loge("No --device not supported\n");
	} else {
		fill_cbstatus_get(portname, index);
	}

	return 0;
}

void cmd_pcpmap_help(void)
{
	printf("Mapping PCP tags to queue number\n \
			--device <ifname>\n \
			--enable\n \
			--help\n\n");
}

int cli_cmd_pcpmap_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int device = 0;
	bool enable = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:h:e", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_pcpmap_help();
			return 0;
		case 'e':
			enable = 1;
			break;
		default:
			cmd_pcpmap_help();
			return -1;
		}
	}

	if (!device) {
		/* Get all the devices with ct capability */
		loge("No --device not supported\n");
	} else {
		fill_pcpmap_set(portname, enable);
	}

	return 0;
}

void cmd_dscpset_help(void)
{
	printf("Mapping DSCP value to queue number and dpl\n \
			--device <ifname>\n \
			--disable\n \
			--index\n \
			--cos\n \
			--dpl\n \
			--help\n\n");
}

int cli_cmd_dscp_set(UNUSED int argc, UNUSED char *argv[], UNUSED int cmdnumber)
{
	int c;
	int ret;
	int device = 0;
	int index = 0;
	int cos = 0;
	int dpl = 0;
	bool disable = 0;
	struct option *long_options = &cli_commands[cmdnumber].long_options[0];
	int option_index = 0;
	char portname[IF_NAMESIZE];

	optind = 0;

	while ((c = getopt_long(argc, argv, "d:u:i:c:p", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			strcpy(portname, optarg);
			logv("device is %s\n", portname);
			device = 1;
			break;
		case 'h':
			cmd_pcpmap_help();
			return 0;
		case 'u':
			disable = 1;
			break;
		case 'i':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			index = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		case 'c':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			cos = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		case 'p':
			ret = is_hex_oct(optarg);
			if (ret < 0)
				return -1;
			dpl = (uint32_t)strtoul(optarg, NULL, ret);
			break;
		default:
			cmd_dscpset_help();
			return -1;
		}
	}
	if (!device) {
		/* Get all the devices with ct capability */
		loge("No --device not supported\n");
	} else {
		fill_dscp_set(portname, disable, index, cos, dpl);
	}

	return 0;
}

