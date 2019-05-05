// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2019 NXP
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/ptp_clock.h>

#define DEVICE "/dev/ptp0"
#define SOURCED "eno0"

#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

#include "tsn/genl_tsn.h"

struct info_type namelist[] = {
	[TSN_MCGRP_QBV] = {.name = "qbv"},
	[TSN_MCGRP_QCI] = {.name = "qci"},
};

struct alarm_info alarminfo;
static int testmode = 0;

static void handle_alarm_qbv(int *s)
{
	struct timespec ts;

	if (clock_gettime(alarminfo.clkid, &ts)) {
		perror("clock_gettime");
	} else {
		printf("qbv clock time: %ld.%09ld or %s",
		ts.tv_sec, ts.tv_nsec, ctime(&ts.tv_sec));
	}

	printf("received qbv signal %d\n", *s);
}

static void handle_alarm_qci(int *s)
{
	struct timespec ts;

	if (clock_gettime(alarminfo.clkid, &ts)) {
		perror("clock_gettime");
	} else {
		printf("qci clock time: %ld.%09ld or %s",
		ts.tv_sec, ts.tv_nsec, ctime(&ts.tv_sec));
	}

	printf("received qci signal %d\n", *s);
}

static void usage(char *progname)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		" -d name    device to open\n"
		" -t         testmode\n"
		" -h         prints this message\n",
		progname);
}

int parse_args(int argc, char *argv[])
{
	char *progname;
	char *device = DEVICE;
	int c;

	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv, "d:t:h"))) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 't':
			testmode = atoi(optarg);
			printf("testmode is %d\n", testmode);
			if (testmode != 1 || testmode != 2)
				return -1;
			printf("ok\n");
			break;
		case 'h':
			usage(progname);
			return 0;
		case '?':
		default:
			usage(progname);
			return -1;
		}
	}

	memset(&alarminfo, 0, sizeof(alarminfo));

	strcpy(alarminfo.ptpdev, device);

	alarminfo.clkid = CLOCK_REALTIME;

	return 0;
}

void die(char * s)
{
    perror(s);
    exit(1);
}

void main(int argc, char *argv[])
{
	struct timespec ts;
	uint64_t nowns;
	int a = 1, b = 2;
	pthread_t *th = NULL;

	parse_args(argc, argv);

	if (clock_gettime(alarminfo.clkid, &ts)) {
		perror("clock_gettime");
	} else {
		printf("clock time: %ld.%09ld or %s",
		ts.tv_sec, ts.tv_nsec, ctime(&ts.tv_sec));
	}

	/* create a blocking timer */
	if (testmode == 1) {
		nowns = pctns(&ts);
		set_period_alarm(nowns, 0, 2000000000ULL, handle_alarm_qbv, &a);
	}

	/* create a non-block timer */
	if (testmode == 2) {
		nowns = pctns(&ts);
		th = create_alarm_common(nowns, 0, 2000000000ULL, handle_alarm_qci, &b);
	}

	alarminfo.qbvmc.callback_func = handle_alarm_qbv;
	alarminfo.qbvmc.data = &a;
	alarminfo.qcimc.callback_func = handle_alarm_qci;
	alarminfo.qcimc.data = &b;

	wait_tsn_multicast(&alarminfo);

	if (th) {
		delete_alarm_common(th);
	}
}
