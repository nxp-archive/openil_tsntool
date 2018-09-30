// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018-2019 NXP
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/ptp_clock.h>

#define DEVICE "/dev/ptp0"

static void usage(char *pid)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		" -d name    ptp device name\n"
		" -g         get ptp time\n"
		" -h         prints help\n",
		pid);
}

int testptp(int argc, char *argv[])
{
	struct timespec ts;

	char *pname;
	int c, cnt, fd;

	char *device = DEVICE;
	clockid_t clkid;

	optind = 0;
	optarg = EOF;

	pname = strrchr(argv[0], '/');

	pname = pname ? 1 + pname : argv[0];

	while (EOF != (c = getopt(argc, argv, "d:gh"))) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 'g':
			break;
		case 'h':
			usage(pname);
			return 0;
		case '?':
		default:
			usage(pname);
			return -1;
		}
	}
	optind = 0;
	optarg = EOF;

	fd = open(device, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "ptpname %s: %s\n", device, strerror(errno));
		return -1;
	}

	clkid = (~(clockid_t) (fd) << 3) | 3;
	if (clkid == -1) {
		fprintf(stderr, "failed to get clock id\n");
		return -1;
	}

	if (clock_gettime(clkid, &ts))
		printf("clock_gettime error\n");
	else
		printf("ptp time: %ld.%09ld\n", ts.tv_sec, ts.tv_nsec);


	close(fd);
	return 0;
}
