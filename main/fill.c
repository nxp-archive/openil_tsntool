// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018-2019 NXP
 */

#include<stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctype.h>
#include <string.h>

#include "tsn/genl_tsn.h"
#include "main.h"
#include "fill.h"
int validate_ifname(char *ifname)
{
	int sockfd;
	int i;
	struct ifconf ifconf;
	struct ifreq *ifreq;
	char buf[512];

	/* init ifconf */
	ifconf.ifc_len = 512;
	ifconf.ifc_buf = buf;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		loge("socket");
		return -1;
	}

	/* get all interfaces info */
	ioctl(sockfd, SIOCGIFCONF, &ifconf);

	ifreq = (struct ifreq *)ifconf.ifc_buf;

	for (i = ifconf.ifc_len/sizeof(struct ifreq); i > 0; i--) {
		/* for ipv4 */
		if (ifreq->ifr_flags == AF_INET) {
			if (strcmp(ifname, ifreq->ifr_name) == 0) {
				close(sockfd);
				return 0;
			}
		}
		ifreq++;
	}

	close(sockfd);
	return -1;
}

int get_all_ifname(char *ifnames)
{
	int sockfd;
	int i, count = 0;
	struct ifconf ifconf;
	struct ifreq *ifreq;
	char buf[512];

	/* init ifconf */
	ifconf.ifc_len = 512;
	ifconf.ifc_buf = buf;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		loge("socket");
		return -1;
	}

	/* get all interfaces info */
	ioctl(sockfd, SIOCGIFCONF, &ifconf);

	ifreq = (struct ifreq *)ifconf.ifc_buf;
	count = ifconf.ifc_len/sizeof(struct ifreq);
	for (i = 0; i < count; i++) {
		/* for ipv4 */
		if (ifreq->ifr_flags == AF_INET)
			strcpy(ifnames + i * IF_NAMESIZE, ifreq->ifr_name);
		ifreq++;
	}

	close(sockfd);

	return count;
}

/* Judge the portname is switch or not
 * char *portname: the input --device <ifname>
 * return :
 *	0 : not a switch
 *	>0 : yes, it is a switch, return switch port number, from 1 to MAXPORTS.
 */
uint8_t is_switch(char *portname)
{
	int i = 0;
	uint8_t p;

	if ((portname[0] != 's') || (portname[1] != 'w') || (portname[3] != 'p')) {
		logv("%s is not a switch\n", portname);
		return 0;
	}

	if ((portname[2] > ('0' + SWITCH_NUMBER)) || (portname[2] < '1')) {
		logv("%s : switch number is out of range\n", portname);
		return 0;
	}

	while (portname[4 + i]) {
		if (isdigit(portname[4 + i])) {
			i++;
			continue;
		}
		logv("%s: device name is not valid digital port number\n", portname);
		return 0;
	}

	p = atoi(portname + 4);
	if (!p || (p > SWITCH_PORTS_NUMBER)) {
		logv("%s: port number %d is out of range 1 to %d\n", portname, atoi(portname+4), SWITCH_PORTS_NUMBER);
		return 0;
	}

	return(p);
}

int qbv_str2gate(char *state)
{
	int i;
	int gate = 0;

	for (i = 0; i < 8; i++) {
		if ((*(state + i) != '0') && (*(state + i) != '1')) {
			printf("no gate[%i] value, less than 8 gates\n", i);
			return -1;
		}

		if (state[i] == '1')
			gate += (1 << (7 - i));
	}

	if ((*(state + 8) == '0') || (*(state + 8) == '1')) {
		printf("gate width larger then 8\n");
		return -1;
	}

	return gate;
}

void qbv_fill_one_entry(struct tsn_qbv_entry *conf, uint32_t num, uint8_t gate, uint32_t period)
{
	(conf + num)->gate_state = gate;
	(conf + num)->time_interval = period;

	logv("---(conf + %d) = %p, ->gce.gate_state = %02x, ->gce.time_interval = %d\n", num,
				(conf + num), (conf + num)->gate_state, (conf + num)->time_interval);
}

int qbv_entry_parse(char *config, struct tsn_qbv_entry *conf, uint32_t *count, uint32_t *cycletime)
{
	char *delim = "\n";
	char *pch;
	uint32_t number;
	char state[10], st[10];
	uint32_t time;
	int gate;

	*count = 0;

	pch = strtok(config, delim);

	while (pch != NULL) {

		while ((*pch == ' ') || (*pch == '\t'))
			pch++;

		if (*pch == '#') {
			pch = strtok(NULL, delim);
			continue;
		}

		if ((*pch == 'T') || (*pch == 't')) {
			sscanf((pch + 1), "%d %s %d", &number, st, &time);

			logv("qbv entry: number: %d		state: %s		time: %d", number, st, time);

			if (number < *count) {
				loge("ERROR: Duplicate number.\n");
				return -1;
			}

			if (number >= MAX_ENTRY_NUMBER) {
				loge("ERROR: larger than max entry number");
				return -1;
			}

			if (!time) {
				logv("WARNING: time period should not be zero.\n");
				pch = strtok(NULL, delim);
				continue;
			}

			sscanf(st, "%[0-1]", state);

			gate = qbv_str2gate(state);
			if (gate < 0) {
				loge("gate value is not valid for entry number T%d.\n", number);
				return -1;
			}

			qbv_fill_one_entry(conf, number, (uint8_t)gate, time);

			(*cycletime) += time;
			(*count)++;
		}

		pch = strtok(NULL, delim);
	}

	return 0;
}

int fill_qbv_set(char *portname, char *config, bool enable, uint8_t configchange,
		uint64_t basetime, uint32_t cycletime,
		uint32_t cycletimeext, uint32_t maxsdu, uint8_t initgate)
{
	int dev_type;
	int sw_number;
	uint32_t count = 0;
	struct tsn_qbv_entry *conf = NULL;
	struct tsn_qbv_conf adminconf;
	int ret;

	if (portname == NULL) {
		loge("--device could not be NULL.\n");
		return -1;
	}

	if (enable && (config == NULL)) {
		loge("--entryfile could not be NULL if not set --disable.\n");
		return -1;
	}

	memset(&adminconf, 0, sizeof(struct tsn_qbv_conf));
	if (enable)
		adminconf.gate_enabled = 1;
	else
		goto qbvset;

	adminconf.admin.gate_states = initgate;
	adminconf.admin.cycle_time = cycletime;
	adminconf.admin.cycle_time_extension = cycletimeext;
	adminconf.admin.base_time = basetime;
	adminconf.config_change = configchange;
	adminconf.maxsdu = maxsdu;

	sw_number = is_switch(portname);
	if (sw_number) {
		logv("switch port number is %d\n", sw_number);
		dev_type = OPT_TYPE_SWITCH;
	} else {
		dev_type = OPT_TYPE_TSN;
	}
/*
	if ((dev_type == OPT_TYPE_TSN) && validate_ifname(portname)) {
		loge("device name is not valid.\n");
		return -1;
	}
*/
	/* malloc space for filling the entry variable */
	conf = (struct tsn_qbv_entry *)malloc(MAX_ENTRY_SIZE);
	if (conf == NULL) {
		loge("malloc space error.\n");
		return -1;
	}

	memset(conf, 0, MAX_ENTRY_SIZE);

	ret  = qbv_entry_parse(config, conf, &count, &cycletime);
	if (ret < 0) {
		free(conf);
		return -1;
	}

	adminconf.admin.cycle_time = cycletime;
	adminconf.admin.control_list = conf;
	adminconf.admin.control_list_length = count;

qbvset:
	/* If the port is tsn */
	ret = tsn_qos_port_qbv_set(portname, &adminconf, enable);
	if (conf != NULL)
		free(conf);

	if (ret < 0)
		return ret;

	return 0;
}

int fill_qbv_get(char *portname)
{
	int dev_type;
	int sw_number;
	//uint32_t count = 0;
	struct tsn_qbv_entry *conf, *status;
	struct tsn_qbv_conf qbvconf;
	struct tsn_qbv_status qbvstatus;
	int ret = 0;

	if (portname == NULL) {
		loge("no portname\n");
		return -1;
	}

	/* malloc space for filling the entry variable */
	conf = (struct tsn_qbv_entry *)malloc(MAX_ENTRY_SIZE);
	if (conf == NULL) {
		loge("malloc space error.\n");
		return -1;
	}

	status = (struct tsn_qbv_entry *)malloc(MAX_ENTRY_SIZE);
	if (status == NULL) {
		loge("malloc space error.\n");
		return -1;
	}

	memset(conf, 0, MAX_ENTRY_SIZE);
	memset(status, 0, MAX_ENTRY_SIZE);
	memset(&qbvconf, 0, sizeof(struct tsn_qbv_conf));
	memset(&qbvstatus, 0, sizeof(struct tsn_qbv_status));

	//count = MAX_ENTRY_SIZE / sizeof(struct tsn_qbv_entry);

	sw_number = is_switch(portname);
	if (sw_number) {
		logv("switch port number is %d\n", sw_number);
		dev_type = OPT_TYPE_SWITCH;
	} else {
		dev_type = OPT_TYPE_TSN;
	}
/*
	if ((dev_type == OPT_TYPE_TSN) && validate_ifname(portname)) {
		loge("device name is not valid.\n");
		goto err;
	}
*/
#if 0
	ret = tsn_qos_port_qbv_get(portname, &qbvconf);
	if (ret < 0) {
		loge("got error in tsn_qos_port_qbv_get");
		goto err;
	}
#endif
	ret = tsn_qos_port_qbv_status_get(portname, &qbvstatus);

	/* TODO: show qbvconf qbvstatus data */
err:
	free(conf);
	free(status);
	return ret;
}

int fill_qci_sfi_set(char *portname, uint32_t streamfilterid, uint8_t enable,
			int32_t streamhandle, int8_t priority, uint32_t gateid,
			uint16_t maxsdu, int32_t flowmeterid, uint8_t osenable, uint8_t oversize)
{
	struct tsn_qci_psfp_sfi_conf sficonf;

	if (portname == NULL) {
		loge("--device could not be NULL.\n");
		return -1;
	}

	memset(&sficonf, 0, sizeof(struct tsn_qci_psfp_sfi_conf));

	sficonf.stream_handle_spec = streamhandle;
	sficonf.priority_spec = priority;
	sficonf.stream_gate_instance_id = gateid;
	sficonf.stream_filter.maximum_sdu_size = maxsdu;
	sficonf.stream_filter.flow_meter_instance_id = flowmeterid;
	sficonf.block_oversize_enable = osenable;
	sficonf.block_oversize = oversize;

	return tsn_qci_psfp_sfi_set(portname, streamfilterid, enable, &sficonf);
}

int fill_qci_sfi_get(char *portname, int32_t streamfilter)
{
	struct tsn_qci_psfp_sfi_conf sficonf;
	int ret = 0;

	memset(&sficonf, 0, sizeof(struct tsn_qci_psfp_sfi_conf));

	if (portname == NULL)
		/*loop to get all ports*/
		printf("try to get all ports stream filter instance\n");
	else if (streamfilter < 0) {
		printf("try to get all stream filter instance on port %s\n", portname);
	} else
		ret = tsn_qci_psfp_sfi_get(portname, (uint16_t)streamfilter, &sficonf);

	return ret;
}

int fill_cb_streamid_set(char *portname, uint32_t index, int8_t enable,
						struct tsn_cb_streamid *streamid)
{
	return tsn_cb_streamid_set(portname, index, enable, streamid);
}

int fill_cbstreamid_get(char *portname, int32_t index)
{
	struct tsn_cb_streamid streamid;
	int ret = 0;

	memset(&streamid, 0, sizeof(struct tsn_cb_streamid));

	if (portname == NULL)
		/*loop to get all ports*/
		printf("try to get all ports stream identify tables\n");
	else if (index < 0) {
		printf("try to get all stream identify tables on port %s\n", portname);
	} else
		ret = tsn_cb_streamid_get(portname, index, &streamid);

	return ret;
}

int qcisgi_entry_parse(char *lists, struct tsn_qci_psfp_gcl *gcl, int *count, uint32_t *timetotal)
{
	char *delim = "\n";
	char *pch;
	int number;
	char state[5], st[5];
	int time;
	bool gate;
	int ipv;
	int octet;

	*count = 0;
	*timetotal = 0;

	pch = strtok(lists, delim);

	while (pch != NULL) {

		while ((*pch == ' ') || (*pch == '\t'))
			pch++;

		if (*pch == '#') {
			pch = strtok(NULL, delim);
			continue;
		}

		if ((*pch == 'T') || (*pch == 't')) {
			sscanf((pch + 1), "%d %s %d %d %d", &number, st, &ipv, &time, &octet);

			logv("qcisgi entry: number: %d	state: %s	ipv: %d		time: %d	octetmax: %d",
					number, st, ipv, time, octet);

			if (number < 0) {
				loge("ERROR: tx NUMBER should not less than 0");
				return -1;
			}

			if (number < *count) {
				loge("ERROR: Duplicate number.\n");
				return -1;
			}

			if (number >= MAX_ENTRY_NUMBER) {
				loge("ERROR: larger than max entry number");
				return -1;
			}

			if (!time) {
				logv("WARNING: time period should not be zero.\n");
				pch = strtok(NULL, delim);
				continue;
			}

			sscanf(st, "%[0-1]", state);

			if (strlen(state) != 1) {
				loge("gate state should '1b' or '0b' ");
				return -1;
			}

			gate = (state[0] == '1') ? 1:0;
			(gcl + number)->gate_state = gate;
			(gcl + number)->ipv = (int8_t)ipv;
			(gcl + number)->time_interval = (uint32_t)time;
			(gcl + number)->octet_max = (uint32_t)octet;

			(*timetotal) += time;
			(*count)++;
		}

		pch = strtok(NULL, delim);
	}

	return 0;
}

int fill_qci_sgi_set(char *portname, uint32_t index, bool enable, char *listtable,
				bool configchange, bool blkinvrx_en, bool blkinvrx,
				bool blkoctex_en, bool blkoctex,
				bool initgate, int8_t initipv, uint64_t basetime,
				uint32_t cycletime, uint32_t cycletimeext)
{
	struct tsn_qci_psfp_sgi_conf sgiconf;
	struct tsn_qci_psfp_gcl *gcl = NULL;
	struct tsn_qci_psfp_stream_param sp;
	int count = 0;
	uint32_t timetotal = 0;
	uint32_t memsize = 0;
	int ret;

	memset(&sgiconf, 0, sizeof(struct tsn_qci_psfp_sgi_conf));
	memset(&sp, 0, sizeof(struct tsn_qci_psfp_stream_param));

	sgiconf.gate_enabled = enable;
	if (!enable)
		goto loadlib;

	sgiconf.config_change = configchange;
	sgiconf.block_invalid_rx_enable = blkinvrx_en;
	sgiconf.block_invalid_rx = blkinvrx;
	sgiconf.block_octets_exceeded_enable = blkoctex_en;
	sgiconf.block_octets_exceeded = blkoctex;
	sgiconf.admin.gate_states = initgate;
	sgiconf.admin.cycle_time_extension = cycletimeext;
	sgiconf.admin.base_time = basetime;
	sgiconf.admin.init_ipv = initipv;

	if (listtable == NULL)
		goto loadlib;

	if (tsn_qci_streampara_get(&sp)) {
		memsize = MAX_ENTRY_SIZE;
	} else {
		count = sp.max_sg_instance;
		memsize = sizeof(struct tsn_qci_psfp_gcl) * count;
	}

	printf("sgi: memsize is %d\n", memsize);
	gcl = (struct tsn_qci_psfp_gcl *)malloc(memsize);
	if (gcl == NULL) {
		loge("qcisgi malloc gate list error");
		return -1;
	}

	memset(gcl, 0, memsize);

	ret = qcisgi_entry_parse(listtable, gcl, &count, &timetotal);
	if (ret < 0) {
		loge("input file entries error");
		goto err;
	}

	sgiconf.admin.gcl = gcl;
	sgiconf.admin.control_list_length = count;
	if (cycletime > timetotal)
		sgiconf.admin.cycle_time = cycletime;
	else
		sgiconf.admin.cycle_time = timetotal;

loadlib:
	ret = tsn_qci_psfp_sgi_set(portname, index, enable, &sgiconf);
	if (ret < 0)
		loge("load tsn_qci_psfp_sgi_set error");

err:
	free(gcl);
	return ret;
}

int fill_qci_sgi_status_get(char *portname, int32_t sgi_handle)
{
	struct tsn_qci_psfp_sgi_conf sgiconf;
	struct tsn_psfp_sgi_status sgistatus;
	struct tsn_qci_psfp_stream_param maxcapb;
	struct tsn_qci_psfp_gcl *gcladmin = NULL, *gcloper = NULL;
	int memsize;
	uint16_t count = 0;
	int ret;

	if (portname == NULL)
		loge("user must input a --device name\n");

	memset(&maxcapb, 0, sizeof(struct tsn_qci_psfp_stream_param));

	if (tsn_qci_streampara_get(&maxcapb)) {
		memsize = MAX_ENTRY_SIZE;
	} else {
		count = maxcapb.max_sg_instance;
		memsize = sizeof(struct tsn_qci_psfp_gcl) * count;
	}

	printf("sgi: memsize is %d\n", memsize);

	gcladmin = (struct tsn_qci_psfp_gcl *)malloc(memsize);
	if (gcladmin == NULL) {
		loge("qcisgi admin malloc gate list error");
		return -1;
	}

	gcloper = (struct tsn_qci_psfp_gcl *)malloc(memsize);
	if (gcloper == NULL) {
		free(gcladmin);
		loge("qcisgi oper malloc gate list error");
		return -1;
	}

	memset(&sgistatus, 0, sizeof(struct tsn_psfp_sgi_status));
	memset(&sgiconf, 0, sizeof(struct tsn_qci_psfp_sgi_conf));
	memset(gcladmin, 0, memsize);
	memset(gcloper, 0, memsize);

	sgistatus.oper.gcl = gcloper;
	sgiconf.admin.gcl = gcladmin;

	ret = tsn_qci_psfp_sgi_get(portname, sgi_handle, &sgiconf);
	if (ret < 0)
		goto err;

//	ret = tsn_qci_psfp_sgi_status_get(portname, sgi_handle, &sgistatus);
err:
	free(gcladmin);
	free(gcloper);
	if (ret < 0)
		return -1;

	return 0;
}

int fill_qci_fmi_set(char *portname, uint32_t index, bool enable, uint32_t cir,
		uint32_t cbs, uint32_t eir, uint32_t ebs, bool cf, bool cm,
		bool dropyellow, bool markred_en, bool markred)
{
	struct tsn_qci_psfp_fmi fmi;

	memset(&fmi, 0, sizeof(struct tsn_qci_psfp_fmi));

	if (portname == NULL)
		loge("port name should not be NULL");

	fmi.cir = cir;
	fmi.cbs = cbs;
	fmi.eir = eir;
	fmi.ebs = ebs;
	fmi.cf = cf;
	fmi.cm = cm;
	fmi.drop_on_yellow = dropyellow;
	fmi.mark_red_enable = markred_en;
	fmi.mark_red = markred;

	return tsn_qci_psfp_fmi_set(portname, index, enable, &fmi);
}

int fill_qci_fmi_get(char *portname, uint32_t index)
{
	struct tsn_qci_psfp_fmi fmi;

	memset(&fmi, 0, sizeof(struct tsn_qci_psfp_fmi));

	return tsn_qci_psfp_fmi_get(portname, index, &fmi);
}

int fill_cbs_set(char *portname, uint8_t tc, uint8_t percentage)
{
	return tsn_cbs_set(portname, tc, percentage);
}

int fill_cbs_get(char *portname, uint8_t tc)
{

	return tsn_cbs_get(portname, tc);
}

int fill_tsd_set(char *portname, bool enable, uint32_t period, uint32_t frame_num, bool imme)
{
	return tsn_tsd_set(portname, enable, period, frame_num, imme);
}

int fill_tsd_get(char *portname)
{
	return tsn_tsd_get(portname);
}

int fill_qbu_set(char *portname, uint8_t preemptable)
{
	return tsn_qbu_set(portname, preemptable);
}

int fill_qbu_get_status(char *portname)
{
	struct tsn_preempt_status pts;

	memset(&pts, 0, sizeof(struct tsn_preempt_status));

	return tsn_qbu_get_status(portname, &pts);
}

int fill_ct_set(char *portname, uint8_t queue_stat)
{
	return tsn_ct_set(portname, queue_stat);
}

int fill_cbgen_set(char *portname, uint32_t index, uint8_t iport_mask,
		   uint8_t split_mask, uint8_t seq_len, uint32_t seq_num)
{
	struct tsn_seq_gen_conf sg;

	memset(&sg, 0, sizeof(struct tsn_seq_gen_conf));
	sg.iport_mask = iport_mask;
	sg.split_mask = split_mask;
	sg.seq_len = seq_len;
	sg.seq_num = seq_num;

	return tsn_cbgen_set(portname, index, &sg);
}

int fill_cbrec_set(char *portname, uint32_t index, uint8_t seq_len,
		   uint8_t his_len, bool rtag_pop_en)
{
	struct tsn_seq_rec_conf sr;

	memset(&sr, 0, sizeof(struct tsn_seq_rec_conf));
	sr.seq_len = seq_len;
	sr.his_len = his_len;
	sr.rtag_pop_en = rtag_pop_en;

	return tsn_cbrec_set(portname, index, &sr);
}

int fill_cbstatus_get(char *portname, int32_t index)
{
	struct tsn_cb_status cbstat;
	int ret = 0;

	memset(&cbstat, 0, sizeof(struct tsn_cb_status));

	if (portname == NULL)
		printf("No device\n");
	else
		ret = tsn_cbstatus_get(portname, index, &cbstat);

	return ret;
}

int fill_pcpmap_set(char *portname, bool enable)
{
	return tsn_pcpmap_set(portname, enable);
}

int fill_dscp_set(char *portname, bool disable, int index, int cos, int dpl)
{
	struct tsn_qos_switch_dscp_conf dscp_conf;

	memset(&dscp_conf, 0, sizeof(struct tsn_qos_switch_dscp_conf));
	dscp_conf.cos = cos;
	dscp_conf.dpl = dpl;
	return tsn_dscp_set(portname, disable, index, &dscp_conf);
}
