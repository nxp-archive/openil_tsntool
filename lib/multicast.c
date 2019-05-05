// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2019 NXP
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netlink/netlink.h>
#include <linux/genetlink.h>
#include <netlink/genl/genl.h>
#include <pthread.h>
#include <sched.h>

#include "tsn/genl_tsn.h"

struct alarm_node {
	pthread_t thread;
	uint32_t iface;
	uint32_t infotype;
	uint64_t ts;
	uint32_t offset;
	uint32_t cycle;
	void (*callback_func)(void *data);
	void *data;
	struct alarm_node *next;
};

static int running = 1;
static struct alarm_node *head_msg = NULL;

static int set_realtime(pthread_t thread, int priority, int cpu)
{
	cpu_set_t cpuset;
	struct sched_param sp;
	int err, policy;

	int min = sched_get_priority_min(SCHED_FIFO);
	int max = sched_get_priority_max(SCHED_FIFO);

	fprintf(stderr, "min %d max %d\n", min, max);

	if (priority < 0) {
		return 0;
	}

	err = pthread_getschedparam(thread, &policy, &sp);
	if (err) {
		fprintf(stderr, "pthread_getschedparam: %s\n", strerror(err));
		return -1;
	}

	sp.sched_priority = priority;

	err = pthread_setschedparam(thread, SCHED_FIFO, &sp);
	if (err) {
		fprintf(stderr, "pthread_setschedparam: %s\n", strerror(err));
		return -1;
	}

	if (cpu < 0) {
		return 0;
	}
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	err = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	if (err) {
		fprintf(stderr, "pthread_setaffinity_np: %s\n", strerror(err));
		return -1;
	}

	return 0;
}

int64_t pctns(struct timespec *t)
{
	return (t->tv_sec * 1000000000ULL + t->tv_nsec);
}

int set_period_alarm(uint64_t ts, uint64_t offset, uint64_t cycle,
		     void (*callback_func)(void *data), void *data)
{
	struct timespec now;

	if (!callback_func)
		return -1;

	ts += offset;

	now.tv_sec = ts/1000000000ULL;
	now.tv_nsec = ts - ts/1000000000ULL*1000000000ULL;

	while (running) {
		clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &now, NULL);
		callback_func(data);
		ts = pctns(&now) + cycle;
		now.tv_sec = ts/1000000000ULL;
		now.tv_nsec = ts - ts/1000000000ULL*1000000000ULL;
	}
}

void alarm_thread(void *data)
{
	struct alarm_node *msg = (struct alarm_node *)data;

	set_realtime(pthread_self(), 1, 0);

	set_period_alarm(msg->ts, msg->offset, msg->cycle, msg->callback_func, msg->data);
}

int create_alarm_thread(uint64_t ts, uint32_t offset, uint32_t cycle,
		        uint32_t iface, uint32_t infotype,
			void (*callback_func)(void *data), void *data)
{
	struct alarm_node *msg, *node, *node1;

	node = head_msg;
	node1 = head_msg;
	while (node) {
		if (node->iface == iface && node->infotype == infotype) {
			pthread_cancel(node->thread);
			if (node == head_msg) {
				head_msg = node1->next;
			} else {
				node1->next = node->next;
			}
			free(node);
			break;
		}
		node1 = node;
		node = node->next;
	}

	msg = (struct alarm_node *)malloc(sizeof(struct alarm_node));
	memset(msg, 0, sizeof(*msg));

	node = head_msg;
	node1 = head_msg;
	while (node) {
		node1 = node;
		node = node->next;
	}

	if (!head_msg) {
		head_msg = msg;
	} else {
		node1->next = msg;
	}

	msg->ts = ts;
	msg->offset = offset;
	msg->cycle = cycle;
	msg->iface = iface;
	msg->infotype = infotype;
	msg->next = NULL;
	msg->callback_func = callback_func;
	msg->data = data;

	pthread_create(&msg->thread, NULL, alarm_thread, msg);

	return 0;
}

pthread_t *create_alarm_common(uint64_t ts, uint32_t offset, uint32_t cycle,
			       void (*callback_func)(void *data), void *data)
{
	struct alarm_node *msg, *node, *node1;
	int res;

	msg = (struct alarm_node *)malloc(sizeof(struct alarm_node));
	memset(msg, 0, sizeof(*msg));

	node = head_msg;
	node1 = head_msg;
	while (node) {
		node1 = node;
		node = node->next;
	}

	if (!head_msg) {
		head_msg = msg;
	} else {
		node1->next = msg;
	}

	msg->ts = ts;
	msg->offset = offset;
	msg->cycle = cycle;
	msg->iface = 0;
	msg->infotype = TSN_MCGRP_MAX + 1;
	msg->next = NULL;
	msg->callback_func = callback_func;
	msg->data = data;

	res = pthread_create(&msg->thread, NULL, alarm_thread, msg);
	if (res) {
		printf("Create alarm failed\n");
		free(msg);
		return NULL;
	}

	return &msg->thread;
}

int delete_alarm_common(pthread_t *thread)
{
	struct alarm_node *node, *node1;
	void *result;
	int res;

	node = head_msg;
	node1 = head_msg;
	while (node) {
		if (node->thread == *thread) {
			pthread_cancel(node->thread);
			res = pthread_join(node->thread, &result);
			if (res) {
				printf("Create alarm failed\n");
				return -1;
			}
			if (node == head_msg) {
				head_msg = node1->next;
			} else {
				node1->next = node->next;
			}
			free(node);
			return 0;
		}
		node1 = node;
		node = node->next;
	}

	return -1;
}

int delete_one_alarm(uint32_t iface, uint32_t infotype)
{
	struct alarm_node *node, *node1;

	node = head_msg;
	node1 = head_msg;
	while (node) {
		if (node->iface == iface && node->infotype == infotype) {
			pthread_cancel(node->thread);
			if (node == head_msg) {
				head_msg = node1->next;
			} else {
				node1->next = node->next;
			}
			free(node);
			return 0;
		}
		node1 = node;
		node = node->next;
	}

	return -1;
}

void clear_alarms()
{
	struct alarm_node *node, *node1;

	node = head_msg;
	node1 = head_msg;
	while (node) {
		pthread_cancel(node->thread);
		node1 = node;
		node = node->next;
		free(node1);
	}

	head_msg = NULL;
}

int genl_sendto_msg(struct nl_sock *sd, uint16_t nlmsg_type, uint32_t nlmsg_pid,
		uint8_t genl_cmd, uint8_t genl_version, uint16_t nla_type,
		void *nla_data, int nla_len)
{
	struct nlattr *na;
	int r, buflen;
	char *buf;
	msgtemplate_t msg;

	if (nlmsg_type == 0)
		return 0;

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	msg.n.nlmsg_seq = 0;
	/*
	 * nlmsg_pid
	 * Linux
	 */
	msg.n.nlmsg_pid = nlmsg_pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = genl_version;
	na = (struct nlattr *) GENLMSG_USER_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + 1 + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len;
	while ((r = nl_sendto(sd, buf, buflen)) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN) {
			return -1;
		}
	}
	return 0;
}

static int tsn_multicast_cb(struct nl_msg *msg, void *data)

{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *genlh = genlmsg_hdr(nlh);
	struct tsn_family_groups *p_fmgroups = data;
	struct alarm_info *ai;
	struct nlattr *payload = genlmsg_attrdata(genlh, NLMSG_ALIGN(MAX_USER_SIZE));

	if (!payload) {
		printf("multicast message with none payload!\n");
		return 0;
	}

	if (!p_fmgroups) {
		printf("No family groups information!\n");
		return 0;
	}

	ai = p_fmgroups->ai;

	if (!ai) {
		printf("No alarm_info input!\n");
		return 0;
	}

	if (nlh->nlmsg_type == p_fmgroups->family_id) {
		switch(genlh->cmd) {
			case TSN_CMD_QBV_SET:
				{
				int nlalen, remain;
				int interface;
				uint64_t cctime;
				uint32_t cytime;
				bool enable = 0;
				struct nlattr *nla;

				nlalen = genlmsg_attrlen(genlh, NLMSG_ALIGN(MAX_USER_SIZE));
				printf("got tsn qbv multicast command!\n");
				nla_for_each_attr(nla, payload, nlalen, remain) {
					if (nla->nla_type == TSN_QBV_ATTR_CTRL_BASETIME) {
						cctime = nla_get_u64(nla);
						printf("got configchangetime %lld\n", cctime);
					}
					if (nla->nla_type == TSN_QBV_ATTR_CTRL_CYCLETIME) {
						cytime = nla_get_u32(nla);
						printf("got cycle time %ld\n", cytime);
					}
					if (nla->nla_type == TSN_QBV_ATTR_ENABLE + TSN_QBV_ATTR_CTRL_MAX) {
						enable = 1;
						printf("got qbv enable flag\n");
					}
					if (nla->nla_type == TSN_QBV_ATTR_DISABLE + TSN_QBV_ATTR_CTRL_MAX) {
						enable = 0;
						printf("got qbv disable flag\n");
					}
					if (nla->nla_type == TSN_QBV_ATTR_CTRL_UNSPEC) {
						interface = nla_get_u32(nla);
						printf("got interface is %d\n", interface);
					}
				}
				if (enable) {
					ai->qbvmc.cct = cctime;
					ai->qbvmc.ifidx = interface;
					create_alarm_thread(cctime, ai->qbvmc.offset, cytime,
							    interface, TSN_MCGRP_QBV,
							    ai->qbvmc.callback_func,
							    ai->qbvmc.data);
				} else {
					delete_one_alarm(interface, TSN_MCGRP_QBV);
				}
				}
				break;
			case TSN_CMD_QCI_SGI_SET:
				printf("got tsn qci multicast command!\n");
				break;
			default:
				printf("not support command type!\n");
				break;
		}
	} else if (nlh->nlmsg_type == GENL_ID_CTRL) {
		printf("got control message!");
		return 0;
	}

	return 0;
}

int wait_tsn_multicast(struct alarm_info *ainfo)
{
	char family_name[] = "TSN_GEN_CTRL";
	int rc;
	struct tsn_family_groups fmgroups;
	struct nl_sock * s = nl_socket_alloc();

	fmgroups.ai = ainfo;

	if (!s) {
		printf("nl_socket_alloc");
		return -1;
	}

	nl_socket_disable_seq_check(s);
	nl_socket_modify_cb(s, NL_CB_VALID, NL_CB_CUSTOM, tsn_multicast_cb, &fmgroups);

	if (genl_connect(s)) {
		nl_socket_free(s);
		printf("nl_connect");
		return -1;
	}

	rc = genl_sendto_msg(s, GENL_ID_CTRL, 0, CTRL_CMD_GETFAMILY, 1,
			CTRL_ATTR_FAMILY_NAME, (void *)family_name,
			strlen(family_name)+1);
	if (rc < 0) {
		nl_socket_free(s);
		printf("failure: send simple\n");
		printf("nl_send_simple");
		return -1;
	}

	//Retrieve the kernel's answer.
	nl_recvmsgs_default(s);

	rc = genl_ctrl_resolve(s, family_name);
	if (rc < 0) {
		printf("got error when genl_ctrl_resolve\n");
		nl_socket_free(s);
		printf("genl_ctrl_resolve");
		return -1;
	}

	printf("family id is %d\n", rc);
	fmgroups.family_id = rc;

	rc = genl_ctrl_resolve_grp(s, family_name, TSN_MULTICAST_GROUP_QBV);
	if (rc < 0) {
		printf("got error when genl_ctrl_resolve_grp\n");
	}

	printf("group id qbv is %d\n", rc);
	fmgroups.mc[TSN_MCGRP_QBV] = rc;
	nl_socket_add_memberships(s, rc, 0);

	rc = genl_ctrl_resolve_grp(s, family_name, TSN_MULTICAST_GROUP_QCI);
	if (rc < 0) {
		printf("got error when genl_ctrl_resolve_grp\n");
	}

	printf("group id qci is %d\n", rc);
	fmgroups.mc[TSN_MCGRP_QCI] = rc;
	nl_socket_add_memberships(s, rc, 0);

	while(1)
		nl_recvmsgs_default(s);

	clear_alarms();
	nl_socket_free(s);

	return 0;
}

