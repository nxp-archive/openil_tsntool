// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * Copyright 2018 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <malloc.h>

#include "tsn/genl_tsn.h"

#define CONFIG_LIBNL3

struct global_conf glb_conf;
/*
 * Create a raw netlink socket and bind
 */
static int tsn_create_nl_socket(int protocol)
{
	int fd;
	struct sockaddr_nl local;

	/* create socket */
	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return -1;

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();

	/* pid */
	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
		goto error;

	return fd;

error:
	close(fd);
	return -1;
}


static int tsn_send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
	     __u8 genl_cmd, __u16 nla_type,
	     void *nla_data, int nla_len)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg;

	/* insert msg, only insert a attr */
	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN) + NLMSG_ALIGN(MAX_USER_SIZE);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = nlmsg_pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = TSN_GENL_VERSION;
	na = (struct nlattr *) GENLMSG_ATTR_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + 1 + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	/* loop */
	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN)
			return -1;
	}

	return 0;
}

struct msgtemplate *tsn_send_cmd_prepare(__u8 genl_cmd)
{
	struct msgtemplate *msg;

	msg = (struct msgtemplate *)malloc(sizeof(struct msgtemplate));
	if (msg == NULL)
		return NULL;

	/* insert msg, only insert a attr */
	msg->n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg->n.nlmsg_type = glb_conf.genl_familyid;
	msg->n.nlmsg_flags = NLM_F_REQUEST;
	msg->n.nlmsg_seq = 0;
	msg->n.nlmsg_pid = glb_conf.pid;
	msg->g.cmd = genl_cmd;
	msg->g.version = TSN_GENL_VERSION;

	return msg;
}

void tsn_send_cmd_append_attr(struct msgtemplate *msg, __u16 nla_type, void *nla_data, int nla_len)
{
	struct nlattr *na;

	//na = (struct nlattr *) GENLMSG_ATTR_DATA(msg);
	na = (struct nlattr *)((char *)msg + (msg->n.nlmsg_len));

	na->nla_type = nla_type;
	na->nla_len = NLMSG_ALIGN(nla_len) + NLA_HDRLEN;
	memcpy(NLA_DATA(na), (char *)nla_data, nla_len);

	PRINTF("add attr at %p , value is %x, len is %d na->nla_len is %d\n", na, *((int *)NLA_DATA(na)), nla_len, na->nla_len);

	msg->n.nlmsg_len += na->nla_len;

	PRINTF("msg len is %d\n", msg->n.nlmsg_len);
}

int tsn_send_to_kernel(struct msgtemplate *msg)
{
	int buflen, r;
	struct sockaddr_nl nladdr;
	char *buf;

	buflen = msg->n.nlmsg_len;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	buf = (char *)msg;

	/* loop */
	while ((r = sendto(glb_conf.genl_fd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN) {
			free(msg);
			return -1;
		}
	}

	free(msg);
	return 0;
}
#if 0
/*
 * Probe the controller in genetlink to find the family id
 * for the TSN_GEN_CTRL family
 */
static int tsn_get_family_id(int sd)
{
	struct msgtemplate ans;

	char name[100];
	int id = 0, ret;
	struct nlattr *na;
	int rep_len;

	/* search family id by gen family name */
	strcpy(name, TSN_GENL_NAME);
	ret = tsn_send_cmd(sd, GENL_ID_CTRL, getpid(), CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, (void *)name, strlen(TSN_GENL_NAME)+1);
	if (ret < 0)
		return 0;

	/* receiv the kernel message */
	rep_len = recv(sd, &ans, sizeof(ans), 0);
	if (ans.n.nlmsg_type == NLMSG_ERROR || (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
		return 0;

	/* parse family id */
	na = (struct nlattr *) GENLMSG_ATTR_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(__u16 *) NLA_DATA(na);
	}

	return id;
}
#endif

int genl_send_msg(int sd, u_int16_t nlmsg_type, u_int32_t nlmsg_pid,
		u_int8_t genl_cmd, u_int8_t genl_version, u_int16_t nla_type,
		void *nla_data, int nla_len)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
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
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
					sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN) {
			return -1;
		}
	}
	return 0;
}

static int genl_get_family_id(int sd, char *family_name)
{
	msgtemplate_t ans;
	int id, rc;
	struct nlattr *na;
	int rep_len;

	rc = genl_send_msg(sd, GENL_ID_CTRL, 0, CTRL_CMD_GETFAMILY, 1,
			CTRL_ATTR_FAMILY_NAME, (void *)family_name,
			strlen(family_name)+1);
	if (rc < 0)
		return -1;

	rep_len = recv(sd, &ans, sizeof(ans), 0);
	if (rep_len < 0)
		return 0;

	if (ans.n.nlmsg_type == NLMSG_ERROR || !NLMSG_OK((&ans.n), rep_len))
		return 0;

	na = (struct nlattr *) GENLMSG_USER_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(__u16 *) NLA_DATA(na);
	} else {
		id = 0;
	}

    return id;
}

int tsn_msg_check(struct msgtemplate msg, int rep_len)
{
	if (msg.n.nlmsg_type == NLMSG_ERROR || !NLMSG_OK((&msg.n), rep_len)) {
		struct nlmsgerr *err = NLMSG_DATA(&msg);
		fprintf(stderr, "fatal reply error,  errno %d\n", err->error);
		return -1;
	}

	return 0;
}

void tsn_msg_recv_analysis(struct showtable *linkdata)
{
	int rep_len;
	int len, len1;
	struct nlattr *na, *na1;
	struct msgtemplate msg;

	int data;
	char *string;
	int remain;
	int tsn;

	if (!linkdata)
		tsn = 0;
	else
		tsn = linkdata->type;

	/* get kernel message echo */
	rep_len = recv(glb_conf.genl_fd, &msg, sizeof(msg), 0);
	if (rep_len < 0 || tsn_msg_check(msg, rep_len) < 0) {
		fprintf(stderr, "nonfatal reply error: errno %d\n", errno);
		return;
	}
	PRINTF("received %d bytes\n", rep_len);
	PRINTF("nlmsghdr size=%zu, nlmsg_len=%d, rep_len=%d\n",
		   sizeof(struct nlmsghdr), msg.n.nlmsg_len, rep_len);

	rep_len = GENLMSG_ATTR_PAYLOAD(&msg.n);
	na = (struct nlattr *) GENLMSG_ATTR_DATA(&msg);
	len = 0;

	/* there may more than one attr in one message, loop to read */
	while (len < rep_len) {
		switch (na->nla_type) {
		case TSN_CMD_ATTR_MESG:
			/* get kernel string message echo */
			string = (char *) NLA_DATA(na);
			printf("echo reply:%s\n", string);
			break;
		case TSN_CMD_ATTR_DATA:
			/* get kernel data echo */
			data = *(int *) NLA_DATA(na);
			printf("echo reply:%d\n", data);
			break;
		case TSN_ATTR_IFNAME:
			string = (char *) NLA_DATA(na);
			printf("echo reply:%s\n", string);
			break;
		case TSN_ATTR_QBV:
		case TSN_ATTR_STREAM_IDENTIFY:
		case TSN_ATTR_QCI_SP:
		case TSN_ATTR_QCI_SFI:
		case TSN_ATTR_QCI_SGI:
		case TSN_ATTR_QCI_FMI:
		case TSN_ATTR_CBS:
		case TSN_ATTR_QBU:

			if (!tsn)
				break;

			if (!linkdata->len1)
				break;

			na1 = nla_data(na);
			len1 = 0;
			int temp = 0;

			printf("tsn: len: %04x type: %04x data:\n", na->nla_len, na->nla_type);

			while (len1 < na->nla_len) {
				switch (linkdata->link1[na1->nla_type].type) {
				case NLA_NESTED:
					{
					struct nlattr *na2;
					int len2 = 0;
					int temp2 = 0;
					printf("  level2: nla->_len: %d type: %d\n\n", na1->nla_len, na1->nla_type);
					len1 += sizeof(struct nlattr);
					na2 = nla_data(na1);

					while(len2 < na1->nla_len) {
						switch(linkdata->link2[na2->nla_type].type) {
						case NLA_NESTED:
							{
							struct nlattr *na3;
							int len3 = 0;
							int temp3 = 0;

							printf("   level3: nla->_len: %d type: %d\n\n", na2->nla_len, na2->nla_type);
							len2 += sizeof(struct nlattr);
							na3 = nla_data(na2);
							while (len3 < na2->nla_len) {
								switch(linkdata->link3[na3->nla_type].type) {
								case NLA_FLAG:
									printf("     %s \n", linkdata->link3[na3->nla_type].name);
									break;
								case NLA_U8:
									printf("     %s = %02x\n", linkdata->link3[na3->nla_type].name, *(uint8_t *)NLA_DATA(na3));
									break;
								case NLA_U16:
									printf("     %s = %x\n", linkdata->link3[na3->nla_type].name, *(uint16_t *)NLA_DATA(na3));
									break;
								case NLA_U32:
									printf("     %s = %x\n", linkdata->link3[na3->nla_type].name, *(uint32_t *)NLA_DATA(na3));
									break;
								case NLA_U64:
									printf("     %s = %llx\n", linkdata->link3[na3->nla_type].name, *(uint64_t *)NLA_DATA(na3));
									break;
								default:
									break;
								}
								len3 += NLA_ALIGN(na3->nla_len);
								na3 = nla_next(na3, &remain);
							}
							}
							break;

						case NLA_FLAG:
							printf("   %s \n", linkdata->link2[na2->nla_type].name);
							break;
						case NLA_U8:
							printf("   %s = %02x\n", linkdata->link2[na2->nla_type].name, *(uint8_t *)NLA_DATA(na2));
							break;
						case NLA_U16:
							printf("   %s = %x\n", linkdata->link2[na2->nla_type].name, *(uint16_t *)NLA_DATA(na2));
							break;
						case NLA_U32:
							printf("   %s = %x\n", linkdata->link2[na2->nla_type].name, *(uint32_t *)NLA_DATA(na2));
							break;
						case NLA_U64:
							printf("   %s = %llx\n", linkdata->link2[na2->nla_type].name, *(uint64_t *)NLA_DATA(na2));
							break;
						default:
							break;
						}

						len2 += NLA_ALIGN(na2->nla_len);
						na2 = nla_next(na2, &remain);
					}
					}
					break;
				case NLA_FLAG:
					printf("   %s \n", linkdata->link1[na1->nla_type].name);
					break;
				case NLA_U8:
					printf("   %s = %02x\n", linkdata->link1[na1->nla_type].name, *(uint8_t *)NLA_DATA(na1));
					break;
				case NLA_U16:
					printf("   %s = %x\n", linkdata->link1[na1->nla_type].name, *(uint16_t *)NLA_DATA(na1));
					break;
				case NLA_U32:
					printf("   %s = %x\n", linkdata->link1[na1->nla_type].name, *(uint32_t *)NLA_DATA(na1));
					break;
				case NLA_U64:
					printf("   %s = %llx\n", linkdata->link1[na1->nla_type].name, *(uint64_t *)NLA_DATA(na1));
					break;
				default:
					break;
				}

				len1 += NLA_ALIGN(na1->nla_len);
				na1 = nla_next(na1, &remain);
				if (temp++ > 100)
					break;
			}
			break;
		default:
			break;
		}

		len += NLA_ALIGN(na->nla_len);
#ifdef CONFIG_LIBNL3
		na = nla_next(na, &remain);
#else
		na += NLA_ALIGN(na->nla_len);
#endif
	}
}


int genl_tsn_init(void)
{
	int nl_fd;
	int nl_family_id;
	int my_pid;

	memset(&glb_conf, 0, sizeof(struct global_conf));

	/* init socket */
	nl_fd = tsn_create_nl_socket(NETLINK_GENERIC);
	if (nl_fd < 0) {
		fprintf(stderr, "failed to create netlink socket\n");
		return -1;
	}

	glb_conf.genl_fd = nl_fd;

	/* to get family id */
	nl_family_id = genl_get_family_id(nl_fd, TSN_GENL_NAME);
	if (!nl_family_id) {
		fprintf(stderr, "Error getting family id, errno %d\n", errno);
		close(nl_fd);
		return -1;
	}
	PRINTF("family id %d\n", nl_family_id);
	glb_conf.genl_familyid = nl_family_id;

	/* send string message */
	my_pid = getpid();
	glb_conf.pid = my_pid;

	return 0;
}

void genl_tsn_close(void)
{
	close(glb_conf.genl_fd);
}

int tsn_echo_test(char *string, int data)
{
	int ret;

	PRINTF("before  tsn_send_cmd\n");
	ret = tsn_send_cmd(glb_conf.genl_fd, glb_conf.genl_familyid, glb_conf.pid, TSN_CMD_ECHO,
			  TSN_CMD_ATTR_MESG, string, strlen(string) + 1);
	if (ret < 0) {
		fprintf(stderr, "failed to send echo cmd\n");
		return -1;
	}

	/* send data message to kernel */
	ret = tsn_send_cmd(glb_conf.genl_fd, glb_conf.genl_familyid, glb_conf.pid, TSN_CMD_ECHO,
			  TSN_CMD_ATTR_DATA, &data, sizeof(data));
	if (ret < 0) {
		fprintf(stderr, "failed to send echo cmd\n");
		return -1;
	}

	/* receive message and (only 2 message types) */
	tsn_msg_recv_analysis(NULL);
	tsn_msg_recv_analysis(NULL);

	return 0;
}
