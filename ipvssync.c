/*
 * MIT License
 *
 * Copyright (c) 2017 KUWAZAWA Takuya
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netlink/route/link.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "libipvs/libipvs.h"
#include "ipvssync.h"

#define TOOL_VERSION  "0.0.1"

struct ipv4_session_list {
	struct ipv4_session_list	*next;
	struct ip_vs_sync_v4		*session;
};

struct svc_config_list {
	struct svc_config_list		*next;
	struct ip_vs_get_dests		*dests;
};

int DEBUG = 0;
int FORCE = 0;
int syncid = 0;
int sync_maxlen = 0;
char *ifname = NULL;
char *mcast_addr = "224.0.0.81";
int mcast_port = 8848;
int mcast_ttl = 1;
int ip_vs_conntrack = 0;

int init(void)
{
	FILE *fp = NULL;
	int version = 0;

	fp = fopen("/proc/sys/net/ipv4/vs/sync_version", "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open /proc/sys/net/ipv4/vs/sync_version: %s\n", strerror(errno));
		return -1;
	}
	if (fscanf(fp, "%d", &version) != 1) {
		fprintf(stderr, "Could not get sync version\n");
		fclose(fp);
		return -1;
	}
	if (version != 1) {
		fprintf(stderr, "Sync version 1 is only supported\n");
		fclose(fp);
		return -1;
	}
	fclose(fp);

	fp = fopen("/proc/sys/net/ipv4/vs/conntrack", "r");
	if (fp != NULL) {
		if (fscanf(fp, "%d", &ip_vs_conntrack) != 1)
			ip_vs_conntrack = 0;
		fclose(fp);
	}

	if (ipvs_init()) {
		fprintf(stderr, "Failed to initialize libipvs\n");
		return -1;
	}

	ipvs_daemon_t *daemon = ipvs_get_daemon();
	if (daemon == NULL) {
		fprintf(stderr, "Failed to get ipvs sync daemon\n");
		return -1;
	}

	int i;
	for (i = 0; i < 2; i++) {
		if (daemon[i].state != IP_VS_STATE_MASTER)
			continue;
		if (daemon[i].sync_maxlen > 0)
			sync_maxlen = daemon[i].sync_maxlen;
		if (daemon[i].mcast_port > 0)
			mcast_port = daemon[i].mcast_port;
		if (daemon[i].mcast_ttl > 0)
			mcast_ttl = daemon[i].mcast_ttl;

		syncid = daemon[i].syncid;

		if (ifname == NULL) {
			ifname = (char *) malloc(strlen(daemon[i].mcast_ifn) + 1);
			if (ifname == NULL) {
				free(daemon);
				return -1;
			}
			memset(ifname, 0, strlen(daemon[i].mcast_ifn) + 1);
			memcpy(ifname, daemon[i].mcast_ifn, strlen(daemon[i].mcast_ifn));
		}

		free(daemon);
		return 0;
	}

	fprintf(stderr, "Master sync daemon is not running\n");

	free(daemon);

	if (FORCE)
		return 0;

	return -1;
}

void free_sessions(struct ipv4_session_list *s)
{
	struct ipv4_session_list *sessions = s;

	while (sessions != NULL && sessions->session != NULL) {
		struct ipv4_session_list *list = sessions;

		if (sessions->session != NULL) {
			free(sessions->session);
			sessions->session = NULL;
		}

		sessions = sessions->next;
		free(list);
		list = NULL;
	}
}

void set_conn_flags(struct svc_config_list *c, struct ip_vs_sync_v4 *session)
{
	struct svc_config_list *config = c;
	int found = 0;

	while (config != NULL && config->dests != NULL) {
		int i;
		for (i = 0; i < config->dests->num_dests; i++) {
			if (session->vaddr != config->dests->addr.ip ||
			    session->vport != config->dests->port ||
			    session->protocol != config->dests->protocol)
				break;
			struct ip_vs_dest_entry d = config->dests->entrytable[i];
			if (session->daddr == d.addr.ip &&
			    session->dport == d.port) {
				session->flags = d.conn_flags & ~IP_VS_CONN_F_BACKUP_UPD_MASK;
        			if (ip_vs_conntrack)
                			session->flags |= IP_VS_CONN_F_NFCT;
				session->flags = htonl(session->flags);
				found = 1;
				goto end;
			}
		}
		config = config->next;
	}

end:
	if (found == 0) {
		fprintf(stderr, "conn_flag of [%s] %x:%d -> %x:%d not found\n",
			session->protocol == IPPROTO_TCP ? "TCP" : "UDP",
			ntohl(session->vaddr), ntohs(session->vport),
			ntohl(session->daddr), ntohs(session->dport));
	}
}

struct ipv4_session_list *get_ipvs_sessions(struct svc_config_list *config)
{
	struct ipv4_session_list *sessions = malloc(sizeof(struct ipv4_session_list));
	if (sessions == NULL) {
		fprintf(stderr, "Failed to malloc: %s", strerror(errno));
		return NULL;
	}
	memset(sessions, 0, sizeof(struct ipv4_session_list));
	struct ipv4_session_list *ret = sessions;

	FILE *fp = fopen("/proc/net/ip_vs_conn", "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open /proc/net/ip_vs_conn: %s\n", strerror(errno));
		return NULL;
	}

	int bufsize = 65536;
	char *buf = malloc(bufsize);
	if (buf == NULL) {
		fprintf(stderr, "Failed to malloc: %s", strerror(errno));
		return NULL;
	}

	char *pos = NULL;
	while (!feof(fp)) {
		if (pos == NULL) {
			fread((void *)buf, bufsize, 1, fp);
		} else {
			int remained = bufsize - (pos - buf);
			memcpy(buf, pos, remained);
			memset(buf+remained, 0, bufsize-remained);
			fread((void *) buf+remained , bufsize - remained, 1, fp);
		}
	
		pos = buf;
		char *newline;
		for (newline = strchr(pos, 0x0a); newline != NULL; newline = strchr(pos, 0x0a)) {
			char protocol[4];
			uint32_t client_addr;
			uint32_t client_port;
			uint32_t virtual_addr;
			uint32_t virtual_port;
			uint32_t dest_addr;
			uint32_t dest_port;
			char state[12];
			unsigned long expire;
			unsigned int len;
	
			sscanf(pos, "%s %X %X %X %X %X %X %11s %7lu",
				protocol, &client_addr, &client_port, &virtual_addr, &virtual_port, &dest_addr, &dest_port,
				state, &expire);
			if (DEBUG) {
				printf("scaned: %s %08X %04X %08X %04X %08X %04X %s %7lu\n",
					protocol, client_addr, client_port, virtual_addr, virtual_port,
					dest_addr, dest_port, state, expire);
			}
	
			pos = newline + 1;
	
			if (strncmp(state, "ESTABLISHED", 12) && strncmp(state, "UDP", 4))
				continue;
	
			sessions->next = malloc(sizeof(struct ipv4_session_list));
			if (sessions->next == NULL) {
				fprintf(stderr, "Failed to malloc: %s", strerror(errno));
				free(buf);
				return NULL;
			}
			memset(sessions->next, 0, sizeof(struct ipv4_session_list));
	
			sessions->session = malloc(sizeof(struct ip_vs_sync_v4));
			if (sessions->session == NULL) {
				fprintf(stderr, "Failed to malloc: %s", strerror(errno));
				free(buf);
				return NULL;
			}
	
			len = sizeof(struct ip_vs_sync_v4);
			sessions->session->type = 0;
			sessions->session->protocol = strncmp(protocol, "TCP", 4) == 0 ? IPPROTO_TCP : IPPROTO_UDP;
			sessions->session->ver_size = htons(len & SVER_MASK);
			if (sessions->session->protocol == IPPROTO_TCP)
				sessions->session->state = htons(IP_VS_TCP_S_ESTABLISHED);
			else
				sessions->session->state = htons(IP_VS_UDP_S_NORMAL);
			sessions->session->cport = htons(client_port);
			sessions->session->vport = htons(virtual_port);
			sessions->session->dport = htons(dest_port);
			sessions->session->fwmark = 0;
			sessions->session->timeout = htonl(expire);
			sessions->session->caddr = htonl(client_addr);
			sessions->session->vaddr = htonl(virtual_addr);
			sessions->session->daddr = htonl(dest_addr);
	
			set_conn_flags(config, sessions->session);
	
			if (DEBUG) {
				printf("session: %d %08X %04X %08X %04X %08X %04X %d %7u\n",
					sessions->session->protocol, sessions->session->caddr, sessions->session->cport,
					sessions->session->vaddr, sessions->session->vport,
					sessions->session->daddr, sessions->session->dport,
					sessions->session->state, sessions->session->timeout);
			}

			sessions = sessions->next;
		}
	}

	fclose(fp);
	free(buf);

	return ret;
}

void free_configs(struct svc_config_list *c)
{
	struct svc_config_list *configs = c;

	while (configs != NULL && configs->dests != NULL) {
		struct svc_config_list *list = configs;

		if (configs->dests != NULL) {
			free(configs->dests);
			configs->dests = NULL;
		}

		configs = configs->next;
		free(list);
		list = NULL;
	}
}

struct svc_config_list *get_config(void)
{
	struct ip_vs_get_services *svcs = NULL;
	struct ip_vs_get_dests *dests = NULL;
	struct svc_config_list *config, *ret;

	svcs = ipvs_get_services();
	if (svcs == NULL) {
		fprintf(stderr, "Failed to get services\n");
		return NULL;
	}
 	ret = config = malloc(sizeof(struct svc_config_list));
	if (config == NULL) {
		fprintf(stderr, strerror(errno));
		goto err;
	}
	memset(config, 0, sizeof(struct svc_config_list));

	int i;
	for (i = 0; svcs->num_services > i; i++) {
		ipvs_service_entry_t svc = svcs->entrytable[i];
		if (strncmp(svc.pe_name, "", 1)) {
			fprintf(stderr, "PE is not supported\n");
			goto err;
		}
		if (svc.fwmark) {
			fprintf(stderr, "FWMARK is not supported\n");
			goto err;
		}
		dests = ipvs_get_dests(&svc);
		if (dests == NULL) {
			fprintf(stderr, "Failed to get dests\n");
			goto err;
		}

		if (dests->af == AF_INET6) {
			fprintf(stderr, "IPv6 is not supported\n");
			goto err;
		}

 		struct svc_config_list *c = malloc(sizeof(struct svc_config_list));
		if (c == NULL) {
			fprintf(stderr, "Failed to malloc: %s", strerror(errno));
			goto err;
		}
		memset(c, 0, sizeof(struct svc_config_list));
		config->next = c;
		config->dests = dests;
		config = config->next;

		int j;
		for (j = 0; dests->num_dests > j; j++) {
			ipvs_dest_entry_t entry = dests->entrytable[j];
			if (entry.conn_flags & IP_VS_CONN_F_SEQ_MASK) {
				fprintf(stderr, "SEQ flag is not supported\n");
				goto err;
			}
		}
	}

	free(svcs);
	return ret;

err:
	free(svcs);
	free_configs(ret);
	return NULL;
}

void dump_sessions(struct ipv4_session_list *s)
{
	struct ipv4_session_list *sessions = s;

	while (sessions->session != NULL) {
		struct ip_vs_sync_v4 *sess = sessions->session;
		printf("dump: %s client=%s:%d, ",
			sess->protocol == IPPROTO_TCP ? "TCP" : "UDP",
			inet_ntoa((struct in_addr) {sess->caddr}), ntohs(sess->cport));
		printf("virt=%s:%d, ",
			inet_ntoa((struct in_addr) {sess->vaddr}), ntohs(sess->vport));
		printf("dest=%s:%d\n",
			inet_ntoa((struct in_addr) {sess->daddr}), ntohs(sess->dport));

		if (sessions->next == NULL)
			return;
		sessions = sessions->next;
	}
}

int get_ifmtu(char *ifname)
{
	int sock;
	ssize_t size;
	int bufsize = 4096;
	char *buf;
	struct {
		struct nlmsghdr  hdr;
		struct ifinfomsg ifi;
		char   attrbuf[512];
	} req;

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.hdr.nlmsg_type = RTM_GETLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = if_nametoindex(ifname);
	req.ifi.ifi_change = 0xffffffff;	// fixed value. see rtnetlink(7)

	if (req.ifi.ifi_index == 0) {
		fprintf(stderr, "%s\n", strerror(errno));
		return -1;
	}

	sock  = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sock < 0){
		fprintf(stderr, "%s\n", strerror(errno));
		return -1;
	}

	buf = malloc(bufsize);
	if (buf == NULL) {
		fprintf(stderr, "%s\n", strerror(errno));
		return -1;
	}

	size = send(sock, &req, req.hdr.nlmsg_len, 0);
	if (size < 0) {
		fprintf(stderr, "%s\n", strerror(errno));
		goto err;
	}

	if (DEBUG)
		printf("sent %lu of %d bytes to netlink\n", size, req.hdr.nlmsg_len);

	size = recv(sock, buf, bufsize, 0);
	if (size < 0) {
		fprintf(stderr, "%s\n", strerror(errno));
		goto err;
	}

	if (DEBUG)
		printf("received %lu bytes from netlink\n", size);

	struct nlmsghdr *hdr = (struct nlmsghdr *) buf;
	if (DEBUG) {
		printf("msglen: %u, type: %u, flag: %u, seq: %u, pid: %u\n",
			hdr->nlmsg_len, hdr->nlmsg_type,
			hdr->nlmsg_flags, hdr->nlmsg_seq, hdr->nlmsg_pid);
	}

	if (! NLMSG_OK(hdr, size)) {
		fprintf(stderr, "netlink message is not recognized (buffer is not enough ?)\n");
		goto err;
	}

	if (hdr->nlmsg_flags & NLM_F_MULTI || hdr->nlmsg_type != RTM_NEWLINK) {
		fprintf(stderr, "unexpected message from netlink.\n");
		goto err;
	}

	struct ifinfomsg *ifi = (struct ifinfomsg *) NLMSG_DATA(hdr);
	struct rtattr *rta = IFLA_RTA(ifi);
	int rta_len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));

	for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
		if (rta->rta_type == IFLA_MTU) {
			int mtu = *((int *) RTA_DATA(rta));
			free(buf);
			return mtu;
		}
	}

err:
	free(buf);
	return -1;
}

int send_packets(struct ipv4_session_list *sessions, char *ifname)
{
	int mtu = get_ifmtu(ifname);
	if (mtu < 0)
		return 1;

	int payload_size = sync_maxlen > 0 ? sync_maxlen : mtu - sizeof(struct udphdr) - sizeof(struct iphdr);

	char *payload = malloc(payload_size);
	if (payload == NULL) {
		fprintf(stderr, strerror(errno));
		return 1;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct in_addr addr;
	if (inet_aton(mcast_addr, &addr) == 0) {
		fprintf(stderr, "invalid address\n");
		goto err;
	}

	struct sockaddr_in sockaddr = {
		.sin_family = AF_INET,
		.sin_port   = htons(mcast_port),
		.sin_addr   = addr,
	};

	struct ip_mreqn req = {
		.imr_multiaddr = addr,
		.imr_ifindex = if_nametoindex(ifname),
	};
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &req, sizeof(req))) {
		fprintf(stderr, strerror(errno));
		goto err;
	}
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &mcast_ttl, sizeof(mcast_ttl))) {
		fprintf(stderr, strerror(errno));
		goto err;
	}

	int sync_count = 0;
	while (sessions != NULL && sessions->session != NULL) {
		memset(payload, 0, payload_size);

		struct ip_vs_sync_mesg *sync_hdr;
		sync_hdr = (struct ip_vs_sync_mesg *) payload;
		sync_hdr->syncid = syncid;
		sync_hdr->size = sizeof(sync_hdr);
		sync_hdr->version = 1;

		int remained = mtu - sizeof(struct ip_vs_sync_mesg) - sizeof(struct udphdr) - sizeof(struct iphdr);
		char *packet_pos = payload;
		packet_pos += sizeof(struct ip_vs_sync_mesg);

		for (; sessions != NULL && sessions->session != NULL; sessions = sessions->next) {
			struct ip_vs_sync_v4 *sess = sessions->session;

			memcpy(packet_pos, sess, sizeof(*sess));
			packet_pos += sizeof(*sess);
			sync_hdr->size += sizeof(*sess);
			sync_hdr->nr_conns++;

			if (DEBUG)
				printf("size: %d, nr_conns: %d\n", sync_hdr->size, sync_hdr->nr_conns);

			remained -= sizeof(*sess);

			if (remained < sizeof(*sess) * 2)
				break;

			sync_count++;
		}
		int size = sync_hdr->size;
		sync_hdr->size = htons(sync_hdr->size);

		// This code does not support optional parameters
		// Last Param data should be padded for 32 bit alignment

		int ret = sendto(sock, payload, size, 0, (struct sockaddr *) &sockaddr, sizeof(sockaddr));
		if (DEBUG)
			printf("sent %d of %d bytes to udp\n", ret, size);
	}

	printf("%d sessions are processed\n", sync_count);

	close(sock);
	free(payload);
	return 0;

err:
	close(sock);
	free(payload);
	return 1;
}

int main(int argc, char *argv[])
{
	int opt;
	int syncid_isset = 0;
	while ((opt = getopt(argc, argv, "dfhi:n:v")) != -1) {
		switch (opt) {
		case 'd':
			DEBUG = 1;
			break;
		case 'f':
			FORCE = 1;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'n':
			syncid = strtol(optarg, NULL, 10);
			syncid_isset = 1;
			break;
		case 'v':
			printf("version %s\n", TOOL_VERSION);
			return 0;
		case 'h':
		default:
			printf("Usage: ipvssync [-d] [-h] [-v] [-f -i ifname -n syncid]\n");
			printf("   -d: enable debug messages\n");
			printf("   -h: show this message\n");
			printf("   -v: print version\n");
			printf("   -f: send sync message even if master daemon is not running\n");
			printf("   -i ifname: multicast interface name\n");
			printf("   -n syncid: id of sync daemon\n");
			return 1;
		}
	}

	if (FORCE) {
		if (ifname == NULL) {
			fprintf(stderr, "You must specify interface name when you use -f option\n");
			return 1;
		}
		if (! syncid_isset)
			printf("NOTICE: use default syncid 0\n");
	}

	if (init())
		return 1;

	struct svc_config_list *config = get_config();
	if (config == NULL)
		return 1;

	if (DEBUG)
		printf("syncid: %d, port: %d, ttl: %d, ifname: %s\n", syncid, mcast_port, mcast_ttl, ifname);

	struct ipv4_session_list *sessions;
	sessions = get_ipvs_sessions(config);
	if (sessions == NULL)
		return 1;

	if (send_packets(sessions, ifname))
		return 1;

	if (DEBUG)
		dump_sessions(sessions);

	free_sessions(sessions);
	free_configs(config);

	return 0;
}
