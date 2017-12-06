// SPDX-License-Identifier: GPL-2.0
/*
 * The code of this file is ported from the following files of the Linux kernel.
 * - include/net/ip_vs.h
 * - include/uapi/linux/ip_vs.h
 * - net/netfilter/ipvs/ip_vs_proto_tcp.c
 * - net/netfilter/ipvs/ip_vs_proto_udp.c
 * - net/netfilter/ipvs/ip_vs_sync.c
 */

// include/net/ip_vs.h
/* TCP State Values */
enum {
	IP_VS_TCP_S_NONE = 0,
	IP_VS_TCP_S_ESTABLISHED,
	IP_VS_TCP_S_SYN_SENT,
	IP_VS_TCP_S_SYN_RECV,
	IP_VS_TCP_S_FIN_WAIT,
	IP_VS_TCP_S_TIME_WAIT,
	IP_VS_TCP_S_CLOSE,
	IP_VS_TCP_S_CLOSE_WAIT,
	IP_VS_TCP_S_LAST_ACK,
	IP_VS_TCP_S_LISTEN,
	IP_VS_TCP_S_SYNACK,
	IP_VS_TCP_S_LAST
};

/* UDP State Values */
enum {
	IP_VS_UDP_S_NORMAL,
	IP_VS_UDP_S_LAST,
};

// net/netfilter/ipvs/ip_vs_proto_tcp.c
static const char *const tcp_state_name_table[IP_VS_TCP_S_LAST+1] = {
	[IP_VS_TCP_S_NONE]		=	"NONE",
	[IP_VS_TCP_S_ESTABLISHED]	=	"ESTABLISHED",
	[IP_VS_TCP_S_SYN_SENT]		=	"SYN_SENT",
	[IP_VS_TCP_S_SYN_RECV]		=	"SYN_RECV",
	[IP_VS_TCP_S_FIN_WAIT]		=	"FIN_WAIT",
	[IP_VS_TCP_S_TIME_WAIT]		=	"TIME_WAIT",
	[IP_VS_TCP_S_CLOSE]		=	"CLOSE",
	[IP_VS_TCP_S_CLOSE_WAIT]	=	"CLOSE_WAIT",
	[IP_VS_TCP_S_LAST_ACK]		=	"LAST_ACK",
	[IP_VS_TCP_S_LISTEN]		=	"LISTEN",
	[IP_VS_TCP_S_SYNACK]		=	"SYNACK",
	[IP_VS_TCP_S_LAST]		=	"BUG!",
};

// net/netfilter/ipvs/ip_vs_proto_udp.c
static const char *const udp_state_name_table[IP_VS_UDP_S_LAST+1] = {
	[IP_VS_UDP_S_NORMAL]		=	"UDP",
	[IP_VS_UDP_S_LAST]		=	"BUG!",
};

// net/netfilter/ipvs/ip_vs_sync.c
#define SVER_MASK  0x0fff
/*
 *  Type 0, IPv4 sync connection format
 */
struct ip_vs_sync_v4 {
	__u8			type;
	__u8			protocol;	/* Which protocol (TCP/UDP) */
	__be16			ver_size;	/* Version msb 4 bits */
	/* Flags and state transition */
	__be32			flags;		/* status flags */
	__be16			state;		/* state info 	*/
	/* Protocol, addresses and port numbers */
	__be16			cport;
	__be16			vport;
	__be16			dport;
	__be32			fwmark;		/* Firewall mark from skb */
	__be32			timeout;	/* cp timeout */
	__be32			caddr;		/* client address */
	__be32			vaddr;		/* virtual address */
	__be32			daddr;		/* destination address */
	/* The sequence options start here */
	/* PE data padded to 32bit alignment after seq. options */
};

/*
     Sync Connection format (sync_conn)

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |    Type       |    Protocol   | Ver.  |        Size           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                             Flags                             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |            State              |         cport                 |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |            vport              |         dport                 |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                             fwmark                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                             timeout  (in sec.)                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                              ...                              |
      |                        IP-Addresses  (v4 or v6)               |
      |                              ...                              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  Optional Parameters.
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Param. Type    | Param. Length |   Param. data                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
      |                              ...                              |
      |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                               | Param Type    | Param. Length |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                           Param  data                         |
      |         Last Param data should be padded for 32 bit alignment |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/* Version 1 header */
struct ip_vs_sync_mesg {
	__u8			reserved;	/* must be zero */
	__u8			syncid;
	__be16			size;
	__u8			nr_conns;
	__s8			version;	/* SYNC_PROTO_VER  */
	__u16			spare;
	/* ip_vs_sync_conn entries start here */
};

/*
  The master mulitcasts messages (Datagrams) to the backup load balancers
  in the following format.

 Version 1:
  Note, first byte should be Zero, so ver 0 receivers will drop the packet.

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      0        |    SyncID     |            Size               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Count Conns  |    Version    |    Reserved, set to Zero      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                    IPVS Sync Connection (1)                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                            .                                  |
      ~                            .                                  ~
      |                            .                                  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                    IPVS Sync Connection (n)                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 Version 0 Header
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Count Conns  |    SyncID     |            Size               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    IPVS Sync Connection (1)                   |
*/


// include/uapi/linux/ip_vs.h
/* Bits allowed to update in backup server */
#define IP_VS_CONN_F_BACKUP_UPD_MASK (IP_VS_CONN_F_INACTIVE | \
				      IP_VS_CONN_F_SEQ_MASK)

/* Flags that are not sent to backup server start from bit 16 */
#define IP_VS_CONN_F_NFCT	(1 << 16)	/* use netfilter conntrack */

