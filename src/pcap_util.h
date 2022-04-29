#ifndef __PCAP_UTIL_H__
#define __PCAP_UTIL_H__


#include <stdint.h>
#include <sys/time.h>
#include <pcap.h>
#include <stdio.h>
#include <pthread.h>
#include <net/if.h> 
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>



#define MAX_NAME_LEN      256
#define READ_SIZE         256
#define MAX_SEND_PACKAGE  100000
#define MAX_CPU_CORE      24
#define SNAP_LEN          65535


#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#define RST_STAT(m, n) (m - n)

#define ng_pktdata_mtod_offset(m, t, o)	\
	((t)((uint8_t *)(m) + (o)))

#ifndef SIZE_ETHERNET 
#define SIZE_ETHERNET 14
#endif

#ifndef SIZE_8021QVLAN 
#define SIZE_8021QVLAN 4
#endif

#ifndef ETHER_ADDR_LEN 
#define ETHER_ADDR_LEN	6
#endif

#ifndef ETHERTYPE_IP
#define	ETHERTYPE_IP		0x0800
#endif

#ifndef ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6		0x86dd
#endif

#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q		0x8100
#endif



typedef struct
{
	void *next;
	void *prev;
}NODE;

typedef struct
{
	NODE node;
	char file_name[MAX_NAME_LEN];
	FILE *fp;
}FILE_NODE;

struct pcap_ethernet
{
	u_char  ether_dhost[ETHER_ADDR_LEN];
	u_char  ether_shost[ETHER_ADDR_LEN];
	uint16_t ether_type;
}__attribute__((__packed__));

struct pcap_ip
{
	u_char  ip_vhl;
	u_char  ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	#define IP_RF 0x8000
	#define IP_DF 0x4000
	#define IP_MF 0x2000
	#define IP_OFFMASK 0x1fff
	u_char  ip_ttl;
	u_char  ip_p;
	u_short ip_sum;
	struct  in_addr ip_src,ip_dst;
}__attribute__((__packed__));

struct pcap_ipv6 {
	uint32_t vtc_flow;
	uint16_t payload_len;
	uint8_t  proto;
	uint8_t  hop_limits;
	uint8_t  src_addr[16];
	uint8_t  dst_addr[16];
}__attribute__((__packed__));


uint16_t ng_arch_bswap16(uint16_t _x);
uint32_t ng_arch_bswap32(uint32_t _x);
uint64_t ng_arch_bswap64(uint64_t _x);


#endif 
