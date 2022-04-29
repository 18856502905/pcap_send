#ifndef __PCAP_CONFIG_H__
#define __PCAP_CONFIG_H__

#include "pcap_util.h"

const char config_name[]="../config/pcap_send.conf";

typedef struct _PCAP_CONF
{
	char pcap_file_name[MAX_NAME_LEN];
	//char pcap_ether_name[MAX_NAME_LEN];
	char pcap_dev_name[MAX_NAME_LEN];
	uint64_t  pcap_send_speed;
	uint8_t   pcap_cycl_send;  
	uint8_t	  pcap_enable;
	uint8_t   pcap_cpu_num;
	int   	  pcap_bind_cpu[MAX_CPU_CORE];

	uint8_t   dpdk_enable;

	_PCAP_CONF(){
		pcap_enable = 1;
		pcap_cycl_send = 1;
	}
	
}pcap_conf;

bool get_config();

#endif