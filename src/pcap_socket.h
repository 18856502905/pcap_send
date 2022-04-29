#ifndef __PCAP_SOCKET_H__
#define __PCAP_SOCKET_H__
#include "pcap_util.h"
#include "pcap_config.h"

class p_socket
{
	public:
		p_socket();
		~p_socket();
	
		void handle_pktData(const unsigned char *pktData, uint32_t packet_len);
		bool set_server(uint8_t *pktdata);
		bool init_pci_dev();

		uint64_t send_success;
		uint64_t send_fail;
			
	protected:
		int socket_fd;
		struct pcap_ethernet *ethernet;
		struct pcap_ip   *ipv4;
		struct pcap_ipv6 *ipv6;
		struct ifreq ifr;
		pcap_t *handle;
		struct sockaddr_ll device;
		
};

#endif
