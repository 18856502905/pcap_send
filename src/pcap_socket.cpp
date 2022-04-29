#include "pcap_socket.h"

extern pcap_conf p_conf;
p_socket::p_socket()
{
	
}


bool p_socket::set_server(uint8_t *pktdata)
{
	int ether_len;
	this->ethernet = (struct pcap_ethernet *)pktdata;
	if(ethernet->ether_type == htons(ETHERTYPE_IP) 
			|| ethernet->ether_type == htons(ETHERTYPE_IPV6)) {
		ether_len = SIZE_ETHERNET;
	} else if (ethernet->ether_type == htons(ETHERTYPE_8021Q)) {
		ether_len = SIZE_8021QVLAN + SIZE_ETHERNET;
	}

	if(ethernet->ether_type == ng_arch_bswap16(ETHERTYPE_IP))
	{
		this->ipv4 = ng_pktdata_mtod_offset(pktdata, struct pcap_ip*, ether_len);
	} else {
		this->ipv6 = ng_pktdata_mtod_offset(pktdata, struct pcap_ipv6*, ether_len);
	}
}

bool p_socket::init_pci_dev()
{
	if(p_conf.pcap_dev_name[0])
	{
		if ((socket_fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {//第一次创建socket是为了获取本地网卡信息
        	perror ("socket() failed to get socket descriptor for using ioctl() ");
        	exit (EXIT_FAILURE);
    	}
		memset (&ifr, 0, sizeof (ifr));
    	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", p_conf.pcap_dev_name);
		
    	if (ioctl (socket_fd, SIOCGIFHWADDR, &ifr) < 0) {
       		perror ("ioctl() failed to get source MAC address ");
       		return false;
    	}
   		close(socket_fd);
		
		memset (&device, 0, sizeof (device));
    	if ((device.sll_ifindex = if_nametoindex (p_conf.pcap_dev_name)) == 0) 
		{
        	perror ("if_nametoindex() failed to obtain interface index ");
    	}
    	printf ("Index for interface %s is %i\n", p_conf.pcap_dev_name, device.sll_ifindex);

		device.sll_family = AF_PACKET;
    	memcpy (device.sll_addr, ifr.ifr_hwaddr.sa_data, 6);
    	device.sll_halen = htons (6);

		if ((socket_fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {//创建正真发送的socket
        	perror ("socket() failed ");
        	return false;
    	}

	}
	return true;
}

void p_socket::handle_pktData(const unsigned char *pktData, uint32_t packet_len)
{

	if(sendto(socket_fd, pktData, packet_len, 0, (struct sockaddr *) &device, sizeof (device)) <= 0)
	{
		send_fail++;
	} else {
		send_success++;
	}
}

p_socket::~p_socket()
{
	
}


