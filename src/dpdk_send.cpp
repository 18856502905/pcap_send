#include "dpdk_send.h"

extern pcap_conf p_conf;

uint8_t DpdkPortId;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

bool dpdk_send::eal_init()
{
	uint64_t core_mask;
	char *option[OPT_MAX];
	for(int i = 0; i < OPT_MAX; i++)
	{
		option[i] = (char*)malloc(OPT_LEN);
	}

	for(int j = 0; j < p_conf.dpdk_cpu_num; j++)
	{
		core_mask |= (uint64_t)1 << p_conf.dpdk_bind_cpu[j];
	}
	strncpy(option[0], "dpdk_send", OPT_LEN);
	snprintf(option[1], "-c0x%" PRIx64 "", core_mask);
	snprintf(option[2], "-n4");
	snprintf(option[3], "--file-prefix=.dpdk_send");

	int option_num = 4;
	
	if(rte_eal_init(option_num, option) < 0)
	{
		printf("rte_eal_init error!\n");
		return false;
	}
	return true;
}

bool dpdk_send::memory_init()
{
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", BUF_SIZE,
							0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (!mbuf_pool)
	{
		rte_panic("Cannot create mbuf pool\n");
        return false;
	}
}

bool dpdk_send::port_init()
{
	uint16_t nb_sys_ports = rte_eth_dev_count_avail();  //判断端口是否可用
	if(0 == nb_sys_ports)
	{
		rte_panic("not found avail dev!\n");
		return false;
	}
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(DpdkPortId, &dev_info);

	const int num_rx_queues = 1;
	const int num_tx_queues = 1;

	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(DpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
	
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;

	if(rte_eth_tx_queue_setup(DpdkPortId, 0 ,512,
				rte_eth_dev_socket_id(DpdkPortId), &txq_conf) < 0)
	{
		rte_panic("tx_queue setup error!\n");
		return false;
	}
	
		
}

void dpdk_send::init()
{
	bool ret = true;
	if(!eal_init())
	{
		printf("eal_init error!\n");
		ret = false;
		return ret;
	}
	if(!memory_init())
	{
		printf("memory_init error!\n");
		ret = false;
		return ret;
	}
	if(!port_init())
	{
		printf("port_init error!\n");
		ret = false;
		return ret;
	}

	return ret;
}

void dpdk_send::Run()
{
	
}

