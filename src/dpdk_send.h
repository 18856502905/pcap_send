#ifndef __DPDK_SEND_H__
#define __DPDK_SEND_H__

#define OPT_MAX 6
#define OPT_LEN 128

class dpdk_send : public p_thread
{
public:
	dpdk_send();
	~dpdk_send();
	void init();
	bool eal_init();
	bool memory_init();
	bool port_init();
	virtual void Run();

	rte_mempool *mbuf_pool;
	
};
#endif
