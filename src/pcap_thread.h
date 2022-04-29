#ifndef __PCAP_THREAD_H__
#define __PCAP_THREAD_H__
#include "pcap_util.h"

class p_thread
{
	private:
		
	public:
		p_thread();
		~p_thread();

		void setcore_id(int core_id);
		bool Start();
			
	protected:
		uint8_t   cpu_bind_cpu;
		pthread_t tid;

		static void *threadFun(void *arg);
		bool bindCore();
		virtual void Run() = 0;
};

#endif
