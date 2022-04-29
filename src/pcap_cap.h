#ifndef __PCAP_CAP_H__
#define __PCAP_CAP_H__
#include "pcap_thread.h"
#include "pcap_socket.h"

class cap_send :public p_thread, public p_socket
{

	public:
		cap_send(int limit);
		bool set_file_list();

	private:
		FILE_NODE *file_list;
		FILE_NODE *cur_node;

	protected:
		uint64_t limit;
		virtual void Run();
};

#endif
