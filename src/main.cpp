#include <stdio.h>
#include <stdint.h>
#include "pcap_util.h"
#include "pcap_config.h"
#include "pcap_cap.h"
#include "pcap_thread.h"
#include "pcap_socket.h"

pcap_conf p_conf;

cap_send *c_send[10];
uint8_t pcap_thread_num;
bool send_exit=false;
time_t	  sec_time_var = 0;
uint32_t  tv_usec;

void show_help()
{
	
	printf("Usage:\n");
	printf("---------\n");
	printf("      ./pcap_send [options] gara ....\n");
	printf("      **Pcap and network adapter must be configured**\n\n");
	printf("options\n");
	printf("       -r Cycle to send\n");
	printf("       -w Files to read\n");
	printf("       -t Add a parameter to indicate shorthand\n");
	printf("       -i Select the specified network adapter\n");
	printf("       -m Select a mode to enable\n\n");
}


int calc_thread_num(int send_speed, uint64_t &limit_last)
{
	int thread_num = send_speed / MAX_SEND_PACKAGE;
	limit_last = send_speed % MAX_SEND_PACKAGE;

	if(limit_last || send_speed == 0)
		return thread_num + 1;
	else
		return thread_num;
}

bool pcap_start()
{
	if(!p_conf.pcap_enable)
	{
		return false;
	}
	uint64_t limit_last = 0;
	uint8_t thread_num = calc_thread_num(p_conf.pcap_send_speed, limit_last);
	pcap_thread_num = thread_num;
	for(int i = 0; i < thread_num; ++i)
	{
		if(thread_num == i + 1)
		{
			limit_last = limit_last > 0 ? limit_last : MAX_SEND_PACKAGE;
			c_send[i] = new cap_send(limit_last);
		} else {
			c_send[i] = new cap_send(MAX_SEND_PACKAGE);
		}

		if(i < thread_num)
		{
			c_send[i]->setcore_id(p_conf.pcap_bind_cpu[i]);
		}

		if(!c_send[i]->set_file_list())
		{
			return false;
		}
		if(!c_send[i]->init_pci_dev())
		{
			return false;
		}

		c_send[i]->Start();
		
	}
	return true;
}

bool dpdk_start()
{
	if(!p_conf.dpdk_enable)
	{
		return true;
	}

	
	
}

bool log_show()
{
	timeval tv_count;
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 1;
	struct tm datetime;
	char tbuf_HMS[16];
	uint8_t head_sign = 64;
	uint64_t pcap_send_success = 0;
	uint64_t pcap_send_fail = 0;
	uint64_t pcap_send_fail_last[10] = {0};
	uint64_t pcap_send_success_last[10] = {0};
	
	while(!send_exit)
	{
		gettimeofday(&tv_count, NULL);
		tv_usec = tv_count.tv_usec;
		int32_t pre_usec;
		localtime_r(&tv_count.tv_sec, &datetime);
		strftime(tbuf_HMS, 16, "%H:%M:%S", &datetime);

		if(sec_time_var != tv_count.tv_sec)
		{
			if(head_sign >= 64)
			{
				head_sign = 0;
				if(p_conf.pcap_enable)
				{
					printf("[ %s ]: pcap_send_success pcap_send_fail \n", tbuf_HMS);
				}

#ifdef DPDK_ENABLE
				if(p_conf.dpdk_enable)
				{
					printf("[ %s ]: dpdk_send_success dpdk_send_fail \n", tbuf_HMS);
				}
#endif
			}
			if(pcap_thread_num)
			{
				for(int idx = 0; idx < pcap_thread_num; idx++)
				{
					pcap_send_success += RST_STAT(c_send[idx]->send_success, pcap_send_success_last[idx]);
					pcap_send_success_last[idx] += RST_STAT(c_send[idx]->send_success, pcap_send_success_last[idx]);
					pcap_send_fail += RST_STAT(c_send[idx]->send_fail, pcap_send_fail_last[idx]);
					pcap_send_fail_last[idx] += RST_STAT(c_send[idx]->send_fail, pcap_send_fail_last[idx]);
					
				}
				printf("[ %s ]: %17llu %14llu \n", tbuf_HMS, pcap_send_success, pcap_send_fail);
			}

			pcap_send_fail = 0;
			pcap_send_success = 0;
			
			head_sign++;
			sec_time_var = tv_count.tv_sec;
		} else {
			//same, then sleep a moment
			if (pre_usec == tv_usec)
			{
				nanosleep(&ts, NULL);
			}
		}
	}
	return true;
}


void parse_option(int argc, char** argv, int *gc_flag)
{
	uint8_t opt = 0;
	while ((opt = getopt(argc, argv, "hw:t::i:m::")) != -1)
	{
		switch (opt) 
		{
			case 'h':
				show_help();
				exit(0);
			case 'w':
				strncpy(p_conf.pcap_file_name, optarg, MAX_NAME_LEN);
				(*gc_flag)++;
				break;
			case 'r':
				p_conf.pcap_cycl_send = atoi(optarg);
				break;
			case 't':
				p_conf.pcap_send_speed = atoi(optarg);
				break;
			case 'i':
				strncpy(p_conf.pcap_dev_name, optarg, MAX_NAME_LEN);
				(*gc_flag)++;
				break;
			case 'm':
				if(!strcasecmp(optarg, "pcap")){
					p_conf.pcap_enable = 1;
				} else if(!strcasecmp(optarg, "dpdk")){
					p_conf.dpdk_enable = 1;
				}
				else{
					printf("mode read error!");
					exit(0);
				}
				break;
			default:
				fprintf(stderr, "Invalid option: -%c\n", opt);
				return;

		}
	}
}

int main(int argc, char *argv[])
{
	int gc_flag = 0;

	//set_default_gara();
	if(argc > 1)
	{
		parse_option(argc, argv, &gc_flag);
	}
	if(0 != gc_flag)
	{
		if(!p_conf.pcap_file_name[0])
		{
			printf("not config pcap file!\n");
		}
	}
	if(0 == gc_flag)
	{
		if(!get_config())
		{
			printf("get config fail!\n");
		}
	}

	if(!pcap_start())
	{
		printf("pcap send fail!\n");
		return -1;
	}

	if(!dpdk_start())
	{
		printf("dpdk send fail!\n");
	}

	if(!log_show())
	{
		printf("log init fail!\n");
	}
	
}
