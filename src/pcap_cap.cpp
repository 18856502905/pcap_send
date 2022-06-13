#include "pcap_cap.h"

extern pcap_conf p_conf;

cap_send::cap_send(int limit)
{
	this->limit = limit;
}

bool cap_send::set_file_list()
{
	bool is_cap = false;
	if (strstr(p_conf.pcap_file_name, ".cap") || strstr(p_conf.pcap_file_name, ".pcap"))
	{
		is_cap = true;
	}

	int len = strlen(p_conf.pcap_file_name);
	if(is_cap)
	{
		if (len >= 1024)
		{
			printf("cap file_list exceed max_len 1024\n");
			return false;
		}
		char * token;
		char * nexttoken;
		int num = 0;

		file_list = NULL;
		token = strtok_r(p_conf.pcap_file_name, ";", &nexttoken);
		while(token)
		{
			FILE_NODE *insert_node  = (FILE_NODE *)calloc(1, sizeof(FILE_NODE));
			strcpy(insert_node->file_name, token);
			if (!file_list)
			{
				file_list = (FILE_NODE *)&insert_node->node;
			}
			else
			{
				NODE *nxt_node = (NODE*)file_list->node.next;
				file_list->node.next = &insert_node->node;
				insert_node->node.next = nxt_node;
			}

			token = strtok_r(NULL, ";", &nexttoken);
		}
	}
	else
	{
		DIR * dir;
		struct dirent * ent;

		dir = opendir(p_conf.pcap_file_name);
		if(!dir)
		{
			printf("faileld to open cap path '%s'\n", p_conf.pcap_file_name);
			return false;
		}
		while(NULL != (ent = readdir(dir)))
		{
			if(0 == strcmp(ent->d_name, ".") || 0 == strcmp(ent->d_name, ".."))
			{
				continue;
			}
			if((strstr(ent->d_name,".cap") == NULL) && (NULL == strstr(ent->d_name,".pcap")))
				continue;
			int nameLen=strlen(ent->d_name);

			if((memcmp(&ent->d_name[nameLen-5], ".pcap",5) != 0) && (memcmp(&ent->d_name[nameLen-4], ".cap",4) != 0))
				continue;
			FILE_NODE *insert_node  = (FILE_NODE *)calloc(1, sizeof(FILE_NODE));
			strncpy(insert_node->file_name, p_conf.pcap_file_name, MAX_NAME_LEN);
			int str_len = strlen(insert_node->file_name);
			if (insert_node->file_name[str_len-1] != '/')
				insert_node->file_name[str_len] = '/';
			strcat(insert_node->file_name, ent->d_name);
			if (!file_list)
			{
				file_list = (FILE_NODE *)&insert_node->node;
			}
			else
			{
				NODE *nxt_node = (NODE*)file_list->node.next;
				file_list->node.next = &insert_node->node;
				insert_node->node.next = nxt_node;
			}

		}
		closedir(dir);
	}
	return true;
}

void cap_send::Run()
{
	bool run_exit = false;
	
	struct timespec next_time;
	uint32_t min_gap = this->limit > 0 ? 1000000000L / this->limit : 0;
	clock_gettime(CLOCK_MONOTONIC, &next_time);
	cur_node = file_list;
	if(!cur_node)
	{
		printf("no pcap file found\n!");
		return;
	}

	char errBuff[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr pktHeader;
	const unsigned char *pktData = NULL;
	pcap_t *handle;

	while(!run_exit)
	{
		while(cur_node)
		{
			handle = pcap_open_offline(cur_node->file_name, errBuff);
			if(!handle)
			{
				cur_node = (FILE_NODE*)cur_node->node.next;
				if(!cur_node)
				{
					if(0 == p_conf.pcap_cycl_send)
					{
						printf("pcap open error!\n");
						return;	
					} else {
						cur_node = file_list;
					}
				}
				continue;
			}
			
			pktData = pcap_next(handle, &pktHeader);
			while(pktData)
			{

				if(min_gap)
				{
					struct timespec now_mo;

					clock_gettime(CLOCK_MONOTONIC, &now_mo);
					if(now_mo.tv_sec < next_time.tv_sec ||
						(now_mo.tv_sec == next_time.tv_sec && now_mo.tv_nsec < next_time.tv_nsec))
					{
						clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_time, NULL);
					}
					next_time.tv_nsec += min_gap;
					if(next_time.tv_nsec >= 1000000000)
					{
						next_time.tv_nsec -= 1000000000;
						next_time.tv_sec++;
					}
				}
			
				
				uint16_t packet_len = pktHeader.caplen;
				
				handle_pktData(pktData, packet_len);
				pktData = pcap_next(handle, &pktHeader);
			}
			//set_server(pktData);
		}
	}
	
}

