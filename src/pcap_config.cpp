#include "pcap_config.h"


extern pcap_conf p_conf;

bool file_check(const char *config_name)
{
	if(!config_name)
		return false;
	int rc = 0;
	rc = access(config_name, F_OK);
	if(rc == -1)
		return false;
	else
		return true;
	
}

bool cpu_check(int core_id)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "/sys/devices/system/cpu/cpu%d", core_id);

    if(access(buf, F_OK))
    {
        return false;
    }
	
    return true;
}


bool cpulist_anal(IN const char *field_name, IN char *field_val,
        OUT uint8_t &cpu_num, OUT int *cpu_list)
{
    char * token;
    char * nexttoken;
    int core_id;
    cpu_num = 0;

    token = strtok_r(field_val, ";", &nexttoken);
    while(token)
    {
        if(cpu_num >= MAX_CPU_CORE)
        {
            break;
        }

        core_id = atoi(token);
        if (!cpu_check(core_id))
        {
            printf("Error: %s invalid core id '%d'!\n", field_name, core_id);
            return false;
        }

        cpu_list[cpu_num++] = core_id;
        token = strtok_r(NULL, ";", &nexttoken);
    }

    return true;
}


bool get_config()
{
	if (!file_check(config_name))
	{
		printf("config_name not exits!");
	}
	char buf[READ_SIZE] = {0};
	char *surplus_buf = NULL;
	FILE *cf_fp = fopen(config_name, "r");
	while(fgets(buf, READ_SIZE, cf_fp))
	{
		if('#' == *buf)
		{
			continue;
		}
		char* key = strtok_r(buf, "=", &surplus_buf);
		if(!key)
			continue;
		char *value = strtok_r(NULL, "\n", &surplus_buf);
		
		
		if(!strcasecmp(key, "pcap_enable") && value)
		{
			p_conf.pcap_enable = atoi(value);
		}
		else if(!strcasecmp(key, "pcap_src_file") && value)
		{
			if(!value[0] || !value)
			{
				perror("pcap file not match!\n");
				return false;
			}
			strncpy(p_conf.pcap_file_name, value, MAX_NAME_LEN);
		}
		else if(!strcasecmp(key, "pcap_cycl_send") && value)
		{
			p_conf.pcap_cycl_send = atoi(value);
		}
		else if(!strcasecmp(key, "pcap_send_speed") && value)
		{
			p_conf.pcap_send_speed = atoi(value);
		}
		else if(!strcasecmp(key, "pcap_dev_name") && value)
		{
			if(!value[0] || !value)
			{
				perror("pci device not match!\n");
				return false;
			}
			strncpy(p_conf.pcap_dev_name, value, MAX_NAME_LEN);
		}
		else if(!strcasecmp(key, "pcap_bind_core") && value)
		{
			if (!cpulist_anal("pcap_bind_core", value,
                       p_conf.pcap_cpu_num, p_conf.pcap_bind_cpu))
            {
                fclose(cf_fp);
                return false;
            }
		}


		else if(!strcasecmp(key, "pcap_dev_name") && value)
		{
			p_conf.dpdk_enable = atoi(value);
		}
	}
	return true;
}


