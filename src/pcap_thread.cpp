#include "pcap_thread.h"

p_thread::p_thread()
{
	
}

bool p_thread::bindCore()
{
    if (cpu_bind_cpu >= 0)
    {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_bind_cpu, &cpuset);
        if (pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset))
        {
            printf("!Error: bind thread [%lu] to cpu-%d failed\n", tid, cpu_bind_cpu);
            return false;
        }
        else
        {
            char thread_name[32];
            snprintf(thread_name, sizeof(thread_name), "lcore-slave-%d", cpu_bind_cpu);
            pthread_setname_np(tid, thread_name);

            return true;
        }
    }

    return false;
}


void *p_thread::threadFun(void *argv)
{
	p_thread *pth_info = (p_thread*)argv;

	pth_info->bindCore();
	pth_info->Run();

	pthread_exit(NULL);
}

bool p_thread::Start()
{
	int ret = pthread_create(&tid, NULL, threadFun, this);
	if(0 == ret)
	{
		ret = pthread_detach(tid);
		if(0 == ret)
		{
			return true;
		}
	} else {
		return false;		
	}
	return true;
}

void p_thread::setcore_id(int core_id)
{
	this->cpu_bind_cpu = core_id;
}

p_thread::~p_thread()
{
	
}



