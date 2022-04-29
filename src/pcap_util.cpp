#include "pcap_util.h"
	

uint16_t ng_arch_bswap16(uint16_t _x)
{
	return (_x >> 8) | ((_x << 8) & 0xff00);
}


uint32_t ng_arch_bswap32(uint32_t _x)
{
	return (_x >> 24) | ((_x >> 8) & 0xff00) | ((_x << 8) & 0xff0000) |
		((_x << 24) & 0xff000000);
}


uint64_t ng_arch_bswap64(uint64_t _x)
{
	return (_x >> 56) | ((_x >> 40) & 0xff00) | ((_x >> 24) & 0xff0000) |
	((_x >> 8) & 0xff000000) | ((_x << 8) & (0xffULL << 32)) |
	((_x << 24) & (0xffULL << 40)) |
	((_x << 40) & (0xffULL << 48)) | ((_x << 56));
}






