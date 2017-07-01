#include<iostream>
#include<assert.h>

/* Make Linux headers choose BSD versions of some of the data structures */
#define __FAVOR_BSD

/* for types */
#include <sys/types.h>
/* for [n/h]to[h/n][ls] */
#include <netinet/in.h>
/* iphdr */
#include <netinet/ip.h>
/* ipv6hdr */
#include <netinet/ip6.h>
/* tcphdr */
//#include <netinet/tcp.h>
/* udphdr */
//#include <netinet/udp.h>
#include <linux/udp.h>
/* eth hdr */
#include <net/ethernet.h>
/* for memset */
#include <string.h>
#include <netinet/ip.h>      /* ether_aton */
#include <netinet/in.h>
#include <unistd.h>	// sysconf()
#include <ifaddrs.h>	/* getifaddrs */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>    
#include <arpa/inet.h>	/* ntohs */
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
//#include <netinet/udp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ip.h>      /* ether_aton */
#include <netinet/ether.h>      /* ether_aton */

using namespace std;

#define MSB32				0x80000000
#define MSB16				0x8000
#define KEY_CACHE_LEN			96
#define SEED				'B' 
#define CLIENT_IP			"169.254.9.3"
#define SERVER_IP			"169.254.9.8"
#define SERVER_PORT			9999
#define CLIENT_START_PORT		5900
#define ITERATIONS			100
#define NUM_CORES			4

/*---------------------------------------------------------------------*/
/**
 *  * The cache table is used to pick a nice seed for the hash value. It is
 *   * built only once when sym_hash_fn is called for the very first time
 *    */
static void
build_sym_key_cache(uint32_t *cache, int cache_len)
{
	static const uint8_t key[] = {
		0x50, 0x6d, 0x50, 0x6d,
                0x50, 0x6d, 0x50, 0x6d,
                0x50, 0x6d, 0x50, 0x6d,
                0x50, 0x6d, 0x50, 0x6d,
                0xcb, 0x2b, 0x5a, 0x5a,
		0xb4, 0x30, 0x7b, 0xae,
                0xa3, 0x2d, 0xcb, 0x77,
                0x0c, 0xf2, 0x30, 0x80,
                0x3b, 0xb7, 0x42, 0x6a,
                0xfa, 0x01, 0xac, 0xbe};
	
        uint32_t result = (((uint32_t)key[0]) << 24) |
                (((uint32_t)key[1]) << 16) |
                (((uint32_t)key[2]) << 8)  |
                ((uint32_t)key[3]);
	
        uint32_t idx = 32;
        int i;
	
        for (i = 0; i < cache_len; i++, idx++) {
                uint8_t shift = (idx % (sizeof(uint8_t) * 8));
                uint32_t bit;
		
                cache[i] = result;
                bit = ((key[idx/(sizeof(uint8_t) * 8)] << shift) 
		       & 0x80) ? 1 : 0;
                result = ((result << 1) | bit);
        }
}

/*---------------------------------------------------------------------*/
/**
 ** Computes symmetric hash based on the 4-tuple header data
 **/
static uint32_t
sym_hash_fn(uint32_t sip, uint32_t dip, uint16_t sp, uint32_t dp)
{

	uint32_t rc = 0;
	int i;
	static int first_time = 1;
	static uint32_t key_cache[KEY_CACHE_LEN] = {0};
	
	if (first_time) {
		build_sym_key_cache(key_cache, KEY_CACHE_LEN);
		first_time = 0;
	}
	
	for (i = 0; i < 32; i++) {
                if (sip & MSB32)
                        rc ^= key_cache[i];
                sip <<= 1;
        }
        for (i = 0; i < 32; i++) {
                if (dip & MSB32)
			rc ^= key_cache[32+i];
                dip <<= 1;
        }
        for (i = 0; i < 16; i++) {
		if (sp & MSB16)
                        rc ^= key_cache[64+i];
                sp <<= 1;
        }
        for (i = 0; i < 16; i++) {
                if (dp & MSB16)
                        rc ^= key_cache[80+i];
                dp <<= 1;
        }

	return rc;
}

int main() {
	int i, portno;
	struct in_addr src,dest;
	inet_aton(CLIENT_IP, &src);
	inet_aton(SERVER_IP, &dest);
	uint32_t sip		= ntohl(src.s_addr);
	uint32_t dip		= ntohl(dest.s_addr);
	uint16_t sport		= CLIENT_START_PORT;
	uint32_t dport		= SERVER_PORT;
	for(i=0;i<100;i++) {
		cout<<"Map Client port "<<sport+i<<" to core "<<sym_hash_fn(sip,dip,sport+i+SEED,dport+SEED)%NUM_CORES<<endl;
	}
	
	return 0;
}
