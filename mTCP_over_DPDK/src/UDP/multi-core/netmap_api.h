#ifndef __NETMAP_API_H_
#define __NETMAP_API_H_

#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <atomic>
#include <ctype.h>	// isprint()
#include<condition_variable>
#include <map>
#include <mutex>
#include <pthread.h>
#include <string>
#include <thread>
#include <queue>
#include <stdbool.h>
#include <inttypes.h>
#include <syslog.h>
using namespace std;

//#define BUSY_WAIT
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

#ifdef linux
#define cpuset_t        cpu_set_t
#endif

//#include "pkt_hash.h"
#include "ctrs.h"
using namespace std;

#define SKIP_PAYLOAD		1 /* do not check payload. XXX unused */
#define MAX_QUEUE_SIZE		10000
#define MAX_BODYSIZE		2048
#define MAX_IFNAMELEN		64	/* our buffer for ifname */
#define MAX_BURST		1000
#define RECV_THREAD_COUNT	1
//#define MAX_CPUS		64
#define MAX_BUF_COUNT		500000


/*
 * use our version of header structs, rather than bringing in a ton
 * of platform specific ones
 */
#ifndef ETH_ALEN
#define ETH_ALEN 		6
#endif
#define MAX_BODYSIZE		2048

#define MAX_IFNAMELEN 		64
#define DEF_OUT_PIPES 		2
#define DEF_EXTRA_BUFS 		0
#define DEF_BATCH		2048
#define DEF_SYSLOG_INT		600
#define BUF_REVOKE		100
#ifndef __PKT_HASH__
#define __PKT_HASH__
/*---------------------------------------------------------------------*/
/**
 ** Packet header hashing function utility - This file contains functions
 ** that parse the packet headers and computes hash functions based on
 ** the header fields. Please see pkt_hash.c for more details...
 **/
/*---------------------------------------------------------------------*/
/* for type def'n */
#include <stdint.h>
/*---------------------------------------------------------------------*/
#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | \
		  (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | \
		  (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
        ((((unsigned long)(n) & 0xFF00)) << 8) | \
        ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
		  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
        ((((unsigned long)(n) & 0xFF00)) << 8) | \
        ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
		  ((((unsigned long)(n) & 0xFF000000)) >> 24))
/*---------------------------------------------------------------------*/
typedef struct vlanhdr {
	uint16_t pri_cfi_vlan;
	uint16_t proto;
} vlanhdr;
/*---------------------------------------------------------------------*/
/**
 ** Analyzes the packet header of computes a corresponding 
 ** hash function.
 **/
uint32_t
pkt_hdr_hash(const unsigned char *buffer,
	     uint8_t hash_split,
	     uint8_t seed);
/*---------------------------------------------------------------------*/
#endif /* __PKT_HASH__ */
struct pkthdr {
	struct ether_header eh;
	struct ip ip;
} __attribute__((__packed__));

struct udp_pkt {
	struct pkthdr pkthdr;
	struct udphdr udp;
	uint8_t body[MAX_BODYSIZE - sizeof(struct pkthdr) - sizeof(struct udphdr)];	// XXX hardwired
} __attribute__((__packed__));

struct tcp_pkt {
	struct pkthdr pkthdr;
	struct tcphdr tcp;
	uint8_t body[MAX_BODYSIZE - sizeof(struct pkthdr) - sizeof(struct tcphdr)];	// XXX hardwired
} __attribute__((__packed__));

struct thread_slot {
	uint32_t cur;
	uint32_t next;
	struct netmap_slot *txslot;
};

struct compact_eth_hdr {
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	u_int16_t h_proto;
};

struct compact_ip_hdr {
	u_int8_t ihl:4, version:4;
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
};

struct compact_ipv6_hdr {
	u_int8_t priority:4, version:4;
	u_int8_t flow_lbl[3];
	u_int16_t payload_len;
	u_int8_t nexthdr;
	u_int8_t hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

struct {
} glob_arg;

/*
 * the overflow queue is a circular queue of buffers
 */
struct overflow_queue {
	char name[MAX_IFNAMELEN];
	queue<netmap_slot> slots;
};

struct port_des {
	struct my_ctrs ctr;
	unsigned int last_sync;
	struct overflow_queue *oq;
	struct nm_desc *nmd;
	struct netmap_ring *ring;
};

struct recv_thread_arg {
	u_int id;
	char *ifname;
	struct nm_desc *parent_nmd;
};

uint16_t checksum(const void *data, uint16_t len, uint32_t sum);
u_int16_t wrapsum(u_int32_t sum);

class NetmapUse {
private:
	struct nm_desc *nmd;
	int wait_link;
	atomic_uint num_pkts;
	atomic_uint counts;
	atomic_uint countr;
	atomic_uint counts_thread;
	atomic_uint countr_thread;
	//thread thread_var_tx;
	thread thread_var_rx;
	thread receiver_threads[MAX_BURST];
	u_int bursts;
	u_int burstr;
	struct pollfd pfdi;
	struct pollfd pfdo;
	struct netmap_ring *rxring;
	struct netmap_slot *txslot;
	//struct netmap_slot *rxslot;
	size_t num_recv;
	
	atomic_uint countr_queue1_cur;
	atomic_uint countr_queue1_cur_sync;
	uint countr_queue1;
	uint countr_queue2;
	atomic_uint next_turn_recv;
	atomic_bool turn_over;
	
	uint8_t virt_header;
	
	char src_ip_addr[20];
	char src_eth_addr[20];
	
	mutex cs_netmap_sync;
	mutex cs_netmap_get_rx_buffer;
	
	u_int testcount;
	map<string,string> arptable;
	
	//New vars added
	int syslog_interval;

	uint64_t dropped;
	uint64_t forwarded;
	uint64_t non_ip;

	char ifname[MAX_IFNAMELEN];
	
	char send_ifname[MAX_IFNAMELEN];
	char send_pipes_ifname[MAX_IFNAMELEN];
	uint16_t send_output_rings;
	uint32_t send_extra_bufs;
	uint16_t send_batch;
	
	char recv_ifname[MAX_IFNAMELEN];
	char recv_pipes_ifname[MAX_IFNAMELEN];
	uint16_t recv_output_rings;
	uint32_t recv_extra_bufs;
	uint16_t recv_batch;
	
	vector<port_des> per_core_send_port;
	vector<pollfd> per_core_send_pfd;
	vector<int> per_core_counts;
	
	vector<port_des> per_core_recv_port;
	vector<pollfd> per_core_recv_pfd;
	vector<int> per_core_countr;
	
	thread stat_thread;
	u_int virt_hdr_len;
	atomic_uint recv_slave_start_count;
	bool safe_to_start_send;
	bool safe_to_start_recv;
	
	struct nm_desc *send_master_nmd;
	struct nm_desc *recv_master_nmd;	
	
	//vector<thread> recv_thread;
	thread send_thread;
	thread recv_thread;
	
public:
	atomic_uint do_abort;
	//atomic_uint cancel;
	struct netmap_ring *txring;
	atomic_long limit_pkt_main;
	atomic_long limit_pkt_netmap;
	
	void init_netmap();
	void open_netmap_dev(char *ifname);
	
	void * get_buffer_tx();
	void syncbuftx(struct udp_pkt *);
	void * get_buffer_tx(int coreid);
	void syncbuftx(int coreid);
	
	void * get_buffer_rx(int coreid, int &pktlen);
	void syncbufrx(int coreid);
	
	//void * get_buffer_rx(u_int &pos);
	//void syncbufrx(u_int pos);
	
	void thread_func_tx();
	void *per_core_send_packet(int coreid);
	
	int source_hwaddr(char *ifname);
	int setaffinity(pthread_t me, int i);
	char *ether_ntoa(const struct ether_addr *n);
	
	//New functions added
	
	void initialize_send_recv();
	void get_vnet_hdr_len(struct nm_desc *nmd);
	//void per_core_send_func(struct recv_thread_arg rta);
	void per_core_recv_funcc(struct recv_thread_arg rta);
	void per_core_recv_func(int coreid);
	void print_stats(struct port_des *ports);
	void free_buffers(vector<port_des> &ports);
	void *send_pkts_to_iface();
	void *receive_pkts_from_iface();
	
	NetmapUse();
	~NetmapUse();
	
	ssize_t get_udp_buffer_tx(struct sockaddr_in * src_addr, const struct sockaddr_in *dest_addr, const void *buf, size_t len);
	struct udp_pkt * get_udp_buffer_rx(u_int &pos);
	void initialize_packet(struct udp_pkt *pkt);
};

extern NetmapUse netmapuse;
#endif
