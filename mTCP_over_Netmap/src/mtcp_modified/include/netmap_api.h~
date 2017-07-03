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
#include <list>
#include <stdbool.h>
#include <inttypes.h>
#include <syslog.h>

#include <sparsehash/dense_hash_map>
#include <sparsehash/dense_hash_set>
#include <concurrentqueue.h>
#include <unordered_map>

using namespace std;
using google::dense_hash_map;
using google::dense_hash_set;

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
#include <time.h>
#include <sys/time.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ip.h>      /* ether_aton */
#include <netinet/ether.h>      /* ether_aton */
#include <libcuckoo/cuckoohash_map.hh>

#ifdef linux
#define cpuset_t        cpu_set_t
#endif

using namespace std;

#define MAX_BODYSIZE			2048		/* Max capacity in bytes of netmap buffer */
#define MAX_IFNAMELEN			32		/* our buffer for ifname */
#define SEND_PIPES_IFNAME		"vale0:1" 	/* Send netmap pipes interface */
#define RECV_PIPES_IFNAME		"vale1:1" 	/* Receive netmap pipes interface */
//#define BUSY_WAIT					/* If polling is NOT used for packet send/receive */

#define MAX_BATCH_SEND			4		/*** Packet send batch ***/
#define MAX_BATCH_RECV			128		/*** Packet receive batch ***/
#define DATA_LEN			1448 		/*** Payload length ***/
#define NO_OF_SAFE_ITR			20000		/*** Iterations after which ethernet layer statistics are computed ***/
//#define OPT_FOR_SINGLE_CORE				/*** For multi-queue operations ***/	
#define IFNAME				"netmap:eth4" 	/*** vNIC interface ***/
#define N_MINUS_1_CONFIG		0 		/*** One core kernel bypass ***/
#define N_MINUS_2_CONFIG		1 		/*** Two core kernel bypass ***/

/*
 * use our version of header structs, rather than bringing in a ton
 * of platform specific ones
 */
#ifndef ETH_ALEN
#define ETH_ALEN 			6
#endif

#define BUF_REVOKE			100
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

// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint32_t sender_ip;
  uint8_t target_mac[6];
  uint32_t target_ip;
} __attribute__((__packed__));
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

/* Ethernet header + IP header */
struct pkthdr {
	struct ether_header eh;
	struct ip ip;
} __attribute__((__packed__));

/* ARP packet */
struct arp_pkt {
	struct ether_header eh;
	arp_hdr ah;
} __attribute__((__packed__));

/* UDP packet */
struct udp_pkt {
	struct pkthdr pkthdr;
	struct udphdr udp;
	uint8_t body[MAX_BODYSIZE - sizeof(struct pkthdr) - sizeof(struct udphdr)];	// XXX hardwired
} __attribute__((__packed__));

/* TCP packet */
struct tcp_pkt {
	struct pkthdr pkthdr;
	struct tcphdr tcp;
	uint8_t body[MAX_BODYSIZE - sizeof(struct pkthdr) - sizeof(struct tcphdr)];	// XXX hardwired
} __attribute__((__packed__));

/* Ethernet header */
struct compact_eth_hdr {
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	u_int16_t h_proto;
};

/*
 * the overflow queue is a circular queue of buffers
 */
struct overflow_queue {
	char name[MAX_IFNAMELEN];
	queue<netmap_slot> slots;
};

/* Netmap port description */
struct port_des {
	struct nm_desc *nmd;
	struct netmap_ring *ring;
	struct overflow_queue *oq;
};

/* Ethernet layer statistics */
struct compute_stats {
	uint64_t dropped;
	uint64_t forwarded;
};

/* New ARP entries */
struct ip_mac_pair {
	uint32_t ip;
	struct ether_addr mac;
};

uint16_t checksum(const void *data, uint16_t len, uint32_t sum);
u_int16_t wrapsum(u_int32_t sum);

#ifdef	OPT_FOR_SINGLE_CORE
/* For multi-core operations */
class NetmapUse {
private:
	char src_eth_addr[20];
	struct in_addr src_ip;
	
	cuckoohash_map < uint32_t, struct ether_addr > arptable;

	vector < dense_hash_set < uint32_t >* > pending_arp_req;
	vector < dense_hash_map < uint32_t, uint32_t >* > pending_arp_req_retries;
	vector < list < tcp_pkt >* > deferred_packets;
	
	uint32_t cores_available;
	
	struct timeval begin_time_send;
	struct timeval begin_time_recv;
	struct timeval end_time;
	
	uint16_t send_output_rings;
	
	uint16_t recv_output_rings;
	
	uint64_t send_iter;
	vector<int> per_core_counts;
	vector < compute_stats > send_stats;
	vector<port_des> per_core_send_port;
	
	uint64_t recv_iter;
	vector<int> per_core_countr;
	vector < compute_stats > recv_stats;
	vector<port_des> per_core_recv_port;
	
	u_int virt_hdr_len;	
public:
	u_int do_abort;
	
	NetmapUse();
	~NetmapUse();
	
	char *ether_ntoa(const struct ether_addr *n);
	int source_hwaddr(const char *ifname);
	void get_vnet_hdr_len(struct nm_desc *nmd);
	
	void initialize_send_recv();
	void free_buffers(vector<port_des> &ports);
	
	void prepare_arp_packet(arp_pkt *arp_pkt, const uint32_t &src_ip, const uint32_t &dest_ip, ether_addr &src_mac, ether_addr &dest_mac, uint16_t htype);
	
	void * get_buffer_tx(int coreid);
	void syncbuftx(int coreid);
	
	void * get_buffer_rx(int coreid, int &pktcount);
	void syncbufrx(int coreid);
};

#else
/* For netmap threads based operations */
class NetmapUse {
private:
	char src_ip_addr[20];
	char src_eth_addr[20];
	struct in_addr src_ip;
	
	dense_hash_map < uint32_t, struct ether_addr > arptable;
	
	dense_hash_set < uint32_t > pending_arp_req_th;
	dense_hash_map < uint32_t, uint32_t > pending_arp_req_retries_th;
	list < tcp_pkt > deferred_packets_th;

	moodycamel::ConcurrentQueue <ip_mac_pair> new_arp_entries_th;
	moodycamel::ConcurrentQueue <uint32_t> enqueued_arp_req_th;
	
	uint32_t cores_available;
	
	struct timeval begin_time_send;
	struct timeval begin_time_recv;
	struct timeval end_time;
	
	uint16_t send_output_rings;
	
	uint16_t recv_output_rings;
	
	uint32_t recv_extra_bufs;
	
	struct nm_desc *send_master_nmd;
	vector<int> per_core_counts;
	vector < compute_stats > send_stats;
	vector<port_des> per_core_send_port;
	
	struct nm_desc *recv_master_nmd;
	vector<int> per_core_countr;
	vector < compute_stats > recv_stats;
	vector<port_des> per_core_recv_port;
	
	u_int virt_hdr_len;
	
	thread send_thread;
	thread recv_thread;
	
public:
	u_int do_abort;
	
	NetmapUse();
	~NetmapUse();
	
	char *ether_ntoa(const struct ether_addr *n);
	int source_hwaddr(const char *ifname);
	void get_vnet_hdr_len(struct nm_desc *nmd);
	
	void initialize_send_recv();
	void free_buffers(vector<port_des> &ports);
	
	void prepare_arp_packet(arp_pkt *arp_pkt, const uint32_t &src_ip, const uint32_t &dest_ip, ether_addr &src_mac, ether_addr &dest_mac, uint16_t htype);
	
	void * get_buffer_tx(int coreid);
	void syncbuftx(int coreid);
	
	void * get_buffer_rx(int coreid, int &pktcount);
	void syncbufrx(int coreid);
	
	void *send_pkts_to_iface();
	void *receive_pkts_from_iface();
};
#endif
extern NetmapUse netmapuse;
#endif
