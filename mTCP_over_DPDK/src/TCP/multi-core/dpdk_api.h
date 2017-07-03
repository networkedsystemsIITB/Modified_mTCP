#ifndef __DPDK_API_H_
#define __DPDK_API_H_

#include <unistd.h>
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_arp.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <string>
#include <map>
#include <set>

using namespace std;


//1KB vs 2KB
#define OPT_KB 0 //0 means one Kernel bypass thread and 1 means two Kernel bypass threads

//This machine IP (example 169.254.9.8)
#define MY_IP_1 169
#define MY_IP_2 254
#define MY_IP_3 9
#define MY_IP_4 8


//Other machine's IP (example 169.254.9.3)
/*#define OTH_IP_1 169
#define OTH_IP_2 254
#define OTH_IP_3 9
#define OTH_IP_4 3

//Other machine's mac (example 02.00.00.00.00.02)
#define OTH_MAC_1 0x02
#define OTH_MAC_2 0x00
#define OTH_MAC_3 0x00
#define OTH_MAC_4 0x00
#define OTH_MAC_5 0x00
#define OTH_MAC_6 0x02
*/
#define RTE_LOGTYPE_DPDKAPI RTE_LOGTYPE_USER1

#define NB_MBUF 8192
#define MEMPOOL_CACHE_SIZE 250
#define MAX_PKT_BURST 1024
#define MAX_PKT_BURST_RING 4096

#define ARP_RING 1024
#define PENDING_PKT_RING 4096

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 0 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 32 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define RTE_TEST_RX_DESC_DEFAULT 4096 // HW NIC RX queue size
#define RTE_TEST_TX_DESC_DEFAULT 4096 // HW NIC TX queue size

static volatile bool force_quit;

//extern void dump_payload(struct rte_mbuf *_p,int len);
extern void signal_handler_dpdk(int signum);

struct ip_mac {
	uint32_t ip;
	struct ether_addr mac;
} __rte_cache_aligned;

/* Per-lcore configuration */
struct lcore_queue_conf {
	struct rte_ring *rx_queue;
	struct rte_ring *tx_queue;
	struct rte_ring *pending_pkts;
	uint64_t camehere;
} __rte_cache_aligned;

/* Per-lcore port statistics struct (maintained by application at dpdk level)*/
struct lcore_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t dropped;
} __rte_cache_aligned;

/* port statistics by maintained by device */
struct initial_eth_dev_stats{
	unsigned portid;
	uint64_t ipkt;
	uint64_t opkt;
	uint64_t ierr;
	uint64_t oerr;
	uint64_t mbuferr;
	uint64_t q_ipkt0;
	uint64_t q_opkt0;
	uint64_t q_err0;
} __rte_cache_aligned;

//in case of 1 KB thread option, this method will creates a single thread handling both RX and TX functionality whereas in case of 2 KB thread option it creates a thread handling just the RX functionality.
int dpdkapi_launch_one_lcore(void *dummy);
// This is used only in case of 2 KB thread option to create a TX thread.
int dpdkapi_launch_one_lcore1(void *dummy);

class DPDKUse {
private:
	/* No of Rx/Tx descriptor for h/w queues of NIC used */
	uint16_t nb_rxd;
	uint16_t nb_txd;

	/* Rx/Tx Queues configuration for per core */
	struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

	/* mask of enabled ports */
	uint32_t dpdkapi_enabled_port_mask;

	/* If multiple ports are dpdk enabled which port application runs on */
	unsigned enabled_port;

	/* ethernet address of enabled port */
	struct ether_addr dpdkapi_port_eth_addr;

	/*Memory Pool (set of pre-allocated packet buffers)*/
	struct rte_mempool *dpdkapi_pktmbuf_pool;

	/* Per-lcore port statistics struct (maintained by application)*/
	struct lcore_port_statistics port_statistics[RTE_MAX_LCORE];

	/* port statistics by maintained by device */
	struct initial_eth_dev_stats my_init_eth_dev_stats;
	
	/* NIC Configuration used during initialization*/
	struct rte_eth_conf port_conf;

	/* HW NIC queue configuration */
	struct rte_eth_rxconf rx_conf;
	struct rte_eth_txconf tx_conf;

	pthread_t rx_thread;
	pthread_t tx_thread;

	map<uint32_t,struct ether_addr> arp_table; //maintains arp entry

	struct rte_ring *add_entry_arp_table; //Rx thread uses this queue to inform tx thread for handling incoming arp response
	struct rte_ring *generate_arp_response; //Rx thread uses this queue to inform tx thread for handling incoming arp request

	set<uint32_t> pending_arp_req; //used by Tx thread for keeping track of how many arp request send and its waiting for their arp response

public:
	unsigned rxtx_lcore_id; //Maintains the core ID on which the KB thread runs (usually the last core provided to the application)
	uint64_t coremask; 
	time_t before;

	DPDKUse();

	//~DPDKUse();
	void release(void);

	/* functions invoked by dpdkapi_launch_one_lcore and dpdkapi_launch_one_lcore1 */
	void dpdkapi_main_loop(void);
	void dpdkapi_main_loop1(void);

	/* Parse the portmask given in the command line of the application */
	int dpdkapi_parse_portmask(const char *portmask);
	
	/* Parse the argument given in the command line of the application */
	int dpdkapi_parse_args(int argc, char **argv);

	/* initialize DPDK layer data structures for use */
	void init_dpdkapi(int argc, char **argv);

	/* tx functions */
	/* --------------------- */

	/* mtcp layer thread calls this to get empty packet for transmit data */
	struct rte_mbuf * get_buffer_tx();
	
	/* buffer tx packet before sending to NIC */
	void addBufferToRing(struct rte_mbuf * pkt, unsigned lcore_id);

	/* TX Functionality: Used in case of 2 KB option to send buffered tx packets to NIC. These packets are accesed from per core TX ring in round-robin order */
	void tx_main_loop(unsigned);

	/* --------------------- */


	/* rx functions */
	/* --------------------- */

	/* Polls NIC, filters read packets and redirect them to rx_queue ring of the output core (which is obtained using soft RSS). In case of 1 KB option this function would also handle TX Functionality */
	void rx_main_loop(unsigned);

	/* per-core mtcp thread calls this to read packets from the respective rx_queue ring */
	struct rte_mbuf * get_buffer_rx(unsigned lcore_id);

	/* per-core mtcp thread call this to get number of packets to be read from the rx_queue */
	int32_t get_rx_count(unsigned);

	/* --------------------- */


	/* print functions */
	/* --------------------- */

	/* dpdk level statistics (RX/TX rate) */
	void print_main_loop(unsigned);

	/* port (NIC) level statistics */
	void print_stats_main_loop();
	
	/* --------------------- */


	/* Check the link status of the enabled port in up to 9s, and print them finally */
	void check_port_link_status();

	/* copy buf data to pkt starting from offset to (offset + len) if len <= pkt->data_len */
	void copy_buf_to_pkt(void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset);

	/* display usage */
	void dpdkapi_usage(const char *prgname);
};

/* Global object used by MTcp thread for creating interface between DPDK layer and upper layers and used for DPDK intialization in the application */
extern DPDKUse dpdkuse_ins;
#endif

