	
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <iostream>
#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include <strings.h>
#include <vector>
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
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ip.h>      /* ether_aton */
#include <netinet/ether.h>      /* ether_aton */
#include "netmap_api.h"
#include "cpu.h"
#include "debug.h"

using namespace std;

#define MSB32				0x80000000
#define MSB16				0x8000
#define KEY_CACHE_LEN			96
#define SEED				'B' 
#define CLIENT_IP			"169.254.9.13"
#define SERVER_IP			"169.254.9.18"
#define SERVER_PORT			9999
#define CLIENT_START_PORT		5900
#define MQ_NIC				0

#define MAX_EVENTS 1024
#define MAX_THREADS 4

struct arg{
	int id;
	int coreno;
	int portno;
};

/*----------------------------------------------------------------------------*/

pthread_t clients[MAX_THREADS];
struct arg arguments[MAX_THREADS];
int done[MAX_THREADS];
char *hostname;

vector < compute_stats > stats;
struct timeval begin_t;
struct timeval end_t;
bool safe_to_compute_tput = false;
uint64_t total;
double rate_t, diff_t;
atomic_uint safe_to_inc_burst;
int mq_ports[6][6] = {{5900}, {5900, 5902}, {5900, 5904, 5901}, {5900, 5902, 5901, 5903}, {5901, 5947, 5903, 5900, 5905}, {5900, 5910, 5901, 5902, 5904, 5903}};

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

void 
CloseConnection(mctx_t mctx, int ep, int sockid)
{
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
	mtcp_close(mctx, sockid);
}

void app_level_stats() {

	gettimeofday(&end_t, NULL);
	diff_t = (end_t.tv_sec - begin_t.tv_sec) + 
              ((end_t.tv_usec - begin_t.tv_usec)/1000000.0);
	
	for(int i=0;i<MAX_THREADS;i++){
		total+= stats[i].forwarded;
	}
	
	rate_t = (total*8) / (diff_t*1024*1024*1024);
	D("Rate in Gbps: %lf", rate_t);
	
}

void populate_ports(vector<uint16_t> &ports_vec, const char *src_ip, const char *dest_ip, const uint16_t sport, const uint16_t dport) {
	struct in_addr src,dest;
	uint32_t num_cores = 0, find_core;
	inet_aton(CLIENT_IP, &src);
	inet_aton(SERVER_IP, &dest);
	uint32_t sip = ntohl(src.s_addr);
	uint32_t dip = ntohl(dest.s_addr);
	
	for (uint16_t i = 0; i < 10000; i++) {
		find_core = sym_hash_fn(sip,dip,CLIENT_START_PORT+i+SEED,SERVER_PORT+SEED)%MAX_THREADS;
		if (!ports_vec[find_core]) {
			num_cores++;
			ports_vec[find_core] = CLIENT_START_PORT+i;
			if (num_cores == MAX_THREADS) {
				return;
			}
		}
	}
}

void
SignalHandler(int signum)
{
	//Handle ctrl+C here
	netmapuse.do_abort = 1;
	for(int i = 0;i<MAX_THREADS;i++){
		done[i] = 1;	
	}
	app_level_stats();
}

void *clientThreadFunc(void* arg1){
	
	struct arg argument = *((struct arg*)arg1);
	int core = argument.coreno; 
	int id = argument.id;
	int portno = argument.portno;
	//step 2. mtcp_core_affinitize
	mtcp_core_affinitize(core);
	D("Coreno = %d, Port no = %d", core, portno);
	//step 3. mtcp_create_context. Here order of affinitization and context creation matters.
	// mtcp_epoll_create
	
	mctx_t mctx = mtcp_create_context(core);
	if (!mctx) {
		TRACE_ERROR("Failed to create mtcp context!\n");
		return NULL;
	}

	sleep(10);
	/* create epoll descriptor */
	int ep = mtcp_epoll_create(mctx, MAX_EVENTS);
	if (ep < 0) {
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}
	
	//step 4. mtcp_socket, mtcp_setsock_nonblock,mtcp_bind
	int sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if (sockid < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		return;
	}
	int ret = mtcp_setsock_nonblock(mctx, sockid);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return;
	}
	
	struct sockaddr_in saddr;
	
	saddr.sin_family = AF_INET;
	inet_aton(CLIENT_IP ,&saddr.sin_addr);
	saddr.sin_port = htons(portno);
	
	ret = mtcp_bind(mctx, sockid,(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	struct sockaddr_in daddr;
	
	daddr.sin_family = AF_INET;
	daddr.sin_addr.s_addr = inet_addr(hostname);
	daddr.sin_port = htons(SERVER_PORT);
	ret = mtcp_connect(mctx, sockid, (struct sockaddr *)&daddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			perror("mtcp_connect");
			mtcp_close(mctx, sockid);
			return;
		}
	}
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLOUT;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, sockid, &ev);
	
	//step 6. mtcp_epoll_wait
	struct mtcp_epoll_event *events;
	int nevents;
	events = (struct mtcp_epoll_event *)calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}
	int newsockfd = -1;
	int burst_increased = 0;
	
	char data[DATA_LEN] = "netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
		"netmap pkt-gen DIRECT payload\n"
		"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload";
		
	ret = mtcp_write(mctx, sockid, data, DATA_LEN);
					
	if (ret < 0) {
		TRACE_APP("Connection closed with server.\n");
	}
	
	struct timeval begin_t;
	struct timeval end_t;
	
	int packets_sent = 0;
	int latency_sum = 0;
	double diff_t;
	
	while(!done[core]){
		nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
		
		if (nevents < 0) {
			if (errno != EINTR)
				perror("mtcp_epoll_wait");
			break;
		}
		for(int i=0;i<nevents;i++) {
			if (events[i].events & MTCP_EPOLLOUT) {
				ret = mtcp_write(mctx, sockid, data, DATA_LEN);
					
				if (ret < 0) {
					TRACE_APP("Connection closed with server.\n");
					break;
				}
					
				if(safe_to_compute_tput) {
					stats[core].forwarded += ret;
				}
			}	
		}
	}
	CloseConnection(mctx,ep,sockid);
	return NULL;

}
/*----------------------------------------------------------------------------*/

int main(int argc, char **argv){
	
	int core = 0;
	int ret = -1;
	cpu_set_t cpu_set;
	
	if (argc != 3) {
       fprintf(stderr,"usage: <hostname> <port>\n", argv[0]);
       exit(0);
    }
    hostname = argv[1];
    
    char* conf_file = "client.conf";
    /* initialize mtcp */
	if (conf_file == NULL) {
		TRACE_CONFIG("You forgot to pass the mTCP startup config file!\n");
		exit(EXIT_FAILURE);
	}

	//step 1. mtcp_init, mtcp_register_signal(optional)
	ret = mtcp_init(conf_file);
	if (ret) {
		TRACE_CONFIG("Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}
	
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);
	
	TRACE_INFO("Application initialization finished.\n");
	
	for(int i=0;i<MAX_THREADS;i++){
		done[i] = 0;
	}
	
	struct in_addr src,dest;
	inet_aton(CLIENT_IP, &src);
	inet_aton(SERVER_IP, &dest);
	uint32_t sip		= ntohl(src.s_addr);
	uint32_t dip		= ntohl(dest.s_addr);
	
	stats.resize(MAX_THREADS);
	
	for(int i=0;i<MAX_THREADS;i++){
		memset(&stats[i], 0, sizeof(struct compute_stats));
	}
	
	vector <uint16_t> ports_vec(MAX_THREADS, 0);
	populate_ports(ports_vec, CLIENT_IP, SERVER_IP, CLIENT_START_PORT, SERVER_PORT);
	
	//spawn server threads
	for(int i=0;i<MAX_THREADS;i++){
		if (!MQ_NIC) {
			arguments[i].coreno = i;
			cout<<"Connection from core "<<arguments[i].coreno<<endl;
			arguments[i].id = arguments[i].coreno;
			arguments[i].portno = ports_vec[i]; 
			pthread_create(&clients[i],NULL,clientThreadFunc,&arguments[i]);
		} else {
			arguments[i].coreno = i;
			cout<<"Connection from core-mq "<<arguments[i].coreno<<endl;
			arguments[i].id = arguments[i].coreno;
			arguments[i].portno = mq_ports[MAX_THREADS-1][i]; //TODO: Determine port no according to four tuple functionlity.
			pthread_create(&clients[i],NULL,clientThreadFunc,&arguments[i]);
			CPU_ZERO(&cpu_set);
			CPU_SET(arguments[i].coreno, &cpu_set);
			int rc = pthread_setaffinity_np(clients[i], sizeof(cpu_set_t), &cpu_set);
			if(rc!=0) {
				D("Unable to set affinity: %s", strerror(errno));
				return;
			} else {
			   for (int j = 0; j < CPU_SETSIZE; j++)
			       if (CPU_ISSET(j, &cpu_set)) {
				   D("CPU %d set for %u\n", j, arguments[i].coreno);
			       }
			}
		}
	}
	
	sleep(60);
	
	safe_to_compute_tput = true;
	gettimeofday(&begin_t, NULL);
	
	//Wait for server threads to complete
	for(int i=0;i<MAX_THREADS;i++){
		pthread_join(clients[i],NULL);		
	}
	return 0;
}
