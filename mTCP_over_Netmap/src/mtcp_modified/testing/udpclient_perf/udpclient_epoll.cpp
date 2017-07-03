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
#include "mtcp_api.h"
#include "mtcp_epoll.h"
#include <iostream>
#include "cpu.h"
#include "debug.h"
#include "mudp_api.h"
#include "netmap_api.h"

#define MSB32				0x80000000
#define MSB16				0x8000
#define KEY_CACHE_LEN			96
#define SEED				'B' 
#define MAX_EVENTS 1024
#define MAX_THREADS 4
#define CLIENT_IP "169.254.9.13"
#define SERVER_IP "169.254.9.18"
#define SERVER_PORT 9999
#define CLIENT_START_PORT 5900

using namespace std;
/*----------------------------------------------------------------------------*/

struct arg{
	int id;
	int coreno;
	int portno;
};

pthread_t clients[MAX_THREADS];
struct arg arguments[MAX_THREADS];
int done[MAX_THREADS];
int portno;
/*----------------------------------------------------------------------------*/

vector < compute_stats > stats;
struct timeval begin_t;
struct timeval end_t;
bool safe_to_compute_tput = false;
uint64_t total;
double rate_t, diff_t;
atomic_uint safe_to_inc_burst;
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

/*----------------------------------------------------------------------------*/

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
void
SignalHandler(int signum)
{
	//Handle ctrl+C here
	app_level_stats();
	//mtcp_destroy();

	for(int i = 0;i<MAX_THREADS;i++){
		done[i] = 1;
	}
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

void clientThreadFunc(void* arg1){

	struct arg argument = *((struct arg*)arg1);
	int core = argument.coreno;
	int id = argument.id;
	int portno = argument.portno;
	//step 2. mtcp_core_affinitize
	mtcp_core_affinitize(core);

	//step 3. mtcp_create_context. Here order of affinitization and context creation matters.
	// mtcp_epoll_create

	mctx_t mctx = mtcp_create_context(core);
	if (!mctx) {
		TRACE_ERROR("Failed to create mtcp context!\n");
		return NULL;
	}
	else{
		TRACE_INFO("mtcp context created.\n");
	}
	/* create epoll descriptor */
	int ep = mtcp_epoll_create(mctx, MAX_EVENTS);
	if (ep < 0) {
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}

	//step 4. mtcp_socket, mtcp_setsock_nonblock,mtcp_bind
	int sockfd = mtcp_socket(mctx, AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}
	int ret = mtcp_setsock_nonblock(mctx, sockfd);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}

	struct sockaddr_in serveraddr,clientaddr;

	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	inet_aton(SERVER_IP, &serveraddr.sin_addr);
	serveraddr.sin_port = htons((unsigned short)SERVER_PORT);

	bzero((char *) &clientaddr, sizeof(clientaddr));
	clientaddr.sin_family = AF_INET;
	inet_aton(CLIENT_IP, &clientaddr.sin_addr);
	clientaddr.sin_port = htons((unsigned short)portno);

	ret = mtcp_bind(mctx, sockfd,(struct sockaddr *)&clientaddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	/* wait for incoming udp messages */
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLOUT;
	ev.data.sockid = sockfd;
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, sockfd, &ev);

	//step 6. mtcp_epoll_wait
	struct mtcp_epoll_event *events;
	int nevents;
	events = (struct mtcp_epoll_event *)calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}

	int pkt_counter = 0;
    int clientlen = sizeof(clientaddr);
    int serverlen = sizeof(serveraddr);
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

	cout << "Waiting for events" << endl;

	int n = mudp_sendto(mctx,sockfd, data, 1448, 0,
	       (struct sockaddr *) &serveraddr, serverlen);
    if (n < 0)
      printf("ERROR in sendto");

	while(!done[id]){
		/*
		n = mudp_sendto(mctx,sockfd, data, 1399, 0, (struct sockaddr *) &serveraddr, serverlen);
		
				

		if (n < 0){

			this_thread::yield();;
		}	
		if(safe_to_compute_tput) {
			stats[core].forwarded += 1399;
		}
		*/
		//printf("Sent %d\n",pkt_counter);
		
		
		nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);

		if (nevents < 0) {
			if (errno != EINTR)
				perror("mtcp_epoll_wait");
			break;
		}

		for(int i=0;i<nevents;i++) {

			if (events[i].events & MTCP_EPOLLOUT) {
				int n;
				//D("Epoll out");
				while(1)
				{
					n = mudp_sendto(mctx,sockfd, data, 1448, 0, (struct sockaddr *) &serveraddr, serverlen);

					if (n < 0){
						break;
					}

					pkt_counter++;
					//D("Sent %d",pkt_counter);
				}
			}
		}
		

	}

	//step 7
	//mtcp_destroy_context(mctx);
}

int main(int argc, char **argv){

	int core = 0;
	int ret = -1;
	//done = 0;

	if (argc != 2) {
       fprintf(stderr,"usage: <port>\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[1]);

    char* conf_file = "client.conf";
    /* initialize mtcp */
	if (conf_file == NULL) {
		TRACE_CONFIG("You forgot to pass the mTCP startup config file!\n");
		exit(EXIT_FAILURE);
	}
	else {
		TRACE_INFO("Reading configuration from %s\n",conf_file);
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
	stats.resize(MAX_THREADS);
	for(int i=0;i<MAX_THREADS;i++){
		memset(&stats[i], 0, sizeof(struct compute_stats));
		done[i] = 0;
	}
	vector <uint16_t> ports_vec(MAX_THREADS, 0);
	populate_ports(ports_vec, CLIENT_IP, SERVER_IP, CLIENT_START_PORT, SERVER_PORT);
	//spawn server threads
	for(int i=0;i<MAX_THREADS;i++){
		arguments[i].coreno = i;
		arguments[i].id = i;
		arguments[i].portno = ports_vec[i];
		pthread_create(&clients[i],NULL,clientThreadFunc,&arguments[i]);
	}

	safe_to_compute_tput = true;
	gettimeofday(&begin_t, NULL);
	//Wait for server threads to complete
	for(int i=0;i<MAX_THREADS;i++){
		pthread_join(clients[i],NULL);
	}

}
