	
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
//#include <net/ethernet.h>
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
//#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
//#include <netinet/udp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ip.h>      /* ether_aton */
//#include <netinet/ether.h>      /* ether_aton */
#include "dpdk_api.h"
#include <sys/time.h>
#include <sched.h>

using namespace std;

#define MSB32				0x80000000
#define MSB16				0x8000
#define KEY_CACHE_LEN			96
#define SEED				'B' 
#define CLIENT_IP			"169.254.9.3"
//"192.168.100.3"
#define SERVER_IP			"169.254.9.8"
//"192.168.100.2"
#define SERVER_PORT			9999
#define CLIENT_START_PORT		5900

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

#include "cpu.h"
#include "debug.h"

#define MAX_EVENTS 2048
#define MAX_THREADS 3

using namespace std;

struct arg{
	int id;
	int coreno;
	int portno;
};

pthread_t clients[MAX_THREADS];
struct arg arguments[MAX_THREADS];
int done[MAX_THREADS];

int ports[MAX_THREADS];
bool isPortSet[MAX_THREADS];
//atomic_uint safe_to_inc_burst;
//int portno;
char *hostname;

/*----------------------------------------------------------------------------*/
void
SignalHandler(int signum)
{
	signal_handler_dpdk(signum);
	sleep(5);
	//Handle ctrl+C here
	mtcp_destroy();
	for(int i = 0;i<MAX_THREADS;i++){
		done[i] = 1;	
	}
	//sleep(25);
}

bool connect_done[3] = {false,false,false};

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

	//sleep(10);
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
	//inet_aton("192.168.100.3",&saddr.sin_addr);
	inet_aton("169.254.9.3",&saddr.sin_addr);
	
	//saddr.sin_addr.s_addr = inet_aton("169.254.9.3",saddr.sin_addr.);
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
	printf("connection done %d\n",core);

	/*char *buf = "hello";
	ret = mtcp_write(mctx, sockid, buf, 5);
	if (ret < 0) {
		TRACE_CONFIG("Connection closed with client.\n");
	}*/
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN;
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
	char data[1448];
	int lSize = 1448;//1448;
	connect_done[core]=true;
//	time(&dpdkuse_ins.before);
	while(!done[id]){
		nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
		
		if (nevents < 0) {
			if (errno != EINTR)
				perror("mtcp_epoll_wait");
			break;
		}
		for(int i=0;i<nevents;i++) {
			if (events[i].events & MTCP_EPOLLIN) {
				//receive data over new connection
				//bzero(data,1024);
				int rd = mtcp_read(mctx, sockid, data, lSize);
				if (rd <= 0) {
					return;
				}
				//cout << rd << " " << core << "|";
			}	
		}
	}
	
	mtcp_destroy_context(mctx);	

}

void populatePorts(uint32_t sip, uint32_t dip){
	bool result=false;
	int coreid=0;
	int i=0;
	while(!result){
		coreid = sym_hash_fn(sip,dip,CLIENT_START_PORT+i+SEED,SERVER_PORT+SEED)%MAX_THREADS;
		if(!isPortSet[coreid]){
			ports[coreid]=CLIENT_START_PORT+i;
			isPortSet[coreid]=true;
		}
		result = isPortSet[0];
		for(int j=1;j<MAX_THREADS;j++)
			result = (result && isPortSet[j]);
		i++;
	}
}

/*----------------------------------------------------------------------------*/

int main(int argc, char **argv){
	
	int core = 0;
	int ret = -1;
	//done = 0;
		dpdkuse_ins.init_dpdkapi(argc,argv);

    hostname = "169.254.9.8";//"192.168.100.2";
    //int portno = atoi(argv[2]); TODO: Port no will be statically allocated for clients.
    
    char* conf_file = "main.conf";
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
		isPortSet[i]=false;
	}

	struct in_addr src,dest;
	inet_aton(CLIENT_IP, &src);
	inet_aton(SERVER_IP, &dest);
	uint32_t sip		= ntohl(src.s_addr);
	uint32_t dip		= ntohl(dest.s_addr);
	
	populatePorts(sip,dip);

	//spawn server threads
	for(int i=0;i<MAX_THREADS;i++){
		//if(i==0){
			arguments[i].portno = ports[i];//5900;
			arguments[i].coreno = sym_hash_fn(sip,dip,ports[i]+SEED,SERVER_PORT+SEED)%MAX_THREADS;
			cout<< arguments[i].portno << "Connection from core "<<arguments[i].coreno<<endl;
			arguments[i].id = arguments[i].coreno;
			//arguments[i].portno = CLIENT_START_PORT+i==5916?5979:CLIENT_START_PORT+i; //TODO: Determine port no according to four tuple functionlity.
		/*}
		if(i==1){
			arguments[i].portno = 5902;
			//arguments[i].coreno = 0;
			arguments[i].coreno = sym_hash_fn(sip,dip,5902+SEED,SERVER_PORT+SEED)%MAX_THREADS;
			arguments[i].id = arguments[i].coreno;
		cout<<"Connection from core "<<arguments[i].coreno<<endl;
		}
		if(i==2){
			arguments[i].portno = 5905;
			//arguments[i].coreno = 0;
			arguments[i].coreno = sym_hash_fn(sip,dip,5905+SEED,SERVER_PORT+SEED)%MAX_THREADS;
			arguments[i].id = arguments[i].coreno;
		cout<<"Connection from core "<<arguments[i].coreno<<endl;
		}
		if(i==3){
			arguments[i].portno = 5908;
			//arguments[i].coreno = 0;
			arguments[i].coreno = sym_hash_fn(sip,dip,5908+SEED,SERVER_PORT+SEED)%MAX_THREADS;
			arguments[i].id = arguments[i].coreno;
		cout<<"Connection from core "<<arguments[i].coreno<<endl;
		}
		if(i==4){
			arguments[i].portno = 5909;
			//arguments[i].coreno = 0;
			arguments[i].coreno = sym_hash_fn(sip,dip,5909+SEED,SERVER_PORT+SEED)%MAX_THREADS;
			arguments[i].id = arguments[i].coreno;
		cout<<"Connection from core "<<arguments[i].coreno<<endl;
		}
		if(i==5){
			arguments[i].portno = 5915;
			//arguments[i].coreno = 0;
			arguments[i].coreno = sym_hash_fn(sip,dip,5915+SEED,SERVER_PORT+SEED)%MAX_THREADS;
			arguments[i].id = arguments[i].coreno;
		cout<<"Connection from core "<<arguments[i].coreno<<endl;
		}
		/*if(arguments[i].portno==5979) {
			arguments[i].coreno = arguments[i].id = 0;
		}*/
		pthread_create(&clients[i],NULL,clientThreadFunc,&arguments[i]);
	}
	//while(connect_done[0]==false || connect_done[1]==false);// || connect_done[2]==false);
	printf("connection done and now starting timer\n");
	time(&dpdkuse_ins.before);
	//sleep(25);
	//Wait for server threads to complete
	for(int i=0;i<MAX_THREADS;i++){
		pthread_join(clients[i],NULL);
		//sleep(25);		
	}
	sleep(25);
}
