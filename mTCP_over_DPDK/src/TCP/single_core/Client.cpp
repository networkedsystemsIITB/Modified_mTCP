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
#include "dpdk_api.h"
#include "cpu.h"
#include "debug.h"
#include <time.h>

#define MAX_EVENTS 2048

using namespace std;
int done;
mctx_t mctx;
/*----------------------------------------------------------------------------*/
void
SignalHandler(int signum)
{
	//Handle ctrl+C here
	signal_handler_dpdk(signum);
	mtcp_destroy_context(mctx);	
	mtcp_destroy();
	done = 1;
}
/*----------------------------------------------------------------------------*/

int main(int argc, char **argv){

	float packets=0, sec=0;
	clock_t before;

	float rate;
	
	int core = 0;
	int ret = -1;
	done = 0;
	dpdkuse_ins.init_dpdkapi(argc,argv);
	/*if (argc != 3) {
       fprintf(stderr,"usage: <hostname> <port>\n", argv[0]);
       exit(0);
    }*/
    char* hostname = "169.254.9.8";//argv[1];
    int portno = 9999;//atoi(argv[2]);
    
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
	
	//step 2. mtcp_core_affinitize
	mtcp_core_affinitize(core);
	
	//step 3. mtcp_create_context. Here order of affinitization and context creation matters.
	// mtcp_epoll_create
	
	mctx = mtcp_create_context(core);
	if (!mctx) {
		TRACE_ERROR("Failed to create mtcp context!\n");
		return NULL;
	}

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
		return -1;
	}
	ret = mtcp_setsock_nonblock(mctx, sockid);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}
	
	struct sockaddr_in saddr,daddr;
	saddr.sin_family = AF_INET;
	//saddr.sin_addr.s_addr = INADDR_ANY;
	inet_aton("169.254.9.3",&saddr.sin_addr);
	saddr.sin_port = htons(portno);

	daddr.sin_family = AF_INET;
	daddr.sin_addr.s_addr = inet_addr(hostname);
	daddr.sin_port = htons(portno);

	ret = mtcp_bind(mctx, sockid,(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the socket!\n");
		return -1;
	}	
	cout << "Trying to connect." << endl;
	ret = mtcp_connect(mctx, sockid, (struct sockaddr *)&daddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			perror("mtcp_connect");
			mtcp_close(mctx, sockid);
			return -1;
		}
	}
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
	char data[1448]; //1420
	uint64_t lSize=1448;
	time(&dpdkuse_ins.before);
	//dpdkuse_ins.before = clock();	
	dpdkuse_ins.count = 128;
	while(!done){
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
				//dpdkuse_ins.tx_app = clock();
				//packets += rd;
				if (rd <= 0) {
					return rd;
				}
				//cout << (c++) << " -- " << rd << endl;
			}	
		}
		/*sec = (float)(clock() - before)/(float)CLOCKS_PER_SEC;
		if(sec>=10){
			
			//printf("sec = %f\n",sec);
			rate = ((float)packets*8)/((float)sec*(1024*1024*1024));
			printf("\n------------------\n Application packet rate (Gbps):%f Gb:%f sec:%f\n------------------\n\n", rate,((packets*8)/(1024*1024*1024)),sec);
			//printf("\n------------------\n%lu Application packet b:%f sec:%f\n------------------\n\n",i,(packets*8),sec);
			packets=0;
			before = clock();
			//dpdkuse_ins.print_stats_main_loop(0);
			//i++;
		}*/
	}
	//sleep(5);
	
}
