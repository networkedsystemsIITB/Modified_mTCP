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
#include "dpdk_api.h"

#define MAX_EVENTS 1024
#define MAX_THREADS 3
#define BUFSIZE 1400

#define CLIENT_IP "169.254.9.3"
#define SERVER_IP "169.254.9.8"
#define SERVER_PORT 9999
#define CLIENT_PORT 5900

using namespace std;
/*----------------------------------------------------------------------------*/

struct arg{
	int id;
	int coreno;
};

pthread_t servers[MAX_THREADS];
struct arg arguments[MAX_THREADS];
int done[MAX_THREADS];
int portno;
/*----------------------------------------------------------------------------*/
time_t start_app,end_app;
double rate=0;
double sec=0;
double packets[7]={0,0,0,0,0,0,0};

void
SignalHandler(int signum)
{
	//Handle ctrl+C here
	time(&end_app);
	sec = difftime(end_app,start_app);
	for(int i=0;i<MAX_THREADS;i++){
		rate+=packets[i];
	}
//	rate=packets[0]+packets[1]+packets[2];
	rate = ((rate*8)/(sec*1024*1024*1024));
	printf("#Application level: rate:%lfGbps, time%lf \n",rate,sec);
	fflush(stdout);
	signal_handler_dpdk(signum);
	sleep(25);
	mtcp_destroy();
	for(int i = 0;i<MAX_THREADS;i++){
		done[i] = 1;	
	}
	sleep(25);
}
bool connect_done[7] = {false,false,false,false,false,false,false};
char *name[7] = {"transfer0","transfer1","transfer2","transfer3","transfer4","transfer5","transfer6"};

void serverThreadFunc(void* arg1){

	struct arg argument = *((struct arg*)arg1);
	int core = argument.coreno;
	int id = argument.id;
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
	//D("Socket: %d",sockfd);
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
	clientaddr.sin_port = htons((unsigned short)CLIENT_PORT);

	ret = mtcp_bind(mctx, sockfd,(struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	/* wait for incoming udp messages */
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = sockfd;
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, sockfd, &ev);

	//step 6. mtcp_epoll_wait
	struct mtcp_epoll_event *events;
	int nevents;
	int newsockfd = -1;
	events = (struct mtcp_epoll_event *)calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}

	int pkt_counter = 0;
    char buf[BUFSIZE];
    int clientlen = sizeof(clientaddr);
    //char *buf1 = "hell";

    /*
    int n = mudp_sendto(mctx,sockfd, buf1, strlen(buf1), 0,(struct sockaddr *) &clientaddr, clientlen);
    if (n < 0)
    	printf("ERROR in sendto");

	*/
    cout << "Waiting for events" << endl;
    bzero(buf, BUFSIZE);
    int n;
    /*
    while(!done[id]){
    	int n = mudp_recvfrom(mctx,sockfd, buf, BUFSIZE, 0,(struct sockaddr *) &clientaddr, &clientlen);
		if (n < 0)
		  printf("ERROR in recvfrom");

		pkt_counter++;
		if(n > 0) stats[core].forwarded += BUFSIZE;
		//printf("server received %d/%d bytes: %s %d\n", strlen(buf), n, buf,pkt_counter);
    }*/

    while(!done[id]){
		nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);

		if (nevents < 0) {
			if (errno != EINTR)
				perror("mtcp_epoll_wait");
			break;
		}

		for(int i=0;i<nevents;i++) {

			if (events[i].events & MTCP_EPOLLIN) {

				while(1){
					n = mudp_recvfrom(mctx,sockfd, buf, BUFSIZE, 0,
						 (struct sockaddr *) &clientaddr, &clientlen);
					if (n <= 0){
					  //printf("ERROR in recvfrom\n");
					  break;
					}

					//pkt_counter++;
					packets[core] += n;

					//printf("server received %d/%d bytes: %s %d\n", strlen(buf), n, buf,pkt_counter);
				}
			}
		}
	}

	//step 7
	mtcp_destroy_context(mctx);
}

int main(int argc, char **argv){
	
	//int core = 0;
	int ret = -1;
	//done = 0;
	
	dpdkuse_ins.init_dpdkapi(argc,argv);    
	portno = 9999;
    
	char* conf_file = "main.conf";
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
	for(int i=0;i<MAX_THREADS;i++){
		done[i] = 0;
	}
	//spawn server threads
	for(int i=0;i<MAX_THREADS;i++){
		arguments[i].coreno = i;
		arguments[i].id = i;
		pthread_create(&servers[i],NULL,serverThreadFunc,&arguments[i]);
	}
	//while(connect_done[0]==false);// || connect_done[1]==false || connect_done[2]==false || connect_done[3]==false);// || connect_done[4]==false || connect_done[5]==false);
	time(&dpdkuse_ins.before);
	time(&start_app);
	//sleep(25);
	//Wait for server threads to complete
	for(int i=0;i<MAX_THREADS;i++){
		pthread_join(servers[i],NULL);
		//sleep(25);		
	}
	sleep(25);
}
