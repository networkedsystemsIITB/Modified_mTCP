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
#include <iostream>
#include "cpu.h"
#include "debug.h"
#include <sys/time.h>
#include <sched.h>

#define MAX_EVENTS 2048
#define MAX_THREADS 3
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
		printf("mtcp context created.\n");
	}
	/* create epoll descriptor */
	int ep = mtcp_epoll_create(mctx, MAX_EVENTS);
	if (ep < 0) {
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}
	
	//step 4. mtcp_socket, mtcp_setsock_nonblock,mtcp_bind
	int listener = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}
	int ret = mtcp_setsock_nonblock(mctx, listener);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}
	
	struct sockaddr_in saddr;
	
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = inet_addr("169.254.9.8");//inet_addr("192.168.100.2");//INADDR_ANY;
	saddr.sin_port = htons(portno);
	
	ret = mtcp_bind(mctx, listener,(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	//step 5. mtcp_listen, mtcp_epoll_ctl
	/* listen (backlog: 4K) */
	ret = mtcp_listen(mctx, listener, 4096);
	if (ret < 0) {
		TRACE_ERROR("mtcp_listen() failed!\n");
		return -1;
	}
		
	/* wait for incoming accept events */
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, listener, &ev);
	
	//step 6. mtcp_epoll_wait
	struct mtcp_epoll_event *events;
	int nevents;
	int newsockfd = -1;
	events = (struct mtcp_epoll_event *)calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}
	cout << "Waiting for events" << endl;

	FILE * pFile;
	long lSize;
	char * data;
	size_t result;
	
	pFile = fopen ( name[core] , "rb" );
	if (pFile==NULL) {fputs ("File error",stderr); exit (1);}

	// obtain file size:
	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);

	lSize = 1448;//1448;
	// allocate memory to contain the whole file:
	data = (char*) malloc (sizeof(char)*lSize);
	if (data == NULL) {fputs ("Memory error",stderr); exit (2);}

	// copy the file into the buffer:
	result = fread (data,1,lSize,pFile);
	if (result != lSize) {fputs ("Reading error",stderr); exit (3);}

	/* the whole file is now loaded in the memory buffer. */

	// terminate
	fclose (pFile);	

	if (ret < 0) {
		TRACE_APP("Connection closed with server.\n");
	}
	//start clock
	
	struct timeval begin_t;
	struct timeval end_t;
	
	uint64_t packets_sent = 0;
	int latency_sum = 0;
	double diff_t;
	
	memset(&begin_t, 0, sizeof(struct timeval));
	memset(&end_t, 0, sizeof(struct timeval));
	//gettimeofday(&begin_t, NULL);


	while(!done[id]){
		nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
		
		if (nevents < 0) {
			if (errno != EINTR)
				perror("mtcp_epoll_wait");
			break;
		}
		
		for(int i=0;i<nevents;i++) {
			if (events[i].data.sockid == listener) {
				//Accept connection
				newsockfd = mtcp_accept(mctx, listener, NULL, NULL);
				printf("New connection %d accepted.\n", core);
				connect_done[core]=true;
				ev.events = MTCP_EPOLLOUT;
				ev.data.sockid = newsockfd;
				mtcp_setsock_nonblock(mctx, newsockfd);
				mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, newsockfd, &ev);
				
			}
			else if (events[i].events & MTCP_EPOLLOUT) {
				//send data over new connection
				//cout << "In here." << endl;
				//char *data = "hello";
				ret = 1;
				while (ret > 0) {
					ret = mtcp_write(mctx, newsockfd, data, lSize);
					if (ret < 0) {
						TRACE_APP("Connection closed with client.\n");
						break;
					}
					packets[core]+=ret;
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
	bool conn_start_flag = true;
	do{
		conn_start_flag = (connect_done[0]==false);
		for(int conn_start_i=1;conn_start_i<MAX_THREADS;conn_start_i++){
				conn_start_flag = (conn_start_flag || (connect_done[conn_start_i]==false));
		}
	}while(conn_start_flag);
	//connect_done[0]==false);// || connect_done[1]==false || connect_done[2]==false || connect_done[3]==false);// || connect_done[4]==false || connect_done[5]==false);
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
