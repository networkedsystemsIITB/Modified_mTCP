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
#include "mudp_api.h"
//#include "netmap_api.h"
#include "cpu.h"
#include "debug.h"

#define MAX_EVENTS 1024
#define BUFSIZE 1024
#define CLIENT_IP "169.254.9.18"
#define SERVER_IP "169.254.9.13"
#define SERVER_PORT_TCP 9999
#define CLIENT_PORT_TCP 5900
#define SERVER_PORT_UDP 9998
#define CLIENT_PORT_UDP 5901


using namespace std;
int done;
mctx_t mctx;
/*----------------------------------------------------------------------------*/
void
SignalHandler(int signum)
{
	//Handle ctrl+C here
	mtcp_destroy_context(mctx);	
	mtcp_destroy();
	done = 1;
}
/*----------------------------------------------------------------------------*/

int main(int argc, char **argv){
	
	int core = 0;
	int ret = -1;
	done = 0;
	

	char* conf_file = "server.conf";
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
	printf("Done.\n");
	/* create epoll descriptor */
	int ep = mtcp_epoll_create(mctx, MAX_EVENTS);
	if (ep < 0) {
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}
	printf("Done.\n");
	
	//step 4. mtcp_socket, mtcp_setsock_nonblock,mtcp_bind
	int tcp_sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if (tcp_sockid < 0) {
		TRACE_ERROR("Failed to create TCP listening socket!\n");
		return -1;
	}
	ret = mtcp_setsock_nonblock(mctx, tcp_sockid);
	if (ret < 0) {
		TRACE_ERROR("Failed to set TCP socket in nonblocking mode.\n");
		return -1;
	}
	printf("Done.\n");
	int udp_sockid = mtcp_socket(mctx, AF_INET, SOCK_DGRAM, 0);
	if (udp_sockid < 0) {
		printf("%d\n",udp_sockid);
		TRACE_ERROR("Failed to create UDP listening socket!\n");
		return -1;
	}
	printf("Done.\n");

	ret = mtcp_setsock_nonblock(mctx, udp_sockid);
	if (ret < 0) {
		TRACE_ERROR("Failed to set TCP socket in nonblocking mode.\n");
		return -1;
	}
	printf("Done.\n");
	struct sockaddr_in serveraddr_tcp,clientaddr_tcp, serveraddr_udp,clientaddr_udp;

	bzero((char *) &serveraddr_tcp, sizeof(serveraddr_tcp));
	serveraddr_tcp.sin_family = AF_INET;
	inet_aton(SERVER_IP, &serveraddr_tcp.sin_addr);
	serveraddr_tcp.sin_port = htons((unsigned short)SERVER_PORT_TCP);

	bzero((char *) &clientaddr_tcp, sizeof(clientaddr_tcp));
	clientaddr_tcp.sin_family = AF_INET;
	inet_aton(CLIENT_IP, &clientaddr_tcp.sin_addr);
	clientaddr_tcp.sin_port = htons((unsigned short)CLIENT_PORT_TCP);

	bzero((char *) &serveraddr_udp, sizeof(serveraddr_udp));
	serveraddr_udp.sin_family = AF_INET;
	inet_aton(SERVER_IP, &serveraddr_udp.sin_addr);
	serveraddr_udp.sin_port = htons((unsigned short)SERVER_PORT_UDP);

	bzero((char *) &clientaddr_udp, sizeof(clientaddr_udp));
	clientaddr_udp.sin_family = AF_INET;
	inet_aton(CLIENT_IP, &clientaddr_udp.sin_addr);
	clientaddr_udp.sin_port = htons((unsigned short)CLIENT_PORT_UDP);

	ret = mtcp_bind(mctx, tcp_sockid,(struct sockaddr *)&serveraddr_tcp, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	ret = mtcp_bind(mctx, udp_sockid,(struct sockaddr *)&serveraddr_udp, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	ret = mtcp_listen(mctx, tcp_sockid, 4096);
	if (ret < 0) {
		TRACE_ERROR("mtcp_listen() failed!\n");
		return -1;
	}

	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = tcp_sockid;
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, tcp_sockid, &ev);
	
	struct mtcp_epoll_event ev1;
	ev1.events = MTCP_EPOLLIN;
	ev1.data.sockid = udp_sockid;
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, udp_sockid, &ev1);

	//step 6. mtcp_epoll_wait
	struct mtcp_epoll_event *events;
	int nevents;
	events = (struct mtcp_epoll_event *)calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}
	char udp_data[BUFSIZE], tcp_data[BUFSIZE],udp_data1[BUFSIZE], tcp_data1[BUFSIZE];
	strcpy(udp_data,"helloudp1");
	strcpy(tcp_data,"hellotcp1");
	int clientlen;
	
	cout << "Waiting for events" << endl;
	while(!done){
		nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
		
		if (nevents < 0) {
			if (errno != EINTR)
				perror("mtcp_epoll_wait");
			break;
		}
		for(int i=0;i<nevents;i++) {
			if (events[i].data.sockid == tcp_sockid) {
				//Accept connection
				int newsockfd = mtcp_accept(mctx, tcp_sockid, NULL, NULL);
				printf("New connection %d accepted.\n", newsockfd);
				ev.events = MTCP_EPOLLIN;
				ev.data.sockid = newsockfd;
				mtcp_setsock_nonblock(mctx, newsockfd);
				mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, newsockfd, &ev);

			} else  if ((events[i].events & MTCP_EPOLLIN) && events[i].data.sockid == udp_sockid) {
				//receive data over new connection
				int rd = mudp_recvfrom(mctx,udp_sockid, udp_data1, BUFSIZE, 0,
						 (struct sockaddr *) &clientaddr_udp, &clientlen);
				if (rd <= 0) {
				
				}
				cout << udp_data1 << endl;
				rd = mudp_sendto(mctx,udp_sockid, udp_data, strlen(udp_data), 0,(struct sockaddr *) &clientaddr_udp, clientlen);

			} else if (events[i].events & MTCP_EPOLLIN) {
				//receive data over new connection
				int rd = mtcp_read(mctx, events[i].data.sockid, tcp_data1, BUFSIZE);
				if (rd <= 0) {
					
				}
				cout << tcp_data1 << endl;
				rd = mtcp_write(mctx, events[i].data.sockid, tcp_data, strlen(tcp_data));

			}
		}
	}
	mtcp_destroy_context(mctx);	
	
}
