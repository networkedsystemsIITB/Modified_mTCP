#ifndef __MUDP_SOCKET_H_
#define __MUDP_SOCKET_H_

#include <netinet/in.h>
#include "mtcp.h"
#include "mtcp_api.h"
#include "wait.h"

using namespace std;

struct udp_receive_queue{

	int size;
	char *data;
	struct sockaddr_in from;
	struct list_head recv_queue; // For next element in receive queue.

};

struct udp_socket {

	unsigned int id;
	unsigned int state;
	unsigned int family;	/* socket family: always AF_INET */
	unsigned int socktype;

	struct sockaddr_in saddr;

	struct mtcp_wait socket_wait;

	TAILQ_ENTRY (udp_socket) free_udp_sockets_link;
	/*Pointer to send and receive Buffers*/
	struct list_head recv_queue;
	/*List data structures*/

};

struct udp_socket *
UDPAllocateSocket(mctx_t mctx, int socktype, int need_lock);

void
UDPFreeSocket(mctx_t mctx, int sockid, int need_lock);

struct udp_socket*
UDPGetSocket(mctx_t mctx, int sockid);

#endif /* _H*/
