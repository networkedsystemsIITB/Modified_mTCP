#include "mtcp.h"
//#include "mudp.h"
#include "debug.h"
#include "wait.h"

#include <iostream>
using namespace std;

/*---------------------------------------------------------------------------*/
struct udp_socket *
UDPAllocateSocket(mctx_t mctx, int socktype, int need_lock)
{
	mtcp_manager_t mtcp = g_mtcp[mctx->cpu];
	struct udp_socket* socket = NULL;

	if (need_lock)
		pthread_mutex_lock(&mtcp->ctx->mudp_socket_lock);

	while (socket == NULL) {
		socket = TAILQ_FIRST(&mtcp->udp_free_socket_list);
		cout <<"id "<< socket->id << endl;
		if (!socket) {
			if (need_lock)
				pthread_mutex_unlock(&mtcp->ctx->mudp_socket_lock);

			TRACE_ERROR("The concurrent sockets are at maximum.\n");
			return NULL;
		}

		TAILQ_REMOVE(&mtcp->udp_free_socket_list, socket, free_udp_sockets_link);
	}

	if (need_lock)
		pthread_mutex_unlock(&mtcp->ctx->mudp_socket_lock);

	memset(&socket->saddr, 0, sizeof(struct sockaddr_in));
	if(!list_empty(&socket->recv_queue)){
		//previous receive queues not yet handled. Error condition.
		return -1;
	}
	INIT_LIST_HEAD(&socket->recv_queue);
	wait_init(&socket->socket_wait);
	cout <<"id " << socket->id << endl;
	cout <<"id " << socket << endl;
	return socket;
}
/*---------------------------------------------------------------------------*/
void
UDPFreeSocket(mctx_t mctx, int sockid, int need_lock)
{
	mtcp_manager_t mtcp = g_mtcp[mctx->cpu];
	struct udp_socket * socket = &mtcp->udp_smap[sockid];

	if (socket->socktype == MTCP_SOCK_UNUSED) {
		return;
	}

	socket->socktype = MTCP_SOCK_UNUSED;
	//TODO: Make all pointers null, all data structures zero.
	wait_exit(&socket->socket_wait);
	if (need_lock)
		pthread_mutex_lock(&mtcp->ctx->mudp_socket_lock);

	/* insert into free stream map */
	TAILQ_INSERT_TAIL(&mtcp->udp_free_socket_list, socket, free_udp_sockets_link);

	if (need_lock)
		pthread_mutex_unlock(&mtcp->ctx->mudp_socket_lock);
}
/*---------------------------------------------------------------------------
struct udp_socket*
UDPGetSocket(mctx_t mctx, int sockid)
{
	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		errno = EBADF;
		return NULL;
	}

	return &g_mtcp[mctx->cpu]->smap[sockid];
}
*/
