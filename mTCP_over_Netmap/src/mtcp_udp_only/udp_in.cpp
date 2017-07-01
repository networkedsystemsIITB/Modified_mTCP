#include "udp_in.h"
#include "mudp_api.h"
#include "eventpoll.h"
#include <unistd.h>
#include <iostream>
#include <thread>
using namespace std;

int
ProcessUDPPacket(mtcp_manager_t mtcp,const struct iphdr *iph, int ip_len){

	//Get the UDP header and data
	struct udp *udph = (struct udp *) ((u_char *)iph + (iph->ihl << 2));
	uint8_t *payload = (uint8_t *)udph + UDP_HEADER_LEN; //TODO: Confirm this
	int payloadlen = ip_len - (payload - (u_char *)iph);

	//Lookup corresponding socket in hashlist
	struct four_tuple_key key;
	key.sip = iph->daddr;
	key.sport = udph->dst;

	struct socket_map *socket = udp_socket_lookup(mtcp->mudp_flow_table, key);
	if(!socket){
		return -1;
	}
	//TODO: Note for Trishal and Priyanka. Add locking here, if required.
	struct udp_receive_queue* elem = TAILQ_FIRST(&mtcp->udp_free_receive_list);
	if(!elem){
		return -1;
	}
	TAILQ_REMOVE(&mtcp->udp_free_receive_list, elem, free_receive_list_link);
	elem->size = payloadlen;
	uint8_t *data = NULL;
	while(data == NULL){
		data = udp_allocate_receive(mtcp->udp_receive_buffer,payloadlen,elem->size);
	}
	/*while (1){
		data = udp_allocate_receive(mtcp->udp_receive_buffer,payloadlen,elem->size);
		if(data == NULL){
			//return -1;
			//usleep(1000);
			//this_thread::yield();
		}else{
			break;
		}
	}*/
	memcpy(data,payload,elem->size);
	elem->data = data;
	elem->from.sin_addr.s_addr = iph->saddr;
	elem->from.sin_port = udph->src;

	INIT_LIST_HEAD(&elem->recv_queue);
	list_add_tail(&elem->recv_queue, &socket->recv_queue);
	if (socket->epoll & MTCP_EPOLLIN) {
		AddEpollEvent(mtcp->ep, MTCP_EVENT_QUEUE, socket, MTCP_EPOLLIN);
	}
}
