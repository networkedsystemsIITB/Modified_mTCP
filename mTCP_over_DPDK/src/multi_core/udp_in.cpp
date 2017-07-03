#include "udp_in.h"
#include "mudp_api.h"
#include "eventpoll.h"
//#include "udp_receive_buffer.h"
#include <unistd.h>
#include <iostream>
#include <thread>
#include "dpdk_api.h"
using namespace std;

int
ProcessUDPPacket(mtcp_manager_t mtcp,const struct iphdr *iph, int ip_len){

	//Get the UDP header and data
	//cout << "Called processUDPPacket" << endl;
	struct udp *udph = (struct udp *) ((u_char *)iph + (iph->ihl << 2));
	uint8_t *payload = (uint8_t *)udph + UDP_HEADER_LEN; //TODO: Confirm this
	int payloadlen = ip_len - (payload - (u_char *)iph);

	//Lookup corresponding socket in hashlist
	struct four_tuple_key key;
	key.sip = iph->daddr;
	//key.dip = iph->saddr;
	key.sport = udph->dst;
	//key.dport = udph->src;

	struct socket_map *socket = udp_socket_lookup(mtcp->mudp_flow_table, key);
	//struct socket_map *socket = &mtcp->smap[1];
	if(!socket){
		return -1;
	}
	//Add this message to receive queue of socket
	//Init udp_receive_queue element
	//struct udp_receive_queue* elem = (struct udp_receive_queue*)calloc(1,sizeof(struct udp_receive_queue));
	struct udp_receive_queue* elem = TAILQ_FIRST(&mtcp->udp_free_receive_list);
	if(!elem && elem != 0x1){
		return -1;
	}
	TAILQ_REMOVE(&mtcp->udp_free_receive_list, elem, free_receive_list_link);
	elem->size = payloadlen;
	//uint8_t *data = (uint8_t *)calloc(1,payloadlen);
	uint8_t *data = NULL;
/*
	while(data == NULL){
		data = udp_allocate_receive(mtcp->udp_receive_buffer,payloadlen,elem->size);
	//usleep(10000);
	//this_thread::yield();
	}
*/
	while (1){
		data = udp_allocate_receive(mtcp->udp_receive_buffer,payloadlen,&elem->size);
		if(data == NULL || data == 0x1 || data == 0x0){
			this_thread::yield();			
			//return -1;
			//usleep(1000);
			//this_thread::yield();
		}else{
			break;
		}
	}
	//printf("%p %p\n",data,payload);
	memcpy(data,payload,elem->size);
	elem->data = data;
	elem->from.sin_addr.s_addr = iph->saddr;
	elem->from.sin_port = udph->src;

	INIT_LIST_HEAD(&elem->recv_queue);
	list_add_tail(&elem->recv_queue, &socket->recv_queue);
	//Signal the sleeping thread on this packet
	//wake_up(&socket->socket_wait);
	//Add Epoll event

	if (socket->epoll & MTCP_EPOLLIN) {
		AddEpollEvent(mtcp->ep, MTCP_EVENT_QUEUE, socket, MTCP_EPOLLIN);
		//printf("Added for %d\n",socket->id);
		//cout << "Event Added" << endl;
	}
	//cout << "Woken up " << socket->id << endl;
}
