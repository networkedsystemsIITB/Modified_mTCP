#include "udp_out.h"
#include <netinet/ip.h>
#include "ip_out.h"
#include "udp.h"
//#include "udp_send_buffer.h"
#include <iostream>
using namespace std;

int 
mudp_send_pkt(mtcp_manager_t mtcp,struct sockaddr_in *from,struct sockaddr_in *to,int tolen,const void *buf, size_t len){

	//get socket from internal socket list
	struct udp *udphdr = (struct udp *)IPOutputUDP(mtcp, from,to, UDP_HEADER_LEN + len);
	if (udphdr == NULL) {
		return -2;
	}
	memset(udphdr, 0, UDP_HEADER_LEN + len);

	//Init UDP header
	udphdr->src = from->sin_port;//skaddr->src_port/*sk->sk_sport*/;	/* bound local address */
	udphdr->dst = to->sin_port;//skaddr->dst_port;
	udphdr->length = htons(len + UDP_HEADER_LEN);
	//memcpy(udphdr->data, buf, size);
	//TODO: Note for Trishal and Priyanka. Add checksum here, if required.
	//copy payload
	memcpy((uint8_t *)udphdr + UDP_HEADER_LEN , buf, len);

	return 0;
}

int write_udp_packets(mtcp_manager_t mtcp){

	//remove from sendlist and send one by one
    while(!list_empty(&mtcp->udp_send_list)){
		struct mudp_send_list *elem = list_first_entry(&(mtcp->udp_send_list), struct mudp_send_list, list_member);
		//printf("%d\n",elem->info);
		//send UDP packets
		struct socket_map * socket = elem->info.socket;
		int ret = mudp_send_pkt(mtcp,elem->info.from,elem->info.to,sizeof(elem->info.to),elem->info.buf, elem->info.len);
		if(ret < 0){
			//error condition
			return ret;
		}
		list_del(&elem->list_member);
		//free up the send buffer
		udp_update_sent(mtcp->udp_send_buffer,elem->info.len);
		//free(elem->info.buf);
		//free(elem);
		TAILQ_INSERT_TAIL(&mtcp->udp_free_send_list, elem, free_send_list_link);
	    if (socket->epoll & MTCP_EPOLLOUT) {
	    	AddEpollEvent(mtcp->ep, MTCP_EVENT_QUEUE, socket, MTCP_EPOLLOUT);
	    	//cout << "Event Added" << endl;
	    }
	}
}
