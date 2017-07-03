#ifndef __UDP_OUT_H_
#define __UDP_OUT_H_

#include "mudp_api.h"
//#include "mudp_socket.h"

int 
mudp_send_pkt(mtcp_manager_t mtcp,struct sockaddr_in *from,struct sockaddr_in *to,int tolen,const void *buf, size_t len);

int 
write_udp_packets(mtcp_manager_t mtcp);

#endif /* _H*/
