#ifndef __UDP_IN_H_
#define __UDP_IN_H_

#include "mtcp.h"
#include "mtcp_api.h"
#include <netinet/ip.h>
#include "udp.h"
#include "tcp_stream.h"
int
ProcessUDPPacket(mtcp_manager_t mtcp,const struct iphdr *iph, int ip_len);

#endif /* _H*/
