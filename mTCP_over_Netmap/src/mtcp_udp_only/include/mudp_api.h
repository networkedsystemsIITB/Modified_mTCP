#ifndef __MUDP_API_H_
#define __MUDP_API_H_

//#include "mudp.h"
//#include "mudp_socket.h"
#include "socket.h"
#include "mudp_hashlist.h"


/*
 * This file contains the mudp api to be exported to applications
 */
/*
 * what should mtcp_manager should have: per-core hashtable of udp sockets based on 4-tuple
 * per-core hashtable
 */

/*
int
mudp_socket(mctx_t mctx, int domain, int type, int protocol);

int
mudp_bind(mctx_t mctx, int sockid, const struct sockaddr *addr, socklen_t addrlen);
*/

ssize_t 
mudp_sendto(mctx_t mctx,int s, const void *buf, size_t len,int flags, const struct sockaddr *to,socklen_t tolen);

ssize_t 
mudp_recvfrom(mctx_t mctx,int sockfd, void *buf, size_t len, int flags,struct sockaddr *src_addr, socklen_t *addrlen);

int
mudp_close(mctx_t mctx, int sockid);

#endif /* _H*/
