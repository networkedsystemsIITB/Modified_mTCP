#ifndef __IP_OUT_H_
#define __IP_OUT_H_

#include <stdint.h>
#include "tcp_stream.h"

extern int
GetOutputInterface(uint32_t daddr);

void
ForwardIPv4Packet(mtcp_manager_t mtcp, int nif_in, char *buf, int len);

uint8_t *
IPOutputStandalone(struct mtcp_manager *mtcp, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t tcplen);

uint8_t *
IPOutput(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen);

uint8_t *
IPOutputUDP(struct mtcp_manager *mtcp, struct sockaddr_in *from, struct sockaddr_in *to, uint16_t udplen);
#endif /* __IP_OUT_H_ */
