#ifndef __UDP_H
#define __UDP_H


struct udp {
	uint16_t src;	/* source port */
	uint16_t dst;	/* destination port */
	uint16_t length;	/* udp head and data */
	uint16_t checksum;
} __attribute__((packed));

#endif	/* udp.h */
