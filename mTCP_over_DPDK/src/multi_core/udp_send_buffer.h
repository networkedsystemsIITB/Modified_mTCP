//#ifndef __UDP_SEND_BUFFER_H_
//#define __UDP_SEND_BUFFER_H_


#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
//#include "debug.h"

struct mudp_send_buffer{

	int total_size;
	uint8_t *begin;
	uint8_t *end;
	uint8_t *to_allocate;
	uint8_t *sent_out;
	pthread_mutex_t send_buffer_lock;

};

void init_send_buffer(struct mudp_send_buffer*,	int total_size);

uint8_t *
udp_allocate_send(struct mudp_send_buffer* buf,int size,int& allocated);

void
udp_update_sent(struct mudp_send_buffer* buf,int sent_size);

//#endif
