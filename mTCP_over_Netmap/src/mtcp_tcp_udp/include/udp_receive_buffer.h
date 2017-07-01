//#ifndef __UDP_RECEIVE_BUFFER_H_
//#define __UDP_RECEIVE_BUFFER_H_

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
//#include "debug.h"

struct mudp_receive_buffer{

	int total_size;
	uint8_t *begin;
	uint8_t *end;
	uint8_t *to_allocate;
	uint8_t *read;
	pthread_mutex_t receive_buffer_lock;

};

void init_receive_buffer(struct mudp_receive_buffer*,	int total_size);

uint8_t *
udp_allocate_receive(struct mudp_receive_buffer* buf,int size,int& allocated);

void
udp_update_read(struct mudp_receive_buffer* buf,int sent_size);

//#endif
