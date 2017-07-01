#include "udp_send_buffer.h"
#include <strings.h>
#include <stdio.h>
using namespace std;
/*
struct mudp_send_buffer{

	int total_size;
	uint8_t *begin;
	uint8_t *end;
	uint8_t *to_allocate;
	uint8_t *sent_out;
	pthread_mutex_t allocate_lock;
	pthread_mutex_t sent_lock;

};
*/
void
init_send_buffer(struct mudp_send_buffer* buf,int total_size){

	//allocate
	buf->begin = (uint8_t *) calloc(1,total_size);
	bzero(buf->begin,total_size);

	//initialize variables appropriately
	buf->total_size = total_size;
	buf->end = buf->begin + total_size;
	buf->to_allocate = buf->begin;
	buf->sent_out = buf->begin;

	if (pthread_mutex_init(&buf->send_buffer_lock, NULL)) {
		perror("pthread_mutex_init of buf->send_buffer_lock\n");
		exit(-1);
	}
}

uint8_t *
udp_allocate_send(struct mudp_send_buffer* buf,int size,int& allocated ){

	pthread_mutex_lock(&buf->send_buffer_lock);

	//Check if the buffer is full
	if(buf->to_allocate == buf->end && buf->sent_out == buf->begin){
		printf("Send Buffer Full. This is Infinite Loop.\n");
		allocated = 0;
		pthread_mutex_unlock(&buf->send_buffer_lock);
		return NULL;
	}

	if(buf->to_allocate + 1 == buf->sent_out){
		printf("Send Buffer Full. This is Infinite Loop.\n");
		allocated = 0;
		pthread_mutex_unlock(&buf->send_buffer_lock);
		return NULL;
	}
	/*
	if(size > buf->total_size){
		return NULL;
	}
	*/
	int current_size = 0;

	if(buf->to_allocate > buf->sent_out){
		current_size = buf->end - buf->to_allocate;
		if(current_size < size){
			buf->to_allocate = buf->begin;
			current_size = buf->sent_out - buf->to_allocate;
		}
	}
	else if(buf->to_allocate == buf->sent_out){
		current_size = buf->total_size;
	}
	else{
		current_size = buf->sent_out - buf->to_allocate;
	}
	uint8_t * ret = buf->to_allocate;

	if(current_size == 0){
		allocated = 0;
		pthread_mutex_unlock(&buf->send_buffer_lock);
		return NULL;

	}
	if(current_size < size){
		//allocated = 0;
		//pthread_mutex_unlock(&buf->send_buffer_lock);
		//return NULL;
		printf("Not enough space in UDP send buffer. Allocating %d bytes instead of %d.\n",current_size,size);
		allocated = current_size;
		buf->to_allocate += current_size;
	}else{
		buf->to_allocate += size;
		allocated = size;
	}
	pthread_mutex_unlock(&buf->send_buffer_lock);

	return ret;
}

void
udp_update_sent(struct mudp_send_buffer* buf,int sent_size){

	pthread_mutex_lock(&buf->send_buffer_lock);
	if(buf->sent_out + sent_size > buf->end){
		buf->sent_out = buf->begin;
	}
	buf->sent_out += sent_size;
	pthread_mutex_unlock(&buf->send_buffer_lock);

}
