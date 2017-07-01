#include "udp_receive_buffer.h"
#include <strings.h>
#include <stdio.h>

using namespace std;
/*
 * struct mudp_receive_buffer{

	int total_size;
	uint8_t *begin;
	uint8_t *end;
	uint8_t *to_allocate;
	uint8_t *read;
	pthread_mutex_t receive_buffer_lock;

};
*/
void
init_receive_buffer(struct mudp_receive_buffer* buf,int total_size){

	//allocate
	buf->begin = (uint8_t *) calloc(1,total_size);
	bzero(buf->begin,total_size);
	//initialize variables appropriately
	buf->total_size = total_size;
	buf->end = buf->begin + total_size;
	buf->to_allocate = buf->begin;
	buf->read = buf->begin;

	if (pthread_mutex_init(&buf->receive_buffer_lock, NULL)) {
		perror("pthread_mutex_init of buf->receive_buffer_lock\n");
		exit(-1);
	}
}

uint8_t *
udp_allocate_receive(struct mudp_receive_buffer* buf,int size,int& allocated){

	pthread_mutex_lock(&buf->receive_buffer_lock);

	//Check if the buffer is full
	if(buf->to_allocate == buf->end && buf->read == buf->begin){
		//printf("Receive Buffer Full. This is Infinite Loop.\n");
		allocated = 0;
		pthread_mutex_unlock(&buf->receive_buffer_lock);
		return NULL;
	}

	if(buf->to_allocate + 1 == buf->read){
		//printf("Receive Buffer Full. This is Infinite Loop.\n");
		allocated = 0;
		pthread_mutex_unlock(&buf->receive_buffer_lock);
		return NULL;
	}

	/*
	if(size > buf->total_size){
		return NULL;
	}*/
	int current_size = 0;

	if(buf->to_allocate > buf->read){
		current_size = buf->end - buf->to_allocate;
		if(current_size < size){
			buf->to_allocate = buf->begin;
			current_size = buf->read - buf->to_allocate;
		}
	}
	else if(buf->to_allocate == buf->read){
		current_size = buf->total_size;
	}
	else{
		current_size = buf->read - buf->to_allocate;
	}

	uint8_t * ret = buf->to_allocate;
	if(current_size == 0){
		allocated = 0;
		pthread_mutex_unlock(&buf->receive_buffer_lock);
		return NULL;
	}
	if(current_size < size){

		//You can change implementation here as you need. You can return NULL
		//and hold up until enough space is available in buffer.

		allocated = 0;
		pthread_mutex_unlock(&buf->receive_buffer_lock);
		return NULL;

		/*
		printf("Not enough space in UDP receive buffer. Allocating %d bytes instead of %d.\n",current_size,size);
		allocated = current_size;
		buf->to_allocate += current_size;
		*/
	}else{
		buf->to_allocate += size;
		allocated = size;
	}
	pthread_mutex_unlock(&buf->receive_buffer_lock);

	return ret;
}

void
udp_update_read(struct mudp_receive_buffer* buf,int read_size){

	pthread_mutex_lock(&buf->receive_buffer_lock);
	if(buf->read + read_size > buf->end){
		buf->read = buf->begin;
	}
	buf->read += read_size;
	pthread_mutex_unlock(&buf->receive_buffer_lock);

}
