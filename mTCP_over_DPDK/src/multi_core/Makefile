ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

CC=g++

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = dpdkapi

# all source are stored in SRCS-y
#packet_burst_generator.o : packet_burst_generator.h packet_burst_generator.c
#	gcc packet_burst_generator.c -o packet_burst_generator.o
#SRCS-y += packet_burst_generator.c
#SRCS-y += main.cpp

SRCS-y += dpdk_api.cpp
SRCS-y += addr_pool.cpp api.cpp config.cpp core.cpp cpu.cpp debug.cpp dpdk_module.cpp eth_in.cpp eth_out.cpp eventpoll.cpp fhash.cpp icmp.cpp io_module.cpp
SRCS-y += ip_in.cpp ip_out.cpp logger.cpp memory_mgt.cpp pipe.cpp rss.cpp socket.cpp tcp_in.cpp 
SRCS-y += tcp_out.cpp tcp_rb_frag_queue.cpp tcp_ring_buffer.cpp tcp_sb_queue.cpp tcp_send_buffer.cpp tcp_stream_queue.cpp tcp_stream.cpp tcp_util.cpp timer.cpp
SRCS-y += mudp_api.cpp mudp_hashlist.cpp udp_in.cpp udp_out.cpp udp_receive_buffer.cpp udp_send_buffer.cpp
SRCS-y += main.cpp

CFLAGS += -std=gnu++11 
CFLAGS += -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable -D__STDC_LIMIT_MACROS
CFLAGS += -Wextra
CFLAGS += -m64 -Wall -fPIC -fgnu89-inline -DNDEBUG -DNETSTAT -DINFO -DDBGERR -DDBGCERR -fpermissive -pthread -Wnarrowing #-g3 #-pg
LDFLAGS += -lstdc++

include $(RTE_SDK)/mk/rte.extapp.mk

clean:
	rm -rf build/*
