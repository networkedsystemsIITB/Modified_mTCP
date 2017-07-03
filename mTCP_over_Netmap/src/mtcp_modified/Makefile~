CPPFLAGS = -I include -I /home/hss/Downloads/MTP/netmap-master/LINUX/../sys -Wextra -DNO_PCAP -std=c++11
EXTRAFLAGS = -m64 -Wall -fPIC -fgnu89-inline -DNDEBUG -DNETSTAT -DINFO -DDBGERR -DDBGCERR -fpermissive -pthread -Wunused-parameter -g
MTCP_OBJECTS = addr_pool.o api.o config.o core.o cpu.o debug.o eth_in.o eth_out.o eventpoll.o fhash.o icmp.o io_module.o\
				ip_in.o ip_out.o logger.o memory_mgt.o mudp_api.o mudp_hashlist.o netmap_api.o netmap_module.o pipe.o rss.o socket.o tcp_in.o \
				tcp_out.o tcp_rb_frag_queue.o tcp_ring_buffer.o tcp_sb_queue.o tcp_send_buffer.o tcp_stream_queue.o tcp_stream.o tcp_util.o \
				timer.o udp_in.o udp_out.o udp_receive_buffer.o udp_send_buffer.o

MTCP_LIB=libmtcp.a

#TODO: add netmap here

all:mtcp_lib.o
mtcp_lib.o:$(MTCP_OBJECTS)
	@echo " [BUILD] $@"
	ld -r -o $@ $^
	#ar rvs $(MTCP_LIB) $(OBJS)
	
#sample:$(MTCP_OBJECTS) sample.o
#	g++ -o sample sample.o $(MTCP_OBJECTS) -pthread
	
#sample.o: sample.cpp
#	g++ -fpermissive -I include -o sample.o -c sample.cpp
		
addr_pool.o: addr_pool.cpp include/addr_pool.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o addr_pool.o addr_pool.cpp
		
api.o : api.cpp include/mtcp_api.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o api.o api.cpp	 

config.o: config.cpp include/config.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o config.o config.cpp

core.o: core.cpp
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o core.o core.cpp
	
cpu.o: cpu.cpp include/cpu.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o cpu.o cpu.cpp 

debug.o: debug.cpp include/debug.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o debug.o debug.cpp 

eth_in.o: eth_in.cpp include/eth_in.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o eth_in.o eth_in.cpp 

eth_out.o: eth_out.cpp include/eth_out.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o eth_out.o eth_out.cpp 

eventpoll.o: eventpoll.cpp include/eventpoll.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o eventpoll.o eventpoll.cpp 

fhash.o: fhash.cpp include/fhash.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o fhash.o fhash.cpp 

icmp.o: icmp.cpp include/icmp.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o icmp.o icmp.cpp

ip_in.o: ip_in.cpp include/ip_in.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o ip_in.o ip_in.cpp

ip_out.o: ip_out.cpp include/ip_out.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o ip_out.o ip_out.cpp

logger.o: logger.cpp include/logger.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o logger.o logger.cpp
			
memory_mgt.o: memory_mgt.cpp include/memory_mgt.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o memory_mgt.o memory_mgt.cpp 
	
mudp_api.o: mudp_api.cpp include/mudp_api.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o mudp_api.o mudp_api.cpp 	

mudp_hashlist.o: mudp_hashlist.cpp include/mudp_hashlist.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o mudp_hashlist.o mudp_hashlist.cpp 	

#mudp_socket.o: mudp_socket.cpp include/mudp_socket.h
#	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o mudp_socket.o mudp_socket.cpp 	

netmap_api.o: netmap_api.cpp include/netmap_api.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o netmap_api.o netmap_api.cpp

netmap_module.o: netmap_module.cpp 
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o netmap_module.o netmap_module.cpp

pipe.o: pipe.cpp include/pipe.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o pipe.o pipe.cpp

rss.o: rss.cpp include/rss.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o rss.o rss.cpp

#pkt_hash.o: pkt_hash.cpp 
#	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o pkt_hash.o pkt_hash.cpp
	
socket.o: socket.cpp include/socket.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o socket.o socket.cpp

tcp_in.o: tcp_in.cpp include/tcp_in.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o tcp_in.o tcp_in.cpp

tcp_out.o: tcp_out.cpp include/tcp_out.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o tcp_out.o tcp_out.cpp
		
tcp_rb_frag_queue.o: tcp_rb_frag_queue.cpp include/tcp_rb_frag_queue.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o tcp_rb_frag_queue.o tcp_rb_frag_queue.cpp 

tcp_ring_buffer.o: tcp_ring_buffer.cpp include/tcp_ring_buffer.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o tcp_ring_buffer.o tcp_ring_buffer.cpp 

tcp_sb_queue.o: tcp_sb_queue.cpp include/tcp_sb_queue.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o tcp_sb_queue.o tcp_sb_queue.cpp 

tcp_send_buffer.o: tcp_send_buffer.cpp include/tcp_send_buffer.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o tcp_send_buffer.o tcp_send_buffer.cpp 

tcp_stream_queue.o: tcp_stream_queue.cpp include/tcp_stream_queue.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o tcp_stream_queue.o tcp_stream_queue.cpp 

tcp_stream.o: tcp_stream.cpp include/tcp_stream.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o tcp_stream.o tcp_stream.cpp 

tcp_util.o: tcp_util.cpp include/tcp_util.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o tcp_util.o tcp_util.cpp
	
timer.o: timer.cpp include/timer.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o timer.o timer.cpp
	
udp_in.o: udp_in.cpp include/udp_in.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o udp_in.o udp_in.cpp 	

udp_out.o: udp_out.cpp include/udp_out.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o udp_out.o udp_out.cpp 	

udp_receive_buffer.o: udp_receive_buffer.cpp include/udp_receive_buffer.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o udp_receive_buffer.o udp_receive_buffer.cpp 	

udp_send_buffer.o: udp_send_buffer.cpp include/udp_send_buffer.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o udp_send_buffer.o udp_send_buffer.cpp 
	
wait.o: wait.cpp include/wait.h
	g++ $(CPPFLAGS) $(EXTRAFLAGS) -c -o wait.o wait.cpp

clean:
	rm -f *.o 
