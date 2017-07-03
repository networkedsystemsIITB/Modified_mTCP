rm udpserver_epoll
rm udpserver_epoll.o

g++ -fpermissive -std=c++11 -g -I /home/hss/Downloads/MTP/netmap-master/LINUX/../sys -I ../../include -o udpserver_epoll.o -c udpserver_epoll.cpp
echo "Server done"
g++ -g -o udpserver_epoll udpserver_epoll.o ../../mtcp_lib.o -pthread
