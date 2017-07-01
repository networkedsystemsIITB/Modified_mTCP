rm udpclient_epoll
rm udpclient_epoll.o

g++ -fpermissive -std=c++11 -g -I /home/hss/Downloads/MTP/netmap-master/LINUX/../sys -I ../../include -o udpclient_epoll.o -c udpclient_epoll.cpp
echo "Client done"
g++ -g -o udpclient_epoll udpclient_epoll.o ../../mtcp_lib.o -pthread
