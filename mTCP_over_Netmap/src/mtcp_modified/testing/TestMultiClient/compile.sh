rm client
rm client.o

g++ -g -fpermissive -I ../../include  -I /home/hss/Downloads/MTP/netmap-master/sys  -std=c++11 -o client.o -c client.cpp
echo "Client done"
g++ -o client client.o ../../mtcp_lib.o -pthread
