
g++ -fpermissive -g -I include -I /home/sink/Downloads/MTP/netmap-master/sys -std=c++11 -o utils.o -c utils.cpp
g++ -fpermissive -g -I include -I /home/sink/Downloads/MTP/netmap-master/sys -std=c++11 -o libpacket.o -c libpacket.cpp
g++ -fpermissive -g -I include -I /home/sink/Downloads/MTP/netmap-master/sys -std=c++11 -o lib.o -c lib.cpp -lboost_system
g++ -fpermissive -g -I include -I /home/sink/Downloads/MTP/netmap-master/sys -std=c++11 -o b.o -c b.cpp -lboost_system
#g++ -fpermissive -g -I ../../include -I /home/sink/Downloads/MTP/netmap-master/sys -std=c++11 -o server_locking.o -c server_locking.cpp
echo "Server done"
g++ -std=c++11 -g -o b b.o lib.o libpacket.o utils.o mtcp_lib.o -pthread -lboost_system
#g++ -o server_rss server_rss.o ../../mtcp_lib.o -pthread
#g++ -o server_locking server_locking.o ../../mtcp_lib.o -pthread
#sudo gdb ./server_rss 9999
