#ifndef LIB_H
#define LIB_H

#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <iostream>
#include "mtcp_api.h"
#include "mtcp_epoll.h"
//#include "dpdk_api.h"
//#include "netmap_api.h"
#include <iostream>
#include "cpu.h"
#include "debug.h"
#include <sys/time.h>
#include <sched.h>
#include <map>
#include <unordered_map>
#include <string>
#include <bitset>
#include <boost/pool/simple_segregated_storage.hpp>  //for memory pool
#include <boost/foreach.hpp>  //for memory pool
#include <vector>  //for memory pool
#include <cstddef>  //for memory pool
#include <algorithm>  //for client_vector
#include "libpacket.h"
#include "rss.h"
#include <mutex>
#define MAX_EVENTS 2048 //65536 //10000 //2048 //65536 //2048 //1024 //2048 //for single core 65536
#define MAX_THREADS 1
#define BUFSIZE 128 //1024
//for multicore B
#define MSB32                           0x80000000
#define MSB16                           0x8000
#define KEY_CACHE_LEN                   96
#define SEED                            'B' 
#define DS_IP				"169.254.9.18"
#define IP_RANGE 1
enum event_type{READ=1,ACCEPT=2,ERROR=3};
enum data_location{LOCAL=1,REMOTE=2,CHECKCACHE=3};
typedef void (*fn)( int, void*, char*, int);
using namespace std;
void initReqPool(int msize[], int m_tot);
void* allocReqObj(int vnf_connid, int index); //uncomment nov28
void freeReqObj(int vnf_connid, int index);  //uncomemnt nov28
void linkReqObj(int vnf_connid, void* requestObj);
void* getPktDNE(int vnf_connid, void* pkt_mem_ptr);
void unsetPktDNE(int vnf_connid, void* pkt_mem_ptr);
char* getPktBuf(int vnf_connid);
void* setKeyDNE(int ds_key);
void unsetKeyDNE(int ds_key);
void SignalHandler(int signum);
void serverThreadFunc(void* arg1);
int createServer(string inter_face, string server_ip, int server_port, string protocol);
void registerCallback(int vnf_connid, enum event_type, void callbackFnPtr(int, void*, char*, int));
void startEventLoop();
void startPerCore(void* arg1);
int createClient(int vnf_connid, string local_ip , string remoteServerIP, int remoteServerPort, string protocol);
int createClientDS(int id, string local_ip , int local_port, string remoteServerIP, int remoteServerPort, string protocol);
void sendData(int vnf_connid, char* packetToSend, int size);
void sendDataClient(int vnf_connid, string packetToSend, int size);
void sendDataServer(int vnf_connid, string packetToSend, int packet_size);
void setData(int vnf_connid, int key, enum data_location, void* value, int value_len);
void getData(int vnf_connid, int key, enum data_location, void callbackFnPtr(int, void*, void*, int));
void delData(int vnf_connid, int key, enum data_location);
void closeConn(int vnf_connid);
#endif //LIB_H
