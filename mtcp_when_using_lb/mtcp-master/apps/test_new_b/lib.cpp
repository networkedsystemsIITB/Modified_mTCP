#include "lib.h"
/*----------------------------------------------------------------------------*/
struct alignas(16) queue_data{
	//stored in queue Q as length of data required for mtcp_write for char* data
	char* data;
	int data_len;
};
typedef queue<queue_data> Q;
vector< vector<uint16_t> > p_vec; //vector for 10000 ports/thread needed in createClient
//vector<Q> queue_vec;
//int queue_count = 100000; 

//int conn_counter = 0,pkt_sent =0,pkt_sent_ds=0,pkt_recv=0,pkt_recv_ds=0;
unordered_map<int, int[MAX_THREADS]> sock_count; //listener sockets created for each core to a int mapping

/*unordered_map<int, fn> funct_ptr; //sock_id to handle function
unordered_map<int, uint64_t> conn_map; //client soc_id to server_sockid mapping
unordered_map<int, uint64_t> data_map;
unordered_map<int, int> client_list;  //keep a list of accepted client sockids..needed for freeing memory
unordered_map<int, void*> ds_map1;   //data store if option is local //TODO make it general using boost
//unordered_map<int, string> ds_map;   //data store if option is local //TODO make it general using boost
unordered_map<int, void*>cache_list; //cache list of addr for clearing cache..cache remove
unordered_map<void*, int>cache_void_list; //cache list of addr for clearing cache..cache remove
unordered_map<void*, int>local_list; //local list of addr for clearing cache..local dnt remove
unordered_map<void*, int>reqptr_list;  //list of addr pointed in req object needed for clearing cache..pointed dnt remove
*/

/*unordered_map<int, void*> mem_ptr;	//sockid to mem pool alloc mapping
unordered_map<void*, int> pkt_ptr;  //map to keep getRefPtr mapping and count
*/
//unordered_map<int, string> wait_for_connect;
int i_count = 0; //index in sock_count map
int s_count = 0; //index inside array of socks corresponding to an index in sock_count
int dummy_connid = 0;
//int ds_sockid,ds_sockid1,set_c=0,get_c=0;
struct arg{
	int id;
	int coreno;
	int portnos;
	string ip;
	fn funct_ptr;	
};
struct event_arguments{
	mctx_t mctx;
	int sockid;
	fn funct_ptr;
	int ep;
	int id;
        int coreno;
};
pthread_t servers[MAX_THREADS];
struct arg arguments[MAX_THREADS];
struct event_arguments event_arg[MAX_THREADS];
int done[MAX_THREADS];
int portno;
string server_ip;
//int memory_size[4];
mctx_t mctx_arr[MAX_THREADS];
int ep_arr[MAX_THREADS];
/*----------------------------------------------------------------------------*/
time_t start_app,end_app;
double rate=0;
double sec=0;
double packets[7]={0,0,0,0,0,0,0};
mutex mct,eparr,sock_c,f_ptr_lock,mp_lock,ds_lock,ds_conn_lock;
// ds_free_lock, ds_map_lock, local_list_lock;

/*boost::simple_segregated_storage<std::size_t> storagepkt;  //memory pool for packet
//std::vector<char> mp_pkt_v(1024*65536);  //assuming pkt size 1024 TODO
std::vector<char> mp_pkt_v(1024*2048);  //assuming pkt size 1024 TODO
*/
unordered_map<int, fn> funct_ptr;
boost::simple_segregated_storage<std::size_t> storageds;  //memory pool for data store
std::vector<char> mp_ds(64*131072);  //assuming value size 64 TODO
unordered_map<int, void*> ds_map1;   //data store if option is local //TODO make it general using boost
unordered_map<void*, int>local_list; //local list of addr for clearing cache..local dnt remove
unordered_map<int, void*>cache_list; //cache list of addr for clearing cache..cache remove
unordered_map<void*, int>cache_void_list; //cache list of addr for clearing cache..cache remove
unordered_map<void*, int>reqptr_list;  //list of addr pointed in req object needed for clearing cache..pointed dnt remove

int ds_size = 0; //to keep count. If exceeds threshold clear
int ds_threshold = 131072, ds_sizing=1;
int ds_portno[4] = {7000,7001,7002,7003};  //TODO make this dynamic afte identifying number of cores 2 connections/core
////boost::simple_segregated_storage<std::size_t> storage;  //memory pool
//boost::simple_segregated_storage<std::size_t> storage1;  //memory pool
/*boost::simple_segregated_storage<std::size_t> storage1; 
boost::simple_segregated_storage<std::size_t> storage2;
boost::simple_segregated_storage<std::size_t> storage3;
boost::simple_segregated_storage<std::size_t> storage4;
std::unordered_map<int,int>::const_iterator got;  //iterator over client_list*/
//*******************************Multicore
struct per_core{
	vector<Q> queue_vec;
//	int queue_count,j;  //j needed for populate_port
//	int conn_counter,pkt_sent,pkt_sent_ds,pkt_recv,pkt_recv_ds;
	unordered_map<int, fn> funct_ptr; //sock_id to handle function
	unordered_map<int, uint64_t> conn_map; //client soc_id to server_sockid mapping
	unordered_map<int, uint64_t> data_map;
	unordered_map<int, int> client_list;  //keep a list of accepted client sockids..needed for freeing memory
//	unordered_map<int, void*> ds_map1;   //data store if option is local //TODO make it general using boost
//	unordered_map<int, void*>cache_list; //cache list of addr for clearing cache..cache remove
//	unordered_map<void*, int>cache_void_list; //cache list of addr for clearing cache..cache remove
//	unordered_map<void*, int>local_list; //local list of addr for clearing cache..local dnt remove
//	unordered_map<void*, int>reqptr_list;  //list of addr pointed in req object needed for clearing cache..pointed dnt remove
	unordered_map<int, void*> mem_ptr;      //sockid to mem pool alloc mapping
	unordered_map<void*, int> pkt_ptr;  //map to keep getRefPtr mapping and count
//	int ds_sockid,ds_sockid1,set_c,get_c,ds_client_port, ds_client_port1;
//	int memory_size[4];
	boost::simple_segregated_storage<std::size_t> storagepkt;  //memory pool for packet
	std::vector<char> mp_pkt_v;  //assuming pkt size 1024 TODO
	boost::simple_segregated_storage<std::size_t> storage1; 
	boost::simple_segregated_storage<std::size_t> storage2;
	boost::simple_segregated_storage<std::size_t> storage3;
	boost::simple_segregated_storage<std::size_t> storage4;
	std::unordered_map<int,int>::const_iterator got;  //iterator over client_list
	int memory_size[4];
	int queue_count,j;  //j needed for populate_port
        int conn_counter,pkt_sent,pkt_sent_ds,pkt_recv,pkt_recv_ds;
	int ds_sockid,ds_sockid1,set_c,get_c,ds_client_port, ds_client_port1;
	per_core(){
		j=0;
		queue_count = 100000;
		conn_counter = 0;
		pkt_sent =0;
		pkt_sent_ds=0;
		pkt_recv=0;
		pkt_recv_ds=0;
		set_c=0;get_c=0;
		mp_pkt_v.resize(1024*2048);
	}

};//__attribute__ ((aligned(64)));
per_core p_core[MAX_THREADS];
////boost::simple_segregated_storage<int> storage1;  //memory pool
//std::vector<char> mp_v;
// storage1.add_block(&v.front(), v.size(), 5);
/*---------------------------------------------------------------------*/
/**
 *  * The cache table is used to pick a nice seed for the hash value. It is
 *   * built only once when sym_hash_fn is called for the very first time
 *    */
static void
build_sym_key_cache(uint32_t *cache, int cache_len)
{
/*        static const uint8_t key[] = {
                0x6d5a, 0x6d5a, 0x6d5a, 0x6d5a,
                0x6d5a, 0x6d5a, 0x6d5a, 0x6d5a,
                0x6d5a, 0x6d5a, 0x6d5a, 0x6d5a,
                0x6d5a, 0x6d5a, 0x6d5a, 0x6d5a,
                0x6d5a, 0x6d5a, 0x6d5a, 0x6d5a};*/
        static const uint8_t key[] = {
                0x50, 0x6d, 0x50, 0x6d,
                0x50, 0x6d, 0x50, 0x6d,
                0x50, 0x6d, 0x50, 0x6d,
                0x50, 0x6d, 0x50, 0x6d,
                0xcb, 0x2b, 0x5a, 0x5a,
                0xb4, 0x30, 0x7b, 0xae,
                0xa3, 0x2d, 0xcb, 0x77,
                0x0c, 0xf2, 0x30, 0x80,
                0x3b, 0xb7, 0x42, 0x6a,
                0xfa, 0x01, 0xac, 0xbe};
//priya
        uint32_t result = (((uint32_t)key[0]) << 24) |
                (((uint32_t)key[1]) << 16) |
                (((uint32_t)key[2]) << 8)  |
                ((uint32_t)key[3]);

        uint32_t idx = 32;
        int i;

        for (i = 0; i < cache_len; i++, idx++) {
                uint8_t shift = (idx % (sizeof(uint8_t) * 8));
                uint32_t bit;

                cache[i] = result;
                bit = ((key[idx/(sizeof(uint8_t) * 8)] << shift)
                       & 0x80) ? 1 : 0;
                result = ((result << 1) | bit);
        }
}

/*---------------------------------------------------------------------*/
/**
 ** Computes symmetric hash based on the 4-tuple header data
 **/
static uint32_t
sym_hash_fn(uint32_t sip, uint32_t dip, uint16_t sp, uint32_t dp)
{

        uint32_t rc = 0;
        int i;
        static int first_time = 1;
        static uint32_t key_cache[KEY_CACHE_LEN] = {0};

        if (first_time) {
                build_sym_key_cache(key_cache, KEY_CACHE_LEN);
                first_time = 0;
        }
        for (i = 0; i < 32; i++) {
                if (sip & MSB32)
                        rc ^= key_cache[i];
                sip <<= 1;
        }
        for (i = 0; i < 32; i++) {
                if (dip & MSB32)
                        rc ^= key_cache[32+i];
                dip <<= 1;
        }
        for (i = 0; i < 16; i++) {
                if (sp & MSB16)
                        rc ^= key_cache[64+i];
                sp <<= 1;
        }
        for (i = 0; i < 16; i++) {
                if (dp & MSB16)
                        rc ^= key_cache[80+i];
                dp <<= 1;
        }

        return rc;
}

/*-------------------------------------------------------------*/
static void
BuildKeyCache1(uint32_t *cache, int cache_len)
{
#define NBBY 8 /* number of bits per byte */

        /* Keys for system testing */
        static const uint8_t key[] = {
                 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
        };

        uint32_t result = (((uint32_t)key[0]) << 24) |
                (((uint32_t)key[1]) << 16) |
                (((uint32_t)key[2]) << 8)  |
                ((uint32_t)key[3]);

        uint32_t idx = 32;
        int i;

        for (i = 0; i < cache_len; i++, idx++) {
                uint8_t shift = (idx % NBBY);
                uint32_t bit;

                cache[i] = result;
                bit = ((key[idx/NBBY] << shift) & 0x80) ? 1 : 0;
                result = ((result << 1) | bit);
        }
}
/*-------------------------------------------------------------*/
static uint32_t
GetRSSHash1(in_addr_t sip, in_addr_t dip, in_port_t sp, in_port_t dp)
{
#define MSB32 0x80000000
#define MSB16 0x8000
#define KEY_CACHE_LEN 96

        uint32_t res = 0;
        int i;
        static int first = 1;
        static uint32_t key_cache[KEY_CACHE_LEN] = {0};

        if (first) {
                BuildKeyCache1(key_cache, KEY_CACHE_LEN);
                first = 0;
        }

        for (i = 0; i < 32; i++) {
                if (sip & MSB32)
                        res ^= key_cache[i];
                sip <<= 1;
        }
        for (i = 0; i < 32; i++) {
                if (dip & MSB32)
                        res ^= key_cache[32+i];
                dip <<= 1;
        }
        for (i = 0; i < 16; i++) {
                if (sp & MSB16)
                        res ^= key_cache[64+i];
                sp <<= 1;
        }
        for (i = 0; i < 16; i++) {
                if (dp & MSB16)
                        res ^= key_cache[80+i];
                dp <<= 1;
        }
        return res;
}
/*-------------------------------------------------------------------*/
/* RSS redirection table is in the little endian byte order (intel)  */
/*                                                                   */
/* idx: 0 1 2 3 | 4 5 6 7 | 8 9 10 11 | 12 13 14 15 | 16 17 18 19 ...*/
/* val: 3 2 1 0 | 7 6 5 4 | 11 10 9 8 | 15 14 13 12 | 19 18 17 16 ...*/
/* qid = val % num_queues */
/*-------------------------------------------------------------------*/
int
GetRSSCPUCore1(in_addr_t sip, in_addr_t dip,
              in_port_t sp, in_port_t dp, int num_queues, uint8_t endian_check)
{
        #define RSS_BIT_MASK 0x0000007F
        uint32_t masked = GetRSSHash1(sip, dip, sp, dp) & RSS_BIT_MASK;

        if (endian_check) {
                static const uint32_t off[4] = {3, 1, -1, -3};
                masked += off[masked & 0x3];
        }

        return (masked % num_queues);
}
/*-------------------------------------------------------------------*/
                                                                               



void populate_ports1(char* client_ip, int client_start_port, char* server_ip1, int server_port) {
        struct in_addr src,dest;
        uint32_t server_cores = MAX_THREADS;
	uint32_t numth = MAX_THREADS, find_core;
        inet_aton(client_ip, &src);
        inet_aton(server_ip1, &dest);
        //uint32_t sip = ntohl(src.s_addr);
        //uint32_t dip = ntohl(dest.s_addr);
	in_addr_t sip = ntohl(src.s_addr);
        in_addr_t dip = ntohl(dest.s_addr);
        int j=0,k=0;
        for(uint16_t i = 0; i < numth; i++){
                j=0;
	/*	if(i==1){
		server_port = 6001; //added priya feb13
		}
		if(i==2){
		server_port = 6002;
		}
	*/ //for multiple C
                p_vec[i].resize(300);
                while(j<300){
                        //find_core = (sym_hash_fn(sip,dip,client_start_port+k+SEED,server_port+SEED))%server_cores;
			find_core = GetRSSCPUCore1(sip, dip,
                                         client_start_port+k, server_port, numth, 1);
                        if(find_core == i){
                                p_vec[i][j] = client_start_port+k;
				j++;
                        }
                        k++;
                        //j++;
                }

        }
/*      for(uint16_t i = 0; i < numth; i++){
                p_vec[i].resize(1000);
        }
         while(j<1000){
        for(uint16_t i = 0; i < numth; i++){
                //p_vec[i].resize(1000);
                        //find_core = (sym_hash_fn(sip,dip,CLIENT_START_PORT+k+SEED,SERVER_PORT+SEED))%server_cores;
                        //if(find_core < server_cores){
                                p_vec[i][j] = CLIENT_START_PORT+i+k;
                        //}
                  //      k++;
                    //    j++;
        }       
        j++;
        k+=numth+1; 
        }
*/  //when hash is only on sport        
}
void populate_port_ds(char* client_ip, int client_start_port, char* server_ip1) {
        struct in_addr src,dest;
        uint32_t server_cores = MAX_THREADS, numth = MAX_THREADS, find_core;
        inet_aton(client_ip, &src);
        inet_aton(server_ip1, &dest); //ds_ip
	//int client_start_port = 4000;
	//int server_port[numth*2];
        uint32_t sip = ntohl(src.s_addr);
        uint32_t dip = ntohl(dest.s_addr);
        int j=0,k=0;
        for(uint16_t i = 0; i < numth*2; i++){
                j=0;
                //p_vec[i].resize(100);
                while(j<1){
                        find_core = (sym_hash_fn(sip,dip,client_start_port+k+SEED,ds_portno[i]+SEED))%server_cores;
                        if(find_core == i){
                                p_core[i].ds_client_port = client_start_port+k;
                                j++;
                        }
			 if(find_core == (i%2)){
                                p_core[find_core].ds_client_port1 = client_start_port+k;
                                j++;
                        }

                        k++;
                        //j++;
                }

        }
/*      for(uint16_t i = 0; i < numth; i++){
                p_vec[i].resize(1000);
        }
         while(j<1000){
        for(uint16_t i = 0; i < numth; i++){
                //p_vec[i].resize(1000);
                        //find_core = (sym_hash_fn(sip,dip,CLIENT_START_PORT+k+SEED,SERVER_PORT+SEED))%server_cores;
                        //if(find_core < server_cores){
                                p_vec[i][j] = CLIENT_START_PORT+i+k;
                        //}
                  //      k++;
                    //    j++;
        }       
        j++;
        k+=numth+1; 
        }
*/  //when hash is only on sport        
}
void initRequest(int msize[], int m_tot){  //size of chunks for request pool and total number of sizes sizeof(msize[])
	int p = 1,i,j;
	 cout<<"reached here"<<endl;
	int temp_memory_size[4];
//	req_pool_needed = 1;
	if(m_tot>4){
		cout<<"Only 4 pools allowed"<<endl;
		return;  //TODO error handling
	}	
        for(i=0;i<m_tot;i++){
		p=1;
		temp_memory_size[i]=0;
		if (msize[i] && !(msize[i] & (msize[i] - 1))){
			temp_memory_size[i] = msize[i];
			continue;
		}
		while (p < msize[i]) 
			p <<= 1;
	
			temp_memory_size[i] = p;
	}
	cout<<"MEMORY_size is "<<temp_memory_size[0]<<endl; 
	for(i=0;i<MAX_THREADS;i++){
		for(j=0;j<m_tot;j++){
			p_core[i].memory_size[j] = temp_memory_size[j];	
		}
	}
/*        cout<<"reached here"<<endl;
	std::vector<char> v(memory_size*100);
	v.reserve(memory_size*100);
	storage.add_block(&v.front(), v.size(), memory_size);
        cout<<"reached here"<<endl;
*/	
}

void free_ds_pool(){
/*	std::unordered_map<void*,int>::const_iterator gotds;  //iterator over client_list
	BOOST_FOREACH(void *item, ds_map1)
    {
	gotds = local_list.find(item);
                if(got_ds == local_list.end()){
		     //   std::cout << "[" << item->num << "] ";
			key = cache_void_list[item];	
			cache_void_list.erase(item);
			cache_list.erase(key);
	       		storageds.free(item);
			
	 	}
    }*/
	std::unordered_map<void*,int>::const_iterator gotds;
	for ( auto it = cache_void_list.begin(); it != cache_void_list.end(); ++it ){
		gotds = reqptr_list.find(it->first);
		if(gotds == reqptr_list.end()){
			cache_list.erase(it->second);
			ds_map1.erase(it->second);
			storageds.free(it->first);
		}
	}
	cache_void_list.clear();
	ds_size = 0;
}

void SignalHandler(int signum)
{
	//Handle ctrl+C here
	int tot_acc=0;
	//time(&end_app);
	//sec = difftime(end_app,start_app);
	for(int i=0;i<MAX_THREADS;i++){
		tot_acc+=p_core[i].conn_counter;
	}
//	rate=packets[0]+packets[1]+packets[2];
	//rate = ((rate*8)/(sec*1024*1024*1024));
	//printf("#Application level: rate:%lfGbps, time%lf \n",rate,sec);
	fflush(stdout);
	//signal_handler_dpdk(signum);
	//sleep(5);
	for(int i = 0;i<MAX_THREADS;i++){
		mtcp_close(mctx_arr[i], p_core[i].ds_sockid);
		mtcp_close(mctx_arr[i], p_core[i].ds_sockid1);
		printf("Accpted:%d  %d\n",i, p_core[i].conn_counter);
	        //printf("Sent to ds :%d   %d\n",i, p_core[i].pkt_sent_ds);
	        //printf("Sent:%d   %d\n",i, p_core[i].pkt_sent);
		//printf("received from ds :%d   %d\n",i, p_core[i].pkt_recv_ds);
	        //printf("recieved :%d   %d\n",i, p_core[i].pkt_recv);
	}
	 printf("Accepted Total : %d\n",tot_acc);
	mtcp_destroy();
	for(int i = 0;i<MAX_THREADS;i++){
		done[i] = 1;	
	}
//	sleep(25);
}

int read_stream(mctx_t mctx, int conn_fd, uint8_t *buf, int len) {
	//needed for read from DS
        int ptr;
        int retval;
        int read_bytes;
        int remaining_bytes;

        ptr = 0;
        remaining_bytes = len;
        if (conn_fd < 0 || len <= 0) {
                return -1;
        }
        while (1) {
                read_bytes = mtcp_read(mctx, conn_fd, buf + ptr, remaining_bytes);
                if (read_bytes <= 0) {
                        retval = read_bytes;
                        break;
                }
                ptr += read_bytes;
                remaining_bytes -= read_bytes;
                if (remaining_bytes == 0) {
                        retval = len;
                        break;
                }
        }
        return retval;
}

bool connect_done[7] = {false,false,false,false,false,false,false};
void serverThreadFunc(void* arg1){
	//int send_sock;
	cout<<"inside server thread func\n";
	struct arg argument = *((struct arg*)arg1);
	int core = argument.coreno; 
	int id = argument.id;
	int portnos = argument.portnos;
	fn fn_ptr = argument.funct_ptr;
        void* mm_ptr;
//	unsigned char data[BUFSIZE];
	char* data;
	char* buf2;
        char* temp_x;
	int buf_sockid,buf_key;
	string buf_value; //uncomment dec22
	//char* buf_value=malloc(5);
        int newsockfd = -1, ret;
        queue_data data_to_send;

	//step 2. mtcp_core_affinitize
	mtcp_core_affinitize(core);
	
	//step 3. mtcp_create_context. Here order of affinitization and context creation matters.
	// mtcp_epoll_create
	mctx_t mctx = mtcp_create_context(core);
	cout<<"id is "<<id<<endl;
	mct.lock();
	mctx_arr[id] = mctx;										//handle locking priya
	mct.unlock();
	if (!mctx) {
		TRACE_ERROR("Failed to create mtcp context!\n");
		return NULL;
	}
	else{
		printf("mtcp context created.\n");
	}
	cout<<"creating mctx context\n";	
	/* create epoll descriptor */
	int ep = mtcp_epoll_create(mctx, MAX_EVENTS+5);							
	eparr.lock();
	ep_arr[id] = ep;											//handle locking priya
	eparr.unlock();
	if (ep < 0) {
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}
	
	//step 4. mtcp_socket, mtcp_setsock_nonblock,mtcp_bind
	int listener = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	//lock																			 handle lock priya DO or make s_count atomic
	//send_sock = i_count;																									
	sock_c.lock();
	sock_count[i_count][s_count++] = listener;
	cout<<"s_coun is "<<s_count<<endl;
	sock_c.unlock();
	//unlock
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}
	ret = mtcp_setsock_nonblock(mctx, listener);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}
	
	struct sockaddr_in saddr;
	
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = inet_addr((argument.ip).c_str());//inet_addr("192.168.100.2");//INADDR_ANY;
	saddr.sin_port = htons(portnos);
	
	ret = mtcp_bind(mctx, listener,(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}
	
	//step 5. mtcp_listen, mtcp_epoll_ctl
	/* listen (backlog: 4K) */
	ret = mtcp_listen(mctx, listener, 4096);  //4096
	if (ret < 0) {
		TRACE_ERROR("mtcp_listen() failed!\n");
		return -1;
	}
	cout<<"listen socket created\n";	
	/* wait for incoming accept events */
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN; // | MTCP_EPOLLET;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, listener, &ev);
	
	//step 6. mtcp_epoll_wait
	struct mtcp_epoll_event *events;
	events = (struct mtcp_epoll_event *)calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}
	cout << "Waiting for events" << endl;
	int nevents;
                cout<<"started per core"<< id << endl;
                //while(true){
int ds_conn=1;
	//memory pool
        //std::vector<char> v(memory_size*100);
        //v.reserve(memory_size*100);
	//mp_v.resize(memory_size*8388608);
	//std::unordered_map<int,int>::const_iterator got;
	std::unordered_map<void*,int>::const_iterator got1;
	//boost::simple_segregated_storage<std::size_t> storage1;  //memory pool
	//boost::simple_segregated_storage<int> storage1;  //memory pool
	//std::vector<char> mp_v(memory_size*8388608);
	std::vector<char> mp_v1;
	std::vector<char> mp_v2;
	std::vector<char> mp_v3;
	std::vector<char> mp_v4;
	if(p_core[id].memory_size[0] != 0){
	//std::vector<char> mp_v1(memory_size[0]*2097152);
	mp_v1.resize((p_core[id].memory_size[0])*2097152);
//	mp_v.resize(memory_size*1000000); //uncomment nov22
	cout<<"vector size is "<<mp_v1.size()<<endl;
        p_core[id].storage1.add_block(&mp_v1.front(), mp_v1.size(), p_core[id].memory_size[0]);  //uncomment nov22
	}
	if(p_core[id].memory_size[1]!=0){
        //std::vector<char> mp_v2(memory_size[1]*2097152);
	mp_v2.resize((p_core[id].memory_size[1])*2097152);
//      mp_v.resize(memory_size*1000000); //uncomment nov22
        cout<<"vector size is "<<mp_v2.size()<<endl;
        p_core[id].storage2.add_block(&mp_v2.front(), mp_v2.size(), p_core[id].memory_size[1]);  //uncomment nov22
        }
	if(p_core[id].memory_size[2]!=0){
        //std::vector<char> mp_v3(memory_size[2]*2097152);
	mp_v3.resize((p_core[id].memory_size[2])*2097152);
//      mp_v.resize(memory_size*1000000); //uncomment nov22
        cout<<"vector size is "<<mp_v3.size()<<endl;
        p_core[id].storage3.add_block(&mp_v3.front(), mp_v3.size(), p_core[id].memory_size[2]);  //uncomment nov22
        }
	if(p_core[id].memory_size[3]!=0){
        //std::vector<char> mp_v4(memory_size[3]*2097152);
	mp_v4.resize((p_core[id].memory_size[3])*2097152);
//      mp_v.resize(memory_size*1000000); //uncomment nov22
        cout<<"vector size is "<<mp_v4.size()<<endl;
        p_core[id].storage4.add_block(&mp_v4.front(), mp_v4.size(), p_core[id].memory_size[3]);  //uncomment nov22
        }
	//Packet memory pool
	//boost::simple_segregated_storage<std::size_t> storage2;  //memory pool
        //boost::simple_segregated_storage<int> storage1;  //memory pool
        //std::vector<char> mp_pkt_v(1024*65536);  //assuming pkt size 32 TODO

//      mp_v.resize(memory_size*1000000); //uncomment nov22
        cout<<"vector size for pkt pool is "<<p_core[id].mp_pkt_v.size()<<endl;
        p_core[id].storagepkt.add_block(&(p_core[id].mp_pkt_v).front(), (p_core[id].mp_pkt_v).size(), 1024);  //uncomment nov22
	cout<<"vector size for pkt pool is "<<mp_ds.size()<<endl;
	ds_lock.lock();
	if(ds_sizing==1){
	        storageds.add_block(&mp_ds.front(), mp_ds.size(), 64);
		ds_sizing=0;
	}
	ds_lock.unlock();

//int ds_sockid =	createClient(id, "", "169.254.9.18", 7000, "tcp");
//cout<<"ds_sockid "<<ds_sockid<<endl;
//sendData(ds_sockid, id, "hello", 5);
                while(!done[id]){
		ds_conn=0; //uncomment feb1
		if(ds_conn==1){
                        ds_conn=0;
		//	sleep(2);
	/*		ds_conn_lock.lock();
				p_core[id].ds_sockid = createClient(id, "", "169.254.9.18", ds_portno[id*2], "tcp");
				p_core[id].ds_sockid1 = createClient(id, "", "169.254.9.18", ds_portno[id*2+1], "tcp");
			ds_conn_lock.unlock();*/ //uncomment dec 14
			if(id==0){
				p_core[id].ds_sockid = createClientDS(id, argument.ip, p_core[id].ds_client_port, "169.254.9.18", 7000, "tcp");
                                p_core[id].ds_sockid1 = createClientDS(id, argument.ip, p_core[id].ds_client_port1, "169.254.9.18", 7001, "tcp");
				cout<<"ds port for "<<id<<"is "<<p_core[id].ds_client_port<<" "<<p_core[id].ds_client_port1<<endl;

			}
			else{
				p_core[id].ds_sockid = createClientDS(id, argument.ip, p_core[id].ds_client_port, "169.254.9.18", 7002, "tcp");
                                p_core[id].ds_sockid1 = createClientDS(id, argument.ip, p_core[id].ds_client_port1, "169.254.9.18", 7003, "tcp");
				cout<<"ds port for "<<id<<"is "<<p_core[id].ds_client_port<<" "<<p_core[id].ds_client_port1<<endl;
			}

	//uncomment for full b dec20
			//cout<<"ds_connection done "<<id<<endl;
			/*if(ds_conn==2){
			LibPacket pkt1;
			pkt1.clear_pkt();
			snd_cmd="get";
			pkt1.append_item(snd_sockid);
			pkt1.append_item(snd_cmd);
			pkt1.append_item(snd_table);
                        pkt1.append_item(snd_key);
			 pkt1.prepend_len();
//			sendData(ds_sockid, id, pkt.data, pkt.len);
			ds_conn=0;
			sendData(ds_sockid, id, pkt1.data, pkt1.len);
			}*/
			//ds_conn=0;
		}
                nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
                //cout<<"nevents        "<<nevents<<endl;
		if(nevents>=MAX_EVENTS)
			cout<<"nevents is "<<nevents<<endl;
                /*if (nevents < 0) {
                        if (errno != EINTR)
                                cout<<"mtcp_epoll_wait"<<endl;

                        break;
                }*/

                for(int i=0;i<nevents;i++) {
			if(     (events[i].events & MTCP_EPOLLERR) ||
                                (events[i].events & MTCP_EPOLLRDHUP) ||
				(events[i].events & MTCP_EPOLLHUP)
                                ) {
			//if(events[i].events & MTCP_EPOLLERR) {
                                cout<<"ERROR: epoll monitoring failed, closing fd"<<errno<<'\n';
				std::unordered_map<int, uint64_t>::const_iterator gotconn;
				gotconn = (p_core[id].conn_map).find(events[i].data.sockid);
				if(gotconn == (p_core[id].conn_map).end()){
					cout<<"socket for A"<<endl;
				}
				else
					cout<<"socket for C"<<endl;
			/*	int       error = 0;
				socklen_t errlen = sizeof(error);
				if (getsockopt(events[i].data.sockid, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen) == 0)
				{
				    //printf("error = %s\n", strerror(error));
					cout<<error<<endl;
				}
                                if(events[i].data.sockid == listener){
                                        cout<<"Oh Oh, lsfd it is"<<'\n';
                                        exit(-1);
                                }*/
				mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_DEL, events[i].data.sockid, NULL);
                        //        mtcp_close(mctx, events[i].data.sockid);
                                continue;
                        }
                        else if (events[i].data.sockid == listener) {
                                //Accept connection
			   while(1){
                                newsockfd = mtcp_accept(mctx, listener, NULL, NULL);
				if(newsockfd < 0){

                                                if((errno == EAGAIN) || //Need lsfd non blocking to run this!!!!!!
                                                   (errno == EWOULDBLOCK))
                                                {
                                                        //processed all connections !!!
                                                        break;
                                                }
                                                else
                                                cout<<"Error on accept"<<'\n';
                                                break;
                                                //exit(-1);
                                }

                                //printf("New connection %d accepted.\n", newsockfd);
                                //connect_done[core]=true;
                                ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT;
                                ev.data.sockid = newsockfd;
                                mtcp_setsock_nonblock(mctx, newsockfd);
                                mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, newsockfd, &ev);
				p_core[id].mem_ptr[newsockfd] = NULL;
				//mem_ptr[newsockfd] = malloc(memory_size);    //lock TODO   commented for mem pool
				//mp_lock.lock();
				//client_list.push_back(newsockfd);
			/*	if(req_pool_needed==1){
				client_list[newsockfd] = newsockfd;
				mem_ptr[newsockfd] = static_cast<void*>(storage1.malloc());    //lock TODO
				if(mem_ptr[newsockfd]==0){
					cout<<"could not malloc"<<endl;
				}
				}*/
				//cout<<"address in acept is "<<newsockfd<<" "<<(void*)mem_ptr[newsockfd]<<endl;
				/*temp_x = static_cast<char*>(mem_ptr[newsockfd]);
				temp_x[0] = 'z';
				temp_x[1] = '\0';*/
				//mp_lock.unlock();
			//	cout<<p_core[id].conn_counter<<endl;
                                p_core[id].conn_counter++;
                                //lock priya
                                //f_ptr_lock.lock();//TODO add lock
                                p_core[id].funct_ptr[newsockfd] = argument.funct_ptr;
                                //f_ptr_lock.unlock();
                          //uncomment july 6
                                //unlock priya
                                //send data over new connection
                                //char *data = "hello";
                                //ret = 1;
			   }
                        }
                        else if (events[i].events & MTCP_EPOLLIN) {
                                //send data over new connection
                                //cout << "In here." << endl;
                                //char *data = "hello";
                                ret = 1;
                                //while (ret > 0) {
                                        //bzero(data,BUFSIZE);                          //TODO: Check this for performance.
                                  /*      int rd = mtcp_read(mctx, events[i].data.sockid, data, BUFSIZE); //5 replace with BUFSIZE
                                        if (rd <= 0) {

                                                //will come here during connection close check?? TODO
						//cout<<"Connection closed with client"<<endl;
                                                mtcp_close(mctx, events[i].data.sockid);
                                                //cout << "Read error " <<events[i].data.sockid << "rd "<<rd<<endl;
                                                continue; 
						//break;
                                                //return rd;
                                        }*/
					if(events[i].data.sockid == p_core[id].ds_sockid || events[i].data.sockid == p_core[id].ds_sockid1){
						while(1){ 
//						pkt_recv_ds++;
						LibPacket pkt;
	                                        int pkt_len,retval;
						pkt.clear_pkt();
                                        	retval = read_stream(mctx, events[i].data.sockid, pkt.data, sizeof(int));
                                        	if(retval < 0)
                                                	{
                                                        	 if (errno == EAGAIN)
                                                        	{
	                                                          //sep20
        	                                                  //perror ("read");
                	                                        //  printf("loop count is %d", loop_count);
                        	                                 // loop_count = 0;
                                	                          break;
                                        	                }
	
        	                                        //      TRACE(cout<<"Error: Read pkt len case 3, exit for now"<<endl;)
                	                                //      exit(-1);
                        	                        }
                                	        else
                                        	        {
								p_core[id].pkt_recv_ds++;
                                                	        memmove(&pkt_len, pkt.data, sizeof(int) * sizeof(uint8_t));
                                                        	pkt.clear_pkt();
	                                                        retval = read_stream(mctx, events[i].data.sockid, pkt.data, pkt_len);
        	                                                pkt.data_ptr = 0;
                	                                        pkt.len = retval;
                        	                                if(retval < 0)
                                	                        {
                                        	                        TRACE(cout<<"Error: Packet from HSS Corrupt, break"<<endl;)
                                                	                //lflag = 1;
                                                        	        break;
	                                                        }
        	                                        }

	                                        pkt.extract_item(buf_sockid);
                        	                pkt.extract_item(buf_key);
						pkt.extract_item(buf_value);
						buf_value = buf_value + '\0'; //uncomment dec21
						void* getds;
						ds_lock.lock();
						if(ds_size==ds_threshold){
							free_ds_pool();
						}
						getds = storageds.malloc();
						ds_size++;
						memcpy(getds,buf_value.c_str(),buf_value.length()); //dec22 uncomment
						//memcpy(getds,buf_value,4);
						//memcpy(getds,buf_value,4);
						ds_map1[buf_key] = getds;
						cache_list[buf_key] = getds;
						cache_void_list[getds] = buf_key;
						ds_lock.unlock();
						//reqptr_list[getds] = buf_key;
						//cout<<"get request is"<<(char*)ds_map1[buf_key]<<endl;
						//f_ptr_lock.lock(); //TODO add lock
                                                fn_ptr = p_core[id].funct_ptr[buf_sockid];
                                                //f_ptr_lock.unlock();
						//mp_lock.lock();
						//mm_ptr = mem_ptr[buf_sockid];
						//mp_lock.unlock();
						//cout<<"request in lib "<<(char*)mem_ptr[buf_sockid]<<endl;
						//fn_ptr(buf_sockid, id, mem_ptr[buf_sockid], buf_value.c_str());  //commented fod ds mempool dec1
						//fn_ptr(buf_sockid, id, p_core[id].mem_ptr[buf_sockid], static_cast<char*>(cache_list[buf_key]));  //commented fod ds mempool dec1  //uncomment dec15
						//fn_ptr(buf_sockid, id, p_core[id].mem_ptr[buf_sockid], static_cast<char*>(getds));  //commented fod ds mempool dec1 //uncomment dec21
						fn_ptr(buf_sockid, id, p_core[id].mem_ptr[buf_sockid], buf_value.c_str());  //commented fod ds mempool dec1
						//fn_ptr(buf_sockid, id, p_core[id].mem_ptr[buf_sockid], buf_value);  //commented fod ds mempool dec1
						//fn_ptr(buf_sockid, id, mem_ptr.find(buf_sockid)->second, buf_value.c_str());
						}
					}  //sep25
                                        //cout<<"data read at core "<<events[i].data.sockid<<endl;
                                                //lock priya
					else{
						data = static_cast<char*>(p_core[id].storagepkt.malloc());
						int rd = mtcp_read(mctx, events[i].data.sockid, data, BUFSIZE); //5 replace with BUFSIZE
						if(rd <= 0){
                                                	//will come here during connection close check?? TODO
	                                                //cout<<"Connection closed with client"<<endl;
							//storage1.free(mem_ptr[events[i].data.sockid]);
							//if ( std::find(client_list.begin(), client_list.end(), events[i].data.sockid) != client_list.end() ){
						//	if(rd<0)
						//		cout<<errno<<endl;
						//	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_DEL, events[i].data.sockid, NULL);
							int close_ret = mtcp_close(mctx, events[i].data.sockid);
							p_core[id].storagepkt.free(static_cast<void*>(data));
                        	                        continue;
                                	                //break;
                                        	        //return rd;
                                        	}

						p_core[id].pkt_recv++;
                                                //f_ptr_lock.lock(); //TODO add lock
						fn_ptr = p_core[id].funct_ptr[events[i].data.sockid];
                                                //f_ptr_lock.unlock();
						//mp_lock.lock();
                                                //mm_ptr = mem_ptr[events[i].data.sockid];
                                                //mp_lock.unlock();
						//cout<<"request in read "<<(char*)(mem_ptr[events[i].data.sockid])<<endl;
						//data = static_cast<char*>(storage2.malloc());
						//data = (char*) malloc(1024);
						fn_ptr(events[i].data.sockid, id, p_core[id].mem_ptr[events[i].data.sockid], data);
						got1 = p_core[id].pkt_ptr.find(static_cast<void*>(data));
                                                        if (got1 == p_core[id].pkt_ptr.end()){
								p_core[id].storagepkt.free(static_cast<void*>(data));
                                                        }
						//free(data);
						//fn_ptr(events[i].data.sockid, id,mem_ptr.find(events[i].data.sockid)->second, data);
					}
                          //uncomment july 6
                                                //unlock priya
                                        //ret = mtcp_write(mctx, events[i].data.sockid, data, 5);
                /*                      if(sock_count.find(events[i].data.sockid)==sock_count.end())
                                        {
                                                //this if loop to handle default server function pointer. Ideally for every newsockfd register callback for that socket needs to be called
                                                fn_ptr = funct_ptr[events[i].data.sockid];
                                                fn_ptr(events[i].data.sockid, id, "", data);                                                            //handle void* request priya
                                        }
                                        else
                                        {
                                                fn_ptr = argument.funct_ptr;
                                                fn_ptr(events[i].data.sockid, id, "", data);            
                                        }
                */
                                        //cout<<"request received"<< events[i].data.sockid <<endl;
					//TODO lock mem_ptr
                                        // fn_ptr(events[i].data.sockid, id, mem_ptr[events[i].data.sockid], data); //uncomment 6 july   //sep18
                                        /*ret = mtcp_write(mctx, newsockfd, data, lSize);
                                        if (ret < 0) {
                                                TRACE_APP("Connection closed with client.\n");
                                                break;
                                        }
                                        packets[core]+=ret;*/
                                //}
                        }
			/*else if (events[i].data.sockid==ds_sockid & MTCP_EPOLLOUT){
					cout<<"DS connected"<<endl;
			}*/
                        else if (events[i].events & MTCP_EPOLLOUT){
//                      else if (wait_for_connect.find(events[i].data.sockid) != wait_for_connect.end()){
//                              if (events[i].events & MTCP_EPOLLOUT){
                                /*if (wait_for_connect.find(events[i].data.sockid) != wait_for_connect.end()){
                                        if(wait_for_connect[events[i].data.sockid].connected==false){
                                                wait_for_connect[events[i].data.sockid].connected = true; //connection established*/
                                        //      printf("Epollout: %d  s\n",events[i].data.sockid);
                                        //      if(wait_for_connect[events[i].data.sockid] != "NULL"){
                                                        //wait for epoll out
                                                        //while (ret > 0) {
                                                        //data_to_send = wait_for_connect[events[i].data.sockid];
                                                        //cout<<"connect done"<<endl;
                                                        while(!(p_core[id].queue_vec[events[i].data.sockid]).empty()){
                                                                data_to_send = (p_core[id].queue_vec[events[i].data.sockid]).front();
                                                        //      int data_length = data_to_send.data_len, ret=0;
                                                        //      while(ret< data_length){
                                                                ret = mtcp_write(mctx, events[i].data.sockid,data_to_send.data,data_to_send.data_len);
								p_core[id].storagepkt.free((void*)data_to_send.data);
                                                                (p_core[id].queue_vec[events[i].data.sockid]).pop();
                                                                //cout<<"data written to HSS "<<events[i].data.sockid<<" "<<ret<<" "<<data_to_send.data<<endl;
                                                                if (ret < 0) {
                                                                        cout<<"Connection closed with client."<<endl;
                                                                        //TRACE_APP("Connection closed with client.\n");
									mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_DEL, events[i].data.sockid, NULL);
                                                                        mtcp_close(mctx, events[i].data.sockid);
                                                                        break;
                                                                }
                                                                //}
                                                                //cout<<"sent data at core "<<events[i].data.sockid<<endl;
                                                        }
                                        //              wait_for_connect[events[i].data.sockid]="NULL";
                                                        //}
							 //while (ret > 0) {
                                                        //data_to_send = wait_for_connect[events[i].data.sockid];
                                                        //cout<<"connect done"<<endl;
                                                    /*    while(!queue_vec[events[i].data.sockid].empty()){
                                                                data_to_send = queue_vec[events[i].data.sockid].front();
                                                        //      int data_length = data_to_send.data_len, ret=0;
                                                        //      while(ret< data_length){
                                                                ret = mtcp_write(mctx, events[i].data.sockid,data_to_send.data,data_to_send.data_len);

                                                                queue_vec[events[i].data.sockid].pop();
                                                                cout<<"data written to HSS "<<events[i].data.sockid<<" "<<ret<<" "<<data_to_send.data<<endl;
                                                                if (ret < 0) {
                                                                        cout<<"Connection closed with client."<<endl;
                                                                        //TRACE_APP("Connection closed with client.\n");
                                                                        mtcp_close(mctx, events[i].data.sockid);
                                                                        break;
                                                                }  
                                                                //}
                                                                //cout<<"sent data at core "<<events[i].data.sockid<<endl;
                                                        } *///sep18
                                        //              wait_for_connect[events[i].data.sockid]="NULL";
                                                        //}
                                        //      }
                                //      }
                                //}
                        }

                        }
                }
                cout<<"exiting while loop"<<endl;

	//return send_sock;
}
int createServer(string inter_face, string server_ip1, int server_port, string protocol){
	portno = server_port;
	server_ip = server_ip1;
	dummy_connid++;
	return dummy_connid;
}
void* allocReqCtxt(int alloc_sockid, int id, int index){
        p_core[id].client_list[alloc_sockid] = alloc_sockid;
	if(index==1){
	        p_core[id].mem_ptr[alloc_sockid] = static_cast<void*>(p_core[id].storage1.malloc());    //lock TODO
	}
	else if(index==2){
		p_core[id].mem_ptr[alloc_sockid] = static_cast<void*>(p_core[id].storage2.malloc());    //lock TODO
	}
	else if(index==3){
                p_core[id].mem_ptr[alloc_sockid] = static_cast<void*>(p_core[id].storage3.malloc());    //lock TODO
        }
	else if(index==4){
                p_core[id].mem_ptr[alloc_sockid] = static_cast<void*>(p_core[id].storage4.malloc());    //lock TODO
        }
        if(p_core[id].mem_ptr[alloc_sockid]==0){
              cout<<"could not malloc"<<endl;
       }
	return p_core[id].mem_ptr[alloc_sockid];

}
void freeReqCtxt(int alloc_sockid, int id, int index){
	 p_core[id].got = p_core[id].client_list.find(alloc_sockid);
         if (p_core[id].got == p_core[id].client_list.end()){
              //free(mem_ptr[events[i].data.sockid]);
              p_core[id].mem_ptr.erase(alloc_sockid);
             //storage1.free(mem_ptr[events[i].data.sockid]);
         }   //uncomment nov23
         else{
             //cout<<"address in erase is "<<newsockfd<<" "<<(void*)mem_ptr[newsockfd]<<endl;
	     if(index==1){
             	p_core[id].storage1.free(static_cast<void*>(p_core[id].mem_ptr[alloc_sockid]));
	     }
	     else if(index==2){
		p_core[id].storage2.free(static_cast<void*>(p_core[id].mem_ptr[alloc_sockid]));
	     }
	     else if(index==3){
                p_core[id].storage3.free(static_cast<void*>(p_core[id].mem_ptr[alloc_sockid]));
             }
	     else if(index==4){
                p_core[id].storage4.free(static_cast<void*>(p_core[id].mem_ptr[alloc_sockid]));
             }
             p_core[id].mem_ptr.erase(alloc_sockid);  //uncomment nov22
             p_core[id].client_list.erase(alloc_sockid);

         }

}

void addReqCtxt(int connID, int id, void* requestObj){
	p_core[id].mem_ptr[connID] = requestObj;
}
void* getRefPtr(int id, void* pkt_mem_ptr){
	p_core[id].pkt_ptr[pkt_mem_ptr] = 1;
	return pkt_mem_ptr;
}
void removeRefPtr(int id, void* pkt_mem_ptr){
	p_core[id].storagepkt.free(pkt_mem_ptr);
	p_core[id].pkt_ptr.erase(pkt_mem_ptr);
//	cout<<"reached here"<<endl;
}
void* getDSptr(int ds_key){
	void* temp_ds;
	ds_lock.lock();
	//cout<<"reached here"<<endl;
	reqptr_list[ds_map1[ds_key]] = ds_key;
	temp_ds = ds_map1[ds_key];
	ds_lock.unlock();
	return temp_ds;
}

void removeDSptr(int ds_key){
	ds_lock.lock();
        reqptr_list.erase(ds_map1[ds_key]);
	ds_lock.unlock();
	//cout<<"reached here remove"<<endl;
	return;
        
}
char* writePktmem(int id){
	/*pkt_ptr[alloc_sockid] = static_cast<void*>(storagepkt.malloc());    //lock TODO
        if(pkt_ptr[alloc_sockid]==0){
              cout<<"could not malloc"<<endl;
       }*/
	char* pkt = static_cast<char*>(p_core[id].storagepkt.malloc());
        return pkt;
}
//int createServer(string inter_face, string server_ip, int server_port, string protocol, void callbackFnPtr(int, int,  void*, char*))
void startEventLoop()
{
	//dpdkuse_ins.init_dpdkapi(argc,argv);    
	int ret = -1;
	//portno = server_port;
	char* conf_file = "server.conf";
	for(int j=0;j<MAX_THREADS;j++){
		for(int i=0;i< p_core[j].queue_count;i++){
        	         p_core[j].queue_vec.push_back(Q());
	        }
	}
cout<<"reached here"<<endl;
    /* initialize mtcp */
	if (conf_file == NULL) {
		TRACE_CONFIG("You forgot to pass the mTCP startup config file!\n");
		exit(EXIT_FAILURE);
	}
	else {
		TRACE_INFO("Reading configuration from %s\n",conf_file);
	}
	//step 1. mtcp_init, mtcp_register_signal(optional)
	ret = mtcp_init(conf_file);
	if (ret) {
		TRACE_CONFIG("Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}
	
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);
	TRACE_INFO("Application initialization finished.\n");
	for(int i=0;i<MAX_THREADS;i++){
		done[i] = 0;
	}
	/*mp_v.resize(memory_size*1000000);
        cout<<"vector size is "<<mp_v.size()<<endl;
        storage1.add_block(&mp_v.front(), mp_v.size(), memory_size);  *///uncomment nov22
	string c_ip = "169.254.9.78";
 	p_vec.resize(MAX_THREADS);	
	populate_ports1(server_ip.c_str(), 8100, c_ip.c_str(), 6000);
	//populate_port_ds(server_ip.c_str(), 9000, DS_IP);
	//spawn server threads
	for(int i=0;i<MAX_THREADS;i++){
		arguments[i].coreno = i;
		arguments[i].id = i;
		arguments[i].ip = server_ip;
		arguments[i].funct_ptr = funct_ptr[dummy_connid];
		arguments[i].portnos = portno;
		if(i==(MAX_THREADS-1))
			funct_ptr.clear();  //TODO start client only after all threads have started or it would clear actual sockid mappings
		pthread_create(&servers[i],NULL,serverThreadFunc,&arguments[i]);
		//sleep(2);
	}
	//while(connect_done[0]==false || connect_done[1]==false );//|| connect_done[2]==false || connect_done[3]==false || connect_done[4]==false || connect_done[5]==false);
	//time(&dpdkuse_ins.before);
	//time(&start_app);
	//sleep(25);
	//Wait for server threads to complete
	for(int i=0;i<MAX_THREADS;i++){
		pthread_join(servers[i],NULL);
		//sleep(25);		
	}
	int send_sock = i_count;
	i_count++;
//	sleep(2);
	return send_sock;
}

void registerCallback(int connID, int id, string event, void callbackFnPtr(int, int,  void*, char*))
{
	/*if(sock_count.find(connID)==sock_count.end())
	{
		//client sock not found
	//	cout<<"register call back reached here "<< connID << callbackFnPtr << endl;
		funct_ptr[connID] = callbackFnPtr;

	}
	else
	{
		//server sock found
		for(int i=0;i<MAX_THREADS;i++){     //should be s_count check priya
		//	cout<<"register call back sock"<<sock_count[0][i]<<endl;
			funct_ptr[sock_count[0][i]] = callbackFnPtr;
		}
		
	}*/
	if(id != -1)
		p_core[id].funct_ptr[connID] = callbackFnPtr;
	else
		funct_ptr[connID] = callbackFnPtr;

}

int createClientDS(int id, string local_ip , int local_port, string remoteServerIP, int remoteServerPort, string protocol){
        int ep;
        mctx_t mctx;
        //mct.lock();
        mctx = mctx_arr[id];
        //mct.unlock();
        //eparr.lock();
        ep = ep_arr[id];
        //eparr.unlock();
        int sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
        int ret = -1;
        if (sockid < 0) {
                TRACE_ERROR("Failed to create listening socket!\n");
                return -1;
        }
        ret = mtcp_setsock_nonblock(mctx, sockid);
	struct sockaddr_in saddr;

        saddr.sin_family = AF_INET;
        inet_aton((local_ip).c_str() ,&saddr.sin_addr);
        saddr.sin_port = htons(local_port);
//        p_core[id].j++;
        ret = mtcp_bind(mctx, sockid,(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
        if (ret < 0) {
                cout<<"Failed to bind to the client socket!"<<endl;
                return -1;
        }

  /*      ret = mtcp_bind(mctx, sockid,(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
        if (ret < 0) {
                TRACE_ERROR("Failed to bind to the listening socket!\n");
                return -1;
        }*/
        struct sockaddr_in daddr;

        daddr.sin_family = AF_INET;
        daddr.sin_addr.s_addr = inet_addr((remoteServerIP).c_str());
        daddr.sin_port = htons(remoteServerPort);
        ret = mtcp_connect(mctx, sockid, (struct sockaddr *)&daddr, sizeof(struct sockaddr_in));
        if (ret < 0) {
                if (errno != EINPROGRESS) {
                        perror("mtcp_connect");
                        cout<<"connect issue"<<errno<<endl;
                        mtcp_close(mctx, sockid);
                        return -1;
                }
                /*if (errno == EINPROGRESS) {
                        wait_for_connect[sockid].connected = false;
                }*/
        }
        struct mtcp_epoll_event ev;
        ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT ;
        ev.data.sockid = sockid;
        mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, sockid, &ev);

      //cout<<"sent connection to DS "<< sockid <<endl;
        //wait_for_connect[sockid] = "NULL";
        return  sockid;
}


int createClient(int id, string local_ip , string remoteServerIP, int remoteServerPort, string protocol){
	int ep;
	mctx_t mctx;
	//mct.lock();
	mctx = mctx_arr[id];
	//mct.unlock();
	//eparr.lock();
	ep = ep_arr[id];
	//eparr.unlock();
	int sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	int ret = -1;
	if (sockid < 0) {
		cout<<"Failed to create listening socket!"<<endl;
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}
	/*if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
                    {
                                cout<<"setsockopt"<<endl;
                    } //dec20 */
//	ret = mtcp_setsock_nonblock(mctx, sockid);
	ret = mtcp_setsock_nonblock(mctx, sockid);
	if (ret < 0) {
		cout<<"Failed to set socket in nonblocking mode."<<endl;
		return -1;
	}
	
	/*if(p_core[id].j==300){
                        p_core[id].j=0;
                }
//	cout<<"port no "<<p_core[id].j<<" "<<p_vec[id][p_core[id].j]<<" "<<endl;
	struct sockaddr_in saddr;
	
	saddr.sin_family = AF_INET;
	inet_aton(local_ip.c_str() ,&saddr.sin_addr);
	saddr.sin_port = htons(p_vec[id][p_core[id].j]);
	p_core[id].j = (p_core[id].j) + 1;
	ret = mtcp_bind(mctx, sockid,(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		cout<<"Failed to bind to the client socket!"<<endl;
		TRACE_ERROR("Failed to bind to the client socket!\n");
		return -1;
	}
	*/ //mar6
	/*ret = mtcp_bind(mctx, sockid,(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}*/
	struct sockaddr_in daddr;
	
	daddr.sin_family = AF_INET;
	daddr.sin_addr.s_addr = inet_addr((remoteServerIP).c_str());
	daddr.sin_port = htons(remoteServerPort);
	ret = mtcp_connect(mctx, sockid, (struct sockaddr *)&daddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			perror("mtcp_connect");
			cout<<"connect issue"<<errno<<endl;
			mtcp_close(mctx, sockid);
			return -1;
		}
		/*if (errno == EINPROGRESS) {
			wait_for_connect[sockid].connected = false;
		}*/
	}
	//cout<<"connect to HSS done lib "<<"  "<< sockid<<endl;
//	ret = mtcp_setsock_nonblock(mctx, sockid);
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT ;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, sockid, &ev);
	
	//wait_for_connect[sockid] = "NULL";
	return	sockid;
}

void sendData(int connID, int id, char* packetToSend, int packet_size){
	if(!p_core[id].queue_vec[connID].empty()){
		queue_data data_to_send;
		data_to_send.data = packetToSend;
		data_to_send.data_len = packet_size;
		p_core[id].queue_vec[connID].push(data_to_send);
	}
	else{  //for c
//		mct.lock();
		mctx_t mctx = mctx_arr[id];
//		mct.unlock();
	        int ret=1;
		ret = mtcp_write(mctx, connID, packetToSend, packet_size);
		//if(ret==-2){
		if(ret<0){
			//cout<<errno<<endl;
//		   if(errno==ENOTCONN){
			queue_data data_to_send;
	//		memcpy(data_to_send.data, packetToSend, packet_size);
	                data_to_send.data = packetToSend;
//			cout<<"data is "<<std::hex<<data_to_send.data<<endl;
        	        data_to_send.data_len = packet_size;
                	p_core[id].queue_vec[connID].push(data_to_send);
		 //  }
		} //for c
		else{
			//cout<<"data sent through sent data "<< connID <<endl;
			if(connID==p_core[id].ds_sockid || connID==p_core[id].ds_sockid1)
				p_core[id].pkt_sent_ds++;
			else
				p_core[id].storagepkt.free((void*)packetToSend);
				p_core[id].pkt_sent++;
			//mtcp_close(mctx, connID);  //TODO remove this
		}
		//else
		//	cout<<"sent data immediate at core "<<connID<<endl;
	}  //for c
}

void sendDataClient(int connID, int id, string packetToSend, int packet_size){
	//mctx_t mctx = mctx_arr[id];
	int ret=1;
	//wait_for_connect[connID] = packetToSend;
//	cout<<"writing data"<<endl;
	//strcpy(wait_for_connect[connID].data, packetToSend.c_str());
//	wait_for_connect[connID].data = packetToSend;
/*	while (ret > 0) {      //check this jayesh
		ret = mtcp_write(mctx, connID, packetToSend.c_str(), packet_size);
		//cout<<"data written"<<endl;
		if (ret < 0) {
		TRACE_APP("Connection closed with client.\n");
		break;
		}
	}*/
}

void sendDataServer(int connID, int id, string packetToSend, int packet_size){
        mctx_t mctx = mctx_arr[id];
        int ret=1;
//      cout<<"writing data"<<endl;
        while (ret > 0) {      //check this jayesh
                ret = mtcp_write(mctx, connID, packetToSend.c_str(), packet_size);
                //cout<<"data written"<<endl;
                if (ret < 0) {
                TRACE_APP("Connection closed with client.\n");
                break;
                }
        }
}

void setData(int connID, int id, int key, string localRemote, string value){
	if(localRemote=="remote"){
		value = value + '\0';
//		uint32_t key1 = key;
		ds_lock.lock();
		if(ds_size==ds_threshold){
                        free_ds_pool();
                }
		void* setds = storageds.malloc();
		ds_size++;
		//value = value + '\0';
                memcpy(setds,value.c_str(),value.length());
                ds_map1[key] = setds;
                cache_list[key] = setds;
		cache_void_list[setds] = key;
		ds_lock.unlock();
		string snd_cmd = "set",snd_table="abc",snd_value="xyz";
	        int snd_sockid=5,snd_key=10;
		LibPacket pkt;
	        pkt.clear_pkt();
	        pkt.append_item(connID);
	        pkt.append_item(snd_cmd);
	        pkt.append_item(snd_table);
	        pkt.append_item(key);
	        pkt.append_item(value);
	        pkt.prepend_len();
		if(p_core[id].set_c==0){
			 sendData(p_core[id].ds_sockid, id, pkt.data, pkt.len);
			 p_core[id].set_c=1;
		}
		else{
	        	//cout<<"ds_sockid in set"<<ds_sockid<<endl;
		        sendData(p_core[id].ds_sockid1, id, pkt.data, pkt.len);
			p_core[id].set_c=0;
		}
	}
	else{
		value = value + '\0';
		void* setds;
		ds_lock.lock();
		if(ds_size==ds_threshold){
                        free_ds_pool();
                }	
		setds = storageds.malloc();
		ds_size++;
		//value = value + '\0';
                memcpy(setds,value.c_str(),value.length());
                ds_map1[key] = setds;
                local_list[setds] = key;
		ds_lock.unlock();
		//ds_map[key]=value;
	}
}

void getData(int connID, int id, int key, string localRemote, void callbackFnPtr(int, int,  void*, char*)){
	registerCallback(connID, id, "read", callbackFnPtr);
	if(localRemote=="checkcache"){
		int cache_check=0;
		std::unordered_map<int,void*>::const_iterator got_ds;
		ds_lock.lock();
		got_ds = cache_list.find(key);
		if(got_ds != cache_list.end()){
			cache_check=1;
		}
		ds_lock.unlock();
		if(cache_check==1){
			//cout<<"data in cache"<<endl;
			cache_check=0;
			fn fn_ptr;
	                 char* ds_value;
        	         ds_value = static_cast<char*>(cache_list[key]);
                	 //f_ptr_lock.lock(); //TODO add lock
	                 fn_ptr = p_core[id].funct_ptr[connID];
        	         //f_ptr_lock.unlock();
                	 fn_ptr(connID, id, p_core[id].mem_ptr[connID], ds_value);
		}
		else{
			string snd_cmd = "get",snd_table="abc",snd_value="xyz";
	                int snd_sockid=5,snd_key=10;
			//uint32_t key1 = key;
        	        LibPacket pkt1;
	                pkt1.clear_pkt();
        	        snd_cmd="get";
        	        pkt1.append_item(connID);
	                pkt1.append_item(snd_cmd);
	                pkt1.append_item(snd_table);
	                pkt1.append_item(key);
	                pkt1.prepend_len();
	        //       sendData(ds_sockid, id, pkt.data, pkt.len);
	                //cout<<"ds_sockid in get"<<ds_sockid<<endl;
	                if(p_core[id].get_c==0){
        	                sendData(p_core[id].ds_sockid, id, pkt1.data, pkt1.len);
                	        p_core[id].get_c=1;
	                }
        	        else{
                	        sendData(p_core[id].ds_sockid1, id, pkt1.data, pkt1.len);
	                        p_core[id].get_c=0;
	                }
		}
	}
	else if(localRemote=="remote"){
		string snd_cmd = "get",snd_table="abc",snd_value="xyz";
	        int snd_sockid=5,snd_key=10;
		LibPacket pkt1;
	        pkt1.clear_pkt();
	        snd_cmd="get";
	        pkt1.append_item(connID);
	        pkt1.append_item(snd_cmd);
	        pkt1.append_item(snd_table);
	        pkt1.append_item(key);
	        pkt1.prepend_len();
	//       sendData(ds_sockid, id, pkt.data, pkt.len);
        	//cout<<"ds_sockid in get"<<ds_sockid<<endl;
		if(p_core[id].get_c==0){
		        sendData(p_core[id].ds_sockid, id, pkt1.data, pkt1.len);
			p_core[id].get_c=1;
		}
		else{	
			sendData(p_core[id].ds_sockid1, id, pkt1.data, pkt1.len);
			p_core[id].get_c=0;
		}
	}
	else{
		 fn fn_ptr;
		 char* ds_value;
		 ds_lock.lock();
		 ds_value = static_cast<char*>(ds_map1[key]);
		 ds_lock.unlock();
		 //f_ptr_lock.lock(); //TODO add lock
                 fn_ptr = p_core[id].funct_ptr[connID];
                 //f_ptr_lock.unlock();
                 fn_ptr(connID, id, p_core[id].mem_ptr[connID], ds_value);
                
		
	}
}

void delData(int connID, int id, int key, string localRemote){
	if(localRemote=="remote"){
		 std::unordered_map<int,void*>::const_iterator gotds;
		 ds_lock.lock();
		 gotds = cache_list.find(key);
		  ds_lock.unlock();
		 if (gotds != cache_list.end()){
	              //free(mem_ptr[events[i].data.sockid]);
		      ds_lock.lock();
		      cache_void_list.erase(cache_list[key]);
		      storageds.free(cache_list[key]);
        	      cache_list.erase(key);
		      ds_map1.erase(key);
		      ds_lock.unlock();
	             //storage1.free(mem_ptr[events[i].data.sockid]);
		 }
         }
	 else{
		void* temp_ds;
		ds_lock.lock();
		temp_ds = ds_map1[key];
		local_list.erase(temp_ds);
		//storageds.free(temp_ds);
		storageds.free(ds_map1[key]);
		ds_map1.erase(key);
		ds_lock.unlock();
 	} 
		 
	
}


void set_data_local(int id, string table_name, int key, uint64_t value){
	if(table_name.compare("")==0)
		p_core[id].conn_map[key] = value;
	else
		p_core[id].data_map[key] = value;
}

uint64_t get_data_local(int id,string table_name, int key){
	if(table_name.compare("")==0)
		return p_core[id].conn_map[key];
	else
		return p_core[id].data_map[key];
}
