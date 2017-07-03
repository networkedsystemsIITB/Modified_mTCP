#include "dpdk_api.h"

using namespace std;

DPDKUse dpdkuse_ins;

DPDKUse::DPDKUse(){
	port_conf.rxmode.mq_mode 	= ETH_MQ_RX_NONE;
	port_conf.rxmode.max_rx_pkt_len	= ETHER_MAX_LEN;
	port_conf.rxmode.split_hdr_size = 0;
	port_conf.rxmode.header_split   = 0; /**< Header Split disabled */
	port_conf.rxmode.hw_ip_checksum = 0; /**< IP checksum offload enabled */
	port_conf.rxmode.hw_vlan_filter = 0; /**< VLAN filtering disabled */
	port_conf.rxmode.hw_vlan_strip 	= 0; /**< VLAN strip enabled. */
	port_conf.rxmode.hw_vlan_extend	= 0; /**< Extended VLAN disabled. */
	port_conf.rxmode.jumbo_frame    = 0;
	port_conf.rxmode.hw_strip_crc   = 0;
	port_conf.rxmode.enable_scatter	= 0; /**< scatter rx disabled */
	port_conf.txmode.mq_mode 	= ETH_MQ_TX_NONE;


	rx_conf.rx_thresh.pthresh 	= RX_PTHRESH;
	rx_conf.rx_thresh.hthresh 	= RX_HTHRESH;
	rx_conf.rx_thresh.wthresh 	= RX_WTHRESH;
	rx_conf.rx_free_thresh 		= 32;


	tx_conf.tx_thresh.pthresh 	= TX_PTHRESH;
	tx_conf.tx_thresh.hthresh 	= TX_HTHRESH;
	tx_conf.tx_thresh.wthresh 	= TX_WTHRESH;
	tx_conf.tx_free_thresh 		= 32; /* Use PMD default values */
	tx_conf.tx_rs_thresh 		= 32; /* Use PMD default values */
	tx_conf.txq_flags 		= (ETH_TXQ_FLAGS_NOMULTSEGS |
					   ETH_TXQ_FLAGS_NOVLANOFFL |   
					   ETH_TXQ_FLAGS_NOXSUMSCTP |
		      			   ETH_TXQ_FLAGS_NOXSUMUDP |
		    		      	   ETH_TXQ_FLAGS_NOXSUMTCP);
	force_quit = false;

	nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	nb_txd = RTE_TEST_TX_DESC_DEFAULT;

	dpdkapi_enabled_port_mask = 0;

	enabled_port=0;
	
	dpdkapi_pktmbuf_pool = NULL;

	coremask = 0;
}

void
DPDKUse::init_dpdkapi(int argc, char **argv){
	int ret;
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_info dev_info;
	uint8_t nb_ports;
	uint8_t nb_lcore_available;
	uint8_t portid;
	unsigned lcore_id;
	unsigned nb_ports_in_mask = 0;
	struct rte_eth_stats eth_stats;
	bool valid_port = false;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	//signal(SIGINT, signal_handler_dpdk);
	//signal(SIGTERM, signal_handler_dpdk);

	/* parse application arguments (after the EAL ones) */
	ret = dpdkapi_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid DPDKAPI arguments\n");

	/* create the mbuf pool */
	dpdkapi_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, MEMPOOL_CACHE_SIZE,
		0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (dpdkapi_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if (nb_ports > RTE_MAX_ETHPORTS)
		nb_ports = RTE_MAX_ETHPORTS;

	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((dpdkapi_enabled_port_mask & (1 << portid)) == 0)
			continue;
		valid_port = true;
		enabled_port = portid;
		rte_eth_dev_info_get(portid, &dev_info);
		printf("Working on port: %u\n",(unsigned) portid);
		break;
	}
	if(valid_port==false){
		rte_exit(EXIT_FAILURE, "Invalid portmask - bye\n");
	}

	/* init port */
	printf("Initializing port %u... ", (unsigned) enabled_port);
	fflush(stdout);
	ret = rte_eth_dev_configure(enabled_port, 1, 1, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
			  ret, (unsigned) enabled_port);

	rte_eth_macaddr_get(enabled_port,&dpdkapi_port_eth_addr);

	ret = rte_eth_rx_queue_setup(enabled_port, 0, nb_rxd,
					     rte_eth_dev_socket_id(enabled_port),
					     &rx_conf,
					     dpdkapi_pktmbuf_pool);
	//printf("queue setup rx%d\n",ret);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u, queue=%u\n",
			  ret, (unsigned) enabled_port, 0);

	/* init TX queue on port */
	ret = rte_eth_tx_queue_setup(enabled_port, 0, nb_txd,
			rte_eth_dev_socket_id(enabled_port),
			&tx_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u, queue=%u\n",
			ret, (unsigned) enabled_port, 0);

	fflush(stdout);

	/* Start device */
	ret = rte_eth_dev_start(enabled_port);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
			  ret, (unsigned) enabled_port);

	printf("done: \n");

	rte_eth_promiscuous_enable(enabled_port);

	printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
			(unsigned) enabled_port,
			dpdkapi_port_eth_addr.addr_bytes[0],
			dpdkapi_port_eth_addr.addr_bytes[1],
			dpdkapi_port_eth_addr.addr_bytes[2],
			dpdkapi_port_eth_addr.addr_bytes[3],
			dpdkapi_port_eth_addr.addr_bytes[4],
			dpdkapi_port_eth_addr.addr_bytes[5]);

	/* initialize port stats maintained dpdk level */
	memset(&port_statistics, 0, sizeof(port_statistics));

	/* capture initial port stats maintain by NIC */
	rte_eth_stats_get(enabled_port,&eth_stats);
	my_init_eth_dev_stats.ipkt = eth_stats.ipackets;
	my_init_eth_dev_stats.opkt = eth_stats.opackets;
	my_init_eth_dev_stats.ierr = eth_stats.ierrors;
	my_init_eth_dev_stats.oerr = eth_stats.oerrors;
	my_init_eth_dev_stats.mbuferr = eth_stats.rx_nombuf;
	my_init_eth_dev_stats.q_ipkt0 = eth_stats.q_ipackets[0];
	my_init_eth_dev_stats.q_opkt0 = eth_stats.q_opackets[0];
	my_init_eth_dev_stats.q_err0 = eth_stats.q_errors[0];

	check_port_link_status();

	add_entry_arp_table = rte_ring_create("add_entry_arp", ARP_RING*sizeof(struct ip_mac *), rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

	generate_arp_response = rte_ring_create("generate_arp_response", ARP_RING*sizeof(struct ip_mac *), rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);


	/* Initialize the queue configuration of each logical core */
	nb_lcore_available = 0;
	coremask = 0;
	string name = "";
	RTE_LCORE_FOREACH(lcore_id){

		#if OPT_KB==1 //2 KB threads
		if( (nb_lcore_available == (rte_lcore_count()-1)) || (nb_lcore_available == (rte_lcore_count()-2))){
			break;
		}
		#endif
		#if OPT_KB==0 //1 KB thread
		if(nb_lcore_available == (rte_lcore_count()-1)){
			break;
		}
		#endif
		qconf = &lcore_queue_conf[lcore_id];
		name = "rx_buffer" + to_string(lcore_id);
		qconf->rx_queue = rte_ring_create(const_cast<char *>(name.c_str()), MAX_PKT_BURST_RING*sizeof(struct rte_mbuf *), rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		name = "tx_buffer" + to_string(lcore_id);
		qconf->tx_queue = rte_ring_create(const_cast<char *>(name.c_str()), MAX_PKT_BURST_RING*sizeof(struct rte_mbuf *), rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		name = "pending_pkts" + to_string(lcore_id);
		qconf->pending_pkts = rte_ring_create(const_cast<char *>(name.c_str()), PENDING_PKT_RING*sizeof(struct rte_mbuf *), rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		qconf->camehere=0;
		coremask = (coremask | (1<<lcore_id));
		nb_lcore_available++;
		printf("Lcore %u initialized\n", lcore_id);
	}
	rxtx_lcore_id = rte_lcore_count()-1;
	printf("Lcore mask %u initialized\n", coremask);

	/* starting rx and tx thread on last enabled core */
	nb_lcore_available = 0;
	rte_eal_remote_launch((lcore_function_t *)dpdkapi_launch_one_lcore, NULL, rxtx_lcore_id);
	#if OPT_KB==1 //2 KB threads
	rte_eal_remote_launch((lcore_function_t *)dpdkapi_launch_one_lcore1, NULL, (rxtx_lcore_id-1));
	#endif

	#if OPT_KB==0 //1 KB threads
	printf("Rx and Tx thread started at %lu\n", rxtx_lcore_id);
	#endif
	#if OPT_KB==1 //2 KB threads
	printf("Rx thread started at %lu\n", rxtx_lcore_id);
	printf("Tx thread started at %lu\n", rxtx_lcore_id-1);
	#endif
}

int dpdkapi_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	dpdkuse_ins.dpdkapi_main_loop();
	return 0;
}

int dpdkapi_launch_one_lcore1(__attribute__((unused)) void *dummy)
{
	dpdkuse_ins.dpdkapi_main_loop1();
	return 0;
}

void * RunRxMainLoop(void *temp){
	unsigned lcore_id = *((unsigned int *)temp);
	dpdkuse_ins.rx_main_loop(lcore_id);
	return NULL;
}

void * RunTxMainLoop(void *temp){
	unsigned lcore_id = *((unsigned int *)temp);
	dpdkuse_ins.tx_main_loop(lcore_id);
	return NULL;
}

/* main processing loop */
void
DPDKUse::dpdkapi_main_loop(void)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();

	RTE_LOG(INFO, DPDKAPI, "entering main loop on lcore %u\n", lcore_id);

	pthread_create(&rx_thread,NULL, RunRxMainLoop, (void *)&lcore_id);
}

void
DPDKUse::dpdkapi_main_loop1(void)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();

	RTE_LOG(INFO, DPDKAPI, "entering main loop on lcore %u\n", lcore_id);

	pthread_create(&tx_thread,NULL, RunTxMainLoop, (void *)&lcore_id);
}

/*---------------------------------------------------------------------*/
/**
 *  * The cache table is used to pick a nice seed for the hash value. It is
 *   * built only once when sym_hash_fn is called for the very first time
 *    */
static void
build_sym_key_cache(uint32_t *cache, int cache_len)
{
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
#define MSB32				0x80000000
#define MSB16				0x8000
#define KEY_CACHE_LEN			96

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
/*---------------------------------------------------------------------*/
/**
 ** Parser + hash function for the IPv4 packet
 **/
static uint32_t
decode_ip_n_hash(struct rte_mbuf *m, uint8_t hash_split, uint8_t seed)
{
	struct ipv4_hdr *iph = NULL;
	uint32_t rc = 0;
	
	iph = (struct ipv4_hdr *)rte_pktmbuf_mtod_offset(m, char *, sizeof(struct ether_hdr));
	if (hash_split == 2) {
		rc = sym_hash_fn(ntohl(iph->src_addr),
			ntohl(iph->dst_addr),
			ntohs(0xFFFD) + seed,
			ntohs(0xFFFE) + seed);
	} else {
		struct tcp_hdr *tcph = NULL;
		struct udp_hdr *udph = NULL;
		
		switch (iph->next_proto_id) {
		case IPPROTO_TCP:
			tcph = (struct tcp_hdr *)rte_pktmbuf_mtod_offset(m, char *, sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));
			rc = sym_hash_fn(ntohl(iph->src_addr), 
					 ntohl(iph->dst_addr), 
					 ntohs(tcph->src_port) + seed,
					 ntohs(tcph->dst_port) + seed);
			break;
		
		case IPPROTO_UDP:
			udph = (struct udp_hdr *)rte_pktmbuf_mtod_offset(m, char *, sizeof(struct ether_hdr)+ sizeof(struct ipv4_hdr));
			rc = sym_hash_fn(ntohl(iph->src_addr),
					 ntohl(iph->dst_addr),
					 ntohs(udph->src_port) + seed,
					 ntohs(udph->dst_port) + seed);
			break;
		
		default:
			/* 
			 ** the hash strength (although weaker but) should still hold 
			 ** even with 2 fields 
			rc = sym_hash_fn(ntohl(iph->ip_src.s_addr),
					 ntohl(iph->ip_dst.s_addr),
					 ntohs(0xFFFD) + seed,
					 ntohs(0xFFFE) + seed);
			 **/
			// We return 0 to indicate that the packet couldn't be balanced.
			return 0;
		}
	}
	return rc;
}

/* Check the payload of the packet for errors
 */
static void dump_payload(struct rte_mbuf *_p,int len){
	char buf[128];
	int i,j,i0;
	const unsigned char *p = (const unsigned char *)rte_pktmbuf_mtod_offset(_p, char *, 0);
	printf("\n======= FIRST PACKET ======= \n");
	for(i=0;i<len;i++){
		printf("%02x ",(uint8_t)(p[i]));
	}
	printf("\n");
}

/* main Rx processing loop */
void
DPDKUse::rx_main_loop(unsigned lcore_id){
	struct rte_mbuf *pkts_burst_in[MAX_PKT_BURST];
	struct rte_mbuf *pkts_burst_out[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned j, nb_rx, nb_tx;
	struct lcore_queue_conf *qconf;
	struct ipv4_hdr *ip_hdr;
	struct arp_hdr *arp_hdr;
	uint8_t *tmp;
	uint8_t a,b,c,d;
//	uint8_t a1=169,b1=254,c1=9,d1=3;
//	uint8_t a1=192,b1=168,c1=100,d1=3;
//	uint8_t a1=10,b1=129,c1=28,d1=121;
	int enq_val=0;

	unsigned rx_lcore_id=0;

	int deq_val=0;
	int deq_arp=0;
	int enq_arp=0;

	int sent;
	unsigned tx_lcore_id=0;
	uint64_t start=0,nmbuf=0;

	#if OPT_KB==1 //2 KB threads
	RTE_LOG(INFO, DPDKAPI, "entering Rx main loop on lcore %u\n", lcore_id);
	#endif

	#if OPT_KB==0 //1 KB threads

	struct rte_mbuf *arp_req = NULL;
	struct rte_mbuf *arp_res = NULL;
	struct ether_hdr *eth_hdr;
	uint32_t my_ip;
	struct ether_addr arp_broadcast_mac = {
		.addr_bytes = {0xff,0xff,0xff,0xff,0xff,0xff}
	};
	struct ether_addr arp_req_dst_mac = {
		.addr_bytes = {0x00,0x00,0x00,0x00,0x00,0x00}
	};

	my_ip = MY_IP_1 | (MY_IP_2 << 8) | (MY_IP_3 << 16) | (MY_IP_4 << 24);

	do{
		arp_req = rte_pktmbuf_alloc(dpdkapi_pktmbuf_pool);
	}while(arp_req==NULL);

	do{
		arp_res = rte_pktmbuf_alloc(dpdkapi_pktmbuf_pool);
	}while(arp_res==NULL);

	//====Making arp request pkt=====
	//ethernet header (adding src ip and mac and broadcast ether address in dst mac)
	eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(arp_req, char *, 0);
	ether_addr_copy(&dpdkapi_port_eth_addr,&eth_hdr->s_addr);
	ether_addr_copy(&arp_broadcast_mac,&eth_hdr->d_addr);
	eth_hdr->ether_type = htons(ETHER_TYPE_ARP);
	//arp header (all header + adding src ip and mac)
	arp_hdr = (struct arp_hdr*)rte_pktmbuf_mtod_offset(arp_req, char *, sizeof(struct ether_hdr));
	arp_hdr->arp_hrd = htons(ARP_HRD_ETHER);
	arp_hdr->arp_pro = htons(0x0800);
	arp_hdr->arp_hln = 6;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARP_OP_REQUEST);
	ether_addr_copy(&dpdkapi_port_eth_addr,&arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip = my_ip;
	ether_addr_copy(&arp_req_dst_mac,&arp_hdr->arp_data.arp_tha);
	//DPDK specific pkt parameters
	arp_req->next = NULL;
	arp_req->nb_segs = 1;
	arp_req->pkt_len = sizeof(struct ether_hdr)+sizeof(struct arp_hdr);
	arp_req->l2_len = sizeof(struct ether_hdr);
	arp_req->vlan_tci  = ETHER_TYPE_ARP;
	arp_req->l3_len = sizeof(struct arp_hdr);
	arp_req->data_len = sizeof(struct ether_hdr)+sizeof(struct arp_hdr);

	//====Making arp response pkt=====
	//ethernet header (adding src ip and mac)
	eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(arp_res, char *, 0);
	ether_addr_copy(&dpdkapi_port_eth_addr,&eth_hdr->s_addr);
	eth_hdr->ether_type = htons(ETHER_TYPE_ARP);
	//arp header (all header + adding src ip and mac)
	arp_hdr = (struct arp_hdr*)rte_pktmbuf_mtod_offset(arp_res, char *, sizeof(struct ether_hdr));
	arp_hdr->arp_hrd = htons(ARP_HRD_ETHER);
	arp_hdr->arp_pro = htons(0x0800);
	arp_hdr->arp_hln = 6;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARP_OP_REPLY);
	ether_addr_copy(&dpdkapi_port_eth_addr,&arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip = my_ip;
	arp_res->next = NULL;
	arp_res->nb_segs = 1;
	arp_res->pkt_len = sizeof(struct ether_hdr)+sizeof(struct arp_hdr);
	arp_res->l2_len = sizeof(struct ether_hdr);
	arp_res->vlan_tci  = ETHER_TYPE_ARP;
	arp_res->l3_len = sizeof(struct arp_hdr);
	arp_res->data_len = sizeof(struct ether_hdr)+sizeof(struct arp_hdr);

	RTE_LOG(INFO, DPDKAPI, "entering Rx and Tx main loop on lcore %u\n", lcore_id);
	#endif

	while(!force_quit) {

		//---------------RX thread work-------------------
		//printf("\nbefore rx\n");
		nb_rx = rte_eth_rx_burst((uint8_t) enabled_port, 0,
					 pkts_burst_in, MAX_PKT_BURST);
		//printf("nb_rx:%lu\n",nb_rx);
		for (j = 0; j < nb_rx; j++) {
			m = pkts_burst_in[j];
			struct ether_hdr *eth = (struct ether_hdr *)rte_pktmbuf_mtod_offset(m,char *,0);
			int eth_type = ntohs(eth->ether_type);

			if(eth_type==ETHER_TYPE_ARP){
				arp_hdr = (struct arp_hdr*)rte_pktmbuf_mtod_offset(m, char *, sizeof(struct ether_hdr));
				tmp = (unsigned char *)&arp_hdr->arp_data.arp_tip;
				a = *tmp;
				tmp++;
				b = *tmp;
				tmp++;
				c = *tmp;
				tmp++;
				d = *tmp;
				//printf("-------------- a: %d.b: %d.c: %d.d: %d\n",a,b,c,d);
				if(a==MY_IP_1 && b==MY_IP_2 && c==MY_IP_3 && d==MY_IP_4){
				//if(arp_hdr->arp_data.arp_tip==my_ip){
					//printf("arp packt received\n");
					if(ntohs(arp_hdr->arp_op)==ARP_OP_REPLY){
						struct ip_mac *new_arp_entry = (struct ip_mac *) rte_calloc (NULL, 1, sizeof(struct ip_mac), 0);//rte_malloc(NULL, sizeof(struct ip_mac),0);
						new_arp_entry->ip = arp_hdr->arp_data.arp_sip;
						ether_addr_copy(&arp_hdr->arp_data.arp_sha,&new_arp_entry->mac);
						do{
							enq_arp = rte_ring_sp_enqueue_burst(add_entry_arp_table, (void**)(&new_arp_entry),1);
						}while(enq_arp==0);
						//printf("arp reply came\n");
					}else if(ntohs(arp_hdr->arp_op)==ARP_OP_REQUEST){
						struct ip_mac *arp_response = (struct ip_mac *) rte_calloc(NULL, 1, sizeof(struct ip_mac), 0);
						arp_response->ip = arp_hdr->arp_data.arp_sip;
						ether_addr_copy(&arp_hdr->arp_data.arp_sha,&arp_response->mac);
						do{
							enq_arp = rte_ring_sp_enqueue_burst(generate_arp_response, (void**)(&arp_response),1);
						}while(enq_arp==0);
						//printf("arp request came\n");
					}
				}
				rte_pktmbuf_free(m);
			}else{
				ip_hdr = (struct ipv4_hdr *)rte_pktmbuf_mtod_offset(m, char *, sizeof(struct ether_hdr));

				tmp = (unsigned char *)&ip_hdr->dst_addr;
				a = *tmp;
				tmp++;
				b = *tmp;
				tmp++;
				c = *tmp;
				tmp++;
				d = *tmp;
				//printf("-------------- a: %d.b: %d.c: %d.d: %d\n",a,b,c,d);
	//			if(a==a1 && b==b1 && c==c1 && d==d1){
				if(a==MY_IP_1 && b==MY_IP_2 && c==MY_IP_3 && d==MY_IP_4){
				
					uint32_t hashv = decode_ip_n_hash(m, 4, 'B');

					#if OPT_KB==0 //1 KB
					rx_lcore_id = hashv%(rte_lcore_count()-1);
					#endif
					#if OPT_KB==1 //2 KB
					rx_lcore_id = hashv%(rte_lcore_count()-2);
					#endif
					//printf("hashed rx lcore %lu\n",rx_lcore_id);
					qconf = &lcore_queue_conf[rx_lcore_id];
					//dump_payload(m,m->data_len);
					port_statistics[rx_lcore_id].rx++;
					port_statistics[rx_lcore_id].rx_bytes += (m->pkt_len);// - sizeof(struct ether_hdr) - sizeof(struct ipv4_hdr) - sizeof(struct tcp_hdr));

					port_statistics[lcore_id].rx++;
					port_statistics[lcore_id].rx_bytes += (m->pkt_len);
					do{
						enq_val = rte_ring_sp_enqueue_burst(qconf->rx_queue, (void**)&pkts_burst_in[j], 1); // keeping pkts_burst_in[j] instead of m because it can cause pointer issue
					}while(enq_val==0);
					//rx_dpdk = clock();
					
				}else{
					rte_pktmbuf_free(m);
				}
			}
		}

		#if OPT_KB==0 //1 KB thread
		//---------------TX thread work-------------------

		//===Handle ARP responses===
		// adding new entry in arp table
		//while(rte_ring_count(add_entry_arp_table)){
		//while(!rte_ring_empty(add_entry_arp_table)){
		deq_arp=0;
		do{
			struct ip_mac *new_arp_entry[1];
			deq_arp = rte_ring_sc_dequeue_burst(add_entry_arp_table, (void**)new_arp_entry,1);
			if(deq_arp>0){
				arp_table.insert(make_pair(new_arp_entry[0]->ip, new_arp_entry[0]->mac));
				set<uint32_t>::iterator ip_to_del = pending_arp_req.find(new_arp_entry[0]->ip);
				if(ip_to_del!=pending_arp_req.end()){
					pending_arp_req.erase(ip_to_del);
				}
				//free(((struct ip_mac *)new_arp_entry[0]));
				//printf("response get\n");
			}
		}while(deq_arp>0);

		//===Handle ARP request===
		// generate arp response and send out
		//while(rte_ring_count(generate_arp_response)){
		/*if(rte_ring_count(generate_arp_response)!=0)
			printf("ring size %d\n",rte_ring_count(generate_arp_response));*/
		//while(!rte_ring_empty(generate_arp_response)){
		deq_arp=0;
		do{
			struct ip_mac *arp_response[1];
			//printf("before deq from arp\n");
			deq_arp = rte_ring_sc_dequeue_burst(generate_arp_response, (void**)arp_response,1);
			//printf("arp_resp: %02X %d\n",arp_response[0]->ip, deq_arp);
			if(deq_arp>0){
				//printf("arp_resp: %02X %d %d\n",arp_response[0]->ip, deq_arp, rte_ring_count(generate_arp_response));
				//add entry to arp first (taking src ip and mac from request pkt)
				arp_table.insert(make_pair(arp_response[0]->ip, arp_response[0]->mac));
				set<uint32_t>::iterator ip_to_del = pending_arp_req.find(arp_response[0]->ip);
				if(ip_to_del!=pending_arp_req.end()){
					pending_arp_req.erase(ip_to_del);
				}
				eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(arp_res, char *, 0);
				ether_addr_copy(&arp_response[0]->mac,&eth_hdr->d_addr);
				arp_hdr = (struct arp_hdr*)rte_pktmbuf_mtod_offset(arp_res, char *, sizeof(struct ether_hdr));
				ether_addr_copy(&arp_response[0]->mac,&arp_hdr->arp_data.arp_tha);
				arp_hdr->arp_data.arp_tip = arp_response[0]->ip;
				do{
					sent = rte_eth_tx_burst(enabled_port, 0,(struct rte_mbuf **)&arp_res,1);
				}while(sent==0);
				//free(((struct ip_mac *)&(*arp_response[0])));
				//printf("response send entries %d\n",rte_ring_count(generate_arp_response));
				//dump_payload(arp_res, arp_res->data_len);
			}
		}while(deq_arp>0);


		RTE_LCORE_FOREACH(tx_lcore_id){
			if(tx_lcore_id == lcore_id){
				continue;
			}
	
			qconf = &lcore_queue_conf[tx_lcore_id];

			//===send pending pkts===
			//while(rte_ring_count(qconf->pending_pkts)){
			//while(!rte_ring_empty(qconf->pending_pkts)){
			//deq_val=0;
			//do{
				deq_val = rte_ring_sc_dequeue_burst(qconf->pending_pkts,(void**)pkts_burst_out,MAX_PKT_BURST);
				nb_tx=deq_val;
				//printf("deq_val %d\n",deq_val);
				for(int i=0;i<nb_tx;i++){
					m = pkts_burst_out[i];
					//if(deq_val>0){
					ip_hdr = (struct ipv4_hdr *)rte_pktmbuf_mtod_offset(m, char *, sizeof(struct ether_hdr));
		
					map<uint32_t, struct ether_addr>::iterator it;
					it = arp_table.find(ip_hdr->dst_addr);
					//entry present in arp table
					if(it!=arp_table.end()){ //yes
						eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(m, char *, 0);
						ether_addr_copy(&((struct ether_addr)it->second),&eth_hdr->d_addr);
						do{
							sent = rte_eth_tx_burst(enabled_port, 0,(void **)&m,1);
						}while(sent==0);
						port_statistics[lcore_id].tx++;
						port_statistics[tx_lcore_id].tx++;
						port_statistics[lcore_id].tx_bytes += (m->pkt_len);
						port_statistics[tx_lcore_id].tx_bytes += (m->pkt_len);
						rte_pktmbuf_free(m);
						//printf("pkt sent\n");
					}else{ //no
						//add back to pending list
						do{
							enq_arp = rte_ring_sp_enqueue_burst(qconf->pending_pkts, (void**)(&m),1);
						}while(enq_arp==0);
						//printf("pkt pending\n");
					}
				}
			//}while(deq_val>0);
	
			//===send new packets===
			deq_val = rte_ring_sc_dequeue_burst(qconf->tx_queue, (void**)pkts_burst_out, MAX_PKT_BURST);
	
			if(deq_val==0){
				continue;
			}
			//printf("tx deq done %d \n",deq_val);
	
			nb_tx = deq_val;
			for(int i=0;i<nb_tx;i++){
				m = pkts_burst_out[i];
				ip_hdr = (struct ipv4_hdr *)rte_pktmbuf_mtod_offset(m, char *, sizeof(struct ether_hdr));
			
				map<uint32_t, struct ether_addr>::iterator it;
				it = arp_table.find(ip_hdr->dst_addr);
				//entry present in arp table
				if(it!=arp_table.end()){ //yes
					eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(m, char *, 0);
					ether_addr_copy(&((struct ether_addr)it->second),&eth_hdr->d_addr);
					do{
						sent = rte_eth_tx_burst(enabled_port, 0,(void **)&m,1);
					}while(sent==0);
					port_statistics[lcore_id].tx++;
					port_statistics[tx_lcore_id].tx++;
					port_statistics[lcore_id].tx_bytes += (m->pkt_len);
					port_statistics[tx_lcore_id].tx_bytes += (m->pkt_len);
					rte_pktmbuf_free(m);
				}else{ //no
					
					//first packet for this ip, so generate arp request
					if(pending_arp_req.find(ip_hdr->dst_addr)==pending_arp_req.end()){
						//send apr request
						arp_hdr = (struct arp_hdr*)rte_pktmbuf_mtod_offset(arp_req, char *, sizeof(struct ether_hdr));
						arp_hdr->arp_data.arp_tip = ip_hdr->dst_addr;
						do{
							sent = rte_eth_tx_burst(enabled_port, 0,(void **)&arp_req,1);
						}while(sent==0);
						//add to pending list (waiting for arp response)
						pending_arp_req.insert(ip_hdr->dst_addr);
					}
	
					//add to pending list
					do{
						enq_arp = rte_ring_sp_enqueue_burst(qconf->pending_pkts, (void**)(&m),1);
					}while(enq_arp==0);
				}
			}
		}
		#endif
	}

	#if OPT_KB==0 //1 KB thread
	rte_pktmbuf_free(arp_req);
	rte_pktmbuf_free(arp_res);
	#endif
}

/* main Tx processing loop */
void
DPDKUse::tx_main_loop(unsigned lcore_id){
	struct rte_mbuf *pkts_burst_in[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned i, j, nb_tx;
	
	uint64_t start=0,nmbuf=0;

	struct lcore_queue_conf *qconf;
	int deq_val=0;
	int deq_arp=0;
	int enq_arp=0;
	int sent;
	unsigned tx_lcore_id=0;

	struct ipv4_hdr *ip_hdr;
	struct rte_mbuf *arp_req = NULL;
	struct rte_mbuf *arp_res = NULL;
	struct ether_hdr *eth_hdr;
	struct arp_hdr *arp_hdr;
	uint32_t my_ip;
	struct ether_addr arp_broadcast_mac = {
		.addr_bytes = {0xff,0xff,0xff,0xff,0xff,0xff}
	};
	struct ether_addr arp_req_dst_mac = {
		.addr_bytes = {0x00,0x00,0x00,0x00,0x00,0x00}
	};

	my_ip = MY_IP_1 | (MY_IP_2 << 8) | (MY_IP_3 << 16) | (MY_IP_4 << 24);

	do{
		arp_req = rte_pktmbuf_alloc(dpdkapi_pktmbuf_pool);
	}while(arp_req==NULL);

	do{
		arp_res = rte_pktmbuf_alloc(dpdkapi_pktmbuf_pool);
	}while(arp_res==NULL);

	//====Making arp request pkt=====
	//ethernet header (adding src ip and mac and broadcast ether address in dst mac)
	eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(arp_req, char *, 0);
	ether_addr_copy(&dpdkapi_port_eth_addr,&eth_hdr->s_addr);
	ether_addr_copy(&arp_broadcast_mac,&eth_hdr->d_addr);
	eth_hdr->ether_type = htons(ETHER_TYPE_ARP);
	//arp header (all header + adding src ip and mac)
	arp_hdr = (struct arp_hdr*)rte_pktmbuf_mtod_offset(arp_req, char *, sizeof(struct ether_hdr));
	arp_hdr->arp_hrd = htons(ARP_HRD_ETHER);
	arp_hdr->arp_pro = htons(0x0800);
	arp_hdr->arp_hln = 6;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARP_OP_REQUEST);
	ether_addr_copy(&dpdkapi_port_eth_addr,&arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip = my_ip;
	ether_addr_copy(&arp_req_dst_mac,&arp_hdr->arp_data.arp_tha);
	//DPDK specific pkt parameters
	arp_req->next = NULL;
	arp_req->nb_segs = 1;
	arp_req->pkt_len = sizeof(struct ether_hdr)+sizeof(struct arp_hdr);
	arp_req->l2_len = sizeof(struct ether_hdr);
	arp_req->vlan_tci  = ETHER_TYPE_ARP;
	arp_req->l3_len = sizeof(struct arp_hdr);
	arp_req->data_len = sizeof(struct ether_hdr)+sizeof(struct arp_hdr);

	//====Making arp response pkt=====
	//ethernet header (adding src ip and mac)
	eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(arp_res, char *, 0);
	ether_addr_copy(&dpdkapi_port_eth_addr,&eth_hdr->s_addr);
	eth_hdr->ether_type = htons(ETHER_TYPE_ARP);
	//arp header (all header + adding src ip and mac)
	arp_hdr = (struct arp_hdr*)rte_pktmbuf_mtod_offset(arp_res, char *, sizeof(struct ether_hdr));
	arp_hdr->arp_hrd = htons(ARP_HRD_ETHER);
	arp_hdr->arp_pro = htons(0x0800);
	arp_hdr->arp_hln = 6;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARP_OP_REPLY);
	ether_addr_copy(&dpdkapi_port_eth_addr,&arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip = my_ip;
	arp_res->next = NULL;
	arp_res->nb_segs = 1;
	arp_res->pkt_len = sizeof(struct ether_hdr)+sizeof(struct arp_hdr);
	arp_res->l2_len = sizeof(struct ether_hdr);
	arp_res->vlan_tci  = ETHER_TYPE_ARP;
	arp_res->l3_len = sizeof(struct arp_hdr);
	arp_res->data_len = sizeof(struct ether_hdr)+sizeof(struct arp_hdr);

	RTE_LOG(INFO, DPDKAPI, "entering Tx main loop on lcore %u\n", lcore_id);
	while(!force_quit) {
		//===Handle ARP responses===
		// adding new entry in arp table
		//while(rte_ring_count(add_entry_arp_table)){
		//while(!rte_ring_empty(add_entry_arp_table)){
		deq_arp=0;
		do{
			struct ip_mac *new_arp_entry[1];
			deq_arp = rte_ring_sc_dequeue_burst(add_entry_arp_table, (void**)new_arp_entry,1);
			if(deq_arp>0){
				arp_table.insert(make_pair(new_arp_entry[0]->ip, new_arp_entry[0]->mac));
				set<uint32_t>::iterator ip_to_del = pending_arp_req.find(new_arp_entry[0]->ip);
				if(ip_to_del!=pending_arp_req.end()){
					pending_arp_req.erase(ip_to_del);
				}
				//free(((struct ip_mac *)new_arp_entry[0]));
				//printf("response get\n");
			}
		}while(deq_arp>0);

		//===Handle ARP request===
		// generate arp response and send out
		//while(rte_ring_count(generate_arp_response)){
		/*if(rte_ring_count(generate_arp_response)!=0)
			printf("ring size %d\n",rte_ring_count(generate_arp_response));*/
		//while(!rte_ring_empty(generate_arp_response)){
		deq_arp=0;
		do{
			struct ip_mac *arp_response[1];
			//printf("before deq from arp\n");
			deq_arp = rte_ring_sc_dequeue_burst(generate_arp_response, (void**)arp_response,1);
			//printf("arp_resp: %02X %d\n",arp_response[0]->ip, deq_arp);
			if(deq_arp>0){
				//printf("arp_resp: %02X %d %d\n",arp_response[0]->ip, deq_arp, rte_ring_count(generate_arp_response));
				//add entry to arp first (taking src ip and mac from request pkt)
				arp_table.insert(make_pair(arp_response[0]->ip, arp_response[0]->mac));
				set<uint32_t>::iterator ip_to_del = pending_arp_req.find(arp_response[0]->ip);
				if(ip_to_del!=pending_arp_req.end()){
					pending_arp_req.erase(ip_to_del);
				}
				eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(arp_res, char *, 0);
				ether_addr_copy(&arp_response[0]->mac,&eth_hdr->d_addr);
				arp_hdr = (struct arp_hdr*)rte_pktmbuf_mtod_offset(arp_res, char *, sizeof(struct ether_hdr));
				ether_addr_copy(&arp_response[0]->mac,&arp_hdr->arp_data.arp_tha);
				arp_hdr->arp_data.arp_tip = arp_response[0]->ip;
				do{
					sent = rte_eth_tx_burst(enabled_port, 0,(struct rte_mbuf **)&arp_res,1);
				}while(sent==0);
				//free(((struct ip_mac *)&(*arp_response[0])));
				//printf("response send entries %d\n",rte_ring_count(generate_arp_response));
				//dump_payload(arp_res, arp_res->data_len);
			}
		}while(deq_arp>0);

		RTE_LCORE_FOREACH(tx_lcore_id){
			if(tx_lcore_id == lcore_id || (tx_lcore_id == (lcore_id+1)) ){
				continue;
			}
	
			qconf = &lcore_queue_conf[tx_lcore_id];

			//===send pending pkts===
			//while(rte_ring_count(qconf->pending_pkts)){
			//while(!rte_ring_empty(qconf->pending_pkts)){
			//deq_val=0;
			//do{
				deq_val = rte_ring_sc_dequeue_burst(qconf->pending_pkts,(void**)pkts_burst_in,MAX_PKT_BURST);
				nb_tx=deq_val;
				//printf("deq_val %d\n",deq_val);
				for(int i=0;i<nb_tx;i++){
					m = pkts_burst_in[i];
					//if(deq_val>0){
					ip_hdr = (struct ipv4_hdr *)rte_pktmbuf_mtod_offset(m, char *, sizeof(struct ether_hdr));
		
					map<uint32_t, struct ether_addr>::iterator it;
					it = arp_table.find(ip_hdr->dst_addr);
					//entry present in arp table
					if(it!=arp_table.end()){ //yes
						eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(m, char *, 0);
						ether_addr_copy(&((struct ether_addr)it->second),&eth_hdr->d_addr);
						do{
							sent = rte_eth_tx_burst(enabled_port, 0,(void **)&m,1);
						}while(sent==0);
						port_statistics[lcore_id].tx++;
						port_statistics[tx_lcore_id].tx++;
						port_statistics[lcore_id].tx_bytes += (m->pkt_len);
						port_statistics[tx_lcore_id].tx_bytes += (m->pkt_len);
						rte_pktmbuf_free(m);
						//printf("pkt sent\n");
					}else{ //no
						//add back to pending list
						do{
							enq_arp = rte_ring_sp_enqueue_burst(qconf->pending_pkts, (void**)(&m),1);
						}while(enq_arp==0);
						//printf("pkt pending\n");
					}
				}
			//}while(deq_val>0);

			//===send new packets===
			deq_val = rte_ring_sc_dequeue_burst(qconf->tx_queue, (void**)pkts_burst_in, MAX_PKT_BURST);
	
			if(deq_val==0){
				continue;
			}
			//printf("tx deq done %d \n",deq_val);
	
			nb_tx = deq_val;
			for(int i=0;i<nb_tx;i++){
				m = pkts_burst_in[i];
				ip_hdr = (struct ipv4_hdr *)rte_pktmbuf_mtod_offset(m, char *, sizeof(struct ether_hdr));
			
				map<uint32_t, struct ether_addr>::iterator it;
				it = arp_table.find(ip_hdr->dst_addr);
				//entry present in arp table
				if(it!=arp_table.end()){ //yes
					eth_hdr = (struct ether_hdr*)rte_pktmbuf_mtod_offset(m, char *, 0);
					ether_addr_copy(&((struct ether_addr)it->second),&eth_hdr->d_addr);
					do{
						sent = rte_eth_tx_burst(enabled_port, 0,(void **)&m,1);
					}while(sent==0);
					port_statistics[lcore_id].tx++;
					port_statistics[tx_lcore_id].tx++;
					port_statistics[lcore_id].tx_bytes += (m->pkt_len);
					port_statistics[tx_lcore_id].tx_bytes += (m->pkt_len);
					rte_pktmbuf_free(m);
				}else{ //no
					
					//first packet for this ip, so generate arp request
					if(pending_arp_req.find(ip_hdr->dst_addr)==pending_arp_req.end()){
						//send apr request
						arp_hdr = (struct arp_hdr*)rte_pktmbuf_mtod_offset(arp_req, char *, sizeof(struct ether_hdr));
						arp_hdr->arp_data.arp_tip = ip_hdr->dst_addr;
						do{
							sent = rte_eth_tx_burst(enabled_port, 0,(void **)&arp_req,1);
						}while(sent==0);
						//add to pending list (waiting for arp response)
						pending_arp_req.insert(ip_hdr->dst_addr);
					}
	
					//add to pending list
					do{
						enq_arp = rte_ring_sp_enqueue_burst(qconf->pending_pkts, (void**)(&m),1);
					}while(enq_arp==0);
				}
			}
		}
	}
	rte_pktmbuf_free(arp_req);
	rte_pktmbuf_free(arp_res);
}


/* Create a buffer and gives a rx buffer to upper layer */
struct rte_mbuf * 
DPDKUse::get_buffer_rx(unsigned lcore_id){
	struct lcore_queue_conf *qconf;
	struct rte_mbuf *pkt;
	
	qconf =	&lcore_queue_conf[lcore_id];
	int deq_val = 0;
	
	deq_val = rte_ring_sc_dequeue_burst(qconf->rx_queue, (void**)&pkt, 1);
	if(deq_val==0){
		return NULL;
	}
	rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
	return pkt;
}

int32_t DPDKUse::get_rx_count(unsigned lcore_id){
	struct lcore_queue_conf *qconf;
	int32_t rx_pkts;

	qconf =	&lcore_queue_conf[lcore_id];
	//rx_pkts = (int32_t)RTE_MIN(rte_ring_count(qconf->rx_queue), 40);
	rx_pkts = (int32_t)rte_ring_count(qconf->rx_queue);
	//rx_pkts = 1;
	
	if(rx_pkts<=0){
		return 0;
	}
	if(rx_pkts<80){
		qconf->camehere++;
		if(qconf->camehere>=100){
			qconf->camehere=0;
//			printf("rx_cnt: %lu\n",rx_pkts);
			return rx_pkts;
		}
		return 0;
	}
	//printf("rx_cnt: %lu\n",rx_pkts);
	qconf->camehere=0;
	return rx_pkts;
}

/* Create a buffer and gives a tx buffer to upper layer */
struct rte_mbuf * 
DPDKUse::get_buffer_tx(){
	//printf("\n ---> get_lcore %d\n",rte_lcore_id());
	struct rte_mbuf *pkt = NULL;
	pkt = rte_pktmbuf_alloc(dpdkapi_pktmbuf_pool);
	if (pkt == NULL) {
		//printf("\nNo more free pkt please try again after some time.\n");
	}else{
		//printf("In get buffer tx\n");
		rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
		//printf("got one succusfully\n");
	}
	return pkt;
}

void
initialize_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac,
		struct ether_addr *dst_mac, uint16_t ether_type,
		uint8_t vlan_enabled, uint16_t van_id)
{
	ether_addr_copy(dst_mac, &eth_hdr->d_addr);
	ether_addr_copy(src_mac, &eth_hdr->s_addr);

	if (vlan_enabled) {
		struct vlan_hdr *vhdr = (struct vlan_hdr *)((uint8_t *)eth_hdr +
				sizeof(struct ether_hdr));

		eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

		vhdr->eth_proto =  rte_cpu_to_be_16(ether_type);
		vhdr->vlan_tci = van_id;
	} else {
		eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
	}
}

/* add ethernet layer to the given tx buffer and sync it to tx_queue */
int i_sync=0;
void 
DPDKUse::addBufferToRing(struct rte_mbuf * pkt, unsigned lcore_id){
	int sent,enq_val=0;
	struct lcore_queue_conf *qconf;
	struct ether_hdr eth_hdr;
	struct rte_eth_dev_tx_buffer *buffer;
//	struct ether_addr dest_addr_mac = {
//		.addr_bytes = {0x02,0x00,0x00,0x00,0x00,0x02}
//		.addr_bytes = {OTH_MAC_1,OTH_MAC_2,OTH_MAC_3,OTH_MAC_4,OTH_MAC_5,OTH_MAC_6}
//		.addr_bytes = {0x56,0x48,0x4f,0x53,0x54,0x01}
//		.addr_bytes = {0x00,0x1e,0x67,0x49,0x89,0x0a}
//	};

	rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
//	initialize_eth_header(&eth_hdr,&dpdkapi_port_eth_addr,&dest_addr_mac,ETHER_TYPE_IPv4,0,0);
	
//	copy_buf_to_pkt(&eth_hdr, sizeof(struct ether_hdr), pkt, 0);
	//printf("copy to packet done\n");
	pkt->next = NULL;
	pkt->nb_segs = 1;
	pkt->pkt_len = pkt->data_len;
	pkt->l2_len = sizeof(struct ether_hdr);
	pkt->vlan_tci  = ETHER_TYPE_IPv4;
	pkt->l3_len = sizeof(struct ipv4_hdr);

	//dump_payload(pkt, pkt->data_len);
	qconf =	&lcore_queue_conf[lcore_id];
	do{
		enq_val = rte_ring_sp_enqueue_burst(qconf->tx_queue, (void**)(&pkt), 1);
	}while(enq_val==0);
	
	//printf("enq success %d %lu \n",enq_val,(pkt));
}

/* main Print processing loop */
void
DPDKUse::print_main_loop(unsigned lcore_id){
	double rate=0;
	double sec=0;

	RTE_LOG(INFO, DPDKAPI, "entering Print main loop on lcore %u\n", lcore_id);

	time_t end;
	time(&end);
	sec = difftime(end,before);
	rate=port_statistics[lcore_id].tx_bytes;
	//port_statistics[lcore_id].tx_bytes=0;
	rate = ((rate*8)/(sec*1024*1024*1024));
	printf("#Tx pkts sent: %lu -- Tx DPDK rate:%lfGbps, time%lf \n",port_statistics[lcore_id].tx,rate,sec);
	rate=port_statistics[lcore_id].rx_bytes;
	//port_statistics[lcore_id].rx_bytes=0;
	rate = ((rate*8)/(sec*1024*1024*1024));
	printf("#Rx pkts %lu -- Rx DPDK rate:%lfGbps, time%lf\n\n",port_statistics[lcore_id].rx,rate,sec);
	port_statistics[lcore_id].tx=0;
	port_statistics[lcore_id].rx=0;
	fflush(stdout);
}

void
DPDKUse::print_stats_main_loop(){
	struct rte_eth_stats eth_stats;

	rte_eth_stats_get(enabled_port,&eth_stats);
	printf("\n====================================================\n");
	printf("\n------------------------------\n Port %u stats:\n------------------------------\n",enabled_port);
	printf(" - Pkts in:	%" PRIu64 "\n",eth_stats.ipackets-my_init_eth_dev_stats.ipkt);
	printf(" - Pkts out:	%" PRIu64 "\n",eth_stats.opackets-my_init_eth_dev_stats.opkt);
	printf(" - In Errors:	%" PRIu64 "\n",eth_stats.ierrors-my_init_eth_dev_stats.ierr);
	printf(" - Out Errors:	%" PRIu64 "\n",eth_stats.oerrors-my_init_eth_dev_stats.oerr);
	printf(" - Mbuf Errors:	%" PRIu64 "\n",eth_stats.rx_nombuf-my_init_eth_dev_stats.mbuferr);
	printf(" - Queue[%u] Pkts in:	%" PRIu64 "\n",0, eth_stats.q_ipackets[0]-my_init_eth_dev_stats.q_ipkt0);
	printf(" - Queue[%u] Pkts out:	%" PRIu64 "\n",0, eth_stats.q_opackets[0]-my_init_eth_dev_stats.q_opkt0);
	printf(" - Queue[%u] Pkts err:	%" PRIu64 "\n",0, eth_stats.q_errors[0]-my_init_eth_dev_stats.q_err0);
	printf("\n====================================================\n");
	fflush(stdout);
}

/* --------------------- less important methods --------------------- */
void signal_handler_dpdk(int signum)
{
	unsigned lcore_id,lcore_id_master;

	lcore_id_master = rte_lcore_id();
	if(lcore_id_master == rte_get_master_lcore()) {
		if(!force_quit){
			if (signum == SIGINT || signum == SIGTERM) {
				printf("\n\nSignal %d received, preparing to exit...\n",
						signum);
				force_quit = true;
				//cumalative stats calculated in KB threads
				dpdkuse_ins.print_main_loop(dpdkuse_ins.rxtx_lcore_id);
				#if OPT_KB==1 //2 KB
				dpdkuse_ins.print_main_loop(dpdkuse_ins.rxtx_lcore_id-1);
				#endif

				//per-core stats
				RTE_LCORE_FOREACH(lcore_id){
					#if OPT_KB==1 //2 KB
					if( (dpdkuse_ins.rxtx_lcore_id == lcore_id) || ((dpdkuse_ins.rxtx_lcore_id-1) == lcore_id)){
						continue;
					}
					#endif

					#if OPT_KB==0 //1 KB
					if(dpdkuse_ins.rxtx_lcore_id == lcore_id){
						continue;
					}
					#endif
					dpdkuse_ins.print_main_loop(lcore_id);
				}
				dpdkuse_ins.print_stats_main_loop();
				dpdkuse_ins.release();
			}
		}
	}
}

void
DPDKUse::release(void)
{
	unsigned lcore_id,lcore_id_master;
	struct lcore_queue_conf *qconf;
	struct rte_mbuf *pkts_burst_in[MAX_PKT_BURST];
	int i=0,deq_val;

	lcore_id_master = rte_lcore_id();
	if(lcore_id_master == rte_get_master_lcore()) {
		RTE_LCORE_FOREACH(lcore_id) {

			/* continue if core is rxtx core */
			#if OPT_KB==1 //2 KB
			if ( (rxtx_lcore_id == lcore_id) || ((rxtx_lcore_id-1) == lcore_id)) {
				continue;
			}
			#endif

			#if OPT_KB==0 //1 KB
			if (rxtx_lcore_id == lcore_id){
				continue;
			}
			#endif

			qconf = &lcore_queue_conf[lcore_id];
			deq_val = rte_ring_sc_dequeue_burst(qconf->tx_queue, (void**)pkts_burst_in, MAX_PKT_BURST);
			if(deq_val!=0){
				for(i=0;i<deq_val;i++){
					rte_pktmbuf_free(pkts_burst_in[i]);
				}
			}

			deq_val = rte_ring_sc_dequeue_burst(qconf->rx_queue, (void**)pkts_burst_in, MAX_PKT_BURST);
			if(deq_val!=0){
				for(i=0;i<deq_val;i++){
					rte_pktmbuf_free(pkts_burst_in[i]);
				}
			}
			
		}

		pthread_join(rx_thread, NULL);

		#if OPT_KB==1 //2 KB
		pthread_join(tx_thread, NULL);
		#endif
		

		RTE_LCORE_FOREACH_SLAVE(lcore_id) {
			if (rte_eal_wait_lcore(lcore_id) < 0) {
				printf("Error Closing lcore %u...", lcore_id);
				break;
			}
		}		
		printf("Closing port %d...", enabled_port);
		rte_eth_dev_stop(enabled_port);
		rte_eth_dev_close(enabled_port);
		printf(" Done\n");
		printf("Bye...\n");
	}
}

void
DPDKUse::copy_buf_to_pkt(void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
	//printf("pkt-len: %u\n", pkt->data_len);
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset), buf,
			   (size_t) len);
		return;
	}
}


/* display usage */
void
DPDKUse::dpdkapi_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK \n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n",
	       prgname);
}

int
DPDKUse::dpdkapi_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

/* Parse the argument given in the command line of the application */
int
DPDKUse::dpdkapi_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			dpdkapi_enabled_port_mask = dpdkapi_parse_portmask(optarg);
			if (dpdkapi_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				dpdkapi_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
			dpdkapi_usage(prgname);
			return -1;

		default:
			dpdkapi_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}


/* Check the link status of the enabled port in up to 9s, and print them finally */
void
DPDKUse::check_port_link_status()
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	struct rte_eth_link link;
	unsigned count;
	bool portup = false, print_flag = false;
	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;

		memset(&link, 0, sizeof(link));
		rte_eth_link_get_nowait(enabled_port, &link);
		/* print link status if flag set */
		if (print_flag) {
			if (link.link_status){
				printf("Port %d Link Up - speed %u "
					"Mbps - %s\n", (uint8_t)enabled_port,
					(unsigned)link.link_speed,
			(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
				("full-duplex") : ("half-duplex\n"));
			}else{
				printf("Port %d Link Down\n",
					(uint8_t)enabled_port);
			}
			break;
		}
		if (link.link_status == ETH_LINK_DOWN) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}else{
			portup = true;
		}
		/* set the print_flag if all ports up or timeout */
		if (portup == true || count == (MAX_CHECK_TIME - 1)) {
			print_flag = true;
			printf("done\n");
		}
	}
}
