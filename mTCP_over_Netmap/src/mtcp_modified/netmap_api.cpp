#include "netmap_api.h"
#include<iostream>
#include<assert.h>
//1. Initialize the netmap device.
NetmapUse netmapuse;

/*
 * locate the src mac address for our interface, put it
 * into the user-supplied buffer. return 0 if ok, -1 on error.
 */
//#include "pkt_hash.h"

/* Make Linux headers choose BSD versions of some of the data structures */
#define __FAVOR_BSD

/* for types */
#include <sys/types.h>
/* for [n/h]to[h/n][ls] */
#include <netinet/in.h>
/* iphdr */
#include <netinet/ip.h>
/* ipv6hdr */
#include <netinet/ip6.h>
/* tcphdr */
//#include <netinet/tcp.h>
/* udphdr */
//#include <netinet/udp.h>
#include <linux/udp.h>
/* eth hdr */
#include <net/ethernet.h>
/* for memset */
#include <string.h>

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
decode_ip_n_hash(struct ip *iph, uint8_t hash_split, uint8_t seed)
{
	uint32_t rc = 0;
	
	if (hash_split == 2) {
		rc = sym_hash_fn(ntohl(iph->ip_src.s_addr),
			ntohl(iph->ip_dst.s_addr),
			ntohs(0xFFFD) + seed,
			ntohs(0xFFFE) + seed);
	} else {
		struct tcphdr *tcph = NULL;
		
		switch (iph->ip_p) {
		case IPPROTO_UDP:
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)((uint8_t *)iph + (iph->ip_hl<<2));
			rc = sym_hash_fn(ntohl(iph->ip_src.s_addr), 
					 ntohl(iph->ip_dst.s_addr), 
					 ntohs(tcph->source) + seed,
					 ntohs(tcph->dest) + seed);
			break;
		case IPPROTO_IPIP:
			/* tunneling */
			rc = decode_ip_n_hash((struct ip *)((uint8_t *)iph + (iph->ip_hl<<2)),
					      hash_split, seed);
			break;
		default:
			// We return 0 to indicate that the packet couldn't be balanced.
			return 0;
			break;
		}
	}
	return rc;
}

/*---------------------------------------------------------------------*/
/**
 ** Parser + hash function for the IPv6 packet
 **/
static uint32_t
decode_ipv6_n_hash(struct ip6_hdr *ipv6h, uint8_t hash_split, uint8_t seed)
{
	uint32_t saddr, daddr;
	uint32_t rc = 0;
	
	/* Get only the first 4 octets */
	saddr = ipv6h->ip6_src.s6_addr[0] |
		(ipv6h->ip6_src.s6_addr[1] << 8) |
		(ipv6h->ip6_src.s6_addr[2] << 16) |
		(ipv6h->ip6_src.s6_addr[3] << 24);
	daddr = ipv6h->ip6_dst.s6_addr[0] |
		(ipv6h->ip6_dst.s6_addr[1] << 8) |
		(ipv6h->ip6_dst.s6_addr[2] << 16) |
		(ipv6h->ip6_dst.s6_addr[3] << 24);
	
	if (hash_split == 2) {
		rc = sym_hash_fn(ntohl(saddr),
				 ntohl(daddr),
				 ntohs(0xFFFD) + seed,
				 ntohs(0xFFFE) + seed);
	} else {
		struct tcphdr *tcph = NULL;
		
		switch(ntohs(ipv6h->ip6_ctlun.ip6_un1.ip6_un1_nxt)) {
		case IPPROTO_UDP:
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(ipv6h + 1);
			rc = sym_hash_fn(ntohl(saddr), 
					 ntohl(daddr), 
					 ntohs(tcph->source) + seed,
					 ntohs(tcph->dest) + seed);
			break;
		case IPPROTO_IPIP:
			/* tunneling */
			rc = decode_ip_n_hash((struct ip *)(ipv6h + 1),
					      hash_split, seed);
			break;
		case IPPROTO_IPV6:
			/* tunneling */
			rc = decode_ipv6_n_hash((struct ip6_hdr *)(ipv6h + 1),
						hash_split, seed);
			break;
		case IPPROTO_ICMP:
		case IPPROTO_GRE:
		case IPPROTO_ESP:
		case IPPROTO_PIM:
		case IPPROTO_IGMP:
		default:
			/* 
			 ** the hash strength (although weaker but) should still hold 
			 ** even with 2 fields 
			 **/
			rc = sym_hash_fn(ntohl(saddr),
					 ntohl(daddr),
					 ntohs(0xFFFD) + seed,
					 ntohs(0xFFFE) + seed);
		}
	}
	return rc;
}

/*---------------------------------------------------------------------*/
/**
 *  *  A temp solution while hash for other protocols are filled...
 *   * (See decode_vlan_n_hash & pkt_hdr_hash functions).
 *    */
static uint32_t
decode_others_n_hash(struct ether_header *ethh, uint8_t seed)
{
	uint32_t saddr, daddr, rc;
	
	saddr = ethh->ether_shost[5] |
		(ethh->ether_shost[4] << 8) |
		(ethh->ether_shost[3] << 16) |
		(ethh->ether_shost[2] << 24);
	daddr = ethh->ether_dhost[5] |
		(ethh->ether_dhost[4] << 8) |
		(ethh->ether_dhost[3] << 16) |
		(ethh->ether_dhost[2] << 24);

	rc = sym_hash_fn(ntohl(saddr),
			 ntohl(daddr),
			 ntohs(0xFFFD) + seed,
			 ntohs(0xFFFE) + seed);

	return rc;
}

/*---------------------------------------------------------------------*/
/**
 ** Parser + hash function for VLAN packet
 **/
static inline uint32_t
decode_vlan_n_hash(struct ether_header *ethh, uint8_t hash_split, uint8_t seed)
{
	uint32_t rc = 0;
	struct vlanhdr *vhdr = (struct vlanhdr *)(ethh + 1);
	
	switch (ntohs(vhdr->proto)) {
	case ETHERTYPE_IP:
		rc = decode_ip_n_hash((struct ip *)(vhdr + 1),
				      hash_split, seed);
		break;
	case ETHERTYPE_IPV6:
		rc = decode_ipv6_n_hash((struct ip6_hdr *)(vhdr + 1),
					hash_split, seed);
		break;
	case ETHERTYPE_ARP:
	default:
		/* others */
		rc = decode_others_n_hash(ethh, seed);
		break;
	}
	return rc;
}

/*---------------------------------------------------------------------*/
/**
 ** General parser + hash function...
 **/
uint32_t
pkt_hdr_hash(const unsigned char *buffer, uint8_t hash_split, uint8_t seed)
{
	int rc = 0;
	struct ether_header *ethh = (struct ether_header *)buffer;
	
	switch (ntohs(ethh->ether_type)) {
	case ETHERTYPE_IP:
		rc = decode_ip_n_hash((struct ip *)(ethh + 1),
				      hash_split, seed);
		break;
	case ETHERTYPE_IPV6:
		rc = decode_ipv6_n_hash((struct ip6_hdr *)(ethh + 1),
					hash_split, seed);
		break;
	case ETHERTYPE_VLAN:
		rc = decode_vlan_n_hash(ethh, hash_split, seed);
		break;
	case ETHERTYPE_ARP:
	default:
		/* others */
		rc = decode_others_n_hash(ethh, seed);
		break;
	}

	return rc;
}

/*---------------------------------------------------------------------*/
/* Compute the checksum of the given ip header. */
uint16_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = (uint8_t *)data;
	uint32_t i;

        /* Checksum all the pairs of bytes first... */
        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return sum;
}

u_int16_t
wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

/*---------------------------------------------------------------------*/
/*
 * Convert a binary representation of an ethernet address to
 * an ASCII string.
 */
char *
NetmapUse::ether_ntoa(const struct ether_addr *n)
{
	int i;
	static char a[18];

	i = sprintf(a, "%02x:%02x:%02x:%02x:%02x:%02x",
	    n->ether_addr_octet[0], n->ether_addr_octet[1], n->ether_addr_octet[2],
	    n->ether_addr_octet[3], n->ether_addr_octet[4], n->ether_addr_octet[5]);
	return (i < 17 ? NULL : (char *)&a);
}

/*---------------------------------------------------------------------*/
/*
 * Class constructor : Initializes various data structures
 */
NetmapUse::NetmapUse() {
	
#ifndef	OPT_FOR_SINGLE_CORE
	// Required operations for google dense map	
	arptable.set_empty_key(0);
	arptable.set_deleted_key(1);
	
	pending_arp_req_th.set_empty_key(0);
	pending_arp_req_th.set_deleted_key(1);
	pending_arp_req_retries_th.set_empty_key(0);
	pending_arp_req_retries_th.set_deleted_key(1);

#endif	
	// Number of cores in the system
	cores_available = sysconf(_SC_NPROCESSORS_ONLN);
	
	// Source IP address and hardware address of interface (IFNAME in netmap_api.h)
	source_hwaddr(IFNAME);
	
	// Initializes number of usable cores
	// Initialized netmap threads related data structures in case of 1/2 core kernel bypass
	initialize_send_recv();
	
	// Resize ethernet layer stats array based on usable cores
	send_stats.resize(send_output_rings);
	recv_stats.resize(recv_output_rings);
	
	for(uint8_t i = 0; i<send_output_rings; i++) {
		memset(&send_stats[i], 0, sizeof(compute_stats));
	}
	
	for(uint8_t i = 0; i<recv_output_rings; i++) {
		memset(&recv_stats[i], 0, sizeof(compute_stats));
	}
}

/*---------------------------------------------------------------------*/
/* Check the payload of the packet for errors (use it for debug).
 * Look for consecutive ascii representations of the size of the packet.
 */
void
dump_payload(const char *_p, int len, struct netmap_ring *ring, int cur)
{
	char buf[128];
	int i, j, i0;
	const unsigned char *p = (const unsigned char *)_p;

	/* get the length in ASCII of the length of the packet. */

	printf("ring %p cur %5d [len %5d]\n",
		ring, cur, len);
	/* hexdump routine */
	for (i = 0; i < len; ) {
		memset(buf, sizeof(buf), ' ');
		sprintf(buf, "%5d: ", i);
		i0 = i;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j*3, "%02x ", (uint8_t)(p[i]));
		i = i0;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j + 48, "%c",
				isprint(p[i]) ? p[i] : '.');
		printf("%s\n", buf);
	}
}

/*---------------------------------------------------------------------*/
/*
 * Class destructor : Joins threads (in case of 1/2 core kernel bypass)
 * computes final ethernet layer statistics
 */ 
NetmapUse::~NetmapUse() {
	double rate_time;
	double diff_time;
	uint64_t tots = 0, totr = 0;
	cout<<"Waiting for completion"<<endl;
	gettimeofday(&end_time, NULL);
	
	for ( uint8_t i=0; i < send_output_rings ; i++ ) {
		tots += send_stats[i].forwarded;
	}
	
	for ( uint8_t i=0; i < recv_output_rings ; i++ ) {
		totr += recv_stats[i].forwarded;
	}
	
	// Stats computation
	diff_time = (end_time.tv_sec - begin_time_send.tv_sec) + 
              ((end_time.tv_usec - begin_time_send.tv_usec)/1000000.0);
	rate_time = (tots*8) / (diff_time*1024*1024*1024);
	D("Rate in Gbps (Send): %lf", rate_time);
	
	diff_time = (end_time.tv_sec - begin_time_recv.tv_sec) + 
              ((end_time.tv_usec - begin_time_recv.tv_usec)/1000000.0);
	rate_time = (totr*8) / (diff_time*1024*1024*1024);
	D("Rate in Gbps (Recieve): %lf", rate_time);
	
#ifndef OPT_FOR_SINGLE_CORE
	// Join netmap threads
	send_thread.join();
	recv_thread.join();
#else
	//Close netmap interfaces
	sleep(10);
	u_int i;
	for (i = 0; i < (u_int)send_output_rings; ++i) {
		nm_close(per_core_send_port[i].nmd);
	}
	for (i = 0; i < (u_int)recv_output_rings; ++i) {
		nm_close(per_core_recv_port[i].nmd);
	}
#endif
	
	sleep(5);
	
	cout<<"Completed"<<endl;
}

/*---------------------------------------------------------------------*/
/*
 * Get virtio header length
 */
void 
NetmapUse::get_vnet_hdr_len(struct nm_desc *nmd)
{
	struct nmreq req;
	int err;

	memset(&req, 0, sizeof(req));
	bcopy(nmd->req.nr_name, req.nr_name, sizeof(req.nr_name));
	req.nr_version = NETMAP_API;
	req.nr_cmd = NETMAP_VNET_HDR_GET;
	err = ioctl(nmd->fd, NIOCREGIF, &req);
	if (err) {
		D("Unable to get virtio-net header length");
		return;
	}

	virt_hdr_len = req.nr_arg1;
	if (virt_hdr_len) {
		D("Port requires virtio-net header, length = %d",
		  virt_hdr_len);
	}
}

/*---------------------------------------------------------------------*/
/*
 * Free netmap extra buffers: used by receiver thread
 * Used in case of 1/2 core kernel bypass
 */
void
NetmapUse::free_buffers(vector<port_des> &ports) {
	int i, tot = 0;
	struct port_des *txport = &ports[recv_output_rings+1];
	/* build a netmap free list with the buffers in all the overflow queues */
	
	for (i = 0; i < recv_output_rings+2; i++) {
		struct port_des *cp = &ports[i];
		struct overflow_queue *q = cp->oq;

		if (!q || q->slots.empty())
			continue;

		while (!q->slots.empty()) {
			struct netmap_slot s = q->slots.front();
			q->slots.pop();
			uint32_t *b = (uint32_t *)NETMAP_BUF(cp->ring, s.buf_idx);

			*b = txport->nmd->nifp->ni_bufs_head;
			txport->nmd->nifp->ni_bufs_head = s.buf_idx;
			tot++;
		}
	}
	D("\n Added %d extra buffers back in total.\nDone all :-)",tot);
}

/*---------------------------------------------------------------------*/
/*
 * Prepares ARP packet in the buffer passed as parameter
 */
void
NetmapUse::prepare_arp_packet(arp_pkt *arp_pkt, const uint32_t &src_ip, const uint32_t &dest_ip, ether_addr &src_mac, ether_addr &dest_mac, uint16_t htype) {
	memcpy(arp_pkt->eh.ether_shost, &src_mac,  6);
	memcpy(arp_pkt->eh.ether_dhost, &dest_mac,  6);
	arp_pkt->eh.ether_type = htons(ETHERTYPE_ARP);

	arp_pkt->ah.htype = htons (1);
	arp_pkt->ah.ptype =  htons (ETHERTYPE_IP);
	arp_pkt->ah.hlen = 6;
	arp_pkt->ah.plen = 4;
	arp_pkt->ah.opcode = htype;
	
	arp_pkt->ah.sender_ip = src_ip;
	arp_pkt->ah.target_ip = dest_ip;
	
	memcpy(arp_pkt->ah.sender_mac, &src_mac,  6);
	if (ntohs(htype) == ARPOP_REQUEST) {
		memset (arp_pkt->ah.target_mac, 0, 6 * sizeof (uint8_t));
	} else {
		memcpy(arp_pkt->ah.target_mac, &dest_mac,  6);
	}
}

/*---------------------------------------------------------------------*/
/*
 * Initializes number of usable cores
 * Initializes per-core data structures
 * Initializes netmap threads related data structures in case of 1/2 core kernel bypass
 * Initializes arp related data structures in case of of multi-queue operations
 */
void
NetmapUse::initialize_send_recv() {
	uint16_t i;

#ifndef	OPT_FOR_SINGLE_CORE
	send_master_nmd = NULL;
	recv_master_nmd = NULL;
#endif
	
	// Initialize number of usable cores
#if	N_MINUS_2_CONFIG
	if(cores_available>=3)  {
		send_output_rings = recv_output_rings = cores_available - 2;
	} else {
		send_output_rings = recv_output_rings = 1;
	}
		
#elif	N_MINUS_1_CONFIG
	if(cores_available>=2)  {
		send_output_rings = recv_output_rings = cores_available - 1;
	} else {
		send_output_rings = recv_output_rings = 1;
	}
#else
	send_output_rings = recv_output_rings = cores_available;
#endif

	// Initialize per-core data structures
	per_core_send_port.resize(send_output_rings);
	per_core_counts.resize(send_output_rings);
	
	per_core_recv_port.resize(recv_output_rings);
	per_core_countr.resize(recv_output_rings);
	
	for (i = 0; i < send_output_rings; ++i) {
		per_core_send_port[i].nmd = NULL;
		per_core_counts[i] = 0;
	}
	for (i = 0; i < recv_output_rings; ++i) {
		per_core_recv_port[i].nmd = NULL;
		per_core_countr[i] = 0;
	}
	
#ifdef	OPT_FOR_SINGLE_CORE

	// Initializes arp related data structures in case of of multi-queue operations
	pending_arp_req.resize(send_output_rings, new dense_hash_set < uint32_t >());
	pending_arp_req_retries.resize(send_output_rings, new dense_hash_map < uint32_t, uint32_t >());
	deferred_packets.resize(send_output_rings, new list < tcp_pkt >());
	
	for (i = 0; i < send_output_rings; ++i) {
		
		pending_arp_req[i]->set_empty_key(0);
		pending_arp_req[i]->set_deleted_key(1);
		pending_arp_req_retries[i]->set_empty_key(0);
		pending_arp_req_retries[i]->set_deleted_key(1);
		
	}
	
#else
	// Create and affinitize sender and receiver netmap threads
	recv_thread = thread(&NetmapUse::receive_pkts_from_iface, this);
	
	cpu_set_t cpu_set;
	
	int thread_core1, thread_core2;
	uint16_t j;
	
#if	N_MINUS_2_CONFIG
	if(cores_available > 2) {
		thread_core1 = recv_output_rings;
		thread_core2 = send_output_rings + 1;
	} else if(cores_available == 2) {
		thread_core1 = 1;
		thread_core2 = 1;
	} else {
		thread_core1 = thread_core2 = 0;
	}
#elif	N_MINUS_1_CONFIG
	if(cores_available > 1) {
		thread_core1 = recv_output_rings;
		thread_core2 = send_output_rings;
	} else {
		thread_core1 = thread_core2 = 0;
	}
#else
	if(cores_available > 1) {
		thread_core1 = recv_output_rings-2;
		thread_core2 = send_output_rings-1;
	} else {
		thread_core1 = thread_core2 = 0;
	}
#endif
	
	CPU_ZERO(&cpu_set);
	CPU_SET(thread_core1, &cpu_set);
	int rc = pthread_setaffinity_np(recv_thread.native_handle(), sizeof(cpu_set_t), &cpu_set);
	if(rc!=0) {
		D("Unable to set affinity: %s", strerror(errno));
		return;
	} else {
	   for (j = 0; j < CPU_SETSIZE; j++)
	       if (CPU_ISSET(j, &cpu_set)) {
	           D("CPU %d set for %u\n", j, i);
	       }
	}
	
	sleep(2);
	
	send_thread = thread(&NetmapUse::send_pkts_to_iface, this);
	
	CPU_ZERO(&cpu_set);
	CPU_SET(thread_core2, &cpu_set);
	rc = pthread_setaffinity_np(send_thread.native_handle(), sizeof(cpu_set_t), &cpu_set);
	if(rc!=0) {
		D("Unable to set affinity: %s", strerror(errno));
		return;
	} else {
	   for (j = 0; j < CPU_SETSIZE; j++)
	       if (CPU_ISSET(j, &cpu_set)) {
	           D("CPU %d set for %u\n", j, i);
	       }
	}
#endif
}

/*---------------------------------------------------------------------*/
/*
 * Used by mTCP at each core to access netmap buffer for packet transmission
 */
void *
NetmapUse::get_buffer_tx(int coreid) {
#ifndef OPT_FOR_SINGLE_CORE
	// Wait till sender thread is ready
	while(!send_master_nmd) {
		this_thread::yield();
	}
#endif
	struct netmap_ring *ring = per_core_send_port[coreid].ring;
	if(unlikely(per_core_send_port[coreid].nmd == NULL)) {
		struct nmreq base_req;
		char interface[32];
		memset(&base_req, 0, sizeof(base_req));
#ifdef OPT_FOR_SINGLE_CORE
		// Open vNIC interface and access particular TX ring
		sprintf(interface, "%s-%d/T", IFNAME, coreid);
		D("opening interface named %s", interface);

		base_req.nr_flags |= NR_ACCEPT_VNET_HDR;
		per_core_send_port[coreid].nmd = nm_open(interface, &base_req, 0, NULL);

		if (per_core_send_port[coreid].nmd == NULL) {
			D("cannot open %s", interface);
			return NULL;
		} else {
			D("successfully opened core #%d %s (tx slots: %d)",
			  coreid + 1, interface, per_core_send_port[coreid].nmd->req.nr_tx_slots);
			ring = per_core_send_port[coreid].ring = NETMAP_TXRING(per_core_send_port[coreid].nmd->nifp, coreid);
		}
		if (coreid==0) {
			get_vnet_hdr_len(per_core_send_port[coreid].nmd);
			D("virt_hdr_len: %d", virt_hdr_len);
		}
#else
		// Open netmap pipe interface and access TX ring
		sprintf(interface, "%s}%d", SEND_PIPES_IFNAME, coreid);
		D("opening pipe named %s", interface);
		per_core_send_port[coreid].nmd = nm_open(interface, NULL, 0, send_master_nmd);

		if (per_core_send_port[coreid].nmd == NULL) {
			D("cannot open %s", interface);
			return NULL;
		} else {
			D("successfully opened pipe #%d %s (tx slots: %d)",
			  coreid + 1, interface, per_core_send_port[coreid].nmd->req.nr_tx_slots);
			ring = per_core_send_port[coreid].ring = NETMAP_TXRING(per_core_send_port[coreid].nmd->nifp, 0);
		}
		D("zerocopy %s",
		  (send_master_nmd->mem == per_core_send_port[coreid].nmd->mem) ? "enabled" : "disabled");
#endif
	}
	
	if(unlikely(per_core_counts[coreid] == 0)) {
		/*
		 * poll/ioctl and determine free buffer count during packet transmit
		 * wait for available room in the send queue(s)
		 */
		 uint16_t n;
		 struct pollfd pfd;
		 pfd.fd = per_core_send_port[coreid].nmd->fd;
		 pfd.events = POLLOUT;
		 pfd.revents = 0;
	#ifdef BUSY_WAIT
		if (ioctl(pfd.fd, NIOCTXSYNC, NULL) < 0) {
			D("ioctl error on queue %d: %s", 0,
					strerror(errno));
			return NULL;
		}
	#else /* !BUSY_WAIT */
		while (!do_abort && poll(&pfd, 1, 1 * 1000) == 0) {
		}
		
		if(do_abort) {
			return NULL;
		}
		
		
		if (pfd.revents & POLLERR) {
			printf("poll error on %d ring %d-%d", pfd.fd,
				per_core_send_port[coreid].nmd->first_tx_ring, per_core_send_port[coreid].nmd->last_tx_ring);
			return NULL;
		}
	#endif /* !BUSY_WAIT */
		n = nm_ring_space(per_core_send_port[coreid].ring);
		if (n <= MAX_BATCH_SEND) {
			per_core_counts[coreid] = n;
		} else {
			per_core_counts[coreid] = MAX_BATCH_SEND;
		}
	}
	
	// return netmap buffer address to mTCP
	if (unlikely(do_abort)) {
		return NULL;
	} else {
		struct netmap_slot *slot = &ring->slot[ring->cur];
		return NETMAP_BUF(ring, slot->buf_idx)+sizeof(struct ether_header)+virt_hdr_len;
	}
}

/*---------------------------------------------------------------------*/
/*
 * Updates RX ring pointers
 *
 * For mutiqueue operations:
 * Performs ethernet layer processing of outbound packet
 * Sends delayed packets for same destination IP (if any)
 * Delays outbound packet and sends ARP request, if ARPTABLE entry not found
 */
void
NetmapUse::syncbuftx(int coreid) {
	if (unlikely(do_abort)) {
		return;
	}
	struct netmap_ring *ring = per_core_send_port[coreid].ring;
	struct netmap_slot *slot = &ring->slot[ring->cur];
	char *tx_buf = NETMAP_BUF(ring, slot->buf_idx);
	struct pkthdr* pkthdr = (struct pkthdr*)(tx_buf + virt_hdr_len);

#ifdef OPT_FOR_SINGLE_CORE

	uint32_t temp_ip = pkthdr->ip.ip_dst.s_addr;
	memcpy(pkthdr->eh.ether_shost, ether_aton(src_eth_addr),  6);
	pkthdr->eh.ether_type = htons(ETHERTYPE_IP);
	
	ether_addr temp_eth_addr;

	if (likely(arptable.find(temp_ip, temp_eth_addr))) {
		// ARPTABLE has an entry
		if (unlikely(pending_arp_req[coreid]->find(temp_ip) != pending_arp_req[coreid]->end())) {
			// send deferred packets for same destination IP address (if any)
			tcp_pkt t_p;
			uint32_t templeng = ntohs(pkthdr->ip.ip_len) + sizeof(struct ether_header);
			nm_pkt_copy(pkthdr, &t_p, templeng);
			
			list <tcp_pkt>::iterator it_dp = deferred_packets[coreid]->begin();
			
			while (it_dp != deferred_packets[coreid]->end()) {
				struct pkthdr* pkthdr_dp = (struct pkthdr*) ((char *)&(*it_dp));
				uint32_t temp_ip_dp = pkthdr_dp->ip.ip_dst.s_addr;
				
				if (temp_ip_dp == temp_ip) {
					size_t templen = ntohs(pkthdr_dp->ip.ip_len) + sizeof(struct ether_header) + virt_hdr_len;
					
					// Send packet
					
					tx_buf = (char *)get_buffer_tx(coreid);
					
					if (unlikely(!tx_buf)) {
						D("TX error occurred");
						break;
					}
					tx_buf -= sizeof(struct ether_header);

					memcpy(pkthdr_dp->eh.ether_dhost, &(temp_eth_addr), 6);
					nm_pkt_copy(&(*it_dp), tx_buf, templen - virt_hdr_len);
					
					slot->len = templen;
	
					slot->flags = 0;
					ring->cur = nm_ring_next(ring,ring->cur);
					
					--per_core_counts[coreid];
					slot->flags |= NS_REPORT;
					ring->cur = nm_ring_next(ring,ring->cur);
	
					ring->head = ring->cur;
					struct pollfd pfd;
					pfd.fd = per_core_send_port[coreid].nmd->fd;
					pfd.events = POLLOUT;
					pfd.revents = 0;
					ioctl(pfd.fd, NIOCTXSYNC, NULL);
					
					it_dp = deferred_packets[coreid]->erase(it_dp);
		
				}
				it_dp++;
			}
			// Send current packet under transmission
			pending_arp_req[coreid]->erase(pending_arp_req[coreid]->find(temp_ip));
			(*pending_arp_req_retries[coreid])[temp_ip] = 0;
			tx_buf = (char *)get_buffer_tx(coreid);
			ring = per_core_send_port[coreid].ring;
			slot = &ring->slot[ring->cur];
			pkthdr = (struct pkthdr*)(tx_buf - (sizeof(struct ether_header)));
			nm_pkt_copy(&t_p, pkthdr, templeng);
		}
		memcpy(pkthdr->eh.ether_dhost, &(temp_eth_addr), 6);
	} else {
		//delay outbound packet as no ARPTABLE entry found
		deferred_packets[coreid]->push_back(*(tcp_pkt *)(tx_buf + virt_hdr_len));
		if (pending_arp_req[coreid]->find(temp_ip) == pending_arp_req[coreid]->end()) {
			bool send_arp_req = true;
			pending_arp_req[coreid]->insert(temp_ip);
			if (pending_arp_req_retries[coreid]->find(temp_ip) == pending_arp_req_retries[coreid]->end() || (*pending_arp_req_retries[coreid])[temp_ip] == 0) {
				(*pending_arp_req_retries[coreid])[temp_ip] = 1;
			} else if ((*pending_arp_req_retries[coreid])[temp_ip] < 16) {
				(*pending_arp_req_retries[coreid])[temp_ip]++;
			} else {
				send_arp_req = false;
			}
			
			// Send an ARP request
			if (likely(send_arp_req)) {
				arp_pkt *arp_pkt = (struct arp_pkt *) (tx_buf + virt_hdr_len);
				ether_addr src_mac = *ether_aton(src_eth_addr);
				ether_addr dest_mac = *ether_aton("ff:ff:ff:ff:ff:ff");
				
				prepare_arp_packet(arp_pkt, src_ip.s_addr, temp_ip, src_mac, dest_mac, htons(ARPOP_REQUEST));
				slot->len = sizeof(struct arp_pkt) + virt_hdr_len;
				slot->flags = 0;
				per_core_counts[coreid] = 0;

				slot->flags |= NS_REPORT;

				ring->cur = nm_ring_next(ring,ring->cur);

				ring->head = ring->cur;
				struct pollfd pfd;
				pfd.fd = per_core_send_port[coreid].nmd->fd;
				pfd.events = POLLOUT;
				pfd.revents = 0;
				ioctl(pfd.fd, NIOCTXSYNC, NULL);
			}
		}
		return;
	}

	if(unlikely(send_iter == NO_OF_SAFE_ITR && coreid == 0)) {
		gettimeofday(&begin_time_send, NULL);
	}

	if(coreid == 0) {
		send_iter++;
	}

	if(send_iter >= NO_OF_SAFE_ITR) {
		send_stats[coreid].forwarded += (slot->len - virt_hdr_len);
	}
#endif

	if (unlikely(do_abort)) {
		return;
	}
	// Update ring pointers and prepare for next outbound packet
	slot->len = ntohs(pkthdr->ip.ip_len) + sizeof(struct ether_header) + virt_hdr_len;
	
	slot->flags = 0;
	--per_core_counts[coreid];
	if(unlikely(per_core_counts[coreid] == 0 || slot->len < 256)) {
		slot->flags |= NS_REPORT;
	}
	ring->cur = nm_ring_next(ring,ring->cur);
	
	if(unlikely(slot->len < 256 || per_core_counts[coreid] == 0)) {
		ring->head = ring->cur;
		struct pollfd pfd;
		pfd.fd = per_core_send_port[coreid].nmd->fd;
		pfd.events = POLLOUT;
		pfd.revents = 0;
		ioctl(pfd.fd, NIOCTXSYNC, NULL);
	}
}

/*---------------------------------------------------------------------*/
/*
 * Used by mTCP at each core to access netmap buffer for packet reception
 *
 * For mutiqueue operations:
 * Sends deferred packets (if any)
 * Performs ethernet layer validation
 * Sends an ARP reply for ARP request packet 
 */
void *
NetmapUse::get_buffer_rx(int coreid, int &pktcount) {
#ifndef OPT_FOR_SINGLE_CORE
	// Wait till receiver thread is ready
	while(!recv_master_nmd) {
		this_thread::yield();
	}
#endif
	struct netmap_ring *ring = per_core_recv_port[coreid].ring;
	if(unlikely(per_core_recv_port[coreid].nmd == NULL)) {
		struct nmreq base_req;
		char interface[32];
		memset(&base_req, 0, sizeof(base_req));
		
#ifdef OPT_FOR_SINGLE_CORE
		// Open vNIC interface and access particular RX ring
		sprintf(interface, "%s-%d/R", IFNAME, coreid);
		D("opening interface named %s", interface);

		base_req.nr_flags |= NR_ACCEPT_VNET_HDR;
		per_core_recv_port[coreid].nmd = nm_open(interface, &base_req, 0, NULL);

		if (per_core_recv_port[coreid].nmd == NULL) {
			D("cannot open %s", interface);
			return NULL;
		} else {
			D("successfully opened core #%d %s (rx slots: %d)",
			  coreid + 1, interface, per_core_recv_port[coreid].nmd->req.nr_rx_slots);
			ring = per_core_recv_port[coreid].ring = NETMAP_RXRING(per_core_recv_port[coreid].nmd->nifp, coreid);
		}
		if (coreid==0) {
			get_vnet_hdr_len(per_core_recv_port[coreid].nmd);
			D("virt_hdr_len: %d", virt_hdr_len);
		}
#else
		// Open netmap pipe interface and access RX ring
		sprintf(interface, "%s}%d", RECV_PIPES_IFNAME, coreid);
		D("opening pipe named %s", interface);
		per_core_recv_port[coreid].nmd = nm_open(interface, NULL, 0, recv_master_nmd);

		if (per_core_recv_port[coreid].nmd == NULL) {
			D("cannot open %s", interface);
			return NULL;
		} else {
			D("successfully opened pipe #%d %s (rx slots: %d)",
			  coreid + 1, interface, per_core_recv_port[coreid].nmd->req.nr_rx_slots);
			ring = per_core_recv_port[coreid].ring = NETMAP_RXRING(per_core_recv_port[coreid].nmd->nifp, 0);
		}
		D("zerocopy %s",
		  (recv_master_nmd->mem == per_core_recv_port[coreid].nmd->mem) ? "enabled" : "disabled");
#endif		  
	}
	
	if(unlikely(pktcount == 0)) {
	
#ifdef OPT_FOR_SINGLE_CORE
		
		// Send deferred packets (if any)
		if (unlikely(!deferred_packets[coreid]->empty())) {
			list <tcp_pkt>::iterator it = deferred_packets[coreid]->begin();
			
			while (it != deferred_packets[coreid]->end()) {
				struct pkthdr* pkthdr = (struct pkthdr*) ((char *)&(*it));
				uint32_t temp_ip = pkthdr->ip.ip_dst.s_addr;
				ether_addr temp_eth_addr;

				if (arptable.find(temp_ip, temp_eth_addr)) {
					size_t templen = ntohs(pkthdr->ip.ip_len) + sizeof(struct ether_header) + virt_hdr_len;
					// Send packet
		
					char *tx_buf = (char *)get_buffer_tx(coreid);
					
					if (unlikely(!tx_buf)) {
						D("TX error occurred");
						break;
					}
					tx_buf = tx_buf - sizeof(struct ether_header);

					memcpy(pkthdr->eh.ether_dhost, &(temp_eth_addr), 6);
					nm_pkt_copy(&(*it), tx_buf, templen - virt_hdr_len);
					struct netmap_ring *ring = per_core_send_port[coreid].ring;
					struct netmap_slot *slot = &ring->slot[ring->cur];
					
					slot->len = templen;
	
					slot->flags = 0;
					--per_core_counts[coreid];
					slot->flags |= NS_REPORT;
					ring->cur = nm_ring_next(ring,ring->cur);
	
					ring->head = ring->cur;
					struct pollfd pfd;
					pfd.fd = per_core_send_port[coreid].nmd->fd;
					pfd.events = POLLOUT;
					pfd.revents = 0;
					ioctl(pfd.fd, NIOCTXSYNC, NULL);
					
					it = deferred_packets[coreid]->erase(it);
					
		
				} else if(unlikely((*pending_arp_req_retries[coreid])[temp_ip] == 0 || (*pending_arp_req_retries[coreid])[temp_ip] == 16)) {
					(*pending_arp_req_retries[coreid])[temp_ip] = 0;
					it = deferred_packets[coreid]->erase(it);
				}
				it++;
			}
	
			get_buffer_tx(coreid);
		
			if (unlikely(!pending_arp_req[coreid]->empty())) {
				pending_arp_req[coreid]->clear();
			}
		}

#endif

		/*
		* poll/ioctl and determine packet count during packet reception
		* wait for available room in the recv queue(s)
		*/
		uint16_t n;
		struct pollfd pfd;
		pfd.fd = per_core_recv_port[coreid].nmd->fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		
		if(unlikely(do_abort)) {
			return NULL;
		}
		
		ring->head = ring->cur;
	#ifdef BUSY_WAIT
		if (ioctl(pfd.fd, NIOCRXSYNC, NULL) < 0) {
			D("ioctl error on queue %d: %s", 0,
					strerror(errno));
			return NULL;
		}
	#else /* !BUSY_WAIT */
		if (!do_abort && poll(&pfd, 1, 1 * 1000) == 0) {
		}
		
		if(unlikely(do_abort)) {
			return NULL;
		}
		
		
		if (pfd.revents & POLLERR) {
			printf("poll error on %d ring %d-%d", pfd.fd,
				per_core_recv_port[coreid].nmd->first_rx_ring, per_core_recv_port[coreid].nmd->last_rx_ring);
			return NULL;
		}
	#endif /* !BUSY_WAIT */
		n = nm_ring_space(per_core_recv_port[coreid].ring);
		if (n <= MAX_BATCH_RECV) {
			per_core_countr[coreid] = n;
		} else {
			per_core_countr[coreid] = MAX_BATCH_RECV;
		}
		pktcount = per_core_countr[coreid];
		return NULL;
	}

#ifdef OPT_FOR_SINGLE_CORE
	start:
#endif
	if(likely(per_core_countr[coreid])) {
		// Packet available for reception
		struct netmap_slot *slot = &ring->slot[ring->cur];
		struct udp_pkt *pkt= (struct udp_pkt *)(NETMAP_BUF(ring, slot->buf_idx)  +virt_hdr_len);
#ifdef OPT_FOR_SINGLE_CORE

		// Ethernet layer validation
		if (unlikely(pkt->pkthdr.ip.ip_dst.s_addr != src_ip.s_addr || ntohs(pkt->pkthdr.eh.ether_type) == ETHERTYPE_ARP)) {
			if (unlikely(ntohs(pkt->pkthdr.eh.ether_type) == ETHERTYPE_ARP)) {
				// ARP packet
				struct arp_pkt *arppkt = (struct arp_pkt *)pkt;
				if(arppkt->ah.target_ip == src_ip.s_addr) {
					ether_addr temp_eh;
					memcpy(&temp_eh, (struct ether_addr *)arppkt->ah.sender_mac, 6);
					uint32_t send_ip = arppkt->ah.sender_ip;
					arptable.insert(send_ip, temp_eh);
					if (ntohs(arppkt->ah.opcode) == ARPOP_REQUEST) {
						// ARP request packet
						// Send response

						char *tx_buf = (char *)get_buffer_tx(coreid);
						
						if (unlikely(!tx_buf)) {
							D("TX error occurred");
						} else {
							ether_addr src_mac = *ether_aton(src_eth_addr);
							prepare_arp_packet((arp_pkt*)(tx_buf - sizeof(struct ether_header)), src_ip.s_addr, arppkt->ah.sender_ip, src_mac, temp_eh, htons(ARPOP_REPLY));
						
							struct netmap_ring *ring = per_core_send_port[coreid].ring;
							struct netmap_slot *slot = &ring->slot[ring->cur];
					
							slot->len = sizeof(arp_pkt) + virt_hdr_len;
	
							slot->flags = 0;
							--per_core_counts[coreid];
							slot->flags |= NS_REPORT;
							ring->cur = nm_ring_next(ring,ring->cur);
	
							ring->head = ring->cur;
							struct pollfd pfd;
							pfd.fd = per_core_send_port[coreid].nmd->fd;
							pfd.events = POLLOUT;
							pfd.revents = 0;
							ioctl(pfd.fd, NIOCTXSYNC, NULL);
						}
					}
				}
				
			}
			ring->cur = nm_ring_next(ring,ring->cur);
			per_core_countr[coreid]--;
			pktcount++;
			goto start;
		}
#endif	
		// Valid packet
		return (void *)((char *)pkt+sizeof(struct ether_header));
	} else {
		// No packets to receive
		return NULL;
	}
}

/*---------------------------------------------------------------------*/
/*
 * Updates RX ring pointers
 */
void
NetmapUse::syncbufrx(int coreid) {
	
	struct netmap_ring *ring = per_core_recv_port[coreid].ring;
	
#ifdef OPT_FOR_SINGLE_CORE
	if(unlikely(recv_iter == NO_OF_SAFE_ITR && coreid == 0)) {
		gettimeofday(&begin_time_recv, NULL);
	}
	
	if(coreid == 0) {
		recv_iter++;
	}
	
	if(recv_iter >= NO_OF_SAFE_ITR) {
		recv_stats[coreid].forwarded += (ring->slot[ring->cur].len - virt_hdr_len);
	}
#endif
	
	ring->cur = nm_ring_next(ring,ring->cur);
	per_core_countr[coreid]--;
}

#ifndef	OPT_FOR_SINGLE_CORE

/*---------------------------------------------------------------------*/
/*
 * Sender netmap thread function
 */
void *
NetmapUse::send_pkts_to_iface() {

	int send_thread_core;
	
	// Determine sender thread core
#if	N_MINUS_2_CONFIG
	if(cores_available > 2) {
		send_thread_core = send_output_rings + 1;
	} else if(cores_available == 2) {
		send_thread_core = 1;
	} else {
		send_thread_core = 0;
	}
#elif	N_MINUS_1_CONFIG
	if(cores_available > 1) {
		send_thread_core = send_output_rings;
	} else {
		send_thread_core = 0;
	}
#else
	if(cores_available > 1) {
		send_thread_core = send_output_rings-1;
	} else {
		send_thread_core = 0;
	}
#endif

	// Wait till affinitized to appropriate core
	while(sched_getcpu()!=send_thread_core) {
		this_thread::yield();
	}
	
	uint32_t i;
	int rv;
	vector<port_des> ports;
	uint64_t iter = 0;
	uint32_t npipes;
	struct port_des *rxport;
	struct port_des *txport;
	/* we need base_req to specify pipes and extra bufs */
	struct nmreq base_req;
	uint32_t extra_bufs;
	struct pollfd pollfd[send_output_rings+1];
	vector<uint32_t> cnts(send_output_rings);
	struct netmap_ring *txring;
	char send_ifname[MAX_IFNAMELEN];
	
	sprintf(send_ifname, "%s/T", IFNAME);

	npipes = send_output_rings;

	setlogmask(LOG_UPTO(LOG_INFO));
	openlog("lb", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	D("npipes:%u",npipes);
	
	ports.resize(npipes+2);
	
	txport = &ports[npipes];
	rxport = &ports[npipes+1];
	 
	if (ports.size()!=npipes+2) {
		D("failed to allocate the stats array");
		return NULL;
	}
	
	memset(&base_req, 0, sizeof(base_req));

	// Open vNIC interface for packet send
	base_req.nr_flags |= NR_ACCEPT_VNET_HDR;
	txport->nmd = nm_open(send_ifname, &base_req, 0, NULL);

	if (txport->nmd == NULL) {
		D("cannot open %s", send_ifname);
		return NULL;
	} else {
		D("successfully opened %s (tx rings: %u)", send_ifname,
		  txport->nmd->req.nr_tx_slots);
	}
	
	get_vnet_hdr_len(txport->nmd);

	memset(&base_req, 0, sizeof(base_req));
	rxport->nmd = nm_open(SEND_PIPES_IFNAME, &base_req, 0, NULL);

	if (rxport->nmd == NULL) {
		D("cannot open %s", SEND_PIPES_IFNAME);
		return NULL;
	} else {
		D("successfully opened %s (tx rings: %u)", SEND_PIPES_IFNAME,
		  rxport->nmd->req.nr_tx_slots);
	}
	
	/* reference ring to access the buffers */
	txport->ring = NETMAP_TXRING(txport->nmd->nifp, 0);
	txring = txport->ring;
	rxport->ring = NETMAP_RXRING(rxport->nmd->nifp, 0);

	extra_bufs = rxport->nmd->req.nr_arg3;

	D("obtained %d extra buffers", extra_bufs);

	// Open one end of netmap pipes for packet receive from multiple cores
	for (i = 0; i < npipes; ++i) {
		char interface[32];
		sprintf(interface, "%s{%d", SEND_PIPES_IFNAME, i);
		D("opening pipe named %s", interface);
		ports[i].nmd = nm_open(interface, NULL, 0, rxport->nmd);

		if (ports[i].nmd == NULL) {
			D("cannot open %s", interface);
			return NULL;
		} else {
			D("successfully opened pipe #%d %s (rx slots: %d)",
			  i + 1, interface, ports[i].nmd->req.nr_rx_slots);
			ports[i].ring = NETMAP_RXRING(ports[i].nmd->nifp, 0);
		}
		D("zerocopy %s",
		  (rxport->nmd->mem == ports[i].nmd->mem) ? "enabled" : "disabled");
	}

	send_master_nmd = rxport->nmd;

	sleep(2);
	
	memset(&pollfd, 0, sizeof(pollfd));

	while (!do_abort) {
		u_int pollo = 0;
		
		if(iter == NO_OF_SAFE_ITR) {
			gettimeofday(&begin_time_send, NULL);
		}
		
		iter++;
		
		// Poll interfaces
		for (i = 0; i < npipes; ++i) {
			struct netmap_ring *ring = ports[i].ring;
			if (nm_ring_next(ring, ring->tail) == ring->cur) {
				/* no need to poll, there are no packets pending */
				continue;
			}
			pollfd[pollo].fd = ports[i].nmd->fd;
			pollfd[pollo].events = POLLIN;
			pollfd[pollo].revents = 0;
			cnts[pollo] = i;
			++pollo;
		}
		pollfd[pollo].fd = txport->nmd->fd;
		pollfd[pollo].events = POLLOUT;
		pollfd[pollo].revents = 0;
		
		rv = poll(pollfd, pollo, 10);
		
		int temp_count;
		bool need_flush = false;
		u_int batch_cur = 0,itemp;
	
		// If there are any ARP table update requests, process them
		
		temp_count = new_arp_entries_th.size_approx();
		
		if (unlikely(temp_count >= 1)) {
			vector <ip_mac_pair> ip_mac_pairs(temp_count);
			temp_count = new_arp_entries_th.try_dequeue_bulk(ip_mac_pairs.begin(), temp_count);
			for (uint32_t i = 0; (int)i < temp_count; i++) {
				arptable[ip_mac_pairs[i].ip] = ip_mac_pairs[i].mac;
			}
		}
		
		temp_count = enqueued_arp_req_th.size_approx();
		
		// If there are any enqueued ARP requests, send a reply to them
		// flush immediately, update batch_cur, ring->head and poll if necessary
		
		if (unlikely(temp_count >= 1)) {
			vector <uint32_t> enqueued_arp_reqs(temp_count);
			temp_count = enqueued_arp_req_th.try_dequeue_bulk(enqueued_arp_reqs.begin(), temp_count);
			need_flush = true;
			
			for (uint32_t i = 0; (int)i < temp_count; i++) {
			
				// Send packet
			
				if(unlikely(batch_cur==0)) {
					batch_cur = MAX_BATCH_SEND;
					txring->head = txring->cur;
					/*
					 * wait for available room in the send queue(s)
					 */
				#ifdef BUSY_WAIT
					if (ioctl(pollfd[pollo].fd, NIOCTXSYNC, NULL) < 0) {
						D("ioctl error on queue %d: %s", 0,
								strerror(errno));
						return NULL;
					}
				#else /* !BUSY_WAIT */
					if (poll(&(pollfd[pollo]), 1, -1) <= 0) {
						printf("poll error/timeout on transmit queue %d: %s", 0,
							strerror(errno));
						return NULL;
					}
					if (pollfd[pollo].revents & POLLERR) {
						printf("poll error on %d ring %d-%d", pollfd[pollo].fd,
							txport->nmd->first_tx_ring, txport->nmd->last_tx_ring);
						return NULL;
					}
				#endif /* !BUSY_WAIT */
					uint32_t n = nm_ring_space(txring);
					if (n < batch_cur)
						batch_cur = n;
				}

				struct netmap_slot *txslot = &txring->slot[txring->cur];
				char *tx_buf = NETMAP_BUF(txring, txslot->buf_idx);
				ether_addr src_mac = *ether_aton(src_eth_addr);
			
				prepare_arp_packet((arp_pkt*)(tx_buf + virt_hdr_len), src_ip.s_addr, enqueued_arp_reqs[i], src_mac, arptable[enqueued_arp_reqs[i]], htons(ARPOP_REPLY));
				txslot->len = sizeof(struct arp_pkt) + virt_hdr_len;
				txslot->flags = 0;
				batch_cur--;
			
				txring->cur = nm_ring_next(txring,txring->cur);
			}
			
		}
	
		// if any enqueued packet in std::list can be sent, send it
		// flush immediately, update batch_cur, ring->head and poll if necessary
		
		if (unlikely(!deferred_packets_th.empty())) {
			need_flush = true;
			list <tcp_pkt>::iterator it = deferred_packets_th.begin();
			while (it != deferred_packets_th.end()) {
				struct pkthdr* pkthdr = (struct pkthdr*) ((char *)&(*it));
				uint32_t temp_ip = pkthdr->ip.ip_dst.s_addr;
				dense_hash_map < uint32_t, struct ether_addr > :: iterator itarp = arptable.find(temp_ip);
				
				if (itarp != arptable.end()) {
					size_t templen = ntohs(pkthdr->ip.ip_len) + sizeof(struct ether_header) + virt_hdr_len;
					// Send packet
					
					if(unlikely(batch_cur==0)) {
						batch_cur = MAX_BATCH_SEND;
						txring->head = txring->cur;
						/*
						 * wait for available room in the send queue(s)
						 */
					#ifdef BUSY_WAIT
						if (ioctl(pollfd[pollo].fd, NIOCTXSYNC, NULL) < 0) {
							D("ioctl error on queue %d: %s", 0,
									strerror(errno));
							return NULL;
						}
					#else /* !BUSY_WAIT */
						if (poll(&(pollfd[pollo]), 1, -1) <= 0) {
							printf("poll error/timeout on transmit queue %d: %s", 0,
								strerror(errno));
							return NULL;
						}
						if (pollfd[pollo].revents & POLLERR) {
							printf("poll error on %d ring %d-%d", pollfd[pollo].fd,
								txport->nmd->first_tx_ring, txport->nmd->last_tx_ring);
							return NULL;
						}
					#endif /* !BUSY_WAIT */
						uint32_t n = nm_ring_space(txring);
						if (n < batch_cur)
							batch_cur = n;
					}

					struct netmap_slot *txslot = &txring->slot[txring->cur];
					char *tx_buf = (char *) NETMAP_BUF(txring, txslot->buf_idx) + virt_hdr_len;
			
					memcpy(pkthdr->eh.ether_dhost, &(itarp->second), 6);
					nm_pkt_copy(&(*it), tx_buf, templen - virt_hdr_len);
					txslot->len = templen;
					txslot->flags = 0;
					batch_cur--;
					
					it = deferred_packets_th.erase(it);
					
					if(iter >= NO_OF_SAFE_ITR) {
						send_stats[i].forwarded += (txslot->len - virt_hdr_len);
					}
					txring->cur = nm_ring_next(txring,txring->cur);
					
				} else if (unlikely(pending_arp_req_retries_th[temp_ip] == 0 || pending_arp_req_retries_th[temp_ip] == 16)) {
					pending_arp_req_retries_th[temp_ip] = 0;
					it = deferred_packets_th.erase(it);
				}
				it++;
			}
		}
		
		if (unlikely(need_flush)) {
			batch_cur = 0;
			txring->head = txring->cur;
			ioctl(pollfd[pollo].fd, NIOCTXSYNC, NULL);
		}
		
		if (unlikely(!pending_arp_req_th.empty())) {
			pending_arp_req_th.clear();
		}
		
		if (rv <= 0) {
			if (rv < 0 && errno != EAGAIN && errno != EINTR)
				RD(1, "poll error %s", strerror(errno));
			continue;
		}

		// Send packets in batches from pipes to transmit vNIC interface
		for (itemp = 0; itemp < pollo; itemp++) {
			i = cnts[itemp];
			struct netmap_ring *ring = ports[i].ring;
			int next_cur = ring->cur;
			struct netmap_slot *next_slot = &ring->slot[next_cur];
			const char *next_buf = NETMAP_BUF(ring, next_slot->buf_idx);
			int recvcount = nm_ring_space(ring);
			if(recvcount>=MAX_BATCH_RECV) {
				recvcount = MAX_BATCH_RECV;
			}
			while (recvcount--) {
				u_int n;
				if(unlikely(batch_cur==0)) {
					batch_cur = MAX_BATCH_SEND;
					/*
					 * wait for available room in the send queue(s)
					 */
				#ifdef BUSY_WAIT
					if (ioctl(pollfd[pollo].fd, NIOCTXSYNC, NULL) < 0) {
						D("ioctl error on queue %d: %s", 0,
								strerror(errno));
						return NULL;
					}
				#else /* !BUSY_WAIT */
					if (poll(&(pollfd[pollo]), 1, -1) <= 0) {
						printf("poll error/timeout on transmit queue %d: %s", 0,
							strerror(errno));
						return NULL;
					}
					if (pollfd[pollo].revents & POLLERR) {
						printf("poll error on %d ring %d-%d", pollfd[pollo].fd,
							txport->nmd->first_tx_ring, txport->nmd->last_tx_ring);
						return NULL;
					}
				#endif /* !BUSY_WAIT */
					n = nm_ring_space(txring);
					if (n < batch_cur)
						batch_cur = n;
				}
				// prefetch the buffer for the next round
				struct netmap_slot *rs = next_slot;
				const char *tempbuf = next_buf;
				next_cur = nm_ring_next(ring, next_cur);
				next_slot = &ring->slot[next_cur];
				next_buf = NETMAP_BUF(ring, next_slot->buf_idx);
				__builtin_prefetch(next_buf);

				struct netmap_slot *txslot = &txring->slot[txring->cur];
				char *tx_buf = NETMAP_BUF(txring, txslot->buf_idx);
				struct pkthdr* pkthdr = (struct pkthdr*)(tx_buf+virt_hdr_len);
				struct pkthdr* pkthdr_rxpkt = (struct pkthdr*)(tempbuf+virt_hdr_len);
				memcpy(pkthdr_rxpkt->eh.ether_shost, ether_aton(src_eth_addr),  6);
				pkthdr_rxpkt->eh.ether_type = htons(ETHERTYPE_IP);
				
				
				
				txslot->len=rs->len;
				
				// use google dense map for arptable
				// find if ip in arptable
					// if yes
						// copy dest address and proceed
					// if no
						// enqueue packet to std::list
						// If not in pending ARP map/set
							// store IP in it
						// else store in it and prepare ARP request flush packet immediately
				uint32_t temp_ip = pkthdr_rxpkt->ip.ip_dst.s_addr;
				dense_hash_map < uint32_t, struct ether_addr > :: iterator it = arptable.find(temp_ip);
				if(pending_arp_req_th.find(temp_ip) == pending_arp_req_th.end() && it != arptable.end()) {
					nm_pkt_copy(tempbuf,tx_buf,rs->len);
					memcpy(pkthdr->eh.ether_dhost, &(it->second), 6);
				} else {
					deferred_packets_th.push_back(*(tcp_pkt *)(tempbuf+virt_hdr_len));
					if (pending_arp_req_th.find(temp_ip) == pending_arp_req_th.end()) {
						bool send_arp_req = true;
						pending_arp_req_th.insert(temp_ip);

						if (pending_arp_req_retries_th.find(temp_ip) == pending_arp_req_retries_th.end() || pending_arp_req_retries_th[temp_ip] == 0) {
							pending_arp_req_retries_th[temp_ip] = 1;
						} else if (pending_arp_req_retries_th[temp_ip] < 16) {
							pending_arp_req_retries_th[temp_ip]++;
						} else {
							send_arp_req = false;
						}
				
						if (likely(send_arp_req)) {
							ether_addr src_mac = *ether_aton(src_eth_addr);
							ether_addr dest_mac = *ether_aton("ff:ff:ff:ff:ff:ff");
							prepare_arp_packet((arp_pkt*)(tx_buf + virt_hdr_len), src_ip.s_addr, temp_ip, src_mac, dest_mac, htons(ARPOP_REQUEST));
							txslot->len = sizeof(struct arp_pkt) + virt_hdr_len;
							txslot->flags = 0;
				
							txslot->flags |= NS_REPORT;
				
							txring->cur = nm_ring_next(txring,txring->cur);
				
							batch_cur = 0;
							txring->head = txring->cur;
							ioctl(pollfd[pollo].fd, NIOCTXSYNC, NULL);
						}
					}
					continue;
				}	
				
				txslot->flags = 0;
				batch_cur--;
				
				if(iter >= NO_OF_SAFE_ITR) {
					send_stats[i].forwarded += (txslot->len - virt_hdr_len);
				}
				if (batch_cur==0 || txslot->len < 256) {
					txslot->flags |= NS_REPORT;
				}
				txring->cur = nm_ring_next(txring,txring->cur);
				if (unlikely(txslot->len < 256 || batch_cur==0)) {
					batch_cur = 0;
					txring->head = txring->cur;
					ioctl(pollfd[pollo].fd, NIOCTXSYNC, NULL);
				}
			}
			ring->head = ring->cur = next_cur;

		}
	}
	
	for (i = 0; i < (u_int)send_output_rings; ++i) {
		while (nm_tx_pending(per_core_send_port[i].ring)) {
			usleep(1); /* wait 1 tick */
		}
	}
	sleep(10);
	for (i = 0; i < (u_int)send_output_rings; ++i) {
		nm_close(per_core_send_port[i].nmd);
	}
	for (i = 0; i < (u_int)send_output_rings + 2; ++i) {
		nm_close(ports[i].nmd);
	}
	return  NULL;
}

/*---------------------------------------------------------------------*/
/*
 * Receiver netmap thread function
 */
void *
NetmapUse::receive_pkts_from_iface() {

	int recv_thread_core;
	
	// Determine receiver thread core
#if	N_MINUS_2_CONFIG
	if(cores_available > 2) {
		recv_thread_core = recv_output_rings;
	} else if(cores_available == 2) {
		recv_thread_core = 1;
	} else {
		recv_thread_core = 0;
	}
#elif	N_MINUS_1_CONFIG
	if(cores_available > 1) {
		recv_thread_core = recv_output_rings;
	} else {
		recv_thread_core = 0;
	}
#else
	if(cores_available > 1) {
		recv_thread_core = recv_output_rings-2;
	} else {
		recv_thread_core = 0;
	}
#endif

	// Wait till affinitized to appropriate core
	while(sched_getcpu()!=recv_thread_core) {
		this_thread::yield();
	}
	
	uint32_t i;
	int rv;
	vector<port_des> ports;
	unsigned int iter = 0;
	uint32_t npipes;
	struct overflow_queue *freeq;
	struct port_des *rxport;
	struct port_des *txport;
	/* we need base_req to specify pipes and extra bufs */
	struct nmreq base_req;
	uint32_t extra_bufs;
	vector<overflow_queue> oq;
	struct pollfd pollfd[recv_output_rings+1];
	char recv_ifname[MAX_IFNAMELEN];
	
	sprintf(recv_ifname, "%s/R", IFNAME);

	npipes = recv_output_rings;
	freeq = NULL;

	setlogmask(LOG_UPTO(LOG_INFO));
	openlog("lb", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	D("npipes:%u",npipes);
	
	ports.resize(npipes+2);
	
	/* one overflow queue for each output pipe, plus one for the
	 * free extra buffers
	 */
	oq.resize(npipes+1);
	if (oq.size()!=npipes+1) {
		D("failed to allocate the core affinity array");
		return NULL;
	}
	
	rxport = &ports[npipes];
	txport = &ports[npipes+1];
	 
	if (ports.size()!=npipes+2) {
		D("failed to allocate the stats array");
		return NULL;
	}
	
	memset(&base_req, 0, sizeof(base_req));

	// Open vNIC interface for packet receive
	base_req.nr_flags |= NR_ACCEPT_VNET_HDR;
	rxport->nmd = nm_open(recv_ifname, &base_req, 0, NULL);

	if (rxport->nmd == NULL) {
		D("cannot open %s", recv_ifname);
		return NULL;
	} else {
		D("successfully opened %s (tx rings: %u)", recv_ifname,
		  rxport->nmd->req.nr_rx_slots);
	}
	
	get_vnet_hdr_len(rxport->nmd);
	recv_extra_bufs = rxport->nmd->req.nr_rx_slots;

	memset(&base_req, 0, sizeof(base_req));
	base_req.nr_arg1 = npipes;
	base_req.nr_arg3 = recv_extra_bufs;
	txport->nmd = nm_open(RECV_PIPES_IFNAME, &base_req, 0, NULL);

	if (txport->nmd == NULL) {
		D("cannot open %s", RECV_PIPES_IFNAME);
		return NULL;
	} else {
		D("successfully opened %s (tx rings: %u)", RECV_PIPES_IFNAME,
		  txport->nmd->req.nr_tx_slots);
	}
	
	/* reference ring to access the buffers */
	rxport->ring = NETMAP_RXRING(rxport->nmd->nifp, 0);
	txport->ring = NETMAP_TXRING(txport->nmd->nifp, 0);

	extra_bufs = txport->nmd->req.nr_arg3;

	D("obtained %d extra buffers", extra_bufs);
	if (!extra_bufs)
		goto run;

	freeq = &oq[npipes];
	rxport->oq = NULL;
	txport->oq = freeq;
	
	snprintf(freeq->name, MAX_IFNAMELEN, "free queue");

	/*
	 * Prepare free queue of extra netmap buffers
	 * the list of buffers uses the first uint32_t in each buffer
	 * as the index of the next buffer.
	 */
	for (rv = txport->nmd->nifp->ni_bufs_head;
	     rv;
	     rv = *(uint32_t *)NETMAP_BUF(txport->ring, rv))
	{
		struct netmap_slot s;
		s.buf_idx = rv;
		ND("freeq <- %d", s.buf_idx);
		freeq->slots.push(s);
	}
	if (freeq->slots.size() != extra_bufs) {
		D("something went wrong: netmap reported %u extra_bufs, but the free list contained %lu",
				extra_bufs, freeq->slots.size());
		return NULL;
	}
	txport->nmd->nifp->ni_bufs_head = 0;

run:
	// Open one end of netmap pipes for packet transmit to multiple cores
	for (i = 0; i < npipes; ++i) {
		char interface[32];
		sprintf(interface, "%s{%d", RECV_PIPES_IFNAME, i);
		D("opening pipe named %s", interface);
		ports[i].nmd = nm_open(interface, NULL, 0, txport->nmd);

		if (ports[i].nmd == NULL) {
			D("cannot open %s", interface);
			return NULL;
		} else {
			D("successfully opened pipe #%d %s (tx slots: %d)",
			  i + 1, interface, ports[i].nmd->req.nr_tx_slots);
			ports[i].ring = NETMAP_TXRING(ports[i].nmd->nifp, 0);
		}
		D("zerocopy %s",
		  (txport->nmd->mem == ports[i].nmd->mem) ? "enabled" : "disabled");

		if (extra_bufs) {
			struct overflow_queue *q = &oq[i];
			snprintf(q->name, MAX_IFNAMELEN, "oq %d", i);
			ports[i].oq = q;
		}
	}
	//FIXME
	if (!extra_bufs) {
		if (!oq.empty()) {
			for (i = 0; i < npipes + 1; i++) {
				while(!oq[i].slots.empty()) {
					oq[i].slots.pop();
				}
				ports[i].oq = NULL;
			}
			ports[i].oq = NULL;
			oq.clear();
		}
		D("*** overflow queues disabled ***");
	}

	recv_extra_bufs = extra_bufs;
	recv_master_nmd = txport->nmd;

	sleep(2);
	
	memset(&pollfd, 0, sizeof(pollfd));

	while (!do_abort) {
		u_int polli = 0;
		
		if(iter == NO_OF_SAFE_ITR) {
			gettimeofday(&begin_time_recv, NULL);
		}
		
		iter++;
		
		// Poll interfaces
		for (i = 0; i < npipes; ++i) {
			struct netmap_ring *ring = ports[i].ring;
			if (nm_ring_next(ring, ring->tail) == ring->cur) {
				/* no need to poll, there are no packets pending */
				continue;
			}
			pollfd[polli].fd = ports[i].nmd->fd;
			pollfd[polli].events = POLLOUT;
			pollfd[polli].revents = 0;
			++polli;
		}
		pollfd[polli].fd = rxport->nmd->fd;
		pollfd[polli].events = POLLIN;
		pollfd[polli].revents = 0;
		++polli;
		
		rv = poll(pollfd, polli, 10);
		if (rv <= 0) {
			if (rv < 0 && errno != EAGAIN && errno != EINTR)
				RD(1, "poll error %s", strerror(errno));
			continue;
		}

		if (!oq.empty()) {
			/* try to push packets from the overflow queues
			 * to the corresponding pipes
			 */
			for (i = 0; i < npipes; i++) {
				struct port_des *p = &ports[i];
				struct overflow_queue *q = p->oq;
				uint32_t j, lim;
				struct netmap_ring *ring;
				struct netmap_slot *slot;

				if (q->slots.empty())
					continue;
				ring = p->ring;
				lim = nm_ring_space(ring);
				if (!lim)
					continue;
				if (q->slots.size() < lim)
					lim = q->slots.size();
				for (j = 0; j < lim; j++) {
					struct netmap_slot s = q->slots.front();
					q->slots.pop();
					slot = &ring->slot[ring->cur];
					freeq->slots.push(*slot);
					*slot = s;
					
					if(iter >= NO_OF_SAFE_ITR) {
						recv_stats[i].forwarded += (s.len - virt_hdr_len);
					}
					
					slot->flags |= NS_BUF_CHANGED;
					ring->cur = nm_ring_next(ring, ring->cur);
				}
				ring->head = ring->cur;
			}
		}

		int batch_cur = 0;
		
		// Receive packets from vNIC interface and send them to appropriate cores
		for (i = rxport->nmd->first_rx_ring; i <= rxport->nmd->last_rx_ring; i++) {
			struct netmap_ring *rxring = NETMAP_RXRING(rxport->nmd->nifp, i);

			int next_cur = rxring->cur;
			struct netmap_slot *next_slot = &rxring->slot[next_cur];
			const char *next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
			int ringspace = nm_ring_space(rxring);
			if(ringspace>=MAX_BATCH_RECV) {
				ringspace = MAX_BATCH_RECV;
			}
			while (ringspace--) {
				struct overflow_queue *q;
				struct netmap_slot *rs = next_slot;
				const char *tempbuf = next_buf;
				struct udp_pkt *pkt= (struct udp_pkt *)(next_buf + virt_hdr_len);
				// Perform ethernet validation operation
				if (unlikely(pkt->pkthdr.ip.ip_dst.s_addr != src_ip.s_addr || ntohs(pkt->pkthdr.eh.ether_type) == ETHERTYPE_ARP)) {
					if (unlikely(ntohs(pkt->pkthdr.eh.ether_type) == ETHERTYPE_ARP)) {
						// ARP packet
						struct arp_pkt *arppkt = (struct arp_pkt *)pkt;
						if(arppkt->ah.target_ip == src_ip.s_addr) {
							if (ntohs(arppkt->ah.opcode) == ARPOP_REQUEST) {
								// ARP request
								// send this information to sender netmap thread 
								enqueued_arp_req_th.enqueue(arppkt->ah.sender_ip);
							}
							struct ip_mac_pair temp_pair;
							temp_pair.ip = arppkt->ah.sender_ip;
							memcpy(&temp_pair.mac, (struct ether_addr *)arppkt->ah.sender_mac, 6);
							new_arp_entries_th.enqueue(temp_pair);
						}
					}
					next_cur = nm_ring_next(rxring, next_cur);
					next_slot = &rxring->slot[next_cur];
					next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
					__builtin_prefetch(next_buf);
					rxring->head = rxring->cur = next_cur;

					batch_cur++;
					if (unlikely(batch_cur >= MAX_BATCH_RECV)) {
						ioctl(rxport->nmd->fd, NIOCRXSYNC, NULL);
						batch_cur = 0;
					}
					continue;
				}
				
				// CHOOSE THE CORRECT OUTPUT PIPE
				uint32_t output_port = 0;
				if(recv_thread_core) {
					uint32_t hash = pkt_hdr_hash((const unsigned char *)(next_buf+virt_hdr_len), 4, 'B');
					output_port = hash % recv_output_rings;
				}
				
				// prefetch the buffer for the next round
				next_cur = nm_ring_next(rxring, next_cur);
				next_slot = &rxring->slot[next_cur];
				next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
				__builtin_prefetch(next_buf);
				struct port_des *port = &ports[output_port];
				struct netmap_ring *ring = port->ring;
				struct netmap_slot free_buf_slot;

				// Move the packet to the output pipe.
				if (nm_ring_space(ring)) {
					struct netmap_slot *ts = &ring->slot[ring->cur];
					char *copy_buf;
					copy_buf = NETMAP_BUF(ring, ts->buf_idx);
					ts->len = rs->len;
					nm_pkt_copy(tempbuf,copy_buf,ts->len);
					
					ring->head = ring->cur = nm_ring_next(ring, ring->cur);

					if(iter >= NO_OF_SAFE_ITR) {
						recv_stats[i].forwarded += (ts->len - virt_hdr_len);
					}
					
					goto forward;
				}

				/* use the overflow queue, if available */
				if (oq.empty() || !freeq->slots.size()) {
					if(iter >= NO_OF_SAFE_ITR) {
						recv_stats[i].dropped += (rs->len - virt_hdr_len);
					}
					goto next;
				}

				q = &oq[output_port];

				if (!freeq->slots.size()) {
					/* revoke some buffers from the longest overflow queue */
					uint32_t j;
					struct port_des *lp = &ports[0];
					uint32_t max = lp->oq->slots.size();

					for (j = 1; j < npipes; j++) {
						struct port_des *cp = &ports[j];
						if (cp->oq->slots.size() > max) {
							lp = cp;
							max = cp->oq->slots.size();
						}
					}

					// XXX optimize this cycle
					for (j = 0; lp->oq->slots.size() && j < BUF_REVOKE; j++) {
						struct netmap_slot tmp = lp->oq->slots.front();
						if(iter >= NO_OF_SAFE_ITR) {
							recv_stats[i].dropped += (tmp.len - virt_hdr_len);
						}
						
						lp->oq->slots.pop();
						freeq->slots.push(tmp);
					}

					ND(1, "revoked %d buffers from %s", j, lq->name);
				}

				free_buf_slot = freeq->slots.front();
				freeq->slots.pop();
				
				// copy to slot buffer
				char *temp_buf;
				temp_buf = NETMAP_BUF(txport->ring, free_buf_slot.buf_idx);
				free_buf_slot.len = rs->len;
				nm_pkt_copy(tempbuf,temp_buf,free_buf_slot.len);
				q->slots.push(free_buf_slot);

			forward:
				//No code
			next:
				rxring->head = rxring->cur = next_cur;

				batch_cur++;
				if (unlikely(batch_cur >= MAX_BATCH_RECV)) {
					ioctl(rxport->nmd->fd, NIOCRXSYNC, NULL);
					batch_cur = 0;
				}
			}

		}
	}

	if (extra_bufs) {
		free_buffers(ports);
	}
	sleep(10);
	for (i = 0; i < (u_int)recv_output_rings; ++i) {
		nm_close(per_core_recv_port[i].nmd);
	}
	for (i = 0; i < (u_int)recv_output_rings + 2; ++i) {
		nm_close(ports[i].nmd);
	}
	return  NULL;
}

#endif

/*---------------------------------------------------------------------*/
/*
 * Determine source IP and ethernet address corresponding to a vNIC
 * Create static ARP entries here (if required)
 */
int
NetmapUse::source_hwaddr(const char *ifname)
{
	int s;
	char src_ip_addr[20];
	struct ifreq buffer;
	s = socket(PF_INET, SOCK_DGRAM, 0);

	memset(&buffer, 0x00, sizeof(buffer));
	strcpy(buffer.ifr_name, ifname+7);

	ioctl(s, SIOCGIFHWADDR, &buffer);

	close(s);
	sprintf(src_eth_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned char)buffer.ifr_hwaddr.sa_data[0], (unsigned char)buffer.ifr_hwaddr.sa_data[1], (unsigned char)buffer.ifr_hwaddr.sa_data[2],
		(unsigned char)buffer.ifr_hwaddr.sa_data[3], (unsigned char)buffer.ifr_hwaddr.sa_data[4], (unsigned char)buffer.ifr_hwaddr.sa_data[5]);
	D("source hwaddr %s %d", src_eth_addr,(int)strlen(src_eth_addr));
	int fd;
	 struct ifreq ifr;

	 fd = socket(AF_INET, SOCK_DGRAM, 0);

	 /* I want to get an IPv4 IP address */
	 ifr.ifr_addr.sa_family = AF_INET;

	 /* I want IP address attached to "eth0" */
	 strncpy(ifr.ifr_name, ifname+7, IFNAMSIZ-1);

	 ioctl(fd, SIOCGIFADDR, &ifr);

	 close(fd);

	 /* display result */
	 src_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	 strcpy(src_ip_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	 cout<<"Source ip:"<<src_ip_addr<<endl;
	
	
	// CREATE STATIC ARP ENTRIES HERE
	
	//struct in_addr att;
#ifndef	OPT_FOR_SINGLE_CORE
	// For multi-queue operations
	/*inet_aton("169.254.9.28", &att);
	arptable[att.s_addr] = *ether_aton("00:aa:bb:cc:dd:07");*/
#else
	// For netmap threads based operations
	/*inet_aton("169.254.9.28", &att);
	arptable.insert(att.s_addr, *ether_aton("00:aa:bb:cc:dd:07"));*/
#endif
	return 0;
}
