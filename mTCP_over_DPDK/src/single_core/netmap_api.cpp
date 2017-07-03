#include "netmap_api.h"
#include<iostream>
#include<assert.h>
//#define BUSY_WAIT 1	
//1. Initialize the netmap device.
NetmapUse netmapuse;
atomic_uint cntt;
static volatile int do_abort;

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
#include <linux/udp.h>
/* eth hdr */
#include <net/ethernet.h>
/* for memset */
#include <string.h>

//#include <libnet.h>
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
		struct udphdr *udph = NULL;
		
		switch (iph->ip_p) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)((uint8_t *)iph + (iph->ip_hl<<2));
			rc = sym_hash_fn(ntohl(iph->ip_src.s_addr), 
					 ntohl(iph->ip_dst.s_addr), 
					 ntohs(tcph->source) + seed,
					 ntohs(tcph->dest) + seed);
			break;
			//TODO: COmmented out for now. Ask Rahul about this. J.
		/*case IPPROTO_UDP:
			udph = (struct udphdr *)((uint8_t *)iph + (iph->ip_hl<<2));
			rc = sym_hash_fn(ntohl(iph->ip_src.s_addr),
					 ntohl(iph->ip_dst.s_addr),
					 ntohs(udph->uh_sport) + seed,
					 ntohs(udph->uh_dport) + seed);
			break;*/
		case IPPROTO_IPIP:
			/* tunneling */
			rc = decode_ip_n_hash((struct ip *)((uint8_t *)iph + (iph->ip_hl<<2)),
					      hash_split, seed);
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
		struct udphdr *udph = NULL;
		
		switch(ntohs(ipv6h->ip6_ctlun.ip6_un1.ip6_un1_nxt)) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(ipv6h + 1);
			rc = sym_hash_fn(ntohl(saddr), 
					 ntohl(daddr), 
					 ntohs(tcph->source) + seed,
					 ntohs(tcph->dest) + seed);
			break;
		/*
		case IPPROTO_UDP:
			udph = (struct udphdr *)(ipv6h + 1);
			rc = sym_hash_fn(ntohl(saddr),
					 ntohl(daddr),
					 ntohs(udph->uh_sport) + seed,
					 ntohs(udph->uh_dport) + seed);
			break;
		*/
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


/* control-C handler */

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

static void
sigint_h(int sig)
{
	int i;

	(void)sig;	/* UNUSED */
	D("Received control-C signal\n");
	netmapuse.do_abort = 1;
	signal(SIGINT, SIG_DFL);
}
 
NetmapUse::NetmapUse() {
	arptable["10.129.26.73"] = "00:22:4d:af:ae:42";
	void *temp;
	u_int i;
	testcount=0;
	num_recv = sysconf(_SC_NPROCESSORS_ONLN);
	counts=countr=0;
	countr_queue1_cur = countr_queue1_cur_sync = countr_queue1 = countr_queue2 = 0;
	next_turn_recv = 0;
	turn_over = true;
	wait_link = 2;
	
	//bursts = 1;
	//burstr = 2048;		// default burst size#TODO
	// strcpy(ifname, "enp0s3");
	sprintf(ifname, "netmap:%s", "eth0");// interface name (REQUIRED)
		
	//strcpy(src_eth_addr, "00:00:00:00:00:00");
	/* retrieve source mac address. */
	//printf("Trying to find out MAC for %s\n",ifname);
	source_hwaddr(ifname);
	//printf("Found:%s\n",ifname);
	//struct in_addr addr=inet_aton("169.254.8.254");
	//arptable[addr]=ether_aton((char *)ifname);
	signal(SIGINT, sigint_h);
	//open_netmap_dev();
	initialize_send_recv();
	safe_to_start_recv = true;
} 

/* Check the payload of the packet for errors (use it for debug).
 * Look for consecutive ascii representations of the size of the packet.
 */
static void
dump_payload(const char *_p, int len, struct netmap_ring *ring, int cur)
{
	char buf[128];
	int i, j, i0;
	const unsigned char *p = (const unsigned char *)_p;

	/* get the length in ASCII of the length of the packet. */

	printf("ring %p cur %5d [buf %6d flags 0x%04x len %5d]\n",
		ring, cur, ring->slot[cur].buf_idx,
		ring->slot[cur].flags, len);
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
 
NetmapUse::~NetmapUse() {
	cout<<"Waiting for completion"<<endl;
	//thread_var_tx.join();
	send_thread.join();
	recv_thread.join();
	sleep(5);
	cout<<"test_count:"<<testcount<<endl;
	cout<<"Queue 1 size:"<<countr_queue1<<endl;
	cout<<"Queue 2 size:"<<countr_queue2<<endl;
	cout<<"Num pckts:"<<num_pkts<<endl;
	for(auto itr=arptable.begin();itr!=arptable.end();itr++) {
		cout<<itr->first<<'\t'<<itr->second<<endl;
	}
	//munmap(nmd->mem, nmd->req.nr_memsize);
	//close(nmd->fd);
	cout<<"Completed"<<endl;
}

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

void
NetmapUse::per_core_recv_funcc(struct recv_thread_arg rta) {

	//struct recv_thread_arg *rta = (struct recv_thread_arg *)arg;
	//struct recv_thread_arg rta = *rtaptr;
	char interface[25];
	struct nm_desc *nmd;
	struct netmap_ring *ring;
	u_int id = rta.id;	
	
	u_int n, burstr=64, countr;
	struct udp_pkt udp_pkt;
	struct netmap_slot *slot;
	struct pkthdr *p;
	struct pollfd pfd;
	
	int prev_cur, next_cur;
	struct netmap_slot *prev_slot, *next_slot;
	const char *prev_buf, *next_buf;
	
	while(!do_abort && (u_int)sched_getcpu()!=id) {
		this_thread::yield();
		//usleep(100);
	}

	sprintf(interface, "%s}%d", rta.ifname, id);
	//D("opening pipe named %s", interface);
	//NM_OPEN_NO_MMAP
	nmd = nm_open(interface, NULL, 0, rta.parent_nmd);

	if (nmd == NULL) {
		D("cannot open %s", interface);
		return;
	} else {
		//D("successfully opened pipe #%d %s (rx slots: %d)",
		//  id + 1, interface, nmd->req.nr_rx_slots);
		//ring = NETMAP_RXRING(nmd->nifp, 0);
	}
	//D("zerocopy %s",
	 // (rta .parent_nmd->mem == nmd->mem) ? "enabled" : "disabled");
	
	
	
	pfd.fd = nmd->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	D("Receiver thread %u started\n",id);
	
	recv_slave_start_count++;	
	
	while (!do_abort) {
#ifdef BUSY_WAIT
		if (ioctl(pfd.fd, NIOCRXSYNC, NULL) < 0) {
			D("ioctl error on queue %d: %s", id,
					strerror(errno));
			return;
		}
#else /* !BUSY_WAIT */
		while (!do_abort && poll(&pfd, 1, 1 * 1000) == 0) {
		}
		
		if(do_abort) {
			return;
		}
		
		if (pfd.revents & POLLERR) {
			D("poll err on queue %d: %s", id,
					strerror(errno));
			return;
		}
#endif /* !BUSY_WAIT */

		n = nm_ring_space(ring);
		if (n > burstr)
			n = burstr;
			
		next_cur = ring->cur;
		next_slot = &ring->slot[next_cur];
		next_buf = NETMAP_BUF(ring, next_slot->buf_idx);
		__builtin_prefetch(next_buf);
		
		while(n--) {
			char temp[MAX_BODYSIZE];
			prev_cur = next_cur;
			prev_slot = next_slot;
			prev_buf = next_buf;		// prefetch the buffer for the next round
			next_cur = nm_ring_next(ring, next_cur);
			next_slot = &ring->slot[next_cur];
			next_buf = NETMAP_BUF(ring, next_slot->buf_idx);
			__builtin_prefetch(next_buf);
			//nm_pkt_copy(prev_buf,temp,prev_slot->len);

			//TODO: after receive
		}
		ring->head = ring->cur = next_cur;
	}
	return;
}

void
NetmapUse::print_stats(struct port_des *ports)
{
	int npipes = recv_output_rings;
	int sys_int = 0;
	struct my_ctrs cur, prev;
	char b1[40], b2[40];
	struct my_ctrs *pipe_prev;

	pipe_prev = (struct my_ctrs *)calloc(npipes, sizeof(struct my_ctrs));
	if (pipe_prev == NULL) {
		D("out of memory");
		exit(1);
	}

	memset(&prev, 0, sizeof(prev));
	gettimeofday(&prev.t, NULL);
	while (!do_abort) {
		int j, dosyslog = 0;
		uint64_t pps, dps, usec;
		struct my_ctrs x;

		memset(&cur, 0, sizeof(cur));
		usec = wait_for_next_report(&prev.t, &cur.t, 1000);

		if (++sys_int == syslog_interval) {
			dosyslog = 1;
			sys_int = 0;
		}

		for (j = 0; j < npipes; ++j) {
			struct port_des *p = &ports[j];

			cur.pkts += p->ctr.pkts;
			cur.drop += p->ctr.drop;

			x.pkts = p->ctr.pkts - pipe_prev[j].pkts;
			x.drop = p->ctr.drop - pipe_prev[j].drop;
			pps = (x.pkts*1000000 + usec/2) / usec;
			dps = (x.drop*1000000 + usec/2) / usec;
			printf("%s/%s|", norm(b1, pps), norm(b2, dps));
			pipe_prev[j] = p->ctr;

			if (dosyslog) {
				syslog(LOG_INFO,
					"{"
						"interface:%s,"
						"output_ring:%hu,"
						"packets_forwarded:%lu,"
						"packets_dropped:%lu}", recv_ifname, j, p->ctr.pkts, p->ctr.drop);
			}
		}
		printf("\n");
		if (dosyslog) {
			syslog(LOG_INFO,
				"{"
					"interface:%s,"
					"output_ring:null,"
					"packets_forwarded:%lu,"
					"packets_dropped:%lu,"
					"non_ip_packets:%lu}", recv_ifname, forwarded, dropped, non_ip);
		}
		x.pkts = cur.pkts - prev.pkts;
		x.drop = cur.drop - prev.drop;
		pps = (x.pkts*1000000 + usec/2) / usec;
		dps = (x.drop*1000000 + usec/2) / usec;
		printf("===> aggregate %spps %sdps\n", norm(b1, pps), norm(b2, dps));
		prev = cur;
	}

	free(pipe_prev);
	D("Done");
	return;
}

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

void
NetmapUse::initialize_send_recv() {
	uint16_t i,j;
	dropped = forwarded = non_ip = 0;

	send_master_nmd = NULL;
	recv_master_nmd = NULL;
	recv_slave_start_count = 0;
	safe_to_start_recv = false;
	sprintf(send_ifname, "%s/T", ifname);
	sprintf(recv_ifname, "%s/R", ifname);
	sprintf(send_pipes_ifname, "vale0:1");
	sprintf(recv_pipes_ifname, "vale1:1");
	send_output_rings = sysconf(_SC_NPROCESSORS_ONLN);
	per_core_send_port.resize(send_output_rings);
	per_core_send_pfd.resize(send_output_rings);
	per_core_counts.resize(send_output_rings);
	recv_output_rings = sysconf(_SC_NPROCESSORS_ONLN);
	per_core_recv_port.resize(recv_output_rings);
	per_core_recv_pfd.resize(recv_output_rings);
	per_core_countr.resize(recv_output_rings);
	/*recv_thread.resize(recv_output_rings+1);
	if (recv_thread.size()!=(u_int)recv_output_rings+1) {
		D("failed to allocate the recv thread array");
		return;
	}*/
	
	for (i = 0; i < send_output_rings; ++i) {
		per_core_send_port[i].nmd = NULL;
		per_core_counts[i] = 0;
	}
	for (i = 0; i < recv_output_rings; ++i) {
		per_core_recv_port[i].nmd = NULL;
		per_core_countr[i] = 0;
	}
	//recv_thread[recv_output_rings] = thread(&NetmapUse::receive_pkts_from_iface, this);
	recv_thread = thread(&NetmapUse::receive_pkts_from_iface, this);
	
	/*for (i = 0; i < recv_output_rings; ++i) {
		struct recv_thread_arg rta;
		rta.id = i;
		rta.ifname = recv_pipes_ifname;
		rta.parent_nmd = recv_master_nmd;
		per_core_recv_port[i].nmd = NULL;
		recv_thread[i] = thread(&NetmapUse::per_core_recv_func, this, i);
	}
	
	cpu_set_t cpu_set;
	
	for(i=0;i<recv_output_rings;i++) {
		CPU_ZERO(&cpu_set);
		CPU_SET(i, &cpu_set);
		int rc = pthread_setaffinity_np(recv_thread[i].native_handle(), sizeof(cpu_set_t), &cpu_set);
		if(rc!=0) {
			D("Unable to set affinity: %s", strerror(errno));
			return;
		} else {
		   for (j = 0; j < CPU_SETSIZE; j++)
		       if (CPU_ISSET(j, &cpu_set)) {
		           D("CPU %d set for %u\n", j, i);
		       }
		}
	}*/
	
	sleep(2);
	
	/*while(recv_slave_start_count < recv_output_rings) {
		this_thread::yield();
	}*/
	send_thread = thread(&NetmapUse::send_pkts_to_iface, this);
}

/*
void *
NetmapUse::get_buffer_tx(int coreid) {
	struct netmap_ring *ring = per_core_send_port[coreid].ring;
	if(unlikely(per_core_send_port[coreid].nmd == NULL)) {
		struct nmreq base_req;
		char interface[25];
		memset(&base_req, 0, sizeof(base_req));
		sprintf(interface, "%s}%d", send_pipes_ifname, coreid);
		D("opening pipe named %s", interface);
		per_core_send_port[coreid].nmd = nm_open(interface, NULL, 0, send_master_nmd);

		if (per_core_send_port[coreid].nmd == NULL) {
			D("cannot open %s", interface);
			return NULL;
		} else {
			D("successfully opened pipe #%d %s (rx slots: %d)",
			  coreid + 1, interface, per_core_send_port[coreid].nmd->req.nr_tx_slots);
			ring = per_core_send_port[coreid].ring = NETMAP_TXRING(per_core_send_port[coreid].nmd->nifp, 0);
		}
		D("zerocopy %s",
		  (send_master_nmd->mem == per_core_send_port[coreid].nmd->mem) ? "enabled" : "disabled");
		  
		per_core_send_pfd[coreid].fd = per_core_send_port[coreid].nmd->fd;
		per_core_send_pfd[coreid].events = POLLOUT;
		per_core_send_pfd[coreid].revents = 0;
	}
	if(unlikely(per_core_counts[coreid] == 0)) {
		*
		 * wait for available room in the send queue(s)
		 *
		 uint16_t n;
	#ifdef BUSY_WAIT
		if (ioctl(per_core_send_pfd[coreid].fd, NIOCTXSYNC, NULL) < 0) {
			D("ioctl error on queue %d: %s", 0,
					strerror(errno));
			return NULL;
		}
	#else * !BUSY_WAIT *
		if (poll(&(per_core_send_pfd[coreid]), 1, -1) <= 0) {
			printf("poll error/timeout on queue %d: %s", 0,
				strerror(errno));
			return NULL;
		}
		if (per_core_send_pfd[coreid].revents & POLLERR) {
			printf("poll error on %d ring %d-%d", per_core_send_pfd[coreid].fd,
				per_core_send_port[coreid].nmd->first_tx_ring, per_core_send_port[coreid].nmd->last_tx_ring);
			return NULL;
		}
	#endif * !BUSY_WAIT *
		n = nm_ring_space(per_core_send_port[coreid].ring);
		if (n <= send_batch) {
			per_core_counts[coreid] = n;
		} else {
			per_core_counts[coreid] = send_batch;
		}
	}
	struct netmap_slot *slot = &ring->slot[ring->cur];
	slot->flags = 0;
	return (void *)NETMAP_BUF(ring, slot->buf_idx);
}

void
NetmapUse::syncbuftx(int coreid) {
	struct netmap_ring *ring = per_core_send_port[coreid].ring;
	if(unlikely(--per_core_counts[coreid] == 0)) {
		ring->slot[ring->cur].flags |= NS_REPORT;
	}
	ring->cur = nm_ring_next(ring,ring->cur);
	
	if(unlikely(per_core_counts[coreid] == 0)) {
		ring->head = ring->cur;
	}
}*/

void
NetmapUse::per_core_recv_func(int coreid) {
	D("core %d recv func started", coreid);
	char tempbuf[MAX_BODYSIZE];
	void *tempptr;
	int pktlen;
	//struct nm_desc *nmd;
	while(sched_getcpu()!=coreid) {
		this_thread::yield();
		//usleep(100);
	}
	while(!recv_master_nmd) {
		this_thread::yield();
	}
	while(!do_abort) {
		tempptr = get_buffer_rx(coreid, pktlen);
		if(tempptr == NULL) {
			D("no buffer available for receive at core id %d. Aborting.", coreid);
			break;
		} else {
			nm_pkt_copy(tempptr, tempbuf, pktlen);
			syncbufrx(coreid);
		}
	}
	D("core %d recv func completed", coreid);
}

void *
NetmapUse::get_buffer_tx(int coreid) {
	while(!send_master_nmd) {
		this_thread::yield();
	}
	struct netmap_ring *ring = per_core_send_port[coreid].ring;
	if(unlikely(per_core_send_port[coreid].nmd == NULL)) {
		struct nmreq base_req;
		char interface[25];
		memset(&base_req, 0, sizeof(base_req));
		sprintf(interface, "%s}%d", send_pipes_ifname, coreid);
		//D("opening pipe named %s", interface);
		per_core_send_port[coreid].nmd = nm_open(interface, NULL, 0, send_master_nmd);

		if (per_core_send_port[coreid].nmd == NULL) {
			D("cannot open %s", interface);
			return NULL;
		} else {
			//D("successfully opened pipe #%d %s (tx slots: %d)",
			  //coreid + 1, interface, per_core_send_port[coreid].nmd->req.nr_tx_slots);
			ring = per_core_send_port[coreid].ring = NETMAP_TXRING(per_core_send_port[coreid].nmd->nifp, 0);
		}
		//D("zerocopy %s",
		  //(send_master_nmd->mem == per_core_send_port[coreid].nmd->mem) ? "enabled" : "disabled");
		  
		/*per_core_send_pfd[coreid].fd = per_core_send_port[coreid].nmd->fd;
		per_core_send_pfd[coreid].events = POLLIN;
		per_core_send_pfd[coreid].revents = 0;*/
	}
	if(unlikely(per_core_counts[coreid] == 0)) {
		/*
		 * wait for available room in the send queue(s)
		 */
		 uint16_t n;
		 int pn;
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
		//D("me %d hoon yahan", coreid);
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
		//D("me %d hoon yahan again", coreid);
	#endif /* !BUSY_WAIT */
		n = nm_ring_space(per_core_send_port[coreid].ring);
		//D("me %d hoon yahan with %d", coreid, n);
		if (n <= send_batch) {
			per_core_counts[coreid] = n;
		} else {
			per_core_counts[coreid] = send_batch;
		}
	}
	struct netmap_slot *slot = &ring->slot[ring->cur];
	//send_buf[coreid]=(void *)(NETMAP_BUF(ring, slot->buf_idx)+virt_hdr_len);
	return NETMAP_BUF(ring, slot->buf_idx)+sizeof(struct ether_header);
}

void
NetmapUse::syncbuftx(int coreid) {
	struct netmap_ring *ring = per_core_send_port[coreid].ring;
	struct netmap_slot *slot = &ring->slot[ring->cur];
	
	//slot->len = pktlen;

	struct pkthdr* pkthdr = (struct pkthdr*)(NETMAP_BUF(ring, slot->buf_idx));
	slot->len = ntohs(pkthdr->ip.ip_len) + sizeof(struct ether_header);
	if(pkthdr->ip.ip_p == IPPROTO_UDP) {
		slot->len += sizeof(struct udphdr);
	} else {
		slot->len += sizeof(struct tcphdr);
	}		
	slot->flags = 0;
	//string str = inet_ntoa(pkthdr->ip.ip_dst);
	//cout<<"Destination is:"<<str<<endl;
	//memcpy(pkthdr->eh.ether_shost, ether_aton(src_eth_addr),  6);
	/*if(arptable.find(str)!=arptable.end()) {
		memcpy(pkthdr->eh.ether_dhost, ether_aton(arptable[str].c_str()), 6);
	} else {*/
		//memcpy(pkthdr->eh.ether_dhost, ether_aton("ff:ff:ff:ff:ff:ff"), 6);
	//}
	//pkthdr->eh.ether_type = htons(ETHERTYPE_IP);
	//D("ETHTYPE:%d",htons(ETHERTYPE_IP));
	if(unlikely(--per_core_counts[coreid] == 0)) {
		ring->slot[ring->cur].flags |= NS_REPORT;
	}
	ring->cur = nm_ring_next(ring,ring->cur);
	
	if(unlikely(per_core_counts[coreid] == 0)) {
		ring->head = ring->cur;
		struct pollfd pfd;
		pfd.fd = per_core_send_port[coreid].nmd->fd;
		pfd.events = POLLOUT;
		pfd.revents = 0;
		ioctl(pfd.fd, NIOCTXSYNC, NULL);
		//poll(&(pfd), 1, -1);
	}
}

void *
NetmapUse::get_buffer_rx(int coreid, int &pktlen) {
	//cout << "IN " << endl;
	while(!recv_master_nmd) {
		this_thread::yield();
	}
	struct netmap_ring *ring = per_core_recv_port[coreid].ring;
	if(unlikely(per_core_recv_port[coreid].nmd == NULL)) {
		struct nmreq base_req;
		char interface[25];
		memset(&base_req, 0, sizeof(base_req));
		sprintf(interface, "%s}%d", recv_pipes_ifname, coreid);
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
		  
		/*per_core_recv_pfd[coreid].fd = per_core_recv_port[coreid].nmd->fd;
		per_core_recv_pfd[coreid].events = POLLIN;
		per_core_recv_pfd[coreid].revents = 0;*/
	}
	if(unlikely(per_core_countr[coreid] == 0)) {
		/*
		 * wait for available room in the recv queue(s)
		 */
		 uint16_t n;
		 int pn;
		 struct pollfd pfd;
		 pfd.fd = per_core_recv_port[coreid].nmd->fd;
		 pfd.events = POLLIN;
		 pfd.revents = 0;
	#ifdef BUSY_WAIT
		if (ioctl(pfd.fd, NIOCRXSYNC, NULL) < 0) {
			D("ioctl error on queue %d: %s", 0,
					strerror(errno));
			return NULL;
		}
	#else /* !BUSY_WAIT */
		//D("me %d hoon yahan", coreid);
		if (!do_abort && poll(&pfd, 1, 1 * 1000) == 0) {
			return NULL;
		}
		//D("per_core_countr[coreid]");
		if(do_abort) {
			return NULL;
		}
		
		
		if (pfd.revents & POLLERR) {
			printf("poll error on %d ring %d-%d", pfd.fd,
				per_core_recv_port[coreid].nmd->first_rx_ring, per_core_recv_port[coreid].nmd->last_rx_ring);
			return NULL;
		}
		//D("me %d hoon yahan again", coreid);
	#endif /* !BUSY_WAIT */
		n = nm_ring_space(per_core_recv_port[coreid].ring);
		//D("me %d hoon yahan with %d", coreid, n);
		if (n <= recv_batch) {
			per_core_countr[coreid] = n;
		} else {
			per_core_countr[coreid] = recv_batch;
		}
	}
	struct netmap_slot *slot = &ring->slot[ring->cur];
	pktlen = slot->len-sizeof(struct ether_header);	
	return (void *)(NETMAP_BUF(ring, slot->buf_idx)+sizeof(struct ether_header));
}

void
NetmapUse::syncbufrx(int coreid) {
	struct netmap_ring *ring = per_core_recv_port[coreid].ring;
	ring->cur = nm_ring_next(ring,ring->cur);
	per_core_countr[coreid]--;
	if(unlikely(per_core_countr[coreid] == 0)) {
		ring->head = ring->cur;
	}
}

void *
NetmapUse::send_pkts_to_iface() {
	int ch;
	uint32_t i,j;
	int rv;
	vector<port_des> ports;
	unsigned int iter = 0;
	uint32_t npipes;
	struct port_des *rxport;
	struct port_des *txport;
	/* we need base_req to specify pipes and extra bufs */
	struct nmreq base_req;
	uint32_t extra_bufs;
	uint32_t scan;
	//uint16_t batch;
	u_int counts;
	struct pollfd pollfd[recv_output_rings+1];
	struct netmap_ring *txring;

	//batch = 2048;
	syslog_interval = DEF_SYSLOG_INT;
	npipes = recv_output_rings;

	setlogmask(LOG_UPTO(LOG_INFO));
	openlog("lb", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	D("npipes:%u",npipes);
	
	ports.resize(npipes+2);
	
	txport = &ports[npipes];
	rxport = &ports[npipes+1];

	//stat_thread = thread(&NetmapUse::stat_thread, this);
	 
	if (ports.size()!=npipes+2) {
		D("failed to allocate the stats array");
		return NULL;
	}
	
	memset(&base_req, 0, sizeof(base_req));

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
	send_extra_bufs = txport->nmd->req.nr_tx_slots;
	send_batch = 1;

	memset(&base_req, 0, sizeof(base_req));
	base_req.nr_arg1 = npipes;
	base_req.nr_arg3 = send_extra_bufs;
	rxport->nmd = nm_open(send_pipes_ifname, &base_req, 0, NULL);

	if (rxport->nmd == NULL) {
		D("cannot open %s", send_pipes_ifname);
		return NULL;
	} else {
		D("successfully opened %s (tx rings: %u)", send_pipes_ifname,
		  rxport->nmd->req.nr_tx_slots);
	}
	
	/* reference ring to access the buffers */
	txport->ring = NETMAP_TXRING(txport->nmd->nifp, 0);
	txring = txport->ring;
	rxport->ring = NETMAP_RXRING(rxport->nmd->nifp, 0);

	extra_bufs = rxport->nmd->req.nr_arg3;

	D("obtained %d extra buffers", extra_bufs);

	for (i = 0; i < npipes; ++i) {
		char interface[25];
		sprintf(interface, "%s{%d", send_pipes_ifname, i);
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

	send_extra_bufs = extra_bufs;
	send_master_nmd = rxport->nmd;

	sleep(2);
	
	memset(&pollfd, 0, sizeof(pollfd));
	uint64_t times=0,time=0;

	//stat_thread = thread(&NetmapUse::print_stats, this, &ports[0]);

	while (!do_abort) {
		u_int pollo = 0;
		iter++;
		for (i = 0; i < npipes; ++i) {
			struct netmap_ring *ring = ports[i].ring;
			if (nm_ring_next(ring, ring->tail) == ring->cur) {
				/* no need to poll, there are no packets pending */
				continue;
			}
			pollfd[pollo].fd = ports[i].nmd->fd;
			pollfd[pollo].events = POLLIN;
			pollfd[pollo].revents = 0;
			++pollo;
		}
		pollfd[pollo].fd = txport->nmd->fd;
		pollfd[pollo].events = POLLOUT;
		pollfd[pollo].revents = 0;
		
		rv = poll(pollfd, pollo, 10);
		if (rv <= 0) {
			if (rv < 0 && errno != EAGAIN && errno != EINTR)
				RD(1, "poll error %s", strerror(errno));
			continue;
		}

		int batch_cur = 0;
		for (i = 0; i < pollo; i++) {
			struct netmap_ring *ring = ports[i].ring;

			//D("prepare to scan rings");
			int next_cur = ring->cur;
			struct netmap_slot *next_slot = &ring->slot[next_cur];
			const char *next_buf = NETMAP_BUF(ring, next_slot->buf_idx);
			int recvcount = nm_ring_space(ring);
			while (recvcount--) {
				int n;
				if(unlikely(batch_cur==0)) {
					batch_cur = send_batch;
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
						printf("poll error on %d ring %d-%d", pfdo.fd,
							rxport->nmd->first_tx_ring, rxport->nmd->last_tx_ring);
						return NULL;
					}
				#endif /* !BUSY_WAIT */
					n = nm_ring_space(txring);
					if (n < batch_cur)
						batch_cur = n;
					//D("Packets to be sent %d", batch_cur);
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
				nm_pkt_copy(tempbuf,tx_buf+virt_hdr_len,rs->len);
				
				
				

				struct pkthdr* pkthdr = (struct pkthdr*)(tx_buf+virt_hdr_len);
				//string str = inet_ntoa(pkthdr->ip.ip_dst);
				//cout<<"Destination is:"<<str<<endl;
				memcpy(pkthdr->eh.ether_shost, ether_aton(src_eth_addr),  6);
				/*if(arptable.find(str)!=arptable.end()) {
					memcpy(pkthdr->eh.ether_dhost, ether_aton(arptable[str].c_str()), 6);
				} else {*/
					//struct ether_addr start;
					//bcopy(ether_aton("00:aa:bb:cc:dd:03"), &start, 6);
					//bcopy(&start,pkthdr->eh.ether_dhost, 6);
					memcpy(pkthdr->eh.ether_dhost,ether_aton("00:22:4d:af:ae:42"), 6);
				//}
				pkthdr->eh.ether_type = htons(ETHERTYPE_IP);
				//D("ETHTYPE:%d",htons(ETHERTYPE_IP));
				
				
				
				
				
				txslot->len=rs->len+virt_hdr_len;
				//dump_payload((char *)tx_buf, txslot->len, txring, txring->cur);
				//D("txslot len=%d",txslot->len);
				txslot->flags = 0;
				batch_cur--;
				ports[i].ctr.pkts++;
				if (batch_cur==0) {
					//D("Packet sent");
					txslot->flags |= NS_REPORT;
				}
				txring->cur = nm_ring_next(txring,txring->cur);
				if (batch_cur==0) {
					txring->head = txring->cur;
					ioctl(pollfd[pollo].fd,NIOCTXSYNC,NULL);
					//poll(&(pollfd[pollo]),1,-1);
				}
			}
			ring->head = ring->cur = next_cur;

		}
	}

	for (i = 0; i < (u_int)send_output_rings + 2; ++i) {
		nm_close(ports[i].nmd);
	}
	//stat_thread.join();

	D("%lu packets forwarded.  %lu packets dropped. Total %lu time %lu times %lu\n", forwarded,
	       dropped, forwarded + dropped, time, times);
	return  NULL;
}


uint64_t numbuf=0;
void *
NetmapUse::receive_pkts_from_iface() {
	int ch;
	uint32_t i,j;
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
	uint32_t scan;
	vector<overflow_queue> oq;
	//uint16_t batch;
	struct pollfd pollfd[recv_output_rings+1];

	//batch = 2048;
	syslog_interval = DEF_SYSLOG_INT;
	npipes = recv_output_rings;
	freeq = NULL;

	setlogmask(LOG_UPTO(LOG_INFO));
	openlog("lb", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	D("npipes:%u",npipes);
	
	ports.resize(npipes+2);
	//pollfd.resize(npipes+1,0);
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

	//stat_thread = thread(&NetmapUse::stat_thread, this);
	 
	if (ports.size()!=npipes+2) {
		D("failed to allocate the stats array");
		return NULL;
	}
	
	memset(&base_req, 0, sizeof(base_req));

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
	recv_batch = 1;

	memset(&base_req, 0, sizeof(base_req));
	base_req.nr_arg1 = npipes;
	base_req.nr_arg3 = recv_extra_bufs;
	txport->nmd = nm_open(recv_pipes_ifname, &base_req, 0, NULL);

	if (txport->nmd == NULL) {
		D("cannot open %s", recv_pipes_ifname);
		return NULL;
	} else {
		D("successfully opened %s (tx rings: %u)", recv_pipes_ifname,
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
	 * the list of buffers uses the first uint32_t in each buffer
	 * as the index of the next buffer.
	 */
	for (scan = txport->nmd->nifp->ni_bufs_head;
	     scan;
	     scan = *(uint32_t *)NETMAP_BUF(txport->ring, scan))
	{
		struct netmap_slot s;
		s.buf_idx = scan;
		ND("freeq <- %d", s.buf_idx);
		freeq->slots.push(s);
	}
	//D("Enqueued buffers in freeq %lu == %lu", freeq->slots.size(), txport->oq->slots.size());
	if (freeq->slots.size() != extra_bufs) {
		D("something went wrong: netmap reported %u extra_bufs, but the free list contained %lu",
				extra_bufs, freeq->slots.size());
		return NULL;
	}
	txport->nmd->nifp->ni_bufs_head = 0;

run:
	for (i = 0; i < npipes; ++i) {
		char interface[25];
		sprintf(interface, "%s{%d", recv_pipes_ifname, i);
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
	
	while(!safe_to_start_recv) {
		this_thread::yield();
	}
	
	memset(&pollfd, 0, sizeof(pollfd));
	uint64_t times=0,time=0;

	//stat_thread = thread(&NetmapUse::print_stats, this, &ports[0]);	

	while (!do_abort) {
		u_int polli = 0;
		iter++;
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
					slot->flags |= NS_BUF_CHANGED;
					ring->cur = nm_ring_next(ring, ring->cur);
				}
				ring->head = ring->cur;
				forwarded += lim;
				p->ctr.pkts += lim;
			}
		}

		int batch_cur = 0;
		for (i = rxport->nmd->first_rx_ring; i <= rxport->nmd->last_rx_ring; i++) {
			struct netmap_ring *rxring = NETMAP_RXRING(rxport->nmd->nifp, i);

			//D("prepare to scan rings");
			int next_cur = rxring->cur;
			struct netmap_slot *next_slot = &rxring->slot[next_cur];
			const char *next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
			while (!nm_ring_empty(rxring)) {
				struct overflow_queue *q;
				struct netmap_slot *rs = next_slot;
				const char *tempbuf = next_buf;
				struct udp_pkt *pkt= (struct udp_pkt *)(next_buf + virt_hdr_len);


				// TODO perform ethernet validation operation
				if(strcmp(inet_ntoa(pkt->pkthdr.ip.ip_dst),src_ip_addr)==0) {
					arptable[inet_ntoa(pkt->pkthdr.ip.ip_src)] = this->ether_ntoa((struct ether_addr *)pkt->pkthdr.eh.ether_shost);
				} else {
					next_cur = nm_ring_next(rxring, next_cur);
					next_slot = &rxring->slot[next_cur];
					next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
					__builtin_prefetch(next_buf);
					rxring->head = rxring->cur = next_cur;

					batch_cur++;
					if (unlikely(batch_cur >= recv_batch)) {
						ioctl(rxport->nmd->fd, NIOCRXSYNC, NULL);
						batch_cur = 0;
					}
					continue;
				}


				// CHOOSE THE CORRECT OUTPUT PIPE
				uint32_t hash = pkt_hdr_hash((const unsigned char *)(next_buf+virt_hdr_len), 4, 'B');
				if (hash == 0)
					non_ip++; // XXX ??
				// prefetch the buffer for the next round
				next_cur = nm_ring_next(rxring, next_cur);
				next_slot = &rxring->slot[next_cur];
				next_buf = NETMAP_BUF(rxring, next_slot->buf_idx);
				__builtin_prefetch(next_buf);
				// 'B' is just a hashing seed
				uint32_t output_port = hash % recv_output_rings;
				//uint32_t output_port = numbuf++ % recv_output_rings;
				output_port=0;
				//D("received packet");
				struct port_des *port = &ports[output_port];
				struct netmap_ring *ring = port->ring;
				struct netmap_slot free_buf_slot;

				// Move the packet to the output pipe.
				if (nm_ring_space(ring)) {
					struct netmap_slot *ts = &ring->slot[ring->cur];
					char *copy_buf;
					copy_buf = NETMAP_BUF(ring, ts->buf_idx);
					ts->len = rs->len - virt_hdr_len;
					nm_pkt_copy(tempbuf+virt_hdr_len,copy_buf,ts->len);
					
					ring->head = ring->cur = nm_ring_next(ring, ring->cur);
					port->ctr.pkts++;
					forwarded++;
					goto forward;
				}

				/* use the overflow queue, if available */
				if (oq.empty() || !freeq->slots.size()) {
					dropped++;
					port->ctr.drop++;
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
						lp->oq->slots.pop();
						freeq->slots.push(tmp);
					}

					ND(1, "revoked %d buffers from %s", j, lq->name);
					lp->ctr.drop += j;
					dropped += j;
				}

				free_buf_slot = freeq->slots.front();
				freeq->slots.pop();
				//TODO copy to slot buffer
				char *temp_buf;
				temp_buf = NETMAP_BUF(txport->ring, free_buf_slot.buf_idx);
				free_buf_slot.len = rs->len - virt_hdr_len;
				nm_pkt_copy(tempbuf+virt_hdr_len,temp_buf,free_buf_slot.len);
				q->slots.push(free_buf_slot);

			forward:
				//No code
			next:
				rxring->head = rxring->cur = next_cur;

				batch_cur++;
				if (unlikely(batch_cur >= recv_batch)) {
					ioctl(rxport->nmd->fd, NIOCRXSYNC, NULL);
					batch_cur = 0;
				}
				ND(1,
				   "Forwarded Packets: %lu Dropped packets: %lu   Percent: %.2f",
				   forwarded, dropped,
				   ((float)dropped / (float)forwarded * 100));
			}

		}
	}

	if (extra_bufs) {
		free_buffers(ports);
	}

	/*for (i = 0; i < recv_output_rings; ++i) {
		recv_thread[i].join();
	}*/
	for (i = 0; i < (u_int)recv_output_rings + 2; ++i) {
		nm_close(ports[i].nmd);
	}
	//stat_thread.join();

	D("%lu packets forwarded.  %lu packets dropped. Total %lu time %lu times %lu\n", forwarded,
	       dropped, forwarded + dropped, time, times);
	return  NULL;
}

/*
 * initialize one packet and prepare for the next one.
 * The copy could be done better instead of repeating it each time.
 */
/*
void
NetmapUse::initialize_packet(struct udp_pkt *pkt)
{
const char *default_payload="netmap pkt-gen DIRECT payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ netmap pkt-gen DIRECT payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ ";
	if(pkt==NULL)
		return;
	struct ip *ip;
	struct udphdr *udp;
	struct ether_header *eh;
	uint16_t paylen = strlen(default_payload) + sizeof(struct udphdr) + 1;
	const char *payload = default_payload;
	int l0 = strlen(payload);
	bcopy(payload, pkt->body, l0);
	pkt->body[l0] = '\0';
	ip = &pkt->pkthdr.ip;
	
	/* prepare the headers *//*
        ip->ip_v = IPVERSION;
        ip->ip_hl = 5;
        ip->ip_id = 0;
        ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = ntohs(paylen + sizeof(*ip));
        ip->ip_id = 0;
        ip->ip_off = htons(IP_DF); /* Don't fragment *//*
        ip->ip_ttl = IPDEFTTL;
	ip->ip_p = IPPROTO_UDP;
	
	
	struct in_addr a,b;
	inet_aton("169.254.8.254", &a);
	inet_aton("169.254.9.3", &b);
	ip->ip_dst.s_addr = b.s_addr;
	ip->ip_src.s_addr = a.s_addr;
	ip->ip_sum = wrapsum(checksum(ip, sizeof(*ip), 0));


	udp = &pkt->udp;
        udp->uh_sport = htons(7891);
        udp->uh_dport = htons(7891);
	udp->uh_ulen = htons(paylen);
	/* Magic: taken from sbin/dhclient/packet.c */
	/*udp->uh_sum = wrapsum(checksum(udp, sizeof(*udp),
                    checksum(pkt->body,
                        paylen - sizeof(*udp),
                        checksum(&ip->ip_src, 2 * sizeof(ip->ip_src),
                            IPPROTO_UDP + (u_int32_t)ntohs(udp->uh_ulen)
                        )
                    )
                ));
	
	//dump_payload((void *)pkt, targ->g->pkt_size, targ->txring, targ->txring->cur, targ->txring->head, targ->txring->tail);
}
*/
u_int16_t
wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

int
NetmapUse::source_hwaddr(char *ifname)
{
	int s;
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
	 strcpy(src_ip_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	 cout<<"Source ip:"<<src_ip_addr<<endl;
	arptable[src_ip_addr] = src_eth_addr;	 
	return 0;
}

void 
NetmapUse::init_netmap()
{
	pfdo = (struct pollfd){ .fd = nmd->fd, .events = POLLOUT };
	pfdi = (struct pollfd){ .fd = nmd->fd, .events = POLLIN };
	counts = 0;
	countr = 0;
	num_pkts = 1800001;
	txring = NETMAP_TXRING(nmd->nifp, nmd->first_tx_ring);
	rxring = NETMAP_RXRING(nmd->nifp, nmd->first_rx_ring);
	while(txring->head!=txring->cur) {
		/*struct pkthdr* pkthdr = (struct pkthdr*)NETMAP_BUF(txring,txring->slot[txring->head].buf_idx);
		bcopy(ether_aton("00:aa:bb:cc:dd"), pkthdr->eh.ether_dhost, 6);
		pkthdr->eh.ether_type = htons(ETHERTYPE_IP);*/
		txring->head = 	nm_ring_next(txring,txring->head);
	}
}

void 
NetmapUse::open_netmap_dev(char *ifname) {

	int i;
	int devqueues = 1;	/* how many device queues */

	struct nmreq base_nmd;

	bzero(&base_nmd, sizeof(base_nmd));
	/*
	 * Open the netmap device using nm_open().
	 *
	 * protocol stack and may cause a reset of the card,
	 * which in turn may take some time for the PHY to
	 * reconfigure. We do the open here to have time to reset.
	 */
	base_nmd.nr_flags |= NR_ACCEPT_VNET_HDR;
	nmd = nm_open(ifname, &base_nmd, 0, NULL);
	if (nmd == NULL) {
		D("Unable to open %s: %s", ifname, strerror(errno));
		//goto out; consider this if error comes
		if (nmd->fd < 0) {
			D("aborting");
			exit(0);
		}
	}
	printf("mapped %dKB at %p", nmd->req.nr_memsize>>10, nmd->mem);
	
	struct netmap_if *nifp = nmd->nifp;
	struct nmreq *req = &nmd->req;

	printf("nifp at offset %d, %d tx %d rx region %d",
	    req->nr_offset, req->nr_tx_rings, req->nr_rx_rings,
	    req->nr_arg2);
	for (i = 0; i <= req->nr_tx_rings; i++) {
		struct netmap_ring *ring = NETMAP_TXRING(nifp, i);
		printf("   TX%d at 0x%p slots %d", i,
		    (void *)((char *)ring - (char *)nifp), ring->num_slots);
	}
	for (i = 0; i <= req->nr_rx_rings; i++) {
		struct netmap_ring *ring = NETMAP_RXRING(nifp, i);
		printf("   RX%d at 0x%p slots %d", i,
		    (void *)((char *)ring - (char *)nifp), ring->num_slots);
	}
	
	devqueues = nmd->req.nr_tx_rings;
	devqueues += nmd->req.nr_rx_rings;
	
	init_netmap();
	sleep(5);
	/* Print some debug information. */
	fprintf(stdout,
		"%s: %d queues.\n",
		ifname,
		devqueues);
	printf("Netmap device opened.\n");
	sleep(5); // wait till netmap_dev and interface is ready
	countr_thread = 1;
	
}


void 
NetmapUse::thread_func_tx() {
	u_int n;
	char *pkt;
	cout<< "Thread tx started"<<endl;
	while(1) {
		cout<< "loop begin"<<endl;
		while(counts_thread==0 && !do_abort) {
			this_thread::yield();
		}
		if(do_abort) {
			break;
		}
		counts_thread=0;
		cout<< "counts_thread made 0" <<endl;
		/*
		 * wait for available room in the send queue(s)
		 */
#ifdef BUSY_WAIT
		if (ioctl(pfdo.fd, NIOCTXSYNC, NULL) < 0) {
			D("ioctl error on queue %d: %s", 0,
					strerror(errno));
			return;
		}
#else /* !BUSY_WAIT */
		if (poll(&(pfdo), 1, -1) <= 0) {
			printf("poll error/timeout on queue %d: %s", 0,
				strerror(errno));
			return;
		}
		if (pfdo.revents & POLLERR) {
			printf("poll error on %d ring %d-%d", pfdo.fd,
				nmd->first_tx_ring, nmd->last_tx_ring);
			return;
		}
#endif /* !BUSY_WAIT */
		n = nm_ring_space(txring);
		cout<<"Sender n: "<<n<<endl;
		/*if(n <= 3) {
			goto up;
		} else */
		if (n <= bursts) {
			counts = n;
		} else {
			counts = bursts;
		}
	}
	cout<< "thread tx end"<<endl;
	return;
} 

void *NetmapUse::get_buffer_tx() {
	return malloc(MAX_BODYSIZE);
}

void 
NetmapUse::syncbuftx(struct udp_pkt *udp_pkt) {
	//cout<<"In sync"<<endl;
	u_int n;
	struct netmap_slot *txslot;
	//struct udp_pkt *pkt = (struct udp_pkt *)udp_pkt;
	std::lock_guard<std::mutex> lk(cs_netmap_sync);

	struct pkthdr* pkthdr = (struct pkthdr*)udp_pkt;
	string str = inet_ntoa(pkthdr->ip.ip_dst);
	cout<<"Destination is:"<<str<<endl;
	memcpy(pkthdr->eh.ether_shost, ether_aton(src_eth_addr),  6);
	if(arptable.find(str)!=arptable.end()) {
		memcpy(pkthdr->eh.ether_dhost, ether_aton(arptable[str].c_str()), 6);
	} else {
		memcpy(pkthdr->eh.ether_dhost, ether_aton("ff:ff:ff:ff:ff:ff"), 6);
	}
	//cout<<inet_ntoa(pkt->pkthdr.ip.ip_dst)<<endl;
	//pkthdr->ip.ip_dst)arptable[inet_ntoa(pkthdr->ip.ip_dst)]
	//memcpy(pkthdr->eh.ether_dhost, ether_aton("00:aa:bb:cc:dd:02"), 6);

	//struct ether_addr *eh = ether_aton("ff:ff:ff:ff:ff:ff");
	/*pkthdr->eh.ether_dhost[0] = eh->ether_addr_octet[0];
	pkthdr->eh.ether_dhost[1] = eh->ether_addr_octet[1];
	pkthdr->eh.ether_dhost[2] = eh->ether_addr_octet[2];
	pkthdr->eh.ether_dhost[3] = eh->ether_addr_octet[3];
	pkthdr->eh.ether_dhost[4] = eh->ether_addr_octet[4];
	pkthdr->eh.ether_dhost[5] = eh->ether_addr_octet[5];*/
	pkthdr->eh.ether_type = htons(ETHERTYPE_IP);
	void *ptr;
	if(counts == 0) {
		//cout<<"In counts 0"<<endl;
		/*
		 * wait for available room in the send queue(s)
		 */
#ifdef BUSY_WAIT
		if (ioctl(pfdo.fd, NIOCTXSYNC, NULL) < 0) {
			D("ioctl error on queue %d: %s", 0,
					strerror(errno));
			return;
		}
#else /* !BUSY_WAIT */
		if (poll(&(pfdo), 1, -1) <= 0) {
			printf("poll error/timeout on queue %d: %s", 0,
				strerror(errno));
			return;
		}
		if (pfdo.revents & POLLERR) {
			printf("poll error on %d ring %d-%d", pfdo.fd,
				nmd->first_tx_ring, nmd->last_tx_ring);
			return;
		}
#endif /* !BUSY_WAIT */
		n = nm_ring_space(txring);
		//cout<<"n: "<<n<<endl;
		/*if(n <= 3) {
			goto up;
		} else */
		if (n <= bursts) {
			counts = n;
		} else {
			counts = bursts;
		}
	}
	//cout<<"In counts not 0"<<endl;
	txslot = &txring->slot[txring->cur];
	txslot->flags = 0;
		txslot->flags |= NS_REPORT;
	txslot->len = ntohs((udp_pkt)->pkthdr.ip.ip_len) + sizeof(struct ether_header);
	if (counts==1) {
		//cout<<cur<<" NS REPORT"<<endl;
		txslot->flags |= NS_REPORT;
	}
	ptr = NETMAP_BUF(txring, txslot->buf_idx);
	nm_pkt_copy((void *)(udp_pkt), ptr, txslot->len);
	

	//dump_payload((char *)udp_pkt, txslot->len, txring, txring->cur);	
	counts--;
	txring->head = txring->cur = nm_ring_next(txring, txring->cur);
	//cout<<"Out sync"<<endl;
}
/*
ssize_t
NetmapUse::get_udp_buffer_tx(struct sockaddr_in * src_addr, const struct sockaddr_in *dest_addr, const void *buf, size_t len) {
	struct netmap_slot *txslot;
	uint32_t cur, next;
	//struct udp_pkt *pkt = (struct udp_pkt *)get_buffer_tx(cur,next,&txslot);
	//cout<<"Pkt:"<<pkt<<endl;
	//if(pkt != NULL) {
	struct udp_pkt udp_pkt;
	struct udp_pkt *pkt;
		pkt = (struct udp_pkt *)get_buffer_tx();
		{
		pkt->pkthdr.ip.ip_v = IPVERSION;
		pkt->pkthdr.ip.ip_hl = 5;
		pkt->pkthdr.ip.ip_id = htonl(54321);
		pkt->pkthdr.ip.ip_tos = IPTOS_LOWDELAY;
		pkt->pkthdr.ip.ip_len = ntohs(len + 1 + sizeof(struct udphdr) + sizeof(struct ip)); // TODO
		//ip->ip_id = 0;
		pkt->pkthdr.ip.ip_off = htons(IP_DF); 
		pkt->pkthdr.ip.ip_ttl = IPDEFTTL;
		pkt->pkthdr.ip.ip_p = IPPROTO_UDP;

		//struct in_addr a,b;
		//inet_aton(targ->g->dst_ip.name, &a);
		//inet_aton(targ->g->src_ip.name, &b);
		pkt->pkthdr.ip.ip_dst.s_addr = dest_addr -> sin_addr.s_addr;
		pkt->pkthdr.ip.ip_src.s_addr = src_addr -> sin_addr.s_addr;
		pkt->udp.uh_sport = htons(src_addr->sin_port);
		pkt->udp.uh_dport = htons(dest_addr->sin_port);
		pkt->udp.uh_ulen = htons(len + 1 + sizeof(struct udphdr));

		//cout<<"Syncbuf"<<endl;
		//bzero(pkt->body,MAX_BODYSIZE);
		bcopy((char*)buf,pkt->body,len);
		pkt->body[len] = '\0';
		//syncbuftx((void *)pkt, len + 1 + sizeof(struct udphdr) + sizeof(struct ip),cur,next,txslot);
	/* Magic: taken from sbin/dhclient/packet.c *//*
	
	struct udphdr *udp = &pkt->udp;
	struct ip *ip = &pkt->pkthdr.ip;
	udp->uh_sum = wrapsum(checksum(udp, sizeof(*udp),
                    checksum(pkt->body,
                        len+1,
                        checksum(&ip->ip_src, 2 * sizeof(ip->ip_src),
                            IPPROTO_UDP + (u_int32_t)ntohs(udp->uh_ulen)
                        )
                    )
                ));
		syncbuftx(pkt);
		free(pkt);
		}
		//cout<<"hi"<<endl;
		return len + 1;
	//}
	//return 0;
} 
*/
