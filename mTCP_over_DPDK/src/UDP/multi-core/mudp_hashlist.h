#ifndef __MUDP_HASHLIST_H_
#define __MUDP_HASHLIST_H_

#include <sparsehash/dense_hash_map>
#include <unordered_map>
#include "mtcp.h"
using namespace std;
using google::dense_hash_map;

//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
/*
 * Google densehashmap can be used for Acive UDP HashList
 *//*
struct four_tuple_key{
	uint32_t sip;
	//uint32_t dip;
	uint16_t sport;
	//uint16_t dport;
};

struct four_tuple_hash {
	size_t operator()(const struct four_tuple_key& k ) const
	{
		return (((size_t)(k.sip) * 59) ^ \
		((size_t)(k.sport) << 16));
		/*
		return (((size_t)(k.sip) * 59) ^ \
		((size_t)(k.dip)) ^\
		((size_t)(k.sport) << 16) ^\
		((size_t)(k.dport)));
		*//*
	}
};

struct four_tuple_eq {
	bool operator () (const struct four_tuple_key& tup1, const struct four_tuple_key& tup2) const
	{
		return (tup1.sip == tup2.sip && tup1.sport == tup2.sport);
	}
};
*/
//extern dense_hash_map<struct four_tuple_key,struct udp_socket *,four_tuple_hash,four_tuple_eq> mudp_flow_table;
//struct socket_map * udp_socket_lookup(unordered_map<struct four_tuple_key,	struct socket_map *,struct four_tuple_hash,struct four_tuple_eq>& mudp_flow_table,struct four_tuple_key k);
struct socket_map * udp_socket_lookup(dense_hash_map<struct four_tuple_key,	struct socket_map *,struct four_tuple_hash,struct four_tuple_eq>& mudp_flow_table,struct four_tuple_key k);

#endif /* _H*/
