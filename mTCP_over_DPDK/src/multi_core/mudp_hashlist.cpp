

#include <iostream>
#include "mudp_hashlist.h"
#include <sparsehash/dense_hash_map>
#include <unordered_map>
using google::dense_hash_map;
using namespace std;

//dense_hash_map<struct four_tuple_key,struct udp_socket *,four_tuple_hash,four_tuple_eq> mudp_flow_table;

/*
 * This lookup will happen for every packet. It's crucial that it's rapid. Here google's dense hashmap has been
 * used for this. If this is not able to cope up, we'll have to modify mTCP's inbuilt hash function for streams.
 */

void display_map(dense_hash_map<struct four_tuple_key,struct socket_map *,four_tuple_hash,four_tuple_eq>& mudp_flow_table){
	dense_hash_map<struct four_tuple_key,struct socket_map *,four_tuple_hash,four_tuple_eq> :: iterator it;
	for(it = mudp_flow_table.begin();it != mudp_flow_table.end();it++){
		cout << htons(it->first.sport) << " " << it->second->id << endl;
	}
}
//struct socket_map * udp_socket_lookup(unordered_map<struct four_tuple_key,struct socket_map *,four_tuple_hash,four_tuple_eq>& mudp_flow_table,struct four_tuple_key k){
struct socket_map * udp_socket_lookup(dense_hash_map<struct four_tuple_key,struct socket_map *,four_tuple_hash,four_tuple_eq>& mudp_flow_table,struct four_tuple_key k){

	//dense_hash_map<struct four_tuple_key,struct udp_socket *,four_tuple_hash,four_tuple_eq> :: iterator it = mudp_flow_table.find(k);
	//display_map(mudp_flow_table);
	//cout << "Looking for:" << endl;
	//cout << k.sip << " " << htons(k.sport) << endl;
	//unordered_map<struct four_tuple_key,struct socket_map *,four_tuple_hash,four_tuple_eq> :: iterator it = mudp_flow_table.find(k);
	dense_hash_map<struct four_tuple_key,struct socket_map *,four_tuple_hash,four_tuple_eq> :: iterator it = mudp_flow_table.find(k);
	if(it != mudp_flow_table.end()){
		return it->second;
	}
	else
	{
		//cout << "Didn't find" << endl;
		return NULL;
	}
}
