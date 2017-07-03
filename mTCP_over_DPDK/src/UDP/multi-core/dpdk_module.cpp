/* for io_module_func def'ns */
#include "io_module.h"
//#ifndef DISABLE_DPDK
/* for mtcp related def'ns */
#include "mtcp.h"
/* for errno */
#include <errno.h>
/* for logging */
#include "debug.h"
/* for num_devices_* */
#include "config.h"
#define ENABLE_STATS_IOCTL		1
#ifdef ENABLE_STATS_IOCTL
/* for close */
#include <unistd.h>
/* for open */
#include <fcntl.h>
/* for ioctl */
#include <sys/ioctl.h>
#endif /* !ENABLE_STATS_IOCTL */

#include "dpdk_api.h"
#include <iostream>
using namespace std;
/*----------------------------------------------------------------------------*/
void
dpdk_init_handle(struct mtcp_thread_context *ctxt)
{
	cout << "It's DPDK." << endl;
}
/*----------------------------------------------------------------------------*/
int
dpdk_link_devices(struct mtcp_thread_context *ctxt)
{
	/* linking takes place during mtcp_init() */
	
	return 0;
}
/*----------------------------------------------------------------------------*/
void
dpdk_release_pkt(struct mtcp_thread_context *ctxt, int ifidx, unsigned char *pkt_data, int len)
{
	/* 
	 * do nothing over here - memory reclamation
	 * will take place in dpdk_recv_pkts 
	 */
}
/*----------------------------------------------------------------------------*/
int
dpdk_send_pkts(struct mtcp_thread_context *ctxt, int nif)
{
	//cout << "Sending." << endl;
	//dpdkuse_ins.syncbuftx(ctxt->cpu);
	//cout << "Sent." << endl;
	return 0;
}
/*----------------------------------------------------------------------------*/
uint8_t *
dpdk_get_wptr(struct mtcp_thread_context *ctxt, int nif, uint16_t pktsize)
{
	struct rte_mbuf * parent = dpdkuse_ins.get_buffer_tx();
	//cout << "Got the buffer" << endl;
	return (void *)parent;
}
/*----------------------------------------------------------------------------*/
int32_t
dpdk_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx)
{
	int32_t count = dpdkuse_ins.get_rx_count(ctxt->cpu);
	return count;
}
/*----------------------------------------------------------------------------*/
uint8_t *
dpdk_get_rptr(struct mtcp_thread_context *ctxt, int ifidx, int index, uint16_t *len)
{
	//cout << "Out of get_buf_rx" << endl;
	struct rte_mbuf *parent = dpdkuse_ins.get_buffer_rx(ctxt->cpu);
	
	if(parent == NULL) return NULL;
	

	return (uint8_t *) parent;
}
/*----------------------------------------------------------------------------*/
int32_t
dpdk_select(struct mtcp_thread_context *ctxt)
{
	return -1;
}
/*----------------------------------------------------------------------------*/
void
dpdk_destroy_handle(struct mtcp_thread_context *ctxt)
{
}
/*----------------------------------------------------------------------------*/
io_module_func dpdk_module_func = {
	load_module		   : NULL,
	init_handle		   : dpdk_init_handle,
	link_devices		   : dpdk_link_devices,
	release_pkt		   : dpdk_release_pkt,
	get_wptr   		   : dpdk_get_wptr,
	send_pkts		   : dpdk_send_pkts,
	get_rptr	   	   : dpdk_get_rptr,
	recv_pkts		   : dpdk_recv_pkts,
	select			   : dpdk_select,
	destroy_handle		   : dpdk_destroy_handle,
	dev_ioctl		   : NULL
};
/*----------------------------------------------------------------------------*/
