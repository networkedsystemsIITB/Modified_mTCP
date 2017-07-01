### Modified mTCP Stack for Virtual Network Functions over Netmap

This directory contains the implementation of modified mTCP. At a high level, we modify mTCP to integrate with our in-house Netmap based API, which is capable of performing incoming packet distribution in software. Due to this, mTCP is capable of running independently of underlying NIC capabilities. Please refer thesis links provided in project page for details of this implementation. In this document we explain directory structure and provide instruction for using our stack.

### Directory Structure

- **src**: It contains three subdirectories.
	1. *mtcp_modified*: This directory contains mTCP stack integrated with Netmap based API. It doesn't support UDP. 'testing' directory contains multi-core client and server applications using this stack. Compilation and running instruction are given in mTCP User Manual. 
	2. *mtcp_udp_only*: This directory contains mTCP stack integrated with Netmap based API with suport to UDP. This stack was tested for UDP applications, and is provided as starting point for UDP related development activities.
	3. *mtcp_tcp_udp*: This stack is contains integration of UDP extensions into stack contained in _mtcp\_modified_. Purpose of this stack is to provide complete TCP/UDP userspace stack. Performance testing of this stack is ongoing, while correctness has been tested.
	  
- **docs**: It contains following documents in respective subdirectories.
	1. Netmap User Manual: It contains netmap related setup instructions to be performed in host machine and guest virtual machine(s) befor using our protocol stack. It also explains various configurable parameters in our netmap based API implementation used by modified mTCP. Configuration to run our sample epoll-based TCP/UDP application has also been provided.
	2. Netmap Developer Manual: It contains design and implementation details of netmap based API.
	3. mTCP User Manual: It contains basic description of mTCP API and UDP extensions developed by us. We explain their usage in our example applications. It also contains instructions to run these programs. 

- **extras**: It contains sample xml of KVM virtual machine that can be used as a reference while creating new VMs or modifying existing ones, to use ptnetmap feature and expose a netmap enable NIC/VALE switch port to a VM.

- **patches**: It contains patches to enable 2048 slot rings in netmap enabled network devices exposed to VMs. It also contains patch to enable software RSS based distribution in case of multi-queue VALE ports.

- **scripts**: It contains script to be used if multi-queue NIC is to be exposed to a VM.

For details related to extras, patches, scripts directories refer netmap user manual.