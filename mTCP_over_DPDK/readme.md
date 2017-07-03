### Modified mTCP Stack for Virtual Network Functions over DPDK

This directory contains the implementation of modified mTCP. At a high level, we modify mTCP to integrate with our in-house DPDK based API, which is capable of performing incoming packet distribution in software. Due to this, mTCP is capable of running independently of underlying NIC capabilities. Please refer thesis links provided in project page for details of this implementation. In this document we explain directory structure and provide instruction for using our stack.

### Directory Structure

- **src**: It contains four subdirectories.
	1. *bess_script*: This directory contains the forward.bess script to be pu in ~/bee/bessctl/conf/samples/ folder to enable communication between the 2 VMs.
	2. *deps*: This directory contains the files that need to be changes in the DPDK folder inside the VM to complie C++ applications.
	3. *TCP*: This directory contains code for running mTCP over DPDK. It contains two sub-directory, for muli-core and single-core VMs.
  4. *UDP*: This directory contains code for running multi-core UDP over DPDK. 
  
	The user-manual contains steps for code execution.
  
- **docs**: It contains following documents in respective subdirectories.
	1. User Manual: It contains netmap related setup instructions to be performed in host machine and guest virtual machine(s) before using our protocol stack. It also explains various configurable parameters in our DPDK based API implementation used by modified mTCP. Configuration to run our sample epoll-based TCP/UDP application has also been provided.
	2. Programmer Manual: It contains design and implementation details of DPDK based API.
	3. mTCP User Manual: It contains basic description of mTCP API and UDP extensions developed by us. We explain their usage in our example applications. It also contains instructions to run these programs. 

- **extras**: It contains sample xml of KVM virtual machine that can be used as a reference while creating new VMs or modifying existing ones for BESS NIC configuration.


