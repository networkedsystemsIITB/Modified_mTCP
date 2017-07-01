This directory contains the implementation of modified mTCP. At a high level, we modify mTCP to integrate with our in-house Netmap based API, which performs the incoming packet distribution in software. Due to this, mTCP is capable of running independently of underlying NIC capabilities. Please refer theses located at <links> for details of this implementation. In this document we explain directory structure and provide instruction for using our stack.

Directory Structure
docs: It contains following documents in respective subdirectories.
	1. Netmap User Manual: It contains netmap related setup in host and guest virtual machine. It also explains various configurable parameters in our netmap based API implementation used by modified mTCP. Various configurations to run our sample epoll-based TCP/UDP application have also been provided.
	2. Netmap Developer Manual: It contains design and implementation of netmap based API.
	3. mTCP User Manual:

extras: It contains sample xml of KVM virtual machine that can be used as a refernece while creating new VMs or modifying existing ones to use ptnetmap feature and expose a netmap enable NIC/VALE switch port to a VM.

patches: It contains patches to enable 2048 slot rings in netmap enabled network devices exposed to VMs. It also contains patch to enable software RSS based distribution in case of multi-queue VALE ports.

scripts: It contains script to be used if multi-queue NIC is to be exposed to a VM.

For details related to extras, patches, scripts directories refer netmap user manual.
