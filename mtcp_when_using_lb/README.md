* The following [modified mTCP](mtcp-master) needs to be used on backend VNF when using mTCP stack

* Changes to be made in mTCP code based on your setup (backend VNF IP, port and LB IP). 
    * In mtcp-master/mtcp/src:
        * In **IPOutput** function in **ip_out.c**
            * line 183: change port 5000 to your backend VNF port
            * line 186: change 2851998040 to the host value of LB IP. (get this value for your LB ip using getip_hostvalue.c provided in this folder)

        * In **SendTCPPacketStandalone** in **tcp_out.cpp**
            * line 157: change port 5000 to your backend VNF port
            * line 160: change 2851998040 to the host value of LB IP.

        * In **SendTCPPacket** in  **tcp_out.cpp**
            * line 336: change port 5000 to your backend VNF port
            * line 339: change 2851998040 to the host value of LB IP.

* Configure this above mTCP using the simlar steps as original mTCP:
    * inside mtcp-master folder:
        * `./configure --enable-netmap CFLAGS="-DMAX_CPUS=1"` #DMAX_CPUS is number of cores in backend VNF
        * `make`
