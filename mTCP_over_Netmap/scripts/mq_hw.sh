QUEUES=$1
NUMBUFS=$2
NIC=$3
DRIVER=$4
IP=$5
NETMASK=$6
rmmod $DRIVER
modprobe vxlan
insmod netmap-master/LINUX/$DRIVER/$DRIVER.ko RSS=$QUEUES,$QUEUES
ethtool -G $NIC rx $NUMBUFS tx $NUMBUFS
ifconfig $NIC $IP netmask $NETMASK
ethtool -K $NIC rx off tx off gro off tso off
ethtool -N $NIC rx-flow-hash tcp4 sdfn
ethtool -N $NIC rx-flow-hash udp4 sdfn
