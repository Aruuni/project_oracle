#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.topo import SingleSwitchTopo
from mininet.node import Controller
from mininet.log import setLogLevel, info
import time, re, os

def get_tcp_retransmissions(host):
    """
    Run 'netstat -s' on the given host and parse the output to find
    how many TCP segments have been retransmitted so far.
    """
    output = host.cmd("netstat -s")
    # Typical line looks like: "    342 segments retransmited"
    match = re.search(r'(\d+)\s+segments? retransm', output, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return 0
def simple_test():
    os.system("sudo fuser -k 6653/tcp")
    # Create a topology with 2 hosts connected by a single switch.
    topo = SingleSwitchTopo(k=2)
    net = Mininet(topo=topo)
    net.start()
    h1, h2 = net.hosts
    s1 = net.get('s1')
    # Remove any existing qdisc (ignore error if not present)
    info("*** Disabling offloads on h1 and h2\n")
    # Turn off TSO, GSO, GRO on each host's interface to capture real wire-sized packets
    h1.cmd("ethtool -K h1-eth0 tso off gso off gro off")
    h2.cmd("ethtool -K h2-eth0 tso off gso off gro off")
    info("*** Attaching custom qdisc 'oracle' to h1's interface\n")
    #h1.cmd("sudo tc qdisc del dev s1-eth1 root 2>/dev/null")
    # Attach the custom queue discipline (ensure your module is loaded)
    s1.cmd("sudo tc qdisc add dev s1-eth1 root handle 1: oracle ")
    s1.cmd("sudo tc qdisc add dev s1-eth2 root handle 1: oracle ")

    info("*** Starting tcpdump on both hosts, saving pcaps in current folder\n")
    h1.cmd("tcpdump -i h1-eth0 -w pcap/h1_current.pcap tcp &")
    h2.cmd("tcpdump -i h2-eth0 -w pcap/h2_current.pcap tcp &")
    s1.cmd("tcpdump -i s1-eth1 -w pcap/s1_eth0_current.pcap tcp &")
    s1.cmd("tcpdump -i s1-eth2 -w pcap/s1_eth1_current.pcap tcp &")
    info("*** Starting iperf server on h2 (port 5001)\n")
    # Start iperf in server mode on h2 in the background
    h2.cmd("iperf3 -s -i 0.1 --one-off -p 5001 > test_server &")
    time.sleep(1)  # Give the server time to start

    info("*** Running iperf client on h1 to send 1 MB of TCP traffic to h2\n")
    # Use iperf client on h1 to send 1MB of data to h2
    # The '-n 1M' option tells iperf to send 1 megabyte of data.
    h1.cmd("iperf3 -c {} -p 5001 -i 0.1 -t 2 > test_client".format(h2.IP()))
    s1.cmd("sudo tc -s qdisc show > test_qdisc_output")
    #CLI(net)
    retrans = get_tcp_retransmissions(h1)
    retranss1 = get_tcp_retransmissions(s1)

    info("*** TCP Retransmissions on h1: {}\n".format(retrans))
    info("*** TCP Retransmissions on s1: {}\n".format(retranss1))
    info("*** Stopping tcpdump and iperf server\n")
    # Stop tcpdump processes and iperf server
    h1.cmd("pkill tcpdump")
    h2.cmd("pkill tcpdump")
    h2.cmd("pkill iperf")
    net.stop()
    info("*** Test complete. PCAP files saved as h1_current.pcap and h2_current.pcap in the current folder.\n")

if __name__ == '__main__':
    setLogLevel('info')
    simple_test()
