"""
 Copyright (c) 2026 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class NetworkTopo(Topo):
    """
    Network topology as specified in Figure 1 of Lab 1:

        h1 (10.0.1.2/24) \
                           s1 --- s3 (router) --- ext (192.168.1.123/24)
        h2 (10.0.1.3/24) /         \
                                     s2 --- ser (10.0.2.2/24)

    Router s3 port assignment (order of addLink calls determines port numbers):
        port 1 → s1  (gateway 10.0.1.1,   MAC 00:00:00:00:01:01)
        port 2 → s2  (gateway 10.0.2.1,   MAC 00:00:00:00:01:02)
        port 3 → ext (gateway 192.168.1.1, MAC 00:00:00:00:01:03)
    """

    def __init__(self):
        Topo.__init__(self)

        # --- Hosts ---
        h1  = self.addHost('h1',  ip='10.0.1.2/24',      defaultRoute='via 10.0.1.1')
        h2  = self.addHost('h2',  ip='10.0.1.3/24',      defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser', ip='10.0.2.2/24',      defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')

        # --- Switches & Router (OpenFlow 1.3, explicit DPIDs) ---
        s1 = self.addSwitch('s1', dpid='0000000000000001', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', dpid='0000000000000002', protocols='OpenFlow13')
        # s3 acts as the router — same OVS switch type, different controller logic
        s3 = self.addSwitch('s3', dpid='0000000000000003', protocols='OpenFlow13')

        # --- Link parameters ---
        link_opts = dict(bw=15, delay='10ms')

        # --- Links for switch s1 (internal hosts) ---
        self.addLink(h1, s1, **link_opts)
        self.addLink(h2, s1, **link_opts)

        # --- Links for switch s2 (internal server) ---
        self.addLink(ser, s2, **link_opts)

        # --- Router s3 links (ORDER MATTERS — determines port numbers!) ---
        # Port 1 of s3: towards s1  (10.0.1.0/24 subnet)
        self.addLink(s1, s3, **link_opts)
        # Port 2 of s3: towards s2  (10.0.2.0/24 subnet)
        self.addLink(s2, s3, **link_opts)
        # Port 3 of s3: towards ext (192.168.1.0/24 subnet)
        self.addLink(ext, s3, **link_opts)


def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1',
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653)
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
