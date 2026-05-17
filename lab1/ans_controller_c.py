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

import ipaddress

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import (packet, ethernet, ether_types,
                             arp, ipv4, icmp)


# ── Router identity ──────────────────────────────────────────────────────────
# DPID of the switch that acts as the router (s3, dpid=3 in run_network.py)
ROUTER_DPID = 3

# Virtual MAC addresses assigned to each router port (given in the lab spec)
PORT_TO_MAC = {
    1: '00:00:00:00:01:01',   # port 1 → s1 side  (10.0.1.0/24)
    2: '00:00:00:00:01:02',   # port 2 → s2 side  (10.0.2.0/24)
    3: '00:00:00:00:01:03',   # port 3 → ext side (192.168.1.0/24)
}

# Gateway IP assigned to each router port
PORT_TO_IP = {
    1: '10.0.1.1',
    2: '10.0.2.1',
    3: '192.168.1.1',
}

# Static routing table: (network, prefix_len) → out_port
ROUTING_TABLE = [
    ('10.0.1.0',    24, 1),
    ('10.0.2.0',    24, 2),
    ('192.168.1.0', 24, 3),
]

# Flow-rule priority levels
PRIO_TABLE_MISS  = 0    # default: send to controller
PRIO_ROUTING     = 5    # reactive per-host route entries
PRIO_ARP_TO_CTRL = 10   # keep ARP going to controller on router
PRIO_SWITCH      = 1    # learned switch entries
PRIO_BLOCK       = 100  # security drop rules (must beat routing rules)


# ─────────────────────────────────────────────────────────────────────────────

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Per-switch MAC-learning table  {dpid: {mac: out_port}}
        self.mac_to_port = {}

        # Router ARP cache  {ip_str: mac_str}
        self.arp_table = {}

        # Packets waiting for ARP resolution  {dst_ip_str: [(datapath, in_port, raw_bytes)]}
        self.pending = {}

    # ── OpenFlow handshake ────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Table-miss: send every unknown packet to the controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, PRIO_TABLE_MISS, match, actions)

        if datapath.id == ROUTER_DPID:
            self._install_router_security_rules(datapath)
            self.logger.info('[Router] Connected — security rules installed')
        else:
            self.logger.info('[Switch s%d] Connected', datapath.id)

    # ── Packet-in dispatcher ──────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # Silently ignore IPv6 (no IPv6 support needed in this lab)
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        if datapath.id == ROUTER_DPID:
            self._handle_router(datapath, in_port, msg, pkt, eth)
        else:
            self._handle_switch(datapath, in_port, msg, pkt, eth)

    # ══════════════════════════════════════════════════════════════════════════
    #  SWITCH LOGIC
    # ══════════════════════════════════════════════════════════════════════════

    def _handle_switch(self, datapath, in_port, msg, pkt, eth):
        """
        Standard MAC-learning Ethernet switch.

        We match on (in_port, eth_dst) rather than eth_dst alone so that:
          • flow rules are port-specific (prevents false matches when a MAC
            is reachable on a different port after a topology change), and
          • we never install a rule that would send a frame back out the
            port it arrived on.
        """
        dpid   = datapath.id
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        # ── Learn source MAC ──
        self.mac_to_port[dpid][eth.src] = in_port

        # ── Look up destination MAC ──
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Safety: never send a frame back out the port it came in on
        if out_port == in_port:
            return

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow rule only for known unicast destinations
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self._add_flow(datapath, PRIO_SWITCH, match, actions)

        self._packet_out(datapath, msg, in_port, actions)

    # ══════════════════════════════════════════════════════════════════════════
    #  ROUTER LOGIC
    # ══════════════════════════════════════════════════════════════════════════

    # ── Security / blocking rules (proactively installed at startup) ──────────

    def _install_router_security_rules(self, datapath):
        """
        Install high-priority drop rules that enforce the lab's security policy:

        1. Block ICMP in *both* directions between ext (192.168.1.0/24) and
           any internal host (10.0.0.0/8).  This makes `ext` unable to ping
           internal hosts AND internal hosts unable to ping `ext`.

        2. Block TCP and UDP in both directions between `ext` (192.168.1.0/24)
           and `ser` (10.0.2.2).
        """
        parser = datapath.ofproto_parser

        # ── Rule set 1: ICMP between external and internal subnets ──
        icmp_pairs = [
            # (src_subnet,       src_mask,        dst_subnet,    dst_mask)
            ('192.168.1.0', '255.255.255.0', '10.0.0.0',  '255.0.0.0'),  # ext→int
            ('10.0.0.0',    '255.0.0.0',    '192.168.1.0','255.255.255.0'),  # int→ext
        ]
        for (src_net, src_mask, dst_net, dst_mask) in icmp_pairs:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ip_proto=1,   # ICMP
                ipv4_src=(src_net, src_mask),
                ipv4_dst=(dst_net, dst_mask),
            )
            self._add_flow(datapath, PRIO_BLOCK, match, [])  # empty actions = drop

        # ── Rule set 2: TCP/UDP between ext subnet and ser (10.0.2.2) ──
        for proto in (6, 17):   # 6=TCP, 17=UDP
            for (src, dst) in [
                (('192.168.1.0', '255.255.255.0'), '10.0.2.2'),   # ext→ser
                ('10.0.2.2',  ('192.168.1.0', '255.255.255.0')),  # ser→ext
            ]:
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ip_proto=proto,
                    ipv4_src=src,
                    ipv4_dst=dst,
                )
                self._add_flow(datapath, PRIO_BLOCK, match, [])

    # ── Top-level router packet handler ──────────────────────────────────────

    def _handle_router(self, datapath, in_port, msg, pkt, eth):
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self._router_handle_arp(datapath, in_port, pkt, eth, arp_pkt)
        elif ip_pkt:
            self._router_handle_ip(datapath, in_port, msg, pkt, eth, ip_pkt)

    # ── ARP handling ─────────────────────────────────────────────────────────

    def _router_handle_arp(self, datapath, in_port, pkt, eth, arp_pkt):
        """
        • Always learn sender IP→MAC.
        • If it is an ARP REQUEST for one of our own port IPs, send a reply.
        • If it is an ARP REPLY (or any ARP teaching us a MAC we were waiting
          for), flush the pending packet queue.
        """
        sender_ip  = arp_pkt.src_ip
        sender_mac = arp_pkt.src_mac

        # Learn / update ARP cache
        self.arp_table[sender_ip] = sender_mac
        self.logger.info('[Router] ARP learn: %s → %s', sender_ip, sender_mac)

        # Flush any packets that were waiting for this MAC
        if sender_ip in self.pending:
            self.logger.info('[Router] Flushing %d pending packet(s) for %s',
                             len(self.pending[sender_ip]), sender_ip)
            for (dp, saved_in_port, raw) in self.pending.pop(sender_ip):
                self._router_forward_raw(dp, saved_in_port, raw, sender_ip)

        # Reply to ARP requests addressed to one of our port IPs
        if (arp_pkt.opcode == arp.ARP_REQUEST
                and PORT_TO_IP.get(in_port) == arp_pkt.dst_ip):
            self._send_arp_reply(datapath, in_port, arp_pkt)

    def _send_arp_reply(self, datapath, in_port, req):
        """Craft and send an ARP reply for a request targeting this router port."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        my_mac = PORT_TO_MAC[in_port]
        my_ip  = PORT_TO_IP[in_port]

        e = ethernet.ethernet(dst=req.src_mac, src=my_mac,
                              ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=my_mac,  src_ip=my_ip,
                    dst_mac=req.src_mac, dst_ip=req.src_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data,
        )
        datapath.send_msg(out)
        self.logger.info('[Router] ARP reply: %s is at %s → port %d',
                         my_ip, my_mac, in_port)

    def _send_arp_request(self, datapath, out_port, target_ip):
        """Broadcast an ARP request out a router port to discover target_ip."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        my_mac = PORT_TO_MAC[out_port]
        my_ip  = PORT_TO_IP[out_port]

        e = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff', src=my_mac,
                              ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REQUEST,
                    src_mac=my_mac,            src_ip=my_ip,
                    dst_mac='00:00:00:00:00:00', dst_ip=target_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data,
        )
        datapath.send_msg(out)
        self.logger.info('[Router] ARP request: who has %s? (port %d)',
                         target_ip, out_port)

    # ── IP handling ───────────────────────────────────────────────────────────

    def _router_handle_ip(self, datapath, in_port, msg, pkt, eth, ip_pkt):
        dst_ip = ip_pkt.dst

        # ── Is this packet destined for one of our own gateway IPs? ──
        for port, gw_ip in PORT_TO_IP.items():
            if dst_ip == gw_ip:
                if port == in_port:
                    # Own gateway on this port → respond to ICMP echo only
                    icmp_pkt = pkt.get_protocol(icmp.icmp)
                    if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                        self._send_icmp_echo_reply(datapath, in_port, eth,
                                                   ip_pkt, icmp_pkt)
                # Packets to *other* gateway IPs are silently dropped
                # (h1 ping 10.0.2.1 must fail per lab spec)
                return

        # ── Route to the correct subnet ──
        out_port = self._lookup_route(dst_ip)
        if out_port is None:
            self.logger.warning('[Router] No route to %s — dropping', dst_ip)
            return

        # ── Do we know the next-hop MAC? ──
        if dst_ip not in self.arp_table:
            # Buffer the packet and trigger ARP discovery
            if dst_ip not in self.pending:
                self.pending[dst_ip] = []
                self._send_arp_request(datapath, out_port, dst_ip)
            self.pending[dst_ip].append((datapath, in_port, msg.data))
            self.logger.info('[Router] Buffering packet for %s (ARP pending)', dst_ip)
            return

        # ── Forward (and install a flow rule for future packets) ──
        self._router_forward_and_learn(datapath, in_port, msg, dst_ip, out_port)

    def _lookup_route(self, dst_ip):
        """Return output port for dst_ip using the static routing table."""
        dst = ipaddress.IPv4Address(dst_ip)
        for (net_str, prefix_len, port) in ROUTING_TABLE:
            net = ipaddress.IPv4Network('{}/{}'.format(net_str, prefix_len))
            if dst in net:
                return port
        return None

    def _router_forward_and_learn(self, datapath, in_port, msg, dst_ip, out_port):
        """
        Install a flow rule for dst_ip and send the triggering packet.

        The flow rule rewrites both Ethernet addresses and decrements the IP TTL
        so that subsequent packets are handled entirely at the data plane.
        """
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        next_hop_mac = self.arp_table[dst_ip]
        my_mac       = PORT_TO_MAC[out_port]

        actions = [
            parser.OFPActionSetField(eth_src=my_mac),
            parser.OFPActionSetField(eth_dst=next_hop_mac),
            parser.OFPActionDecNwTtl(),
            parser.OFPActionOutput(out_port),
        ]

        # Install flow entry (priority < security drop rules)
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=dst_ip,
        )
        self._add_flow(datapath, PRIO_ROUTING, match, actions)
        self.logger.info('[Router] Flow installed: → %s via port %d (MAC %s)',
                         dst_ip, out_port, next_hop_mac)

        # Send the current packet using the same actions
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _router_forward_raw(self, datapath, in_port, raw_bytes, dst_ip):
        """
        Forward a buffered (raw) packet after ARP resolution.
        Always uses OFP_NO_BUFFER because the original buffer was long gone.
        """
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        out_port     = self._lookup_route(dst_ip)
        next_hop_mac = self.arp_table.get(dst_ip)
        if out_port is None or next_hop_mac is None:
            return

        my_mac = PORT_TO_MAC[out_port]
        actions = [
            parser.OFPActionSetField(eth_src=my_mac),
            parser.OFPActionSetField(eth_dst=next_hop_mac),
            parser.OFPActionDecNwTtl(),
            parser.OFPActionOutput(out_port),
        ]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=raw_bytes,
        )
        datapath.send_msg(out)

    # ── ICMP echo reply (gateway ping) ────────────────────────────────────────

    def _send_icmp_echo_reply(self, datapath, in_port, eth, ip_pkt, icmp_pkt):
        """
        Respond to an ICMP echo request addressed to this router's port IP.
        Allows `h1 ping 10.0.1.1` to succeed while `h1 ping 10.0.2.1` fails
        (the latter never reaches this branch).
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        my_mac = PORT_TO_MAC[in_port]
        my_ip  = PORT_TO_IP[in_port]

        # Build ICMP echo reply (mirror id/seq from the request)
        echo_data = icmp_pkt.data
        echo_reply = icmp.echo(id_=echo_data.id, seq=echo_data.seq,
                               data=echo_data.data)
        icmp_reply = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=0,
                               csum=0, data=echo_reply)

        ip_reply = ipv4.ipv4(dst=ip_pkt.src, src=my_ip,
                             proto=1, ttl=64)
        eth_reply = ethernet.ethernet(dst=eth.src, src=my_mac,
                                      ethertype=ether_types.ETH_TYPE_IP)

        p = packet.Packet()
        p.add_protocol(eth_reply)
        p.add_protocol(ip_reply)
        p.add_protocol(icmp_reply)
        p.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data,
        )
        datapath.send_msg(out)
        self.logger.info('[Router] ICMP echo reply: %s → %s', my_ip, ip_pkt.src)

    # ══════════════════════════════════════════════════════════════════════════
    #  HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    def _add_flow(self, datapath, priority, match, actions):
        """Install a flow rule. Pass actions=[] to install a drop rule."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    def _packet_out(self, datapath, msg, in_port, actions):
        """Send a PacketOut, reusing the switch's buffer when available."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
