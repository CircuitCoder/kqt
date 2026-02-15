# Routing

This document describes the general approach to determine how to deliver a packet. There are four target configurations $\{L2, L3\} \times \{P2P, Mesh\}$, so the protocol should be modular so that it can easily support all of them.

The delivery procedure is split into two steps: resolving and forwarding. Resolver maps the layer-specific destination to a node ID, and the forwarding plane will strictly operates based on node IDs.

A small side effect is that broadcasts/multicasts are duplicated to be sent to multiple node IDs. Future upgrades to the protocol may introduces STP.

## Resolver

We assume that the underlying data plane can tell us the source node ID of a packet. Detailed mechanism will be described in the later part of this document.

The way resolver works changes based on the operating layer.

For L2, resolver is relatively simple. Resolver records MAC -> node ID mapping based on incoming packets. Unknown unicast packets are broadcasted. (Note: a option may be added to supress unknown unicast packets).

For L3, each node will broadcast its prefixes to all other nodes. The routing protocol / data plane will ensure that nodes know all participating nodes in the network, as well as how to reach them.

The prefix broadcast will only be enabled in L3 mode, so the packet content is necessarily IP packets. Let's hope that no future standard (or other civilization) will use IP version 5, and reuse that protocol version number to indicate a prefix broadcast.

Each node should broadcast its prefixes at least every T duration. Prefixes expires after 5T duration. Tombstones should be kept for at least 10T duration. Since source node broadcasts all its prefix, and no prefix propagation is done, there is no risk of routing loops.

Current protocol sets T = 30s. It's important that the entire network agrees on the value of T, so it's not exposed as a configuration option.

## Forwarding

This part is about the data plane forwarding, routing protocol, and the packet format.

The routing protocol should let each node know how to:
- What's the nodes in the network.
- How to reach them.
- What's the MTU along the path.

In P2P mode, each node naturally knows all about these information, directly from underlying QUIC connections. Fragmentation / reachability check is done at the source node.

In mesh mode, packets are wrapped in an envelope. The envelope header contains the source / destnation node IDs, and a forwarding-level TTL. We also want to keep the fragmentation / reachability check at the source node. That facilitates the need of the PMTU information. Right now forwarding nodes don't peek into the packet, so we add another TTL on the outside. Dropped packets won't return a ICMP message, but that might be added in the future.

We employ a distance vector protocol similar to BABEL to guarantee loop-free forwarding. The routing information consists of (node ID, (distance, PMTU)). Routing decision is decided purely based on the distance, but PMTU is also recorded and propagated along the path.

Within the forwarding / routing protocol, node IDs are copressed down to 32 bits. Uniqueness within the network is **not checked** right now. We need to figure out how to check & change node ids during collision.

Since this is a _flat_ routing scenario, BABEl guarantees loop-free forwarding.