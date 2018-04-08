# mptunnel 

Create a super reliable connection by tunnelling packets over multiple paths. Switch networks instantly without even dropping TCP connections.

'mptunnel' works by encapsulating IP traffic inside regular UCP packets and sending them over multiple interfaces/paths to your own proxy server which recombines them and forwards them on to the internet. It tries to replicate the 'redundant' scheduler mode of MPTCP but without using special TCP options so all middle boxes should be able to pass the traffic. It should also work with all NAT boxes.

## Why?

'mptunnel' is an experimental solutiuon to the 'multi-homing' issue. It is designed be used where a client has multiple tempermental (perhaps cell/satellite) connections to the internet. It makes no attempt to use mutiple interfaces on the proxy server and assumes the server has (at least) one single reliable interface.

This is an experiment, is not secure at all, and should not be used in production. It also uses significanty more network bandwidth as all packets are duplicated. There are probably much better ways to acheive the same thing.

## Why not SCTP?

SCTP passes IP addresses in the packet, and so has difficulty with NAT boxes.

## Why not MPTCP

MPTCP has issues getting through some middle boxes / accelerators which can strip the MPTCP option from the packets.

## Use Cases

1. A laptop with a WiFi and an Ethernet connection.
2. An embedded remote sensor with a cellular and a satellite connection.
3. A remote controlled vehicle with multiple network connections & stringent requirements about handover times.

## Requirements

1. A POSIX-compliant host with root access and multiple network interfaces. This will be the client.
2. A POSIX-compliant host with root access with full access to the internet. This will act as our proxy server.
3. The proxy server should be accessible from the client host.

_Note: Although icmptunnel has been successfully tested on Ubuntu 16.04 LTS, it should work on others as well._

## Step-by-step instructions

1. Install `cmake` on both machines.

2. Clone this repository:

  ```
  git clone https://github.com/stevegolton/mptunnel
  ```

3. Build it:

  ```
  cmake . && make
  ```

4. On the server side run the tunnel with root privileges:

  ```
  [sudo] ./mptunnel -s
  ```

5. On the client side, find out your gateway and the corresponding interface:

  ```
  route -n

  Destination     Gateway         Genmask         Flags Metric Ref    Use Iface

  0.0.0.0         172.25.30.1     0.0.0.0         UG    0      0        0 eth0
  ```

  Edit client.sh and replace \<server\> with the IP address of the proxy server. \<gateway\> with gateway address obtained above and similarly for \<interface\>.

6. Check the DNS server at client side. Make sure it does not use any server not accessible by our proxy server. One suggestion is to use `8.8.8.8`(Google's DNS server) which will be accessible to the proxy server. You would need to edit your DNS settings for this. *You might need to manually delete the route for your local DNS server from your routing table.*

7. Run the tunnel on your client with root privileges, listing the IP addresses of all the interfaces you want to send packets over:

  ```
  [sudo] ./icmptunnel -c <server> -i <if_address_0> -i <ip_address_1>
  ```

The tunnel should run and your client machine should be able to access the internet. All traffic will be tunneled over all the interfaces.

## Issues

The proxy makes no attempt to throw away duplicated packets, leaving this up to upper level protocol I.e. TCP. Perhaps it _should_ do this....

## Architecture

icmptunnel works by creating a virtual tunnel interface(say `tun0`). All the user traffic on the client host is routed to `tun0`. icmptunnel listens on this interface for IP packets. These packets are encapsulated in an ICMP echo packet(i.e. the payload of the ICMP packet is nothing but the original IP packet). This newly generated ICMP packet is sent outside the client machine, to the proxy server, through the restricted internet connection.

The proxy server receives these ICMP packets and decapsulates the original IP packet. This is retransmitted onto the Internet after implementing IP masquerading. Hence, the target believes that it's the proxy server making the request. The target then responds back to the proxy server with an IP packet. This is again captured by icmptunnel, encapsulated in an ICMP reply packet and send back to the client. 

On the client side, the IP packet is retrieved from the payload of the ICMP reply packet and injected in `tun0`. The user applications read from this virtual interface and hence get the proper IP packet.

#### Overall Architecture

```
+--------------+                             +------------+
|              |                             |            |
|            +------+  ------------------->  |            |
|            | eth0 |      UDP traffic       |            |
|            +------+  <-------------------  |   Proxy    |  ---------------->
|    Client    |                             |   Server   |     IP traffic       Proper Internet
|            +------+  ------------------->  |            |  <----------------
|            | eth1 |      UDP traffic       |            |
|            +------+  <-------------------  |            |
|              |                             +------------+
+--------------+
```

## Implementation

* [Tun](https://www.kernel.org/doc/Documentation/networking/tuntap.txt) driver is used for creating a virtual interface and binding to user space programs.

* The virtual interface is configured through `ifconfig`.

* `route` is used to change the routing tables of the client so as to route all traffic to the virtual tunnel interface.

* `iptables` is used to set up `nat` on the server side.

## Contribution

Feel free to [file issues](https://github.com/stevegolton/mptunnel/issues) and submit [pull requests](https://github.com/stevegolton/mptunnel/pulls) – contributions are welcome.

## License

icmptunnel is licensed under the MIT license.
