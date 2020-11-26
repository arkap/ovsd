# ovsd

ovsd is an external device handler enabling native UCI configuration of Open vSwitch on OpenWrt systems.
It interacts with OpenWrt's netifd to allow configuration through the familiar UCI file at `/etc/config/network`.
Using the external device handler extension for netifd, it relays commands to the `ovs-vsctl` command-line interface for Open vSwitch.

## Installation

Install this as a feed by adding the following line to `feeds.conf` in your OpenWrt source tree
```
src-git sdwn git@gitlab.hhi.fraunhofer.de:wn-ina/sdwn-feed.git
```
and running
```bash
scripts/feeds update sdwn && scripts/feeds install ovsd
```
There should now be a submenu called `SDWN` under `Network` when you run
`make menuconfig` where you can select `ovsd`.

## Configuration

### Basic
The following example creates an Open vSwitch bridge called `ovs-lan` with the interfaces `eth1` and `eth2`:

```bash
# /etc/config/network
config interface 'lan'
	option type 'ovs'
	option ifname 'eth1 eth2'
	option proto 'dhcp'
	option ofcontrollers 'tcp:1.2.3.4:5678'
	option controller_fail_mode 'standalone'
	option ofproto '13 14'
```
 - `ofcontrollers` - set an OpenFlow controller
 - `controller_fail_mode` - fall-back behavior in case of controller unavailability. `standalone` means learning switch behavior. `secure` (the default) disables the installation of new flow rules.
 - `ofproto` - set the OpenFlow protocol versions that are permitted on the control channel.

### Encrpytion
The following example demonstrates how to configure encryption for the control channel:

```bash
# /etc/config/network
config interface 'lan'
	...
	option ssl_cert '/path/to/cert'
	option ssl_private_key '/path/to/private_key'
	option ssl_ca_cert '/path/to/ca_cert'
	option ssl_bootstrap 'true'
```
 - `ssl_cert`, `ssl_private_key`, and `ssl_ca_cert` set the certificate, private ke, and CA certificate, respectively. All of them must be given to use encryption.
 - `ssl_bootstrap` is an optional boolean flag enabling a trust-on-first-use connection to the controller to retrieve the CA certificate.

### VLANs
The following example demonstrates how to configure VLANs with ovsd:

```bash
# /etc/config/network

config interface 'lan'
	option type 'ovs'
	option proto 'dhcp'
	option empty 'true'
	option ofcontrollers 'tcp:1.2.3.4:5678'

config interface 'vlan100'
	option type 'ovs'
	option ifname 'eth1 eth2'
	option parent 'ovs-lan'
	option vlan '100'
```
This will result in the creation of two Open vSwitch bridges: `ovs-lan` and `ovs-vlan100`. `ifname`s listed within the scope of `vlan100` will become members of the VLAN 100.
 - `parent`- is the name of an Open vSwitch bridge. Setting this makes the bridge a fake-bridge or pseudo-bridge created on top of the parent bridge. Note, that you'll have to add the prefix `ovs-` to the parent bridge's name.
 - `vlan` - 802.1q VLAN tag for the fake-bridge. To create a fake bridge both the parent and VLAN options must be given.

Notice the option `empty` within the scope of `ovs-lan`. Since it does not list any `ifname`s, this ensures the bridge gets created even if it does not have members.

## Acknowledgements

This work was started in 2016 during Google Summer of Code. I would like to thank my advisor and mentor Julius Schulz-Zander for introducing me to GSoC and his counsel throughout the process.
An initial protoype of the mechanism was started during a student project at Technische Universität Berlin under his guidance.
A big thank you also to Felix Fietkau, author and maintainer of netifd, from whom I have learned a lot and who has given me feedback on my work. 
Thanks to Freifunk, who hosted the project and, of course, to Google for organizing GSoC.
