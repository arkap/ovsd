# ovsd

ovsd is an external device handler for Open vSwitch devices in conjunction with OpenWrt's netifd.
It integrates Open vSwitch configuration into the UCI configuration file `/etc/config/network`.
Using the external device handler extension for netifd, it receives commands to create and configure Open vSwitch devices from netifd and relays them to the Open vSwitch software using the `ovs-vsctl` command-line interface.

## Installation


Install this as a feed by adding the following line to `feeds.conf` in your OpenWRT source tree
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

This example configuration demonstrates all the options ovsd understands:

```bash
# /etc/config/network

config interface 'lan'
	option type 'ovs'
	option ifname 'eth0 eth1 eth2'
	option proto 'static'
	option ipaddr '172.17.1.123'
	option gateway '172.17.1.1'
	option netmask '255.255.255.0'
	option ip6assign '60'
	option ofcontrollers 'tcp:1.2.3.4:5678'
	option controller_fail_mode 'standalone'
	option ofproto '13 14'
	option ssl_cert '/root/cert.pem'
	option ssl_private_key '/root/key.pem'
	option ssl_ca_cert '/root/cacert_bootstrap.pem'
	option ssl_bootstrap 'true'

config interface 'fake'
	option type 'ovs'
	option ifname 'eth1 eth2'
	option proto 'static'
	option ipaddr '172.17.1.124'
	option netmask '255.255.255.0'
	option parent 'ovs-lan'
	option vlan '2'
	option empty 'true'
```
This will result in the creation of two Open vSwitch bridges: `ovs-lan` and `ovs-fake`.

### Config Options
 - `ofcontrollers`: a list of strings setting the bridge's OpenFlow controllers. Please refer to the [ovs-vsctl manpage](http://manpages.ubuntu.com/manpages/trusty/man8/ovs-vsctl.8.html) for the exact format of the addresses.
 - `ofproto`: Optional list of OpenFlow protocol versions to allow. Valid options are `10`, `11`, `12`, `13`, `14`, and `15`.
 - `controller_fail_mode`: Can be one of two options, `standalone` or `secure`. Standalone makes the bridge fall back to standard learning switch behavior in case of controller failure. Secure disables the installation of new flows while the controller is disconnected. Defaults to `secure`.
 - `ssl_cert`, `ssl_private_key`, `ssl_ca_cert`: paths to PEM files containing an SSL certificate, SSL private key and CA certificate, respectively. To enable transport layer encryption, all three options must be given.
 - `ssl_bootstrap`: optional boolean flag enabling a trust-on-first-use controller connection to retrieve the CA cert. This facilitates setup but is vulnerable to man-in-the-middle attacks. Please refer to the [ovs-vsctl manpage](http://manpages.ubuntu.com/manpages/trusty/man8/ovs-vsctl.8.html) for further detail.

`ovs-fake` has some other options set:
- `parent`: Name of another non-fake Open vSwitch bridge. Setting this makes the bridge a fake-bridge or pseudo-bridge created on top of the parent bridge. Note, that you'll have to add the prefix `ovs-` to the parent bridge's name.
- `vlan`: 802.1q VLAN tag for the fake-bridge. To create a fake bridge both the parent and VLAN options must be given.

## Contact

Please post to the Google group [ovsd-dev](https://groups.google.com/forum/#!forum/ovsd-dev) if you have problems with or suggestions for ovsd.

## Acknowledgements

This work was started in 2016 during Google Summer of Code. I would like to thank my advisor and mentor Julius Schulz-Zander for introducing me to GSoC and his counsel throughout the process.
An initial protoype of the mechanism was started during a student project at Technische Universität Berlin under his guidance.
A big thank you also to Felix Fietkau, author and maintainer of netifd, from whom I have learned a lot and who has given me feedback on my work. 
Thanks to Freifunk, who hosted the project and, of course, to Google for organizing GSoC.
