![Alt text](repo_data/dreamer-logo.png "Optional title")

Dreamer-Mininet-Extensions
==========================

Mininet Extensions For Dreamer Project (GÉANT Open Call).

Using this tool you can emulate OSHI networks on Mininet environment.

License
=======

This sofware is licensed under the Apache License, Version 2.0.

Information can be found here:
 [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Tips
==============

See [Dreamer-Mininet-Extensions How-To](http://netgroup.uniroma2.it/twiki/bin/view/Oshi/OshiExperimentsHowto#MininetExtensions)

Mininet Extensions Dependencies
=============================

1) netaddr (pip)

2) ipaddress (pip)

3) OSHI dependecies, see setup.sh of the [Dreamer-Setup-Scripts](https://github.com/netgroup/Dreamer-Setup-Scripts) project

3.1) Open vSwitch 2.390 for MPLS-VLL and MPLS-PW [Open vSwitch](https://github.com/openvswitch/ovs) (git)

3.2) RYU for MPLS-VS, MPLS-PW and MPLS-VLL [RYU](https://github.com/osrg/ryu) (git)

3.3) networkx for MPLS-VS (pip)

4) Open vSwitchd service (init.d):

#####Install the Open vSwitchd service:

		sudo update-rc.d -f openvswitch-controller remove
		sudo update-rc.d -f openvswitch-switch remove
		./install.sh

5) [Mininet](http://mininet.org), in particular the commit: aae0affae46a63ef5e54d86351c96417c3888112 (git)

#####Install the commit

		git clone git://github.com/mininet/mininet
		cd mininet/
		git reset --hard aae0affae46a63ef5e54d86351c96417c3888112
		cd ..
		mininet/util/install.sh -ent

6) [Dreamer-Topology-Parser-and-Validator](https://github.com/netgroup/Dreamer-Topology-Parser-and-Validator) (git)
