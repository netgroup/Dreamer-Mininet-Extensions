#!/usr/bin/python

##############################################################################################
# Copyright (C) 2014 Pier Luigi Ventre - (Consortium GARR and University of Rome "Tor Vergata")
# Copyright (C) 2014 Giuseppe Siracusano, Stefano Salsano - (CNIT and University of Rome "Tor Vergata")
# www.garr.it - www.uniroma2.it/netgroup - www.cnit.it
#
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Implementation of Dreamer Nodes.
#
# @author Pier Luigi Ventre <pl.ventre@gmail.com>
# @author Giuseppe Siracusano <a_siracusano@tin.it>
# @author Stefano Salsano <stefano.salsano@uniroma2.it>
#
#/

# This code has been taken from mininet's example bind.py, but we had to fix some stuff
# because some thing don't work properly (for example xterm)

ENABLE_SEGMENT_ROUTING = False

import sys
import shutil
import os
import re
import time
from subprocess import Popen,PIPE

from mininet.node import Host, OVSKernelSwitch, Node
from mininet.log import info, error

from coexistence_mechanisms import *
from ingress_classifications import *

#self.remounts = findRemounts( fstypes=[ 'devpts' ] )

# Simple Host with defaultVia
class IPHost(Host):

	def __init__(self, name, *args, **kwargs ):
		Host.__init__( self, name, *args, **kwargs )
		self.id = self.newId()

	def newId( self ):
		"Derive id from name, s1 -> 1"
		try:
			hid = int( re.findall( r'\d+', self.name )[ 0 ] )
			hid = hex( hid )[ 2: ]
			hid = '0' * ( 16 - len( hid ) ) + hid
			return hid
		except IndexError:
			raise Exception( 'Unable to derive default ID - '
							'please either specify a id or use a '
							'canonical name such as cer23.' )
	
	def start(self, defaultVia):
		info("%s " % self.name)
		data = defaultVia.split("#")
		gw = data[0].split("/")[0]
		intf = data[1]
		net = data[2]
		#self.cmd('ip link set dev %s up' % intf)
		#self.cmd( 'ip route del default' )
		self.cmd( 'ip route add %s via %s dev %s' %(net, gw, intf) )

		# Running SSHD
		#self.cmd('chown root:root /var/run/sshd')
		#self.cmd('chmod 711 /var/run/sshd')
		self.cmd('/usr/sbin/sshd -o UseDNS=no -u0')	

# Simple Host with IP and TCP port data
class InBandController(IPHost):

	def __init__(self, name, tcp_port, *args, **kwargs ):
		IPHost.__init__( self, name, *args, **kwargs )
		self.ip = None
		self.tcp_port = tcp_port
	
# Class that inherits from PrivateHost and extends it with 
# OSHI functionalities
class OSHI(Host):

	# XXX
	zebra_exec = '/usr/lib/quagga/zebra'
	ospfd_exec = '/usr/lib/quagga/ospfd'
	zebra_exec_2 = '/usr/sbin/zebra'
	ospfd_exec_2 = '/usr/sbin/ospfd'
	quaggaPath_msg = '/usr/lib/quagga/ OR /usr/sbin/'



	ovs_initd = "/etc/init.d/openvswitchd"

	checked = False


	baseDIR = "/tmp"
	dpidLen = 16

	OF_V = "OpenFlow13"

	SR = ENABLE_SEGMENT_ROUTING
	SR_exec = '/usr/bin/fpm-of.bin'
	SR_path = '/usr/bin/'
	
	def __init__(self, name, loopback, CR, cluster_id, *args, **kwargs ):
		dirs = ['/var/log/', '/var/log/quagga', '/var/run', '/var/run/quagga', '/var/run/openvswitch', '/var/run/sshd']
		Host.__init__(self, name, privateDirs=dirs, *args, **kwargs )
		self.loopback = loopback

		if cluster_id == "default":
			cluster_id = "0"
		cluster_id = int(cluster_id)
		if CR:
			cluster_id = cluster_id + 128	
	
		extrainfo = '%02x000000' % cluster_id

		self.dpid = self.loopbackDpid(self.loopback, extrainfo)
		self.mac = self.loopbackMac(self.loopback,"0200")
		self.path_ovs = "%s/%s/ovs" %(self.baseDIR, self.name)
		self.path_quagga =  "%s/%s/quagga" %(self.baseDIR, self.name)
		self.path_fpm = "%s/%s/fpm-of" %(self.baseDIR, self.name)
		if OSHI.checked == False:
			self.checkQuagga()
			if self.OF_V == "OpenFlow13":
				self.checkOVS()
			if OSHI.SR == True:
				self.checkSR()
			OSHI.checked = True
	
	def loopbackMac(self, loopback, extrainfo):
		splitted_loopback = loopback.split('.')
		hexloopback = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, splitted_loopback))
		mac = "%s%s" %(extrainfo, hexloopback)
		if len(mac)>12:
			error("Unable To Derive MAC From Loopback and ExtraInfo\n")
			sys.exit(-1)
		return mac
		
	
	def loopbackDpid(self, loopback, extrainfo):
		splitted_loopback = loopback.split('.')
		hexloopback = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, splitted_loopback))
		dpid = "%s%s" %(extrainfo, hexloopback)
		if len(dpid)>16:
			error("Unable To Derive DPID From Loopback and ExtraInfo\n")
			sys.exit(-1)
		return dpid

	
	def defaultDpid( self ):
		"Derive dpid from switch name, s1 -> 1"
		try:
			dpid = int( re.findall( r'\d+', self.name )[ 0 ] )
			dpid = hex( dpid )[ 2: ]
			dpid = '0' * ( self.dpidLen - len( dpid ) ) + dpid
			return dpid
		except IndexError:
			raise Exception( 'Unable to derive default datapath ID - '
							'please either specify a dpid or use a '
							'canonical switch name such as s23.' )

	def checkSR(self):
		root = Node( 'root', inNamespace=False)
		sr = root.cmd('ls %s 2> /dev/null | wc -l' % self.SR_exec)
		if '1' not in sr:
			error( 'Cannot find required executable fpm-of.bin\nPlease make sure that fpm-of.bin is properly installed in ' + self.SR_path + '\n'
				   'Otherwise change sr_path variable according to your configuration\n' )
			exit( 1 )

	def checkQuagga(self):
		root = Node( 'root', inNamespace=False )
		zebra = root.cmd('ls %s 2> /dev/null | wc -l' % OSHI.zebra_exec)
		if '1' not in zebra:
			OSHI.zebra_exec = OSHI.zebra_exec_2
			zebra = root.cmd('ls %s 2> /dev/null | wc -l' % OSHI.zebra_exec)
			if '1' not in zebra:
				error( 'Cannot find required executable zebra\nPlease make sure that Zebra is properly installed in ' + OSHI.quaggaPath_msg + '\n'
				   		'Otherwise change configuration in Dreamer-Mininet-Extensions/nodes.py \n' )
				exit( 1 )
		ospfd = root.cmd('ls %s 2> /dev/null | wc -l' % OSHI.ospfd_exec)
		if '1' not in ospfd:
			OSHI.ospfd_exec = OSHI.ospfd_exec_2
			ospfd = root.cmd('ls %s 2> /dev/null | wc -l' % OSHI.ospfd_exec)
			if '1' not in ospfd:
				error( 'Cannot find required executable ospfd\nPlease make sure that OSPFD is properly installed in ' + OSHI.quaggaPath_msg + '\n'
					   'Otherwise change configuration in Dreamer-Mininet-Extensions/nodes.py \n' )
				exit( 1 )

	def checkOVS(self):
		root = Node('root', inNamespace=False)
		modinfo = root.cmd("modinfo openvswitch | grep version: |awk -F':' '{print $2}' | awk '{ gsub (\" \", \"\", $0); print}'")
		versions = modinfo.split("\n")
		version = versions[0]
		print "modinfo openviswitch : " + version
		# SS 2017-10-21 I've disabled the version check because in the packaged openvswitch there is no version info
		# modversion = float(version[:3])
		# if modversion < 2.3:
		# 	error( 'OVS Kernel Module does not respect version requirement\nPlease check your OVS installation\n' )
		# 	exit( 1 )

		vswitchdinfo = root.cmd("ovs-vswitchd --version | grep ovs-vswitchd |awk -F')' '{print $2}' | awk '{ gsub (\" \", \"\", $0); print}'")
		versions = vswitchdinfo.split("\n")
		version = versions[0]
		print "ovs-vswitchd --version : " + version
		vswitchdversion = float(version[:3])
		if vswitchdversion < 2.3:
			error( 'OVS vswitchd does not respect version requirement\nPlease check your OVS installation\n' )
			exit( 1 )

		# SS 2017-10-21 I've disabled the version check because in the packaged openvswitch there is no version info
		# if modversion != vswitchdversion:
		# 	error( 'OVS Kernel module version and OVS vswitchd version are different\nPlease check your OVS installation\n' )
		# 	exit( 1)

		openvswitchd = root.cmd('ls %s 2> /dev/null | wc -l' % self.ovs_initd)
		if '1' not in openvswitchd:
			error( 'Cannot find required executable /etc/init.d/openvswitchd\nPlease make sure that OVS is properly installed\n')
			exit( 1 )

	def start_pw( self, table, pws_data = []):
		
		if self.OF_V != "OpenFlow13" and len(pws_data) != 0:
			error("ERROR PW configuration is not possibile for %s - OpenFlow version != 1.3\n" % self.name)
			sys.exit(-2)	
	
		rules = []

		# TODO In futuro incapsularlo
		for pw_data in pws_data:

			eth = pw_data['eth']
			v_eth1 = pw_data['v_eth1']
			v_eth2 = pw_data['v_eth2']

			if eth:
				self.cmd("ifconfig %s 0" % eth)
			if v_eth1:
				self.cmd("ifconfig %s 0" % v_eth1)
			self.cmd("ifconfig %s 0" % v_eth2)
			if eth:
				self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-port %s %s" %(self.path_ovs, self.name, eth))
			if v_eth1:			
				self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-port %s %s" %(self.path_ovs, self.name, v_eth1))
			self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-port %s %s" %(self.path_ovs, self.name, v_eth2))

			if eth and v_eth1:
				rules.append('ovs-ofctl -O %s add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.OF_V, self.name,
				table, 32768, eth, v_eth1))
				rules.append('ovs-ofctl -O %s add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.OF_V, self.name, 
				table, 32768, v_eth1, eth))
				for rule in rules:
					rule = self.translate_rule(rule)
					self.cmd(rule)


	def start( self, controllers = [], intfs_to_data = [],  coex={}):
		info("%s " % self.name)

		if len(controllers) == 0:
			info("WARNING %s Controllers\n" % len(controllers))

		if len(intfs_to_data) == 0:
			error("ERROR configuration is not possibile for %s\n" % self.name)
			sys.exit(-2)

		# Running SSHD
		self.cmd('chown root:root /var/run/sshd')
		self.cmd('chmod 711 /var/run/sshd')
		self.cmd('/usr/sbin/sshd -o UseDNS=no -u0')
		
		if coex == {}:
			error("ERROR coexistence is {}\n")
			sys.exit(-2)

		lo_data = {'intfname':'lo', 'ip':'%s' %(self.loopback), 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':self.loopback, 'netbit':32, 'cost':1, 'hello':5, 'area':'0.0.0.0'}}

		self.initial_configuration(controllers)
		self.configure_ovs(intfs_to_data, coex)
		self.configure_quagga(intfs_to_data, lo_data, coex)
		self.final_configuration(intfs_to_data)
	
	def initial_configuration(self, controllers):
		
		shutil.rmtree("%s/%s" %(self.baseDIR, self.name), ignore_errors=True)
		os.mkdir("%s/%s" %(self.baseDIR, self.name))
		os.mkdir(self.path_ovs)
		
		self.cmd("ovsdb-tool create %s/conf.db" % self.path_ovs)
		self.cmd("ovsdb-server %s/conf.db --remote=punix:%s/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --no-chdir --unixctl=%s/ovsdb-server.sock --detach" %(self.path_ovs, self.path_ovs, self.path_ovs))
		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait init" % self.path_ovs)
		self.cmd("ovs-vswitchd unix:%s/db.sock -vinfo --log-file=%s/ovs-vswitchd.log --no-chdir --detach" %(self.path_ovs, self.path_ovs))
		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-br %s" %(self.path_ovs, self.name))
		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait set bridge %s protocols=%s 2> /dev/null" %(self.path_ovs, 
		self.name, self.OF_V))

		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait set-fail-mode %s secure" %(self.path_ovs, self.name))
		# Add controllers"
		tmp = []
		for ctrl in controllers:
			if not ctrl.ip:
				error("ERROR Controller %s Not Connected - its IP is None\n" %ctrl.name)
			data = ctrl.ip.split("/")
			tmp.append('tcp:%s:%d' % ( data[0], ctrl.tcp_port ))
		clist = ' '.join(tmp)
		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait set-controller %s %s" %(self.path_ovs, self.name, clist)) 
		uids = self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait find controller | grep _uuid |awk -F':' '{print $2}' | awk '{ gsub (\" \", \"\", $0); print}'" % self.path_ovs)
		uids = uids[:-1]
		uid_set = uids.split("\n")
		for uid in uid_set:
			uid = uid.strip(' \t\n\r')
			self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait set controller %s connection-mode=out-of-band" %(self.path_ovs, uid))

		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait -- set Bridge %s other_config:datapath-id=%s" %(self.path_ovs, self.name, self.dpid))
	
		os.mkdir(self.path_quagga)
		zebra_conf = open(self.path_quagga + "/zebra.conf","w")
		ospfd_conf = open(self.path_quagga + "/ospfd.conf","w")
		ospfd_conf.write("hostname %s\n" % self.name)
		ospfd_conf.write("password zebra\n")
		ospfd_conf.write("log file /var/log/quagga/ospfd.log\n\n")
		zebra_conf.write("hostname %s\n" % self.name)
		zebra_conf.write("password zebra\n")
		zebra_conf.write("enable password zebra\n")
		zebra_conf.write("log file /var/log/quagga/zebra.log\n\n")
		ospfd_conf.close()
		zebra_conf.close()

		if OSHI.SR == True:
			os.mkdir(self.path_fpm)
	
	def configure_ovs(self, intfs_to_data, coex):

		eths = []
		vis = []
		rules = []
		temp = []

		
		coexFactory = CoexFactory()
		ingressFactory = IngressFactory()

		for intf in intfs_to_data:
		
			eth_name = intf['intfname']
			vi_name = "vi%s" %(self.strip_number(eth_name))
			eths.append(eth_name)
			vis.append(vi_name)

			self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-port %s %s" %(self.path_ovs, self.name, eth_name))
			self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-port %s %s -- set Interface %s type=internal" %(self.path_ovs, self.name, 
			vi_name, vi_name))

			if intf['ingrtype'] != None:
				ingr = ingressFactory.getIngr(coex['coex_type'], coex['coex_data'], intf['ingrtype'], intf['ingrdata'], eth_name, vi_name, self.name, 
				self.OF_V)
				temp = ingr.getOVSRules()				
				for rule in temp:
					rules.append(rule)

		coex = coexFactory.getCoex(coex['coex_type'], coex['coex_data'], eths, vis, self.name, self.OF_V)
		temp = coex.getOVSRules()		
		for rule in temp:
			rules.insert(0,rule)

		for rule in rules:
			rule = self.translate_rule(rule)
			self.cmd(rule)

	def get_if_index(self, in_if_name):
		output = self.cmd('ovs-vsctl --db=unix:%s/db.sock --no-wait find Interface name=%s' %(self.path_ovs, in_if_name))
		if output != None and output != "" :
			return re.search( r'ofport(.*): (\d*)', output).group(2)
		else:
			error("ERROR %s port not available\n" %in_if_name)
			sys.exit(-2)

	def translate_rule(self, rule):
		# ports reg exp
		out_port = re.compile('output:(.*?),')
		in_port = re.compile('in_port=(.*?),')
		out_port_end = ","
	
		#test if rule has in_port
		if 'in_port' in rule and not re.search(in_port, rule):
			error("ERROR wrong format for in_port\n")
			sys.exit(-2)	
		elif 'in_port' in rule and re.search(in_port, rule):
			in_if_name = in_port.search(rule).group(1)
			in_if_index = self.get_if_index(in_if_name)
			rule = re.sub(in_port, "in_port="+in_if_index+",", rule)

		#test if rule has output_port
		if 'output' in rule and not re.search(out_port, rule):
			#print "output: not followed by comma, retry.."
			out_port = re.compile('output:(.*?)\"(\Z)')
			out_port_end = "\""
			if not re.search(out_port, rule):
				error("ERROR wrong format for out_put port\n")
				sys.exit(-2)
			out_if_name = out_port.search(rule).group(1)
			out_if_index = self.get_if_index(out_if_name)	
			rule = re.sub(out_port, "output:"+out_if_index+out_port_end, rule)
		elif 'output' in rule and re.search(out_port, rule):	
			out_if_name = out_port.search(rule).group(1)
			out_if_index = self.get_if_index(out_if_name)
			rule = re.sub(out_port, "output:"+out_if_index+out_port_end, rule)

		return rule

	def configure_quagga(self, intfs_to_data, lo_data, coex):

		eths = []
		vis = []

		for intf in intfs_to_data:
		
			eth_name = intf['intfname']
			vi_name = "vi%s" %(self.strip_number(eth_name))
			eths.append(eth_name)
			vis.append(vi_name)

		coexFactory = CoexFactory()
		coex = coexFactory.getCoex(coex['coex_type'], coex['coex_data'], eths, vis, self.name, self.OF_V)

		commands = coex.getIPCommands()

		vis = coex.getQuaggaInterfaces()

		for command in commands:

			self.cmd(command)

		zebra_conf = open(self.path_quagga + "/zebra.conf","a")
		ospfd_conf = open(self.path_quagga + "/ospfd.conf","a")


		i = 0
		for intf in intfs_to_data:

			eth_name = intf['intfname']
			vi_name = vis[i]
			
			intfname = vi_name
			cost = intf['net']['cost']
			hello_int = intf['net']['hello']
			ip = intf['ip']
			netbit = intf['net']['netbit']

			
			ospfd_conf.write("interface " + intfname + "\n")
			ospfd_conf.write("ospf cost %s\n" % cost)
			ospfd_conf.write("ospf hello-interval %s\n\n" % hello_int)
			zebra_conf.write("interface " + intfname + "\n")
			zebra_conf.write("ip address %s/%s\n" % (ip, netbit))
			zebra_conf.write("link-detect\n\n")

			i = i + 1

		intf = lo_data
		intfname = intf['intfname']
		cost = intf['net']['cost']
		hello_int = intf['net']['hello']
		ip = intf['ip']
		net = intf['net']['net']
		netbit = intf['net']['netbit']
		area = intf['net']['area']

		ospfd_conf.write("interface " + intfname + "\n")
		ospfd_conf.write("ospf cost %s\n" % cost)
		ospfd_conf.write("ospf hello-interval %s\n\n" % hello_int)
		zebra_conf.write("interface " + intfname + "\n")
		zebra_conf.write("ip address %s/%s\n" %(ip, netbit))
		zebra_conf.write("link-detect\n\n")
		ospfd_conf.write("router ospf\n")
		ospfd_conf.write("network %s/%s area %s\n" %(net, netbit, area))

		#riconoscere qui che una rete verso mgm1 non deve essere aggiunta

		net_added = []

		for intf in intfs_to_data:

			net = intf['net']['net']
			if net not in net_added and net != '0.0.0.0':
				# if a network is the management connection with the host, it does not add it to ospf
				addr_bytes = net.split('.') 
				#info("addr_bytes = ", addr_bytes [0], addr_bytes[1], addr_bytes [2], addr_bytes[3])
				low_part = 255 - int(addr_bytes[2])
				high_part = 255 - int(addr_bytes[1])
				net_num = high_part * 256 + low_part
				if net_num > 1023 : #MAX_NUM_MANAGEMENT_NETWORKS
					net_added.append(net)
					area = intf['net']['area']
					netbit = intf['net']['netbit']
					ospfd_conf.write("network %s/%s area %s\n" %(net, netbit, area))

		ospfd_conf.close()
		zebra_conf.close()

	def final_configuration(self, intfs_to_data):

		self.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward ")
		self.cmd("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter") 		

		for intf in intfs_to_data:

			eth_name = intf['intfname']
			self.cmd('iconfig %s 0' % eth_name)
			vi_name = "vi%s" %(self.strip_number(eth_name))
			self.cmd('echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter' % eth_name)
			self.cmd('echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter' % vi_name)
		
		self.cmd("chmod -R 777 /var/log/quagga")
		self.cmd("chmod -R 777 /var/run/quagga")	
		self.cmd("chmod -R 777 %s" %(self.path_quagga))	

		self.cmd("%s -f %s/zebra.conf -A 127.0.0.1 &" %(OSHI.zebra_exec, self.path_quagga))
		self.cmd("%s -f %s/ospfd.conf -A 127.0.0.1 &" %(OSHI.ospfd_exec, self.path_quagga))

		if OSHI.SR == True:
			self.cmd("fpm-of.bin -b %s &" % self.name)

	def terminate( self ):
		Host.terminate(self)
		shutil.rmtree("%s/%s" %(self.baseDIR, self.name), ignore_errors=True)

	def strip_number(self, intf):
		intf = str(intf)
		intf_pattern = re.search(r'%s-eth\d+$' %(self.name), intf)
		if intf_pattern is None:
			error("ERROR bad name for intf\n")
			sys.exit(-2)
		data = intf.split('-')
		return int(data[1][3:])

class VSF(Host):

	ovs_initd = "/etc/init.d/openvswitchd"
	baseDIR = "/tmp"
	
	def __init__(self, name, *args, **kwargs ):
		dirs = ['/var/log/', '/var/run', '/var/run/openvswitch']
		Host.__init__(self, name, privateDirs=dirs, *args, **kwargs )
		self.path_ovs = "%s/%s/ovs" %(self.baseDIR, self.name)
	
		
	def start( self, pws_data=[]):
		info("%s " % self.name)

		if len(pws_data) == 0:
			error("ERROR PW configuration is not possibile for %s\n" % self.name)
			sys.exit(-2)

		self.initial_configuration()
		self.configure_ovs(pws_data)

	def initial_configuration(self):
		
		shutil.rmtree("%s/%s" %(self.baseDIR, self.name), ignore_errors=True)
		os.mkdir("%s/%s" %(self.baseDIR, self.name))

		os.mkdir(self.path_ovs)
		self.cmd("ovsdb-tool create %s/conf.db" % self.path_ovs)
		self.cmd("ovsdb-server %s/conf.db --remote=punix:%s/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --no-chdir --unixctl=%s/ovsdb-server.sock --detach" %(self.path_ovs, self.path_ovs, self.path_ovs))
		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait init" % self.path_ovs)
		self.cmd("ovs-vswitchd unix:%s/db.sock -vinfo --log-file=%s/ovs-vswitchd.log --no-chdir --detach" %(self.path_ovs, self.path_ovs))
		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-br %s" %(self.path_ovs, self.name))
	
	def configure_ovs(self, pws_data):

		rules = []
		
		for pw in pws_data:
		
			eth = pw['eth']
			remoteip = pw['remoteip']
			v_eth = pw['v_eth']	
			temp = 	remoteip.split('/')
			remoteip = temp[0]
			remotemac = pw['remotemac']
			gre = "gre%s" %(self.strip_number(eth))
			
			self.cmd("ifconfig %s 0" % eth)
			self.cmd( 'arp', '-s', remoteip, remotemac, '-i', v_eth)
			self.cmd( 'ip', 'r', 'a', remoteip, 'dev', v_eth)
			self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-port %s %s" %(self.path_ovs, self.name, eth))
			self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-port %s %s -- set Interface %s type=gre options:remote_ip=%s" %(self.path_ovs, 
			self.name, gre, gre, remoteip))
			
			rules.append('ovs-ofctl add-flow %s "table=0,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"'%(self.name, 32768, eth, 
			gre))
			rules.append('ovs-ofctl add-flow %s "table=0,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"'%(self.name, 32768, gre, 
			eth))			

		for rule in rules:
			rule = self.translate_rule(rule)
			self.cmd(rule)

	def get_if_index(self, in_if_name):
		output = self.cmd('ovs-vsctl --db=unix:%s/db.sock --no-wait find Interface name=%s' %(self.path_ovs, in_if_name))
		if output != None and output != "" :
			return re.search( r'ofport(.*): (\d*)', output).group(2)
		else:
			error("ERROR port not available\n")
			sys.exit(-2)

	def translate_rule(self, rule):
		# ports reg exp
		out_port = re.compile('output:(.*?),')
		in_port = re.compile('in_port=(.*?),')
		out_port_end = ","
	
		#test if rule has in_port
		if 'in_port' in rule and not re.search(in_port, rule):
			error("ERROR wrong format for in_port\n")
			sys.exit(-2)	
		elif 'in_port' in rule and re.search(in_port, rule):
			in_if_name = in_port.search(rule).group(1)
			in_if_index = self.get_if_index(in_if_name)
			rule = re.sub(in_port, "in_port="+in_if_index+",", rule)

		#test if rule has output_port
		if 'output' in rule and not re.search(out_port, rule):
			#print "output: not followed by comma, retry.."
			out_port = re.compile('output:(.*?)\"(\Z)')
			out_port_end = "\""
			if not re.search(out_port, rule):
				error("ERROR wrong format for out_put port\n")
				sys.exit(-2)
			out_if_name = out_port.search(rule).group(1)
			out_if_index = self.get_if_index(out_if_name)	
			rule = re.sub(out_port, "output:"+out_if_index+out_port_end, rule)
		elif 'output' in rule and re.search(out_port, rule):	
			out_if_name = out_port.search(rule).group(1)
			out_if_index = self.get_if_index(out_if_name)
			rule = re.sub(out_port, "output:"+out_if_index+out_port_end, rule)

		return rule

	def terminate( self ):
		Host.terminate(self)
		shutil.rmtree("%s/%s" %(self.baseDIR, self.name), ignore_errors=True)

	def strip_number(self, intf):
		intf = str(intf)
		intf_pattern = re.search(r'%s-eth\d+$' %(self.name), intf)
		if intf_pattern is None:
			error("ERROR bad name for intf\n")
			sys.exit(-2)
		data = intf.split('-')
		return int(data[1][3:])

class VS(Host):

	ovs_initd = "/etc/init.d/openvswitchd"
	baseDIR = "/tmp"
	
	def __init__(self, name, *args, **kwargs ):
		dirs = ['/var/log/', '/var/run', '/var/run/openvswitch']
		Host.__init__(self, name, privateDirs=dirs, *args, **kwargs )
		self.path_ovs = "%s/%s/ovs" %(self.baseDIR, self.name)
	
		
	def start( self, pws_data=[]):
		info("%s " % self.name)
	
		if len(pws_data) == 0:
			error("ERROR PW configuration is not possibile for %s\n" % self.name)
			sys.exit(-2)

		self.initial_configuration()
		self.configure_ovs(pws_data)
	

	def initial_configuration(self):
		
		shutil.rmtree("%s/%s" %(self.baseDIR, self.name), ignore_errors=True)
		os.mkdir("%s/%s" %(self.baseDIR, self.name))

		os.mkdir(self.path_ovs)

		self.cmd( 'ifconfig lo up' )
			
		self.cmd("ovsdb-tool create %s/conf.db" % self.path_ovs)
		self.cmd("ovsdb-server %s/conf.db --remote=punix:%s/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --no-chdir --unixctl=%s/ovsdb-server.sock --detach" %(self.path_ovs, self.path_ovs, self.path_ovs))
		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait init" % self.path_ovs)
		self.cmd("ovs-vswitchd unix:%s/db.sock -vinfo --log-file=%s/ovs-vswitchd.log --no-chdir --detach" %(self.path_ovs, self.path_ovs))
		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-br %s" %(self.path_ovs, self.name))
		self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait set-fail-mode %s standalone" %(self.path_ovs, self.name))	

	def configure_ovs(self, pws_data):
	
		rules = []
				
		for pw in pws_data:
		
			eth = pw['eth']
			remoteip = pw['remoteip']
			temp = 	remoteip.split('/')
			remoteip = temp[0]
			remotemac = pw['remotemac']
			gre = "gre%s" %(self.strip_number(eth))
			
			self.cmd( 'arp', '-s', remoteip, remotemac, '-i', eth)
			self.cmd( 'ip', 'r', 'a', remoteip, 'dev', eth)
			self.cmd("ovs-vsctl --db=unix:%s/db.sock --no-wait add-port %s %s -- set Interface %s type=gre options:remote_ip=%s" %(self.path_ovs, 
			self.name, gre, gre, remoteip))

	def terminate( self ):
		Host.terminate(self)
		shutil.rmtree("%s/%s" %(self.baseDIR, self.name), ignore_errors=True)

	def strip_number(self, intf):
		intf = str(intf)
		intf_pattern = re.search(r'%s-eth\d+$' %(self.name), intf)
		if intf_pattern is None:
			error("ERROR bad name for intf\n")
			sys.exit(-2)
		data = intf.split('-')
		return int(data[1][3:])

# Class that inherits from Host and extends it with 
# Router functionalities
class Router(Host):

	def __init__(self, name, loopback, *args, **kwargs ):
		dirs = ['/var/log/', '/var/log/quagga', '/var/run', '/var/run/quagga']
		Host.__init__(self, name, privateDirs=dirs, *args, **kwargs )
		self.loopback = loopback


# Class that inherits from OVSKernelSwitch and acts
# like a LegacyL2Switch. We enable also the STP.
class LegacyL2Switch(OVSKernelSwitch):
	
	priority = 1000
	
	def __init__(self, name, **params ):	
		failMode='standalone'
		datapath='kernel'
		OVSKernelSwitch.__init__(self, name, failMode, datapath, **params)

	
	def start( self, controllers ):
		OVSKernelSwitch.start(self, controllers)
		LegacyL2Switch.priority += 1
		self.cmd( 'ovs-vsctl set Bridge', self.name,\
						'stp_enable=true',\
						'other_config:stp-priority=%d' % LegacyL2Switch.priority )
		for intf in self.intfList():
			if 'lo' not in intf.name:
				self.cmd( 'ovs-vsctl set Port %s other_config:stp-path-cost=1' % intf.name)
