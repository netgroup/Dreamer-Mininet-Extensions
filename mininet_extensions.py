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
# Implementation of Dreamer Extensions.
#
# @author Pier Luigi Ventre <pl.ventre@gmail.com>
# @author Giuseppe Siracusano <a_siracusano@tin.it>
# @author Stefano Salsano <stefano.salsano@uniroma2.it>
#
#

import sys
import time
import subprocess
import json
from collections import defaultdict

from mininet.net import Mininet
from mininet.node import Node
from mininet.log import lg, info, error
from mininet.util import quietRun
from nodes import OSHI, Router, LegacyL2Switch, IPHost, InBandController, VSF
from utility import fixIntf, unmountAll, VTEPAllocator
from coexistence_mechanisms import *

class MininetOSHI(Mininet):

	zebraPath = '/usr/lib/quagga/zebra'
	ospfdPath = '/usr/lib/quagga/ospfd'

	
	def __init__(self, verbose=False):

		Mininet.__init__(self, build=False)

		self.cr_oshis = []
		self.pe_oshis = []
		self.ce_routers = []
		self.ctrls = []
		self.mgms = []
		self.nodes_in_rn = []
		self.node_to_data = defaultdict(list)
		self.node_to_node = {}
		self.node_to_default_via = {}
		self.coex = {}

		self.verbose = verbose
		lg.setLogLevel('info')

		self.vlls = []

		self.node_to_pw_data = defaultdict(list)
		self.pws = []

		self.cer_to_customer = {}
		self.customer_to_vtepallocator = {}

		self.vsfs = []
		self.pe_cer_to_vsf = {}
		
		
	
	# Create and Add a new OSHI
	def addOSHI(self, params, name=None):
		loopback = params.loopback
		if not loopback:
			error("ERROR loopback not provided\n")
			sys.exit(-2)
		oshi = Mininet.addHost(self, name, cls=OSHI, loopback=loopback)
		return oshi

	
	# Create and Add a new OSHI insert
	# it in the Core OSHI set
	def addCrOSHI(self, params, name=None):
		if not name:
			name = self.newCrName()
		oshi = self.addOSHI(params, name)
		self.cr_oshis.append(oshi)
		return oshi
	
	
	# Create and Add a new OSHI insert it
	# in the Provider Edge OSHI set
	def addPeOSHI(self, params, name=None):
		if not name:
			name = self.newPeName()
		oshi = self.addOSHI(params, name)
		self.pe_oshis.append(oshi)
		return oshi

	
	# Create and Add a new Remote Controller
	def addController(self, name=None, ip="127.0.0.1" ,tcp_port=6633):
		if not name:
			name = self.newCtrlName()
		ctrl = Mininet.addHost(self, name, cls=InBandController, tcp_port=tcp_port)
		self.ctrls.append(ctrl)
		return ctrl

	# Create and Add a new Customer Edge Router.
	# In our case it is a simple host
	def addCeRouter(self, cid, name=None):
		if not name:
			name = self.newCeName()
		ce_router = Mininet.addHost(self, name, cls=IPHost)
		self.ce_routers.append(ce_router)

		#XXX in futuro puo' cambiare
		temp = int(cid)
		exist = self.customer_to_vtepallocator.get(cid, None)
		if not exist:
			self.customer_to_vtepallocator[cid] = VTEPAllocator()
		self.cer_to_customer[name]=cid

		return ce_router

	# Create and Add a new Remote Management
	def addManagement(self, name=None):
		if not name:
			name = self.newMgmtName()
		mgmt = Mininet.addHost(self, name, cls=IPHost, inNamespace=True)
		self.mgms.append(mgmt)
		self.nodes_in_rn.append(mgmt)
		return mgmt

	def addCoexistenceMechanism(self, coex_type, coex_data):

		if coex_type is None:
			error("ERROR Coex Type is None\n")
			sys.exit(-2)

		if coex_data is None:
			error("ERROR Coex Data is None\n")
			sys.exit(-2)

		self.coex['coex_type']=coex_type
		self.coex['coex_data']=coex_data

	
	# Add Link to MininetOSHI
	def addLink(self, lhs, rhs, properties):
		info("*** Connect %s to %s\n" %(lhs.name, rhs.name))
		link = Mininet.addLink(self, lhs, rhs)

		data_lhs = { 'intfname':link.intf1.name, 'ip':properties.ipLHS, 'ingrtype':properties.ingr.type, 'ingrdata':properties.ingr.data, 'net':{ 'net':properties.net.net, 'netbit':properties.net.netbit, 'cost':properties.net.costLHS, 'hello':properties.net.helloLHS, 'area':properties.net.area}}
		data_rhs = { 'intfname':link.intf2.name, 'ip':properties.ipRHS, 'ingrtype':properties.ingr.type, 'ingrdata':properties.ingr.data, 'net':{ 'net':properties.net.net, 'netbit':properties.net.netbit, 'cost':properties.net.costRHS, 'hello':properties.net.helloRHS, 'area':properties.net.area}}

		if properties.ipLHS: 
			lhs.setIP(ip="%s/%s" %(properties.ipLHS, properties.net.netbit), intf=link.intf1)
		if properties.ipRHS:
			rhs.setIP(ip="%s/%s" %(properties.ipRHS, properties.net.netbit), intf=link.intf2)

		if type(lhs) is InBandController:
			lhs.ip = "%s/%s" %(properties.ipLHS, properties.net.netbit)
			lhs.port = 6633 
		if type(rhs) is InBandController:
			rhs.ip = "%s/%s" %(properties.ipRHS, properties.net.netbit)
			rhs.port = 6633 

		self.node_to_data[lhs.name].append(data_lhs)
		self.node_to_data[rhs.name].append(data_rhs)
		if properties.ingr.type != None:
			self.node_to_node[lhs.name]=rhs.name
			self.node_to_node[rhs.name]=lhs.name
		self.node_to_default_via[lhs.name]= "%s/%s#%s" %(properties.ipRHS, properties.net.netbit, link.intf1.name)
		self.node_to_default_via[rhs.name]= "%s/%s#%s" %(properties.ipLHS, properties.net.netbit, link.intf2.name)
		return link

	def addVLL(self, lhs_cer, rhs_cer, properties):
		info("*** Connect %s to %s through Vll\n" %(lhs_cer.name, rhs_cer.name))		

		lhs_peo = self.node_to_node[lhs_cer.name]
		rhs_peo = self.node_to_node[rhs_cer.name]

		lhs_peo = self.getNodeByName(lhs_peo)
		rhs_peo = self.getNodeByName(rhs_peo)

		if type(lhs_cer) is not IPHost or type(rhs_cer) is not IPHost or type(lhs_peo) is not OSHI or type(rhs_peo) is not OSHI:
			error("ERROR cannot provide VLL among %s and %s through %s and %s" %(lhs_cer.name, rhs_cer.name, lhs_peo.name, rhs_peo.name))
			sys.exit(-2)

		self.checkLLfeasibility(lhs_cer, rhs_cer)

		link1 = Mininet.addLink(self, lhs_cer, lhs_peo)

		temp = properties.net.split("/")

		data_lhs_cer = { 'intfname':link1.intf1.name, 'ip':properties.ipLHS, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':temp[0], 
		'netbit':temp[1], 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
		data_lhs_peo = { 'intfname':link1.intf2.name, 'ip':'0.0.0.0', 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':'0.0.0.0', 
		'netbit':32, 'cost':1, 'hello':1, 'area':'0.0.0.0'}}

		if properties.ipLHS: 
			lhs_cer.setIP(ip="%s/%s" %(properties.ipLHS, temp[1]), intf=link1.intf1)

		self.node_to_data[lhs_cer.name].append(data_lhs_cer)
		self.node_to_data[lhs_peo.name].append(data_lhs_peo)

		link2 = Mininet.addLink(self, rhs_cer, rhs_peo)

		data_rhs_cer = { 'intfname':link2.intf1.name, 'ip':properties.ipRHS, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':temp[0], 
		'netbit':temp[1], 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
		data_rhs_peo = { 'intfname':link2.intf2.name, 'ip':'0.0.0.0', 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':'0.0.0.0', 
		'netbit':32, 'cost':1, 'hello':1, 'area':'0.0.0.0'}}

		if properties.ipRHS:
			rhs_cer.setIP(ip="%s/%s" %(properties.ipRHS, temp[1]), intf=link2.intf1)

  		self.node_to_data[rhs_cer.name].append(data_rhs_cer)
		self.node_to_data[rhs_peo.name].append(data_rhs_peo)	

		self.addLineToVLLCFG(lhs_peo.dpid, link1.intf2.name, rhs_peo.dpid, link2.intf2.name)

		return (link1, link2)

	def addLineToVLLCFG(self, lhs_dpid, lhs_intf, rhs_dpid, rhs_intf):
		lhs_dpid = ':'.join(s.encode('hex') for s in lhs_dpid.decode('hex'))
		rhs_dpid = ':'.join(s.encode('hex') for s in rhs_dpid.decode('hex'))
		self.vlls.append({'lhs_dpid':lhs_dpid, 'rhs_dpid':rhs_dpid, 'lhs_intf':lhs_intf, 'rhs_intf':rhs_intf, 'lhs_label':'0', 'rhs_label':'0'})

	def addPW(self, lhs_cer, rhs_cer, properties):
		info("*** Connect %s to %s through Pw\n" %(lhs_cer.name, rhs_cer.name))		

		lhs_peo = self.node_to_node[lhs_cer.name]
		rhs_peo = self.node_to_node[rhs_cer.name]

		lhs_peo = self.getNodeByName(lhs_peo)
		rhs_peo = self.getNodeByName(rhs_peo)
		
		lhs_vsf = self.getVSFByCERandPEO(lhs_cer.name, lhs_peo.name)
		rhs_vsf = self.getVSFByCERandPEO(rhs_cer.name, rhs_peo.name)

		if type(lhs_cer) is not IPHost or type(rhs_cer) is not IPHost or type(lhs_peo) is not OSHI or type(rhs_peo) is not OSHI:
			error("ERROR cannot provide PW among %s and %s through %s and %s\n" %(lhs_cer.name, rhs_cer.name, lhs_peo.name, rhs_peo.name))
			sys.exit(-2)

		self.checkLLfeasibility(lhs_cer, rhs_cer)

		vtepallocator = self.customer_to_vtepallocator[self.cer_to_customer[lhs_cer.name]]

		temp = properties.net.split("/")

		link1 = Mininet.addLink(self, lhs_cer, lhs_peo)
		data_lhs_cer = { 'intfname':link1.intf1.name, 'ip':properties.ipLHS, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':temp[0], 
		'netbit':temp[1], 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
		if properties.ipLHS: 
			lhs_cer.setIP(ip="%s/%s" %(properties.ipLHS, temp[1]), intf=link1.intf1)
		self.node_to_data[lhs_cer.name].append(data_lhs_cer)

		vsflink1 = Mininet.addLink(self, lhs_peo, lhs_vsf)
		vsflink2 = Mininet.addLink(self, lhs_peo, lhs_vsf)
		data_lhs_peo = { 'eth':link1.intf2.name, 'v_eth1':vsflink1.intf1.name, 'v_eth2':vsflink2.intf1.name}
		self.node_to_pw_data[lhs_peo.name].append(data_lhs_peo)
		lhs_vtep = vtepallocator.next_vtep()
		rhs_vtep = vtepallocator.next_vtep()
		data_lhs_vsf = { 'eth': vsflink1.intf2.name, 'remoteip': rhs_vtep.IP, 'remotemac': rhs_vtep.MAC, 'v_eth':vsflink2.intf2.name}
		if lhs_vtep:
			vsflink2.intf2.setIP(lhs_vtep.IP)
			vsflink2.intf2.setMAC(lhs_vtep.MAC)
		#if rhs_vtep:
			#temp = rhs_vtep.IP.split("/")
			#IP = temp[0]
			#lhs_vsf.setARP(IP, rhs_vtep.MAC)
		self.node_to_pw_data[lhs_vsf.name].append(data_lhs_vsf)

		link2 = Mininet.addLink(self, rhs_cer, rhs_peo)
		data_rhs_cer = { 'intfname':link2.intf1.name, 'ip':properties.ipRHS, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':temp[0], 
		'netbit':temp[1], 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
		if properties.ipRHS:
			rhs_cer.setIP(ip="%s/%s" %(properties.ipRHS, temp[1]), intf=link2.intf1)
  		self.node_to_data[rhs_cer.name].append(data_rhs_cer)

		vsflink3 = Mininet.addLink(self, rhs_peo, rhs_vsf)
		vsflink4 = Mininet.addLink(self, rhs_peo, rhs_vsf)
		data_rhs_peo = { 'eth': link2.intf2.name, 'v_eth1':vsflink3.intf1.name, 'v_eth2':vsflink4.intf1.name}
		self.node_to_pw_data[rhs_peo.name].append(data_rhs_peo)
		data_rhs_vsf = {'eth': vsflink3.intf2.name, 'remoteip': lhs_vtep.IP, 'remotemac': lhs_vtep.MAC, 'v_eth':vsflink4.intf2.name}
		if rhs_vtep:
			vsflink4.intf2.setIP(rhs_vtep.IP)
			vsflink4.intf2.setMAC(rhs_vtep.MAC)
		#if lhs_vtep:
			#temp = lhs_vtep.IP.split("/")
			#IP = temp[0]
			#rhs_vsf.setARP(IP, lhs_vtep.MAC)
		self.node_to_pw_data[rhs_vsf.name].append(data_rhs_vsf)
	
		self.addLineToPWCFG(lhs_peo.dpid, vsflink2.intf1.name, lhs_vtep, rhs_peo.dpid, vsflink4.intf1.name, rhs_vtep)

		return (link1, vsflink1, vsflink2, link2, vsflink3, vsflink4)

	def getVSFByCERandPEO(self, cer, peo):
		key = "%s-%s" %(cer,peo)
		vsf = self.pe_cer_to_vsf.get(key, None)
		if not vsf:
			name = self.newVsfName()
			vsf = Mininet.addHost(self, name, cls=VSF)
			self.vsfs.append(vsf)
			self.pe_cer_to_vsf[key]=vsf
		return vsf

	def addLineToPWCFG(self, lhs_dpid, lhs_intf, lhs_vtep, rhs_dpid, rhs_intf, rhs_vtep):
		lhs_dpid = ':'.join(s.encode('hex') for s in lhs_dpid.decode('hex'))
		rhs_dpid = ':'.join(s.encode('hex') for s in rhs_dpid.decode('hex'))
		lhs_mac = ':'.join(s.encode('hex') for s in lhs_vtep.MAC.decode('hex'))
		rhs_mac = ':'.join(s.encode('hex') for s in rhs_vtep.MAC.decode('hex'))
		self.pws.append({'lhs_dpid':lhs_dpid, 'rhs_dpid':rhs_dpid, 'lhs_intf':lhs_intf, 'rhs_intf':rhs_intf, 'lhs_label':'0', 'rhs_label':'0',
		'lhs_mac': lhs_mac, 'rhs_mac': rhs_mac})

	def configHosts( self ):
		"Configure a set of hosts."

		for host in self.hosts:
			info( host.name + ' ' )
			host.cmd( 'ifconfig lo up' )
		info( '\n' )

	def fixEnvironment(self):
		
		info("*** Fix environment\n")

		for node in self.nodes_in_rn:
			fixIntf(node)
		root = Node( 'root', inNamespace=False )
		
		info("*** Stop unwanted traffic\n")
		root.cmd('stop avahi-daemon')
		root.cmd('killall dhclient')

		info("*** Kill old processes\n")
		root.cmd('killall zebra')
		root.cmd('killall ospfd')
		root.cmd('killall sshd')
		root.cmd('killall apache2')
	
		cfile = '/etc/environment'
	  	line1 = 'VTYSH_PAGER=more\n'
	  	config = open( cfile ).read()
	  	if ( line1 ) not in config:
			info( '*** Adding %s to %s\n' %(line1.strip(), 'to', cfile))
			with open( cfile, 'a' ) as f:
		  		f.write( line1 )
		  	f.close();
		
		root.cmd('service network-manager restart')
		info("*** Restart Network Manager\n")
		time.sleep(10)

	def start(self):

		self.fixEnvironment()

		if not self.built:
			self.build()
		info( '*** Starting %s cr oshis\n' % len(self.cr_oshis) )
		for cr_oshi in self.cr_oshis:
			cr_oshi.start(self.ctrls, self.node_to_data[cr_oshi.name],  self.coex)

		coexFactory = CoexFactory()
		coex = coexFactory.getCoex(self.coex['coex_type'], self.coex['coex_data'], [], [], "", OSHI.OF_V)		
		
		info( '\n' )
		info( '*** Starting %s pe oshis\n' % len(self.pe_oshis) )
		for pe_oshi in self.pe_oshis:
			pe_oshi.start(self.ctrls, self.node_to_data[pe_oshi.name],  self.coex)
			pe_oshi.start_pw(coex.tableIP, self.node_to_pw_data[pe_oshi.name])
		info( '\n' )
		info( '*** Starting %s vsfs\n' % len(self.vsfs) )
		for vsf in self.vsfs:
			vsf.start(self.node_to_pw_data[vsf.name])		
		info( '\n' )
		info( '*** Starting %s in band controllers\n' % len(self.ctrls) )
		for controller in self.ctrls:
			controller.start(self.node_to_default_via[controller.name])
		info( '\n' )
		info( '*** Starting %s ce routers\n' % len(self.ce_routers) )
		for ce_router in self.ce_routers:
			ce_router.start(self.node_to_default_via[ce_router.name])
		info( '\n' )
		info( '*** Starting %s management servers\n' % len(self.mgms) )
		for mgm in self.mgms:
			mgm.start(self.node_to_default_via[mgm.name])
		info( '\n' )


		vllcfg_file = open('vll_pusher.cfg','w')

		
		vllcfg = {}
		vllcfg['tableSBP'] = coex.tableSBP
		vllcfg['tableIP'] = coex.tableIP
		vllcfg['vlls'] = self.vlls
		vllcfg['pws'] = self.pws

		vllcfg_file.write(json.dumps(vllcfg, sort_keys=True, indent=4))

		vllcfg_file.close()

	def cleanEnvironment(self):
		
		info("*** Clean environment\n")
		subprocess.call(["sudo", "mn", "-c"], stdout=None, stderr=None)
		
		root = Node( 'root', inNamespace=False )
		
		info("*** Restart network-manager\n")
		root.cmd('service network-manager restart')
		
		info("*** Kill all processes started\n")
		root.cmd('killall ovsdb-server')
		root.cmd('killall ovs-vswitchd')
		root.cmd('killall zebra')
		root.cmd('killall ospfd')
		root.cmd('killall sshd')
		root.cmd('killall apache2')

		info("*** Restart Avahi, Open vSwitch and sshd\n")	
		root.cmd('/etc/init.d/avahi-daemon start')

		if OSHI.OF_V == None: 
			root.cmd('/etc/init.d/openvswitch-switch start') 
		elif OSHI.OF_V == "OpenFlow13":
			root.cmd('/etc/init.d/openvswitchd start')

		root.cmd('/etc/init.d/ssh start')

		info('*** Unmounting host bind mounts\n')
		unmountAll()

	def stop(self):

		if self.terms:
		    info( '*** Stopping %i terms\n' % len( self.terms ) )
		    self.stopXterms()

		info( '*** Stopping %i hosts\n' % len( self.hosts ) )
		for host in self.hosts:
		    info( host.name + ' ' )
		    host.terminate()
		
		info( '\n' )
		self.cleanEnvironment()

		info( '*** Done\n' )

	def checkLLfeasibility(self, lhs, rhs):
		if lhs not in self.ce_routers or rhs not in self.ce_routers:
			error("Error misconfiguration Leased Line\n")
			error("Error cannot connect %s to %s\n" % (lhs, rhs))
			sys.exit(2)

		# XXX In futuro puo' combiare
		cid_lhs = self.cer_to_customer[lhs.name]
		cid_rhs = self.cer_to_customer[rhs.name]
		if cid_lhs != cid_rhs:
			error("Error misconfiguration Virtual Leased Line\n")
			error("Error cannot connect %s to %s - Different Customer\n" % (lhs, rhs))
			sys.exit(2)

	# Utility functions to generate
	# automatically new names

	def newCrName(self):
		index = str(len(self.cr_oshis) + 1)
		name = "cro%s" % index
		return name	

	def newPeName(self):
		index = str(len(self.pe_oshis) + 1)
		name = "peo%s" % index
		return name	

	def newCtrlName(self):
		index = str(len(self.controllers) + 1)
		name = "ctr%s" % index
		return name

	def newCeName(self):
		index = str(len(self.ce_routers) + 1)
		name = "cer%s" % index
		return name

	def newVsfName(self):
		index = str(len(self.vsfs) + 1)
		name = "vsf%s" % index
		return name

	def newMgmtName(self):
		index = str(len(self.mgms) + 1)
		name = "mgm%s" % index
		return name


