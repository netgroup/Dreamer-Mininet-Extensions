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
from collections import defaultdict

from mininet.net import Mininet
from mininet.node import Node
from mininet.log import lg, info, error
from mininet.util import quietRun
from nodes import OSHI, Router, LegacyL2Switch, IPHost, InBandController
from utility import fixIntf, unmountAll


# TODO
# call fixintf after the start


class MininetOSHI(Mininet):

	zebraPath = '/usr/lib/quagga/zebra'
	ospfdPath = '/usr/lib/quagga/ospfd'

	# XXX TESTED
	def __init__(self, verbose=False):

		Mininet.__init__(self, switch=LegacyL2Switch, build=False)

		self.cr_oshis = []
		self.pe_oshis = []
		self.ce_routers = []
		self.ctrls = []
		self.nodes_in_rn = []
		self.node_to_data = defaultdict(list)
		self.node_to_node = {}
		self.node_to_default_via = {}
		self.coex = {}

		self.verbose = verbose
		lg.setLogLevel('info')

		self.vllcfg = open("vll_pusher.cfg", "w")
		
		
	# XXX TESTED
	# Create and Add a new OSHI
	def addOSHI(self, params, name=None):
		loopback = params.loopback
		if not loopback:
			error("ERROR loopback not provided\n")
			sys.exit(-2)
		oshi = Mininet.addHost(self, name, cls=OSHI, loopback=loopback)
		return oshi

	# XXX TESTED
	# Create and Add a new OSHI insert
	# it in the Core OSHI set
	def addCrOSHI(self, params, name=None):
		if not name:
			name = self.newCrName()
		oshi = self.addOSHI(params, name)
		self.cr_oshis.append(oshi)
		return oshi
	
	# XXX TESTED
	# Create and Add a new OSHI insert it
	# in the Provider Edge OSHI set
	def addPeOSHI(self, params, name=None):
		if not name:
			name = self.newPeName()
		oshi = self.addOSHI(params, name)
		self.pe_oshis.append(oshi)
		return oshi

	# XXX TESTED
	# Create and Add a new Remote Controller
	# if it is in the rootnamespace, save it in
	# nodes_in_rn array
	def addController(self, name=None, ip="127.0.0.1" ,tcp_port=6633):
		if not name:
			name = self.newCtrlName()
		ctrl = Mininet.addHost(self, name, cls=InBandController, tcp_port=tcp_port)
		self.ctrls.append(ctrl)
		return ctrl

	# XXX TESTED
	# Create and Add a new LegacyL2Switch
	# save it in nodes_in_rn array
	def addSwitch(self, name=None):
		if not name:
			name = self.newSwitchName()
		switch = Mininet.addSwitch(self, name)
		self.nodes_in_rn.append(switch)
		return switch

	# XXX TESTED
	# Create and Add a new Customer Edge Router.
	# In our case it is a simple host
	def addCeRouter(self, name=None):
		if not name:
			name = self.newCeName()
		ce_router = Mininet.addHost(self, name, cls=IPHost)
		self.ce_routers.append(ce_router)
		return ce_router

	def addCoexistenceMechanism(self, coex_type, coex_data):

		if coex_type is None:
			error("ERROR Coex Type is None\n")
			sys.exit(-2)

		if coex_data is None:
			error("ERROR Coex Data is None\n")
			sys.exit(-2)

		self.coex['coex_type']=coex_type
		self.coex['coex_data']=coex_data

	# XXX TESTED
	# Add Link to MininetOSHI
	def addLink(self, lhs, rhs, properties):
		info("*** Connect %s to %s\n" %(lhs.name, rhs.name))
		link = Mininet.addLink(self, lhs, rhs)

		data_lhs = { 'intfname':link.intf1.name, 'ip':properties.ipLHS, 'ingrtype':properties.ingr.type, 'ingrdata':properties.ingr.data, 'net':{ 'net':properties.net.net, 'netbit':properties.net.netbit, 'cost':properties.net.costLHS, 'hello':properties.net.helloLHS, 'area':properties.net.area}}
		data_rhs = { 'intfname':link.intf2.name, 'ip':properties.ipRHS, 'ingrtype':properties.ingr.type, 'ingrdata':properties.ingr.data, 'net':{ 'net':properties.net.net, 'netbit':properties.net.netbit, 'cost':properties.net.costRHS, 'hello':properties.net.helloRHS, 'area':properties.net.area}}

		if properties.ipLHS: 
			lhs.setIP(ip=properties.ipLHS, intf=link.intf1)
		if properties.ipRHS:
			rhs.setIP(ip=properties.ipRHS, intf=link.intf2)

		if type(lhs) is InBandController:
			lhs.ip = properties.ipLHS
			lhs.port = 6633 
		if type(rhs) is InBandController:
			rhs.ip = properties.ipRHS
			rhs.port = 6633 

		self.node_to_data[lhs.name].append(data_lhs)
		self.node_to_data[rhs.name].append(data_rhs)
		if properties.ingr.type != None:
			self.node_to_node[lhs.name]=rhs.name
			self.node_to_node[rhs.name]=lhs.name
		self.node_to_default_via[lhs.name]= "%s#%s" %(properties.ipRHS, link.intf1.name)
		self.node_to_default_via[rhs.name]= "%s#%s" %(properties.ipLHS, link.intf2.name)
		return link

	def addVLL(self, lhs_cer, rhs_cer, properties):
		info("*** Connect %s to %s through Vll\n" %(lhs_cer.name, rhs_cer.name))		

		lhs_aos = self.node_to_node[lhs_cer.name]
		rhs_aos = self.node_to_node[rhs_cer.name]

		lhs_aos = self.getNodeByName(lhs_aos)
		rhs_aos = self.getNodeByName(rhs_aos)

		if type(lhs_cer) is not IPHost or type(rhs_cer) is not IPHost or type(lhs_aos) is not OSHI or type(rhs_aos) is not OSHI:
			error("ERROR cannot provide VLL among %s and %s through %s and %s" %(lhs_cer.name, rhs_cer.name, lhs_aos.name, rhs_aos.name))
			sys.exit(-2)

		self.checkVllfeasibility(lhs_cer, rhs_cer)

		link1 = Mininet.addLink(self, lhs_cer, lhs_aos)

		data_lhs_cer = { 'intfname':link1.intf1.name, 'ip':properties.ipLHS, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':properties.net, 
		'netbit':properties.netbit, 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
		data_lhs_aos = { 'intfname':link1.intf2.name, 'ip':'0.0.0.0/32', 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':'0.0.0.0', 
		'netbit':32, 'cost':1, 'hello':1, 'area':'0.0.0.0'}}

		if properties.ipLHS: 
			lhs_cer.setIP(ip=properties.ipLHS, intf=link1.intf1)

		self.node_to_data[lhs_cer.name].append(data_lhs_cer)
		self.node_to_data[lhs_aos.name].append(data_lhs_aos)

		link2 = Mininet.addLink(self, rhs_cer, rhs_aos)

		data_rhs_cer = { 'intfname':link2.intf1.name, 'ip':properties.ipRHS, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':properties.net, 
		'netbit':properties.netbit, 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
		data_rhs_aos = { 'intfname':link2.intf2.name, 'ip':'0.0.0.0/32', 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':'0.0.0.0', 
		'netbit':32, 'cost':1, 'hello':1, 'area':'0.0.0.0'}}

		if properties.ipRHS:
			rhs_cer.setIP(ip=properties.ipRHS, intf=link2.intf1)

  		self.node_to_data[rhs_cer.name].append(data_rhs_cer)
		self.node_to_data[rhs_aos.name].append(data_rhs_aos)	

		self.addLineToCFG(lhs_aos.dpid, link1.intf2.name, rhs_aos.dpid, link2.intf2.name)

		return (link1, link2)

	def addLineToCFG(self, lhs_dpid, lhs_intf, rhs_dpid, rhs_intf):
		lhs_dpid = ':'.join(s.encode('hex') for s in lhs_dpid.decode('hex'))
		rhs_dpid = ':'.join(s.encode('hex') for s in rhs_dpid.decode('hex'))
		self.vllcfg.write(("%s|%s|%s|%s|0|0|\n" %(lhs_dpid, rhs_dpid, lhs_intf, rhs_intf)))

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
		info( '\n' )
		info( '*** Starting %s pe oshis\n' % len(self.pe_oshis) )
		for pe_oshi in self.pe_oshis:
			pe_oshi.start(self.ctrls, self.node_to_data[pe_oshi.name],  self.coex)
		info( '\n' )
		info( '*** Starting %s in band controllers\n' % len(self.ctrls) )
		for controller in self.ctrls:
			controller.start(self.node_to_default_via[controller.name])
		info( '\n' )
		info( '*** Starting %s ce routers\n' % len(self.ce_routers) )
		for ce_router in self.ce_routers:
			ce_router.start(self.node_to_default_via[ce_router.name])
		info( '\n' )
		info( '*** Starting %s switches\n' % len( self.switches ) )
		for switch in self.switches:
			info( switch.name + ' ')
			switch.start( [] )
		info( '\n' )

		self.vllcfg.close()

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

		info("*** Restart Avahi and Open vSwitch\n")	
		root.cmd('start avahi-daemon') 
		root.cmd('/etc/init.d/openvswitchd start') 

		info('*** Unmounting host bind mounts\n')
		unmountAll()

	def stop(self):

		if self.terms:
		    info( '*** Stopping %i terms\n' % len( self.terms ) )
		    self.stopXterms()
		info( '*** Stopping %i switches\n' % len( self.switches ) )
		for switch in self.switches:
		    info( switch.name + ' ' )
		    switch.stop()
		info( '\n' )
		info( '*** Stopping %i hosts\n' % len( self.hosts ) )
		for host in self.hosts:
		    info( host.name + ' ' )
		    host.terminate()
		
		info( '\n' )
		self.cleanEnvironment()

		info( '*** Done\n' )

	def checkVllfeasibility(self, lhs, rhs):
		if lhs not in self.ce_routers or rhs not in self.ce_routers:
			error("Error misconfiguration Virtual Leased Line\n")
			error("Error cannot connect %s to %s\n" % (lhs, rhs))
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

	def newSwitchName(self):
		index = str(len(self.switches) + 1)
		name = "swi%s" % index
		return name

	def newCeName(self):
		index = str(len(self.ce_routers) + 1)
		name = "cer%s" % index
		return name


