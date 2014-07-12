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
from collections import defaultdict

from mininet.net import Mininet
from mininet.node import RemoteController, Node
from mininet.log import lg, info
from nodes import OSHI, Router, LegacyL2Switch, IPHost
from utility import fixIntf


# TODO
# call fixintf after the start


class MininetOSHI(Mininet):

	# XXX TESTED
	def __init__(self, verbose=False):
		Mininet.__init__(self, switch=LegacyL2Switch, controller=RemoteController, build=False)
		self.cr_oshis = []
		self.pe_oshis = []
		self.ce_routers = []
		self.ctrls = []
		self.nodes_in_rn = []
		self.node_to_data = defaultdict(list)
		self.node_to_node = {}
		self.node_to_default_via = {}
		self.verbose = verbose
		lg.setLogLevel('info')
		
	# XXX TESTED
	# Create and Add a new OSHI
	def addOSHI(self, params, name=None):
		loopback = params.loopback
		if not loopback:
			print "ERROR loopback not provided"
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
		ctrl = Mininet.addHost(self, name, cls=IPHost)
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

	# XXX TESTED
	# Add Link to MininetOSHI
	def addLink(self, lhs, rhs, properties):
		info("*** Connect %s to %s\n" %(lhs.name, rhs.name))
		link = Mininet.addLink(self, lhs, rhs)
		data_lhs = { 'intfname':link.intf1.name, 'ip':properties.ipLHS, 'ingrtype':properties.ingr.type, 'ingrdata':properties.ingr.data}
		data_rhs = { 'intfname':link.intf2.name, 'ip':properties.ipRHS, 'ingrtype':properties.ingr.type, 'ingrdata':properties.ingr.data}
		if properties.ipLHS: 
			lhs.setIP(ip=properties.ipLHS, intf=link.intf1)
		if properties.ipRHS:
			rhs.setIP(ip=properties.ipRHS, intf=link.intf2)
		if type(lhs) is RemoteController:
			lhs.ip = properties.ipLHS
			lhs.port = 6633 
		if type(rhs) is RemoteController:
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

	def configHosts( self ):
		"Configure a set of hosts."
		print "QUI"
		for host in self.hosts:
			info( host.name + ' ' )
			host.cmd( 'ifconfig lo up' )
		info( '\n' )

	def start(self):

		for node in self.nodes_in_rn:
			fixIntf(node)
		root = Node( 'root', inNamespace=False )
		root.cmd('service network-manager restart')
		info("*** Restarting Network Manager\n")
		time.sleep(10)



		if not self.built:
			self.build()
		info( '*** Starting %s cr oshis\n' % len(self.cr_oshis) )
		for cr_oshi in self.cr_oshis:
			cr_oshi.start()
		info( '\n' )
		info( '*** Starting %s pe oshis\n' % len(self.pe_oshis) )
		for pe_oshi in self.pe_oshis:
			pe_oshi.start()
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


