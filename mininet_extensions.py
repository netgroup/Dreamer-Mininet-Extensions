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
#/

import sys

from mininet.net import Mininet
from mininet.node import RemoteController
from dreamer_nodes import OSHI, Router, LegacyL2Switch

def MininetOSHI(Mininet):

	def __init__(self, verbose=False):
		Mininet.__init__(self, switch=LegacyL2Switch, controller=RemoteController, build=False)
		self.ctrls = []
		self.cr_oshis = []
		self.pe_oshis = []
		
	def addOSHI(self, name, params):
		if verbose:
			print "addOSHI"
		loopback = params.get("loopback", None)
		if not loopback:
			print "ERROR loopback not provided"
			sys.exit(-2)
		oshi = self.addHost(name, cls=OSHI, loopback)
		return oshi

	def addCrOSHI(self, name=None, params):
		if verbose:
			print "addCrOSHI"
		if not name:
			name = self.newCrName()
		oshi = self.addOSHI(name, params)
		self.cr_oshis.append(oshi)

	def addPeOSHI(self, name=None, params):
		if verbose:
			print "addPeOSHI"
		if not name:
			name = self.newPeName()
		oshi = self.addOSHI(name, params)
		self.pe_oshis.append(oshi)

	def addController(self, name=None, ip, tcp_port=6633)
		if verbose:
			print "addCTRL"
		if not name:
			name = self.newCtrlName()
		ctrl = RemoteController(name, ip=ip, port=tcp_port)
		self.ctrls.append(ctrl)
		
	def newCrName(self):
		index = str(len(self.cr_oshis) + 1)
		name = "cro%s" % index
		return name	

	def newPeName(self):
		index = str(len(self.pe_oshis) + 1)
		name = "peo%s" % index
		return name	

	def newCtrlName(self):
		index = str(len(self.ctrls) + 1)
		name = "ctr%s" % index
		return name


