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
# Utility functions.
#
# @author Pier Luigi Ventre <pl.ventre@gmail.com>
# @author Giuseppe Siracusano <a_siracusano@tin.it>
# @author Stefano Salsano <stefano.salsano@uniroma2.it>
#
#

from netaddr import *
from ipaddress import *

class VTEPAllocator(object):

	vtepnet = ("172.16.0.0/255.240.0.0").decode('unicode-escape')
	bit = 12

	def __init__(self, used):	
		print "*** Calculating Available VTEP Addresses"
		self.vtepnet = (IPv4Network(self.vtepnet))
		self.hosts = list(self.vtepnet.hosts())
		used = IPv4Network("%s/32" % used)
		
		done = False
		while not done:
			host = IPv4Network("%s/32" % self.hosts[0])
			if host.compare_networks(used) < 0:
				self.hosts.pop(0)
				continue
			done = True
	
	def next_hostAddress(self):
		host = self.hosts.pop(0)
		return host.__str__()

	def next_vtep(self):
		host = self.next_hostAddress()
		mac = self.IPtoMAC(host, '0000')
		return VTEP("%s/%s" %(host,self.bit), mac)
				

	def IPtoMAC(self, IP, extrainfo):
		splitted_IP = IP.split('.')
		hexIP = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, splitted_IP))
		MAC = "%s%s" %(extrainfo, hexIP)
		if len(MAC)>12:
			error("Unable To Derive MAC From IP and ExtraInfo\n")
			sys.exit(-1)
		return MAC

class VTEP(object):

	def __init__(self, IP, MAC):
		self.IP = IP
		self.MAC = MAC

	def __str__(self):
		return "{'ip':'%s', 'mac':'%s'}" %(self.IP, self.MAC)
