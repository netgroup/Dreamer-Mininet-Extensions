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

from os.path import realpath
from mininet.util import errFail, errRun
from mininet.log import debug, info

from netaddr import *
from ipaddress import *
import sys
import re


class LoopbackAllocator(object):

	def __init__(self):	
		print "*** Calculating Available Loopback Addresses"
		self.loopbacknet = (IPv4Network(("172.16.0.0/255.240.0.0").decode('unicode-escape')))
		self.hosts = list(self.loopbacknet.hosts())
	
	def next_hostAddress(self):
		host = self.hosts.pop(0)
		return host.__str__()
	

class NetAllocator(object):

	ipnet = "10.0.0.0/255.0.0.0".decode('unicode-escape')
	
	def __init__(self):		
		print "*** Calculating Available IP Networks"
		self.ipnet = (IPv4Network(self.ipnet))
		self.iternets = self.ipnet.subnets(new_prefix=24)
		self.iternets24 = self.iternets.next().subnets(new_prefix=24)
	
	def next_netAddress(self):
		DONE = False
		while DONE == False :	
			try:						
				try:
					net = self.iternets24.next()
					DONE = True
				except StopIteration:
					self.iternets24 = self.iternets.next().subnets(new_prefix=24)
			except StopIteration:
				print "Error IP Net SoldOut"
				sys.exit(-2)
		return net


class PropertiesGenerator(object):

	allowed_name = ["cro","peo","ctr","swi","cer"]

	def __init__(self, verbose):
		self.verbose = verbose
		self.netAllocator = NetAllocator()
		self.loopbackAllocator = LoopbackAllocator()

	def getLinksProperties(self, links):
		output = []
		net = self.netAllocator.next_netAddress()
		if self.verbose == True:		
			print net
		hosts = list(net.hosts())	
		if self.verbose == True:			
			print hosts
		for link in links:
			if self.verbose == True:		
				print "(%s,%s)" % (link[0], link[1])
			lhs = link[0][:3]
			rhs = link[1][:3]
			
			a = re.search(r'cro\d+$', link[0])
			b = re.search(r'peo\d+$', link[0])
			c = re.search(r'ctr\d+$', link[0])
			d = re.search(r'swi\d+$', link[0])
			e = re.search(r'cer\d+$', link[0])
			
			if a is None and b is None and c is None and d is None and e is None:
				print "ERROR Not Allowed Name (%s,%s)" %(link[0],link[1])
				sys.exit(-2)

			f = re.search(r'cro\d+$', link[1])
			g = re.search(r'peo\d+$', link[1])
			h = re.search(r'ctr\d+$', link[1])
			i = re.search(r'swi\d+$', link[1])
			l = re.search(r'cer\d+$', link[1])
			
			if f is None and g is None and h is None and i is None and l is None:
				print "ERROR Not Allowed Name (%s,%s)" %(link[0],link[1])
				sys.exit(-2)
				
			ipLHS = None
			ipRHS = None
			ingrType = None
			ingrData = None
			OSPFnet=OSPFNetwork("0.0.0.0/32")

			if d is None:
				ipLHS = hosts.pop(0).__str__()
			if i is None:
				ipRHS = hosts.pop(0).__str__()
			if (b is not None or g is not None) and (e is not None or l is not None):
				ingrType = "INGRB"
				ingrData = None
			if ipLHS is not None or ipRHS is not None:
				OSPFnet = OSPFNetwork(net.__str__())

			linkproperties = LinkProperties(ipLHS, ipRHS, ingrType, ingrData, OSPFnet)
			if self.verbose == True:			
				print linkproperties
			output.append(linkproperties)
		return output

	def getVLLsProperties(self, vll):
		net = self.netAllocator.next_netAddress()
		if self.verbose == True:		
			print net
		hosts = list(net.hosts())				
		if self.verbose == True:
			print hosts		
			print "(%s,%s)" % (vll[0], vll[1])
		
		e = re.search(r'cer\d+$', vll[0])
			
		if e is None:
			print "Error Both Hand Side != from Customer Edge Router (%s,%s)" %(vll[0],vll[1])
			sys.exit(-2)

		e = re.search(r'cer\d+$', vll[1])
			
		if e is None:
			print "Error Both Hand Side != from Customer Edge Router (%s,%s)" %(vll[0],vll[1])
			sys.exit(-2)

		
		ipLHS = "%s" %(hosts.pop(0).__str__())
		ipRHS = "%s" %(hosts.pop(0).__str__())
		
		vllproperties = VLLProperties(ipLHS, ipRHS, net.__str__())
		if self.verbose == True:			
			print vllproperties
		return vllproperties
		
	def getVerticesProperties(self, nodes):
		output = []
		for node in nodes:
			if self.verbose == True:
				print node
			host = None

			c = re.search(r'ctr\d+$', node)
			d = re.search(r'swi\d+$', node)
			e = re.search(r'cer\d+$', node)
			
			if c is None and d is None and e is None:
				host = self.loopbackAllocator.next_hostAddress()
				
			vertexproperties = VertexProperties(host)
			if self.verbose == True:
				print vertexproperties
			output.append(vertexproperties)
		return output

class OSPFNetwork: 
	
	def __init__(self, net, costLHS="1", costRHS="1", helloLHS="5", helloRHS="5", area="0.0.0.0"):
		temp = net.split("/")
		self.net = temp[0]
		self.netbit = temp[1]
		self.costLHS = costLHS
		self.costRHS = costRHS
		self.helloLHS = helloLHS
		self.helloRHS = helloRHS
		self.area = area

	def __str__(self):
		return "{'net':'%s', 'nebit': %s, 'costLHS':'%s', 'costRHS':'%s', 'helloLHS':'%s', 'helloRHS':'%s','area':'%s'}" %(self.net, self.netbit, self.costLHS, self.costRHS, self.helloLHS, self.helloRHS, self.area)


class LinkProperties(object):

	def __init__(self, ipLHS, ipRHS, ingrType, ingrData, net):
		self.ipLHS = ipLHS
		self.ipRHS = ipRHS
		self.ingr = IngressData(ingrType, ingrData)
		self.net = net

	def __str__(self):
		return "{'ipLHS':'%s', 'ipRHS':'%s', 'ingr':'%s', 'net':'%s'}" %(self.ipLHS, self.ipRHS, self.ingr, self.net)


class VLLProperties(object):

	def __init__(self, ipLHS, ipRHS, net):
		self.ipLHS = ipLHS
		self.ipRHS = ipRHS
		self.net = net		

	def __str__(self):
		return "{'ipLHS':'%s', 'ipRHS':'%s', 'net':'%s'}" %(self.ipLHS, self.ipRHS, self.net)

class VertexProperties(object):
	
	def __init__(self, loopback):
		self.loopback = loopback

	def __str__(self):
		return "{'loopback':'%s'}" %(self.loopback)

class IngressData(object):

	def __init__(self, ingrtype, ingrdata):
		self.type = ingrtype
		self.data = ingrdata
	
	def __str__(self):
		return "{'type':'%s', 'data':'%s'}" %(self.type, self.data)

# Utility functions for unmounting a tree
# Real path of OSHI's dir
MNRUNDIR = realpath( '/var/run/mn' )


# Take the mounted points of the root machine
def mountPoints():
    "Return list of mounted file systems"
    mtab, _err, _ret = errFail( 'cat /proc/mounts' )
    lines = mtab.split( '\n' )
    mounts = []
    for line in lines:
        if not line:
            continue
        fields = line.split( ' ')
        mount = fields[ 1 ]
        mounts.append( mount )
    return mounts

 
# Utility Function for unmount all the dirs
def unmountAll( rootdir=MNRUNDIR ):
    "Unmount all mounts under a directory tree"
    rootdir = realpath( rootdir )
    # Find all mounts below rootdir
    # This is subtle because /foo is not
    # a parent of /foot
    dirslash = rootdir + '/'
    mounts = [ m for m in mountPoints()
              if m == dir or m.find( dirslash ) == 0 ]
    # Unmount them from bottom to top
    mounts.sort( reverse=True )
    for mount in mounts:
        debug( 'Unmounting', mount, '\n' )
        _out, err, code = errRun( 'umount', mount )
        if code != 0:
            info( '*** Warning: failed to umount', mount, '\n' )
            info( err )

# Fix network manager problem
def fixIntf(host):
	for intf in host.nameToIntf:
		if 'lo' not in intf:
			fixNetworkManager(intf)	
	fixNetworkManager(host)    
	
# Add interface in /etc/network/interfaces
# in order to declare a manual management
def fixNetworkManager(intf):
	cfile = '/etc/network/interfaces'
  	line1 = 'iface %s inet manual\n' % intf
  	config = open( cfile ).read()
  	if ( line1 ) not in config:
		print '*** Adding', line1.strip(), 'to', cfile
		with open( cfile, 'a' ) as f:
	  		f.write( line1 )
	  	f.close();