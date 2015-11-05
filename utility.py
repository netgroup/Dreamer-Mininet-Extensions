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

#management networks start from 10.255.255.0/24 and go backward 10.255.254.0/24, ..253.0/24, ... 
MAX_NUM_MANAGEMENT_NETWORKS = 1023


class LoopbackAllocator(object):

	loopbacknet = ("172.16.0.0/255.240.0.0").decode('unicode-escape')
	bit = 32

	def __init__(self):	
		print "*** Calculating Available Loopback Addresses"
		self.loopbacknet = (IPv4Network(self.loopbacknet))
		self.hosts = list(self.loopbacknet.hosts())
	
	def next_hostAddress(self):
		host = self.hosts.pop(0)
		return host.__str__()
	

class NetAllocator(object):

	ipnet = "10.0.0.0/255.0.0.0".decode('unicode-escape')
	bit = 24
	
	def __init__(self):		
		print "*** Calculating Available IP Networks"
		self.ipnet = (IPv4Network(self.ipnet))
		self.iternets = self.ipnet.subnets(new_prefix=self.bit)
		self.iternets24 = self.iternets.next().subnets(new_prefix=self.bit)
	
	def next_netAddress(self):
		DONE = False
		while DONE == False :	
			try:						
				try:
					net = self.iternets24.next()
					DONE = True
				except StopIteration:
					self.iternets24 = self.iternets.next().subnets(new_prefix=self.bit)
			except StopIteration:
				print "Error IP Net SoldOut"
				sys.exit(-2)
		return net

class MgtNetAllocator(object):

	bits = 24
	allocated = 0

	def __init__(self):		
		print "*** doing nothing"
	
	def next_netAddress(self):
		if self.allocated == MAX_NUM_MANAGEMENT_NETWORKS:
			print "Error : Management IP Networks soldout"
			sys.exit(-2)

		(high_part, low_part) = divmod(self.allocated, 256)
		net3 = 255 - low_part
		net2 = 255 - high_part
		self.allocated = self.allocated + 1
		ipnet = ("10."+str(net2)+"."+str(net3)+".0/255.255.255.0").decode('unicode-escape')
		print ipnet
		return (IPv4Network(ipnet))



class VTEPAllocator(object):

	vtepnet = ("172.16.0.0/255.240.0.0").decode('unicode-escape')
	bit = 12

	def __init__(self):	
		print "*** Calculating Available VTEP Addresses"
		self.vtepnet = (IPv4Network(self.vtepnet))
		self.hosts = list(self.vtepnet.hosts())
	
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

class PropertiesGenerator(object):

	allowed_name = ["cro","peo","ctr","swi","cer","mgm"]

	def __init__(self, verbose):
		self.verbose = verbose
		self.netAllocator = NetAllocator()
		self.loopbackAllocator = LoopbackAllocator()
		self.mgtNetAllocator = MgtNetAllocator()

	def getLinksProperties(self, links):

		# links can be a list only if a set of links belonging to the same switched network is given
		# the case of multiple link in the same switched network has not been tested after the recent changes
		
		output = []
		
		# if we are allocating addresses for a set of links belonging to the same switched network
		# we will allocate the network address only once
		net_allocated = False 
		hosts = []
		for link in links:
			if self.verbose == True:		
				print "(%s,%s)" % (link[0], link[1])
			lhs = link[0][:3]
			rhs = link[1][:3]

			
			if link[1][:3] == "mgm":
				#if we are linking a node with the management node (mgm is the rhs - right hand side)
				#we allocate a management address
				net = self.mgtNetAllocator.next_netAddress()
				if self.verbose == True:		
					print net
				hosts = list(net.hosts())	
				if self.verbose == True:			
					print hosts
			else:
				if net_allocated == False:
					net_allocated = True
					net = self.netAllocator.next_netAddress()
					if self.verbose == True:		
						print net
					hosts = list(net.hosts())	
					if self.verbose == True:			
						print hosts

			a = re.search(r'cro\d+$', link[0])
			b = re.search(r'peo\d+$', link[0])
			c = re.search(r'ctr\d+$', link[0])
			d = re.search(r'swi\d+$', link[0])
			e = re.search(r'cer\d+$', link[0])
			f = re.search(r'mgm\d+$', link[0])
			
			if a is None and b is None and c is None and d is None and e is None and f is None:
				print "ERROR Not Allowed Name (%s,%s)" %(link[0],link[1])
				sys.exit(-2)

			g = re.search(r'cro\d+$', link[1])
			h = re.search(r'peo\d+$', link[1])
			i = re.search(r'ctr\d+$', link[1])
			l = re.search(r'swi\d+$', link[1])
			m = re.search(r'cer\d+$', link[1])
			n = re.search(r'mgm\d+$', link[1])
			
			if g is None and h is None and i is None and l is None and m is None and n is None:
				print "ERROR Not Allowed Name (%s,%s)" %(link[0],link[1])
				sys.exit(-2)
				
			ipLHS = None
			ipRHS = None
			ingrType = None
			ingrData = None
			OSPFnet=OSPFNetwork("0.0.0.0/32")

			if d is None:
				ipLHS = hosts.pop(0).__str__()
			if l is None:
				ipRHS = hosts.pop(0).__str__()
			if ((b is not None or h is not None) and (e is not None or m is not None)) or ((a is not None or g is not None) and (c is not None or i is not None)) or ((a is not None or g is not None) and (f is not None or n is not None)):
				ingrType = "INGRB"
				ingrData = None
			if ipLHS is not None or ipRHS is not None:
				OSPFnet = OSPFNetwork(net.__str__())

			linkproperties = LinkProperties(ipLHS, ipRHS, ingrType, ingrData, OSPFnet)
			if self.verbose == True:			
				print linkproperties
			output.append(linkproperties)
		return output

	def getVLLProperties(self, vll):
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
			f = re.search(r'mgm\d+$', node)
			
			if c is None and d is None and e is None and f is None:
				host = self.loopbackAllocator.next_hostAddress()
				
			vertexproperties = VertexProperties(host)
			if self.verbose == True:
				print vertexproperties
			output.append(vertexproperties)
		return output

	def getVSProperties(self, endnodes):
		net = self.netAllocator.next_netAddress()
		if self.verbose == True:		
			print net
		hosts = list(net.hosts())				
		if self.verbose == True:
			print hosts		
			print "endnodes: %s" % ' '.join(endnode.name for endnode in endnodes)

		ips = []

		for endnode in endnodes:		
			e = re.search(r'cer\d+$', endnode)
			
			if e is None:
				print "All sides must be Customer Edge Router %s" % endnode
				sys.exit(-2)
		
			ips.append("%s" %(hosts.pop(0).__str__()))

		vsproperties = VSProperties(ips, net.__str__())
		if self.verbose == True:			
			print vsproperties
		return vsproperties

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

class VSProperties(object):

	def __init__(self, ips, net):
		self.ips = ips
		self.net = net
		self.next = 0

	def next_hostAddress(self):
		host = self.ips[self.next]
		self.next = self.next + 1
		return host		

	def __str__(self):
		return "{'ips':'%s', 'net':'%s'}" %(self.ips, self.net)

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


if __name__ == '__main__':
	first = IPv4Network(u"0.0.0.0/32")
	second = IPv4Network(u"0.0.1.0/32")
	
	print first.compare_networks(second)

		
