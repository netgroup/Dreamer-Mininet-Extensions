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

import sys
import shutil
import os
import re
from subprocess import Popen,PIPE

from mininet.node import Host, OVSKernelSwitch, Node
from mininet.util import errFail, quietRun
from mininet.log import info, error
from os.path import realpath

from utility import MNRUNDIR, unmountAll
from coexistence_mechanisms import *
from ingress_classifications import *


# Class that inherits from Host and extends it with 
# the private dirs functionalities
class PrivateHost( Host ):
    "Host with private directories"

    mnRunDir = MNRUNDIR

    def __init__(self, name, privateDirs, *args, **kwargs ):
        """privateDirs: list of private directories
        remounts: dirs to remount
        unmount: unmount dirs in cleanup? (True)
        Note: if unmount is False, you must call unmountAll()
        manually."""
        self.privateDirs = privateDirs
        self.remounts = findRemounts( fstypes=[ 'devpts' ] )
        self.unmount = False
        Host.__init__( self, name, *args, **kwargs )
        self.rundir = '%s/%s' % ( self.mnRunDir, name )
        self.root, self.private = None, None  # set in createBindMounts
        if self.privateDirs:
            self.privateDirs = [ realpath( d ) for d in self.privateDirs ]
            self.createBindMounts()
        # These should run in the namespace before we chroot,
        # in order to put the right entries in /etc/mtab
        # Eventually this will allow a local pid space
        # Now we chroot and cd to wherever we were before.
        pwd = self.cmd( 'pwd' ).strip()
        self.sendCmd( 'exec chroot', self.root, 'bash -ms mininet:'
        + self.name )
        self.waiting = False
        self.cmd( 'cd', pwd )
        # In order for many utilities to work,
        # we need to remount /proc and /sys
        self.cmd( 'mount /proc' )
        self.cmd( 'mount /sys' )

    def mountPrivateDirs( self ):
        "Create and bind mount private dirs"
        for dir_ in self.privateDirs:
            privateDir = self.private + dir_
            errFail( 'mkdir -p ' + privateDir )
            mountPoint = self.root + dir_
            errFail( 'mount -B %s %s' %
                           ( privateDir, mountPoint) )

    def mountDirs( self, dirs ):
        "Mount a list of directories"
        for dir_ in dirs:
            mountpoint = self.root + dir_
            errFail( 'mount -B %s %s' %
                     ( dir_, mountpoint ) )

    @classmethod
    def findRemounts( cls, fstypes=None ):
        """Identify mount points in /proc/mounts to remount
           fstypes: file system types to match"""
        if fstypes is None:
            fstypes = [ 'nfs' ]
        dirs = quietRun( 'cat /proc/mounts' ).strip().split( '\n' )
        remounts = []
        for dir_ in dirs:
            line = dir_.split()
            mountpoint, fstype = line[ 1 ], line[ 2 ]
            # Don't re-remount directories!!!
            if mountpoint.find( cls.mnRunDir ) == 0:
                continue
            if fstype in fstypes:
                remounts.append( mountpoint )
        return remounts

    def createBindMounts( self ):
        """Create a chroot directory structure,
           with self.privateDirs as private dirs"""
        errFail( 'mkdir -p '+ self.rundir )
        unmountAll( self.rundir )
        # Create /root and /private directories
        self.root = self.rundir + '/root'
        self.private = self.rundir + '/private'
        errFail( 'mkdir -p ' + self.root )
        errFail( 'mkdir -p ' + self.private )
        # Recursively mount / in private doort
        # note we'll remount /sys and /proc later
        errFail( 'mount -B / ' + self.root )
        self.mountDirs( self.remounts )
        self.mountPrivateDirs()

    def unmountBindMounts( self ):
        "Unmount all of our bind mounts"
        unmountAll( self.rundir )

    def popen( self, *args, **kwargs ):
        "Popen with chroot support"
        chroot = kwargs.pop( 'chroot', True )
        mncmd = kwargs.get( 'mncmd',
                           [ 'mnexec', '-a', str( self.pid ) ] )
        if chroot:
            mncmd = [ 'chroot', self.root ] + mncmd
            kwargs[ 'mncmd' ] = mncmd
        return Host.popen( self, *args, **kwargs )

    def cleanup( self ):
        """Clean up, then unmount bind mounts
           unmount: actually unmount bind mounts?"""
        # Wait for process to actually terminate
        self.shell.wait()
        Host.cleanup( self )
        if self.unmount:
            self.unmountBindMounts()
            errFail( 'rmdir ' + self.root )

# Convenience aliases
findRemounts = PrivateHost.findRemounts

# Simple Host with defaultVia
class IPHost(Host):

	def __init__(self, name, *args, **kwargs ):
		Host.__init__( self, name, *args, **kwargs )
	
	def start(self, defaultVia):
		info("%s " % self.name)
		data = defaultVia.split("#")
		gw = data[0].split("/")[0]
		intf = data[1]
		self.cmd( 'ip route del default' )
		self.cmd( 'route add default gw %s %s' %(gw, intf) )

# Simple Host with IP and TCP port data
class InBandController(IPHost):

	def __init__(self, name, tcp_port, *args, **kwargs ):
		IPHost.__init__( self, name, *args, **kwargs )
		self.ip = None
		self.tcp_port = tcp_port
	
# Class that inherits from PrivateHost and extends it with 
# OSHI functionalities
class OSHI(PrivateHost):

	# XXX
	zebra_exec = '/usr/lib/quagga/zebra'
	ospfd_exec = '/usr/lib/quagga/ospfd'

	checked = False


	baseDIR = "/tmp"
	dpidLen = 16

	OF_V = None #"OpenFlow13"
	
	
	def __init__(self, name, loopback, *args, **kwargs ):
		dirs = ['/var/log/', '/var/log/quagga', '/var/run', '/var/run/quagga', '/var/run/openvswitch']
		PrivateHost.__init__(self, name, privateDirs=dirs, *args, **kwargs )
		self.loopback = loopback
		self.dpid = self.loopbackDpid(self.loopback, "00000000")
		self.path_ovs = "%s/%s/ovs" %(self.baseDIR, self.name)
		self.path_quagga =  "%s/%s/quagga" %(self.baseDIR, self.name)
		if OSHI.checked == False:
			self.checkQuagga()
			OSHI.checked = True
	
	
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

	def checkQuagga(self):
		root = Node( 'root', inNamespace=False )
		zebra = root.cmd('ls %s 2> /dev/null | wc -l' % self.zebra_exec)
		if '1' not in zebra:
			error( 'Cannot find required executable zebra\nPlease make sure that Zebra is properly installed in ' + self.zebraPath + '\n'
				   'Otherwise change zebraPath variable according to your configuration\n' )
			exit( 1 )
		ospfd = root.cmd('ls %s 2> /dev/null | wc -l' % self.ospfd_exec)
		if '1' not in ospfd:
			error( 'Cannot find required executable ospfd\nPlease make sure that OSPFD is properly installed in ' + self.ospfdPath + '\n'
				   'Otherwise change ospfdPath variable according to your configuration\n' )
			exit( 1 )

	def start( self, controllers = [], intfs_to_data = [],  coex={}):
		info("%s " % self.name)

		if len(controllers) == 0:
			info("WARNING %s Controllers\n" % len(controllers))

		if len(intfs_to_data) == 0:
			error("ERROR configuration is not possibile for %s\n" % self.name)
			sys.exit(-2)

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

		net_added = []

		for intf in intfs_to_data:

			net = intf['net']['net']
			if net not in net_added and net != '0.0.0.0':
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
			self.cmd('echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter' % eth_name)
		
		self.cmd("chmod -R 777 /var/log/quagga")
		self.cmd("chmod -R 777 /var/run/quagga")	
		self.cmd("chmod -R 777 %s" %(self.path_quagga))	

		self.cmd("%s -f %s/zebra.conf -A 127.0.0.1 &" %(self.zebra_exec, self.path_quagga))
		self.cmd("%s -f %s/ospfd.conf -A 127.0.0.1 &" %(self.ospfd_exec, self.path_quagga))

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
		

# Class that inherits from PrivateHost and extends it with 
# Router functionalities
class Router(PrivateHost):

	def __init__(self, name, loopback, *args, **kwargs ):
		dirs = ['/var/log/', '/var/log/quagga', '/var/run', '/var/run/quagga']
		PrivateHost.__init__(self, name, privateDirs=dirs, *args, **kwargs )
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
