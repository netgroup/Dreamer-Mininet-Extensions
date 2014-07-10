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

from mininet.node import Host, OVSKernelSwitch

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
	    #print mountPoint
            errFail( 'mount -B %s %s' %
                           ( privateDir, mountPoint) )

    def mountDirs( self, dirs ):
        "Mount a list of directories"
        for dir_ in dirs:
            mountpoint = self.root + dir_
	    #print mountpoint
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

# Class that inherits from PrivateHost and extends it with 
# OSHI functionalities
class OSHI(PrivateHost):

	dpidLen = 16

	def __init__(self, name, loopback, *args, **kwargs ):
		dirs = ['/var/log/', '/var/log/quagga', '/var/run', '/var/run/quagga', '/var/run/openvswitch']
		PrivateHost.__init__(self, name, privateDirs=dirs, *args, **kwargs )
		self.loopback = loopback
		self.dpid = self.loopbackDpid(self.loopback, "00000000")
	
	def loopbackDpid(self, loopback, extrainfo):
        splitted_loopback = loopback.split('.')
        hexloopback = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, splitted_loopback))
        dpid = "%s%s" %(extrainfo, hexloopback)
        if len(dpid)>16:
            print "Unable To Derive DPID From Loopback and ExtraInfo";
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

# Class that inherits from PrivateHost and extends it with 
# Router functionalities
class Router(PrivateHost):

	def __init__(self, name, loopback, *args, **kwargs ):
		dirs = ['/var/log/', '/var/log/quagga', '/var/run', '/var/run/quagga']
		PrivateHost.__init__(self, name, privateDirs=dirs, *args, **kwargs )
		self.loopback = loopback

# Class that inherits from OVSKernelSwitch and acts
# like a LegacyL2Switch
class LegacyL2Switch(OVSKernelSwitch):

	def __init__(self, name, **params ):	
		failMode='standalone'
		datapath='kernel'
		OVSKernelSwitch.__init__(self, name, failMode, datapath, **params)






