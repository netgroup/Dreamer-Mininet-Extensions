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
import os
import signal
import shutil
from collections import defaultdict
from ipaddress import IPv4Network

from mininet.net import Mininet
from mininet.node import Node
from mininet.log import lg, info, error
from mininet.util import quietRun
from mininet.term import cleanUpScreens, makeTerms

from nodes import OSHI, Router, LegacyL2Switch, IPHost, InBandController, VSF, VS
from utility import fixIntf, unmountAll, VTEPAllocator, VTEP
from coexistence_mechanisms import *

#choose a log type: INFO uses info() to output on system logger
logtype = "INFO"
#logtype = "PRINT"

def mylog(mystring):
    if logtype == "PRINT":
        print mystring
    if logtype == "INFO":
        info(mystring)

"""
Example of overall_info json file
{
  "peo6": {
    "mgt_IP": "10.255.252.1",
    "loopback_IP": "172.16.0.4",
    "dpid": "00000000AC100004",
    "interfaces": {
      "peo6-eth1": {
        "ip": "10.0.2.1/24",
        "mac": "02:9e:fb:26:73:c4",
        "peers": [
          "cro3"
        ]
      },
      "peo6-eth0": {
        "ip": "10.255.252.1/24",
        "mac": "8a:67:81:17:44:8e",
        "peers": [
          "mgm1"
        ]
      }
    }
  }
}
"""


class MininetOSHI(Mininet):
    """Parses a T3D topology (for the OSHI model) and generates the Mininet deployment"""

    temp_cfg = "temp.cfg"
    VS_OPTION = '-o'
    RYU_PATH = '/home/user/workspace/dreamer-ryu/ryu/app/'
    PROJECT_PATH = '/home/user/workspace/Dreamer-Mininet-Extensions/'
    #OVERALL_INFO_FILE = '/tmp/overall_info.json'

    
    def __init__(self, verbose=False):

        self.checkPATHs()

        Mininet.__init__(self, build=False)

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

        self.vlls = []

        self.node_to_pw_data = defaultdict(list)
        self.pws = []

        self.cer_to_customer = {}
        self.customer_to_vtepallocator = {}

        self.vsfs = []
        self.pe_cer_to_vsf = {}

        self.is_vs = False
        self.vss = []
        self.vss_data = []
        self.id_peo_to_vs = {}
        self.last_ipnet = IPv4Network(u'0.0.0.0/24')

        self.id_to_node = {}
        self.ip_to_mac = {}

        self.overall_info = {}
        
        self.mgmt = None

        root = Node( 'root', inNamespace=False )
        root.cmd('/etc/init.d/network-manager stop')
        mylog("*** Stop Network Manager\n")

        self.cluster_to_ctrl = defaultdict(list)
        self.cluster_to_nodes = defaultdict(list)
        self.nodes_to_cluster = {}

    def checkPATHs(self):

        if MininetOSHI.RYU_PATH == "":
            error("Error Set RYU_PATH in mininet_extensions.py\n")
            sys.exit(-2)

        if not os.path.exists(MininetOSHI.RYU_PATH):
            error("Error : RYU_PATH in mininet_extensions.py points to a non existing folder\n")
            sys.exit(-2)

        if MininetOSHI.PROJECT_PATH == "":
            error("Error Set PROJECT_PATH in mininet_extensions.py\n")
            sys.exit(-2)

        if not os.path.exists(MininetOSHI.PROJECT_PATH):
            error("Error : PROJECT_PATH in mininet_extensions.py points to a non existing folder\n")
            sys.exit(-2)


    def manageOSHIproperties(self, properties, ctrl, name):
        """Manages OSHI properties

        ctrl : controller
        name : name of the node
        """
        exist = properties.get("domain-oshi", None)
        if not exist:
            error("Error domain-oshi properties cannot be found\n")
            sys.exit(-2)
        oshi_properties = properties["domain-oshi"]
        exist = oshi_properties.get("layer-Control", None)
        if not exist:
            error("Error layer-Control properties cannot be found\n")
            sys.exit(-2)
        control_properties = oshi_properties["layer-Control"]
        cluster_id = control_properties["cluster_id"]
        if cluster_id == "":
            cluster_id = "default"
        if ctrl:
            self.cluster_to_ctrl[cluster_id].append(name)
        else:
            self.cluster_to_nodes[cluster_id].append(name)
            self.nodes_to_cluster[name] = cluster_id

            
    def getNodeById(self, id_):
        return self.id_to_node[id_]

    
    def addOSHI(self, nodeproperties, ctrl, CR, name=None):
        """Creates and Adds a new OSHI node

        ctrl : controller
        CR : True if CR, false otherwise

        It updates self.overall_info
        """

        loopback = nodeproperties['loopback']
        if not loopback:
            error("ERROR loopback not provided\n")
            sys.exit(-2)
        self.manageOSHIproperties(nodeproperties, ctrl, name)
        oshi = Mininet.addHost(self, name, cls=OSHI, loopback=loopback, CR=CR, cluster_id=self.nodes_to_cluster[name])
        self.id_to_node[oshi.dpid]=oshi

        # adding information in overall_info
        self.overall_info[name]={}
        self.overall_info[name]['dpid']=oshi.dpid
        self.overall_info[name]['loopback_IP']=loopback
        self.overall_info[name]['interfaces']={}
        
        return oshi

    def addCrOSHI(self, nodeproperties, name=None):
        """Creates and Adds a new OSHI CR (Core Router)"""

        if not name:
            name = self.newCrName()
        oshi = self.addOSHI(nodeproperties, False, True, name)
        self.cr_oshis.append(oshi)
        return oshi
        
    def addPeOSHI(self, nodeproperties, name=None):
        """ Creates and Adds a new OSHI PE (Provider Edge)"""
        if not name:
            name = self.newPeName()
        oshi = self.addOSHI(nodeproperties, False, False, name)
        self.pe_oshis.append(oshi)
        return oshi

    
    # Create and Add a new Remote Controller
    def addController(self, nodeproperties, name=None, ip="127.0.0.1" ,tcp_port=6633):
        """ Creates and Adds a Controller"""
        if not name:
            name = self.newCtrlName()
        tcp_port = int(nodeproperties['tcp_port'])
        self.manageOSHIproperties(nodeproperties, True, name)
        ctrl = Mininet.addHost(self, name, cls=InBandController, tcp_port=tcp_port)
        self.ctrls.append(ctrl)

        # adding information in overall_info
        self.overall_info[name]={}
        self.overall_info[name]['interfaces']={}

        return ctrl

    def addCeRouter(self, cid, nodeproperties, name=None):
        """ Creates and Adds a new OSHI CER (Customer Edge Router)

        A CER is like a simple host for us
        """

        if not name:
            name = self.newCeName()
            
        ce_router = Mininet.addHost(self, name, cls=IPHost)
        self.ce_routers.append(ce_router)

        # adding information in overall_info
        self.overall_info[name]={}
        self.overall_info[name]['interfaces']={}


        #XXX in futuro puo' cambiare
        temp = int(cid)
        exist = self.customer_to_vtepallocator.get(cid, None)
        if not exist:
            self.customer_to_vtepallocator[cid] = VTEPAllocator()
        self.cer_to_customer[name]=cid

        self.id_to_node[ce_router.id]=ce_router

        return ce_router

    def addManagement(self, name=None):
        """Adds the node for the management connection between the Host and all the Mininet VMs"""
        if not name:
            name = self.newMgmtName()
        mgmt = Mininet.addHost(self, name, cls=IPHost, inNamespace=False)
        self.mgmt = mgmt
        self.nodes_in_rn.append(mgmt)

        # adding information in overall_info
        self.overall_info[name]={}
        self.overall_info[name]['interfaces']={}

        return mgmt

    def addCoexistenceMechanism(self, coex_type, coex_data):
        """defines the coexistence mechanism between IP and SDN traffic

        coex_types=["COEXA", "COEXB", "COEXH"] see coexistence_mechanisms.py
        """

        if coex_type is None:
            error("ERROR Coex Type is None\n")
            sys.exit(-2)

        if coex_data is None:
            error("ERROR Coex Data is None\n")
            sys.exit(-2)

        self.coex['coex_type']=coex_type
        self.coex['coex_data']=coex_data

    
    def addLink(self, lhs, rhs, properties):
        """Adds a Link to OSHI Mininet 

        lhs -> mininet node object
        rhs -> mininet node object

        A point to point link between two nodes is added only once,
        because it is a bidirectional etherrnet link
        """
    
        mylog("*** Connecting %s to %s\n" %(lhs.name, rhs.name))
        
        link = Mininet.addLink(self, lhs, rhs)

        data_lhs = { 'intfname':link.intf1.name, 'ip':properties.ipLHS, 'ingrtype':properties.ingr.type, 'ingrdata':properties.ingr.data,
                     'net':{ 'net':properties.net.net, 'netbit':properties.net.netbit, 'cost':properties.net.costLHS,
                             'hello':properties.net.helloLHS, 'area':properties.net.area }}
        data_rhs = { 'intfname':link.intf2.name, 'ip':properties.ipRHS, 'ingrtype':properties.ingr.type, 'ingrdata':properties.ingr.data,
                     'net':{ 'net':properties.net.net, 'netbit':properties.net.netbit, 'cost':properties.net.costRHS,
                             'hello':properties.net.helloRHS, 'area':properties.net.area}}

        if properties.ipLHS:
            ip_string = "%s/%s" %(properties.ipLHS, properties.net.netbit)
            lhs.setIP(ip=ip_string, intf=link.intf1)
            # adding information in overall_info
            self.overall_info[lhs.name]['interfaces'][link.intf1.name]={}
            self.overall_info[lhs.name]['interfaces'][link.intf1.name]['ip']=ip_string
            self.overall_info[lhs.name]['interfaces'][link.intf1.name]['mac']= link.intf1.MAC()
            self.overall_info[lhs.name]['interfaces'][link.intf1.name]['peers']=[]
            self.overall_info[lhs.name]['interfaces'][link.intf1.name]['peers'].append(rhs.name)

        if properties.ipRHS:
            ip_string = "%s/%s" %(properties.ipRHS, properties.net.netbit)
            rhs.setIP(ip=ip_string, intf=link.intf2)
            # adding information in overall_info
            self.overall_info[rhs.name]['interfaces'][link.intf2.name]={}
            self.overall_info[rhs.name]['interfaces'][link.intf2.name]['ip']=ip_string
            self.overall_info[rhs.name]['interfaces'][link.intf2.name]['mac']= link.intf2.MAC()
            self.overall_info[rhs.name]['interfaces'][link.intf2.name]['peers']=[]
            self.overall_info[rhs.name]['interfaces'][link.intf2.name]['peers'].append(lhs.name)

        if isinstance(lhs, InBandController):
            lhs.ip = "%s/%s" %(properties.ipLHS, properties.net.netbit)
            lhs.port = 6633 
        if isinstance(rhs, InBandController):
            rhs.ip = "%s/%s" %(properties.ipRHS, properties.net.netbit)
            rhs.port = 6633 

        if isinstance(lhs, OSHI):
            link.intf1.setMAC(lhs.mac)
            self.ip_to_mac[properties.ipLHS] = ':'.join(s.encode('hex') for s in lhs.mac.decode('hex'))
            
        if isinstance(rhs, OSHI):
            link.intf2.setMAC(rhs.mac)
            self.ip_to_mac[properties.ipRHS]= ':'.join(s.encode('hex') for s in rhs.mac.decode('hex'))

        self.node_to_data[lhs.name].append(data_lhs)
        self.node_to_data[rhs.name].append(data_rhs)
        if properties.ingr.type != None:
            self.node_to_node[lhs.name]=rhs.name
            self.node_to_node[rhs.name]=lhs.name
        self.node_to_default_via[lhs.name]= "%s/%s#%s#%s" %(properties.ipRHS, properties.net.netbit, link.intf1.name, "10.0.0.0/8")
        self.node_to_default_via[rhs.name]= "%s/%s#%s#%s" %(properties.ipLHS, properties.net.netbit, link.intf2.name, "10.0.0.0/8")

        if properties.net.net != None:
            toCompare = IPv4Network("%s/%s" %(properties.net.net, properties.net.netbit))
            if self.last_ipnet.compare_networks(toCompare)<0 :
                self.last_ipnet = toCompare     

        return link

    def addVLL(self, lhs_cer, rhs_cer, properties):
        mylog("*** Connect %s to %s through Vll\n" %(lhs_cer.name, rhs_cer.name))       

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

        if properties.net != None:
            toCompare = IPv4Network("%s/%s" %(temp[0], temp[1]))
            if self.last_ipnet.compare_networks(toCompare)<0:
                self.last_ipnet = toCompare 

        return (link1, link2)

    def addLineToVLLCFG(self, lhs_dpid, lhs_intf, rhs_dpid, rhs_intf):
        lhs_dpid = ':'.join(s.encode('hex') for s in lhs_dpid.decode('hex'))
        rhs_dpid = ':'.join(s.encode('hex') for s in rhs_dpid.decode('hex'))
        self.vlls.append({'lhs_dpid':lhs_dpid, 'rhs_dpid':rhs_dpid, 'lhs_intf':lhs_intf, 'rhs_intf':rhs_intf, 'lhs_label':'0', 'rhs_label':'0'})

    def addPW(self, lhs_cer, rhs_cer, properties):
        mylog("*** Connect %s to %s through Pw\n" %(lhs_cer.name, rhs_cer.name))        

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

        if properties.net != None:
            toCompare = IPv4Network("%s/%s" %(temp[0], temp[1]))
            if self.last_ipnet.compare_networks(toCompare)<0:
                self.last_ipnet = toCompare 

        return (link1, vsflink1, vsflink2, link2, vsflink3, vsflink4)

    """
    def addVS(self, endnodes = [], properties = None):
        mylog("*** Connect %s through VS\n" % ' '.join(endnode.name for endnode in endnodes))

        self.is_vs = True       

        i = 0
        for i in range(0, len(endnodes)-1):
            for j in range(i+1, len(endnodes)):
                self.checkLLfeasibility(endnodes[i], endnodes[j])

        pid = self.newVssPropertiesId()
        self.vss_properties.append({'id':pid,'properties':properties})

        temp = properties.net.split("/")

        endOSHIs = []
        accessLinks = []
        endCERs = []
        for endnode in endnodes:
            peo = self.node_to_node[endnode.name]
            peo = self.getNodeByName(peo)

            accessLink = (endnode.name, peo.name)
            accessLinks.append(accessLink)
            endCERs.append(":".join(s.encode('hex') for s in endnode.id.decode('hex')))

            if type(endnode) is not IPHost or type(peo) is not OSHI:
                error("ERROR cannot provide VS to %s through %s\n" %(endnode.name, peo.name))
                sys.exit(-2)

            cid = self.cer_to_customer[endnode.name]
            endOSHIs.append(":".join(s.encode('hex') for s in peo.dpid.decode('hex')))
            
            #link1 = Mininet.addLink(self, endnode, peo)
            #ip = properties.next_hostAddress()
            #data_endnode = { 'intfname':link1.intf1.name, 'ip':ip, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':temp[0], 
            #'netbit':temp[1], 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
            #if ip: 
            #   endnode.setIP(ip="%s/%s" %(ip, temp[1]), intf=link1.intf1)
            #self.node_to_data[endnode.name].append(data_endnode)

        self.addLineToVSCFG(endOSHIs, endCERs, accessLinks, cid, pid)

        if properties.net != None:
            toCompare = IPv4Network("%s/%s" %(temp[0], temp[1]))
            if self.last_ipnet.compare_networks(toCompare)<0:
                self.last_ipnet = toCompare 
    """ 

    
    def addVS(self, endnodes = [], properties = None):
        mylog("*** Connect %s through VS\n" % ' '.join(endnode.name for endnode in endnodes))

        i = 0
        for i in range(0, len(endnodes)-1):
            for j in range(i+1, len(endnodes)):
                self.checkLLfeasibility(endnodes[i], endnodes[j])

        self.is_vs = True

        output = []
        pws = []

        for endnode in endnodes:
            pw = {}
            peo = self.node_to_node[endnode.name]
            peo = self.getNodeByName(peo)
            vsf = self.getVSFByCERandPEO(endnode.name, peo.name)
            
            if type(endnode) is not IPHost or type(peo) is not OSHI:
                error("ERROR cannot provide VS to %s through %s\n" %(endnode.name, peo.name))
                sys.exit(-2)

            cid = self.cer_to_customer[endnode.name]
            vtepallocator = self.customer_to_vtepallocator[cid]
            temp = properties.net.split("/")
            
            link1 = Mininet.addLink(self, endnode, peo)
            ip = properties.next_hostAddress()
            data_endnode = { 'intfname':link1.intf1.name, 'ip':ip, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':temp[0], 
            'netbit':temp[1], 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
            if ip: 
                endnode.setIP(ip="%s/%s" %(ip, temp[1]), intf=link1.intf1)
            self.node_to_data[endnode.name].append(data_endnode)

            vsflink1 = Mininet.addLink(self, peo, vsf)
            vsflink2 = Mininet.addLink(self, peo, vsf)
            data_peo = { 'eth':link1.intf2.name, 'v_eth1':vsflink1.intf1.name, 'v_eth2':vsflink2.intf1.name}
            self.node_to_pw_data[peo.name].append(data_peo)
            lhs_vtep = vtepallocator.next_vtep()
            rhs_vtep = vtepallocator.next_vtep()
            data_vsf = { 'eth': vsflink1.intf2.name, 'remoteip': rhs_vtep.IP, 'remotemac': rhs_vtep.MAC, 'v_eth':vsflink2.intf2.name}
            if lhs_vtep:
                vsflink2.intf2.setIP(lhs_vtep.IP)
                vsflink2.intf2.setMAC(lhs_vtep.MAC)
            self.node_to_pw_data[vsf.name].append(data_vsf)

            pw['cer_id'] = ":".join(s.encode('hex') for s in endnode.id.decode('hex'))

            pw['lhs_id'] = ":".join(s.encode('hex') for s in peo.dpid.decode('hex'))
            pw['lhs_intf'] = vsflink2.intf1.name
            pw['lhs_label'] = "0"
            pw['lhs_gre_ip'] = lhs_vtep.IP
            pw['lhs_gre_mac'] = ":".join(s.encode('hex') for s in lhs_vtep.MAC.decode('hex'))

            pw['rhs_id'] = None
            pw['rhs_intf'] = None
            pw['rhs_label'] = "0"
            pw['rhs_gre_ip'] = rhs_vtep.IP
            pw['rhs_gre_mac'] = ":".join(s.encode('hex') for s in rhs_vtep.MAC.decode('hex'))

            pws.append(pw)
            output.append((link1, vsflink1, vsflink2, None, None, None))
        
        self.addLineToVSCFG(pws, cid)

        if properties.net != None:
            toCompare = IPv4Network("%s/%s" %(temp[0], temp[1]))
            if self.last_ipnet.compare_networks(toCompare)<0:
                self.last_ipnet = toCompare 

        return output

    def addLineToVSCFG(self, pws, cid):
        self.vss_data.append({'cid':cid, 'pws':pws})

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
            mylog( host.name + ' ' )
            host.cmd( 'ifconfig lo up' )
        mylog( '\n' )

    def fixEnvironment(self):
        
        mylog("*** Fix environment\n")

        for node in self.nodes_in_rn:
            fixIntf(node)
        root = Node( 'root', inNamespace=False )
        
        mylog("*** Stop unwanted traffic\n")
        root.cmd('stop avahi-daemon')
        #root.cmd('killall dhclient')

        mylog("*** Kill old processes\n")
        root.cmd('killall -r zebra')
        root.cmd('killall -r ospfd')
        root.cmd('killall sshd')
    
        cfile = '/etc/environment'
        line1 = 'VTYSH_PAGER=more\n'
        config = open( cfile ).read()
        if ( line1 ) not in config:
            mylog( '*** Adding %s to %s\n' %(line1.strip(), cfile))
            with open( cfile, 'a' ) as f:
                f.write( line1 )
            f.close();

        if os.path.exists(self.temp_cfg):
            os.remove(self.temp_cfg)
        
        #root.cmd('/etc/init.d/network-manager restart')
        #mylog("*** Stop Network Manager\n")
        #time.sleep(10)

    def start(self):
        """Start mininet emulation

        returns the overall_info with all the nodes and link information

        """

        self.fixEnvironment()

        if not self.built:
            self.build()

        ip_to_mac_file = open('/tmp/ip_to_mac.cfg', 'w') #TODO it does not work in multiple users environment
        ip_to_mac_file.write(json.dumps(self.ip_to_mac, sort_keys=True, indent=4))
        ip_to_mac_file.close()

        mylog( '*** Starting %s cr oshis\n' % len(self.cr_oshis) )
        for cr_oshi in self.cr_oshis:
            cluster = self.nodes_to_cluster[cr_oshi.name]
            ctrls_names = []
            ctrls_names = self.cluster_to_ctrl[cluster]
            ctrls = []
            for ctrl_name in ctrls_names:
                ctrls.append(self.getNodeByName(ctrl_name))
            cr_oshi.start(ctrls, self.node_to_data[cr_oshi.name],  self.coex)

        coexFactory = CoexFactory()
        coex = coexFactory.getCoex(self.coex['coex_type'], self.coex['coex_data'], [], [], "", OSHI.OF_V)       
        
        mylog( '\n' )
        mylog( '*** Starting %s pe oshis\n' % len(self.pe_oshis) )
        for pe_oshi in self.pe_oshis:
            cluster = self.nodes_to_cluster[pe_oshi.name]
            ctrls_names = self.cluster_to_ctrl[cluster]
            ctrls = []
            for ctrl_name in ctrls_names:
                ctrls.append(self.getNodeByName(ctrl_name))
            pe_oshi.start(ctrls, self.node_to_data[pe_oshi.name],  self.coex)
        mylog( '\n' )
        mylog( '*** Starting %s vsfs\n' % len(self.vsfs) )
        for vsf in self.vsfs:
            vsf.start(self.node_to_pw_data[vsf.name])       
        mylog( '\n' )
        mylog( '*** Starting %s in band controllers\n' % len(self.ctrls) )
        for controller in self.ctrls:
            controller.start(self.node_to_default_via[controller.name])
        mylog( '\n' )
        mylog( '*** Starting %s ce routers\n' % len(self.ce_routers) )
        for ce_router in self.ce_routers:
            ce_router.start(self.node_to_default_via[ce_router.name])
        mylog( '\n' )
        mylog( '*** Starting management server\n')
        self.mgmt.start(self.node_to_default_via[self.mgmt.name])
        mylog( '\n' )

        vscfg_file = open('vs_selector.cfg', 'w')
        vscfg = {}
        vscfg['tableSBP'] = coex.tableSBP
        vscfg['tableIP'] = coex.tableIP
        customers = {}
        for customer, vtep_allocator in self.customer_to_vtepallocator.iteritems():
            customers[customer]= vtep_allocator.next_hostAddress()
        vscfg['customers_vtep']=customers
        vscfg['last_ipnet']=self.last_ipnet.__str__()
        vscfg['vss']=self.vss_data
        vscfg_file.write(json.dumps(vscfg, sort_keys=True, indent=4))
        vscfg_file.close()

        if self.is_vs:
    
            """
            if 'DISPLAY' not in os.environ:
                error( "Error starting terms: Cannot connect to display\n" )
                return
            mylog( "*** Running ctrls terms on %s\n" % os.environ[ 'DISPLAY' ] )
            cleanUpScreens()
            self.terms += makeTerms( self.ctrls, 'controller' )
            self.terms += makeTerms( self.ctrls, 'controller2' )

            mylog("*** Waiting for the creation of the file %s" % self.temp_cfg)
            mylog("\n")
            """

            mylog("*** Starting VS selection\n")
            shutil.copyfile("vs_selector.cfg", "ext/vs_selector.cfg")
            controller = self.ctrls[0]
            
            mylog("*** Launch RYU Controller\n")
            controller.cmd('cd', MininetOSHI.RYU_PATH)
            controller.cmd('ryu-manager', '--observe-links', 'rest_topology.py', 'ofctl_rest.py', "&")
            controller.cmd('cd', "%s/ext/" % MininetOSHI.PROJECT_PATH)

            mylog("*** Launch VS Selector\n")
            while not os.path.exists(self.temp_cfg):
                controller.cmd('./vs_selector.py','--controller localhost:8080', MininetOSHI.VS_OPTION)
                time.sleep(5)
            root = Node( 'root', inNamespace=False )
            mylog("*** Kill all processes started\n")
            root.cmd('killall ryu-manager')
            self.configureVS()
            
            mylog( '*** Starting and configuring %s vss\n' % len(self.vss) )
            for vs in self.vss:
                vs.start(self.node_to_pw_data[vs.name])     
            mylog( '\n' )

        for cr_oshi in self.cr_oshis:
            cr_oshi.start_pw(coex.tableIP, self.node_to_pw_data[cr_oshi.name])      
        for pe_oshi in self.pe_oshis:
            pe_oshi.start_pw(coex.tableIP, self.node_to_pw_data[pe_oshi.name])
            

        vllcfg_file = open('vll_pusher.cfg','w')
        vllcfg = {}
        vllcfg['tableSBP'] = coex.tableSBP
        vllcfg['tableIP'] = coex.tableIP
        vllcfg['vlls'] = self.vlls
        vllcfg['pws'] = self.pws
        vllcfg_file.write(json.dumps(vllcfg, sort_keys=True, indent=4))
        vllcfg_file.close()

        mylog("*** Nodes are running sshd at the following addresses\n")

        for host in self.hosts:
            if "vs" not in host.name: 
                mylog("*** %s is running sshd at the following address %s\n" %(host.name, host.IP()))
                self.overall_info[host.name]['mgt_IP']=host.IP()

        return (self.overall_info)
        #self.store_overall_info()

        #end of start() method


    # def store_overall_info(self):

    #     stro = json.dumps(self.overall_info)
    #     if os.path.exists(self.OVERALL_INFO_FILE):
    #         os.remove(self.OVERALL_INFO_FILE)
    #     overall_file = open(self.OVERALL_INFO_FILE,'a+')
    #     overall_file.write(stro+"\n")
    #     overall_file.close()


    def configureVS(self):
        
        if os.path.exists(self.temp_cfg):
            conf = open(self.temp_cfg,'r')
            cfg = json.load(conf)
            conf.close()

        else:
            error("temp.cfg does not exist - unable to configure VS")
            self.stop()
            exit(-1)

        mylog("#######################################\n")
        for vs in cfg['vss']:

            cid = vs['cid']
            id_ = vs['id']

            mylog("The VSS %s is composed by these PWs:" % id_)

            for pw in vs['pws']:

                lhs_id = pw['lhs_id'].upper().replace(":","")
                lhs_intf = pw['lhs_intf']
                lhs_vtep = VTEP(pw['lhs_gre_ip'], pw['lhs_gre_mac'].upper().replace(":",""))

                # Case PW among OSHI
                if pw['cer_id'] is None:
                    lhs_id = pw['lhs_id'].upper().replace(":","")
                    lhs_peo = self.getNodeById(lhs_id)
                    lhs_vs = self.getVSByIDandPEO(id_,lhs_id)
                
                    vslink1 = Mininet.addLink(self, lhs_peo, lhs_vs)
                    data_lhs_vs = { 'eth': vslink1.intf2.name, 'remoteip': pw['rhs_gre_ip'], 'remotemac': pw['rhs_gre_mac'].upper().replace(":","")}
                    self.node_to_pw_data[lhs_vs.name].append(data_lhs_vs)

                    data_lhs_peo = { 'eth':None, 'v_eth1':None, 'v_eth2':vslink1.intf1.name}
                    self.node_to_pw_data[lhs_peo.name].append(data_lhs_peo)
                
                    vslink1.intf2.setIP(pw['lhs_gre_ip'])
                    vslink1.intf2.setMAC(pw['lhs_gre_mac'].upper().replace(":",""))
                    lhs_intf = vslink1.intf1.name

                rhs_id = pw['rhs_id'].upper().replace(":","")
                rhs_peo = self.getNodeById(rhs_id)
                rhs_vs = self.getVSByIDandPEO(id_,rhs_id)
            
                vslink2 = Mininet.addLink(self, rhs_peo, rhs_vs)
                data_rhs_vs = { 'eth': vslink2.intf2.name, 'remoteip': pw['lhs_gre_ip'], 'remotemac': pw['lhs_gre_mac'].upper().replace(":","")}
                self.node_to_pw_data[rhs_vs.name].append(data_rhs_vs)

                data_rhs_peo = { 'eth':None, 'v_eth1':None, 'v_eth2':vslink2.intf1.name}
                self.node_to_pw_data[rhs_peo.name].append(data_rhs_peo)
            
                vslink2.intf2.setIP(pw['rhs_gre_ip'])
                vslink2.intf2.setMAC(pw['rhs_gre_mac'].upper().replace(":",""))

                rhs_vtep = VTEP(pw['rhs_gre_ip'], pw['rhs_gre_mac'].upper().replace(":",""))

                mylog("(%s,%s)" %(lhs_intf,vslink2.intf1.name))

                self.addLineToPWCFG(lhs_id, lhs_intf, lhs_vtep, rhs_peo.dpid, vslink2.intf1.name, rhs_vtep)
            mylog("\n#######################################\n")        

    def getVSByIDandPEO(self, id_, peo):
        key = "%s-%s" %(id_,peo)
        vs = self.id_peo_to_vs.get(key, None)
        if not vs:
            name = self.newVsName()
            vs = Mininet.addHost(self, name, cls=VS)
            self.vss.append(vs)
            self.id_peo_to_vs[key]=vs
        return vs

    def cleanEnvironment(self):
        
        mylog("*** Clean environment\n")
        subprocess.call(["sudo", "mn", "-c"], stdout=None, stderr=None)
        
        root = Node( 'root', inNamespace=False )
        
        mylog("*** Restart network-manager\n")
        root.cmd('/etc/init.d/network-manager restart')
        
        mylog("*** Kill all processes started\n")
        root.cmd('killall ovsdb-server')
        root.cmd('killall ovs-vswitchd')
        root.cmd('killall -r zebra')
        root.cmd('killall -r ospfd')
        root.cmd('killall sshd')

        mylog("*** Restart Avahi, Open vSwitch, and sshd\n")    
        root.cmd('/etc/init.d/avahi-daemon start')
        
        root.cmd('/etc/init.d/openvswitchd start')

        root.cmd('/etc/init.d/ssh start')

        mylog('*** Unmounting host bind mounts\n')
        unmountAll()

    def stop(self):

        if self.terms:
            mylog( '*** Stopping %i terms\n' % len( self.terms ) )
            self.stopXterms()

        mylog( '*** Stopping %i hosts\n' % len( self.hosts ) )
        for host in self.hosts:
            mylog( host.name + ' ' )
            host.terminate()
        
        mylog( '\n' )
        self.cleanEnvironment()

        mylog( '*** Done\n' )

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
    
    def newVsName(self):
        index = str(len(self.vss) + 1)
        name = "vs%s" % index
        return name

    def newMgmtName(self):
        name = "mgm1"
        return name


	temp_cfg = "temp.cfg"
	VS_OPTION = '-o'
	RYU_PATH = '/home/user/workspace/ryu/ryu/app/'
	PROJECT_PATH = '/home/user/workspace/Dreamer-Mininet-Extensions/'

	
	def __init__(self, verbose=False):

		self.checkPATHs()

		Mininet.__init__(self, build=False)

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

		self.vlls = []

		self.node_to_pw_data = defaultdict(list)
		self.pws = []

		self.cer_to_customer = {}
		self.customer_to_vtepallocator = {}

		self.vsfs = []
		self.pe_cer_to_vsf = {}

		self.is_vs = False
		self.vss = []
		self.vss_data = []
		self.id_peo_to_vs = {}
		self.last_ipnet = IPv4Network(u'0.0.0.0/24')

		self.id_to_node = {}
		self.ip_to_mac = {}

		
		self.mgmt = None

		root = Node( 'root', inNamespace=False )
		root.cmd('/etc/init.d/network-manager stop')
		info("*** Stop Network Manager\n")

		self.cluster_to_ctrl = defaultdict(list)
		self.cluster_to_nodes = defaultdict(list)
		self.nodes_to_cluster = {}

	def checkPATHs(self):

		if MininetOSHI.RYU_PATH == "":
			error("Error Set RYU_PATH In MininetOSHI\n")
			sys.exit(-2)

		if MininetOSHI.PROJECT_PATH == "":
			error("Error Set PROJECT_PATH In MininetOSHI\n")
			sys.exit(-2)

	def manageOSHIproperties(self, properties, ctrl, name):
		exist = properties.get("domain-oshi", None)
		if not exist:
			error("Error domain-oshi properties cannot be found\n")
			sys.exit(-2)
		oshi_properties = properties["domain-oshi"]
		exist = oshi_properties.get("layer-Control", None)
		if not exist:
			error("Error layer-Control properties cannot be found\n")
			sys.exit(-2)
		control_properties = oshi_properties["layer-Control"]
		cluster_id = control_properties["cluster_id"]
		if cluster_id == "":
			cluster_id = "default"
		if ctrl:
			self.cluster_to_ctrl[cluster_id].append(name)
		else:
			self.cluster_to_nodes[cluster_id].append(name)
			self.nodes_to_cluster[name] = cluster_id

			
	def getNodeById(self, id_):
		return self.id_to_node[id_]
	
	# Create and Add a new OSHI
	def addOSHI(self, nodeproperties, ctrl, CR, name=None):
		loopback = nodeproperties['loopback']
		if not loopback:
			error("ERROR loopback not provided\n")
			sys.exit(-2)
		self.manageOSHIproperties(nodeproperties, ctrl, name)
		oshi = Mininet.addHost(self, name, cls=OSHI, loopback=loopback, CR=CR, cluster_id=self.nodes_to_cluster[name])
		self.id_to_node[oshi.dpid]=oshi
		return oshi
	
	# Create and Add a new OSHI insert
	# it in the Core OSHI set
	def addCrOSHI(self, nodeproperties, name=None):
		if not name:
			name = self.newCrName()
		oshi = self.addOSHI(nodeproperties, False, True, name)
		self.cr_oshis.append(oshi)
		return oshi
		
	# Create and Add a new OSHI insert it
	# in the Provider Edge OSHI set
	def addPeOSHI(self, nodeproperties, name=None):
		if not name:
			name = self.newPeName()
		oshi = self.addOSHI(nodeproperties, False, False, name)
		self.pe_oshis.append(oshi)
		return oshi

	
	# Create and Add a new Remote Controller
	def addController(self, nodeproperties, name=None, ip="127.0.0.1" ,tcp_port=6633):
		if not name:
			name = self.newCtrlName()
		tcp_port = int(nodeproperties['tcp_port'])
		self.manageOSHIproperties(nodeproperties, True, name)
		ctrl = Mininet.addHost(self, name, cls=InBandController, tcp_port=tcp_port)
		self.ctrls.append(ctrl)
		return ctrl

	# Create and Add a new Customer Edge Router.
	# In our case it is a simple host
	def addCeRouter(self, cid, nodeproperties, name=None):
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

		self.id_to_node[ce_router.id]=ce_router

		return ce_router

	# Create and Add a new Remote Management
	def addManagement(self, name=None):
		if not name:
			name = self.newMgmtName()
		mgmt = Mininet.addHost(self, name, cls=IPHost, inNamespace=False)
		self.mgmt = mgmt
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

		if isinstance(lhs, InBandController):
			lhs.ip = "%s/%s" %(properties.ipLHS, properties.net.netbit)
			lhs.port = 6633 
		if isinstance(rhs, InBandController):
			rhs.ip = "%s/%s" %(properties.ipRHS, properties.net.netbit)
			rhs.port = 6633 

		if isinstance(lhs, OSHI):
			link.intf1.setMAC(lhs.mac)
			self.ip_to_mac[properties.ipLHS] = ':'.join(s.encode('hex') for s in lhs.mac.decode('hex'))
			
		if isinstance(rhs, OSHI):
			link.intf2.setMAC(rhs.mac)
			self.ip_to_mac[properties.ipRHS]= ':'.join(s.encode('hex') for s in rhs.mac.decode('hex'))

		self.node_to_data[lhs.name].append(data_lhs)
		self.node_to_data[rhs.name].append(data_rhs)
		if properties.ingr.type != None:
			self.node_to_node[lhs.name]=rhs.name
			self.node_to_node[rhs.name]=lhs.name
		self.node_to_default_via[lhs.name]= "%s/%s#%s#%s" %(properties.ipRHS, properties.net.netbit, link.intf1.name, "10.0.0.0/8")
		self.node_to_default_via[rhs.name]= "%s/%s#%s#%s" %(properties.ipLHS, properties.net.netbit, link.intf2.name, "10.0.0.0/8")

		if properties.net.net != None:
			toCompare = IPv4Network("%s/%s" %(properties.net.net, properties.net.netbit))
			if self.last_ipnet.compare_networks(toCompare)<0 :
				self.last_ipnet = toCompare		

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

		if properties.net != None:
			toCompare = IPv4Network("%s/%s" %(temp[0], temp[1]))
			if self.last_ipnet.compare_networks(toCompare)<0:
				self.last_ipnet = toCompare	

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

		if properties.net != None:
			toCompare = IPv4Network("%s/%s" %(temp[0], temp[1]))
			if self.last_ipnet.compare_networks(toCompare)<0:
				self.last_ipnet = toCompare	

		return (link1, vsflink1, vsflink2, link2, vsflink3, vsflink4)

	"""
	def addVS(self, endnodes = [], properties = None):
		info("*** Connect %s through VS\n" % ' '.join(endnode.name for endnode in endnodes))

		self.is_vs = True		

		i = 0
		for i in range(0, len(endnodes)-1):
			for j in range(i+1, len(endnodes)):
				self.checkLLfeasibility(endnodes[i], endnodes[j])

		pid = self.newVssPropertiesId()
		self.vss_properties.append({'id':pid,'properties':properties})

		temp = properties.net.split("/")

		endOSHIs = []
		accessLinks = []
		endCERs = []
		for endnode in endnodes:
			peo = self.node_to_node[endnode.name]
			peo = self.getNodeByName(peo)

			accessLink = (endnode.name, peo.name)
			accessLinks.append(accessLink)
			endCERs.append(":".join(s.encode('hex') for s in endnode.id.decode('hex')))

			if type(endnode) is not IPHost or type(peo) is not OSHI:
				error("ERROR cannot provide VS to %s through %s\n" %(endnode.name, peo.name))
				sys.exit(-2)

			cid = self.cer_to_customer[endnode.name]
			endOSHIs.append(":".join(s.encode('hex') for s in peo.dpid.decode('hex')))
			
			#link1 = Mininet.addLink(self, endnode, peo)
			#ip = properties.next_hostAddress()
			#data_endnode = { 'intfname':link1.intf1.name, 'ip':ip, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':temp[0], 
			#'netbit':temp[1], 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
			#if ip: 
			#	endnode.setIP(ip="%s/%s" %(ip, temp[1]), intf=link1.intf1)
			#self.node_to_data[endnode.name].append(data_endnode)

		self.addLineToVSCFG(endOSHIs, endCERs, accessLinks, cid, pid)

		if properties.net != None:
			toCompare = IPv4Network("%s/%s" %(temp[0], temp[1]))
			if self.last_ipnet.compare_networks(toCompare)<0:
				self.last_ipnet = toCompare	
	"""	

	
	def addVS(self, endnodes = [], properties = None):
		info("*** Connect %s through VS\n" % ' '.join(endnode.name for endnode in endnodes))

		i = 0
		for i in range(0, len(endnodes)-1):
			for j in range(i+1, len(endnodes)):
				self.checkLLfeasibility(endnodes[i], endnodes[j])

		self.is_vs = True

		output = []
		pws = []

		for endnode in endnodes:
			pw = {}
			peo = self.node_to_node[endnode.name]
			peo = self.getNodeByName(peo)
			vsf = self.getVSFByCERandPEO(endnode.name, peo.name)
			
			if type(endnode) is not IPHost or type(peo) is not OSHI:
				error("ERROR cannot provide VS to %s through %s\n" %(endnode.name, peo.name))
				sys.exit(-2)

			cid = self.cer_to_customer[endnode.name]
			vtepallocator = self.customer_to_vtepallocator[cid]
			temp = properties.net.split("/")
			
			link1 = Mininet.addLink(self, endnode, peo)
			ip = properties.next_hostAddress()
			data_endnode = { 'intfname':link1.intf1.name, 'ip':ip, 'ingrtype':None, 'ingrdata':None, 'net':{ 'net':temp[0], 
			'netbit':temp[1], 'cost':1, 'hello':1, 'area':'0.0.0.0'}}
			if ip: 
				endnode.setIP(ip="%s/%s" %(ip, temp[1]), intf=link1.intf1)
			self.node_to_data[endnode.name].append(data_endnode)

			vsflink1 = Mininet.addLink(self, peo, vsf)
			vsflink2 = Mininet.addLink(self, peo, vsf)
			data_peo = { 'eth':link1.intf2.name, 'v_eth1':vsflink1.intf1.name, 'v_eth2':vsflink2.intf1.name}
			self.node_to_pw_data[peo.name].append(data_peo)
			lhs_vtep = vtepallocator.next_vtep()
			rhs_vtep = vtepallocator.next_vtep()
			data_vsf = { 'eth': vsflink1.intf2.name, 'remoteip': rhs_vtep.IP, 'remotemac': rhs_vtep.MAC, 'v_eth':vsflink2.intf2.name}
			if lhs_vtep:
				vsflink2.intf2.setIP(lhs_vtep.IP)
				vsflink2.intf2.setMAC(lhs_vtep.MAC)
			self.node_to_pw_data[vsf.name].append(data_vsf)

			pw['cer_id'] = ":".join(s.encode('hex') for s in endnode.id.decode('hex'))

			pw['lhs_id'] = ":".join(s.encode('hex') for s in peo.dpid.decode('hex'))
			pw['lhs_intf'] = vsflink2.intf1.name
			pw['lhs_label'] = "0"
			pw['lhs_gre_ip'] = lhs_vtep.IP
			pw['lhs_gre_mac'] = ":".join(s.encode('hex') for s in lhs_vtep.MAC.decode('hex'))

			pw['rhs_id'] = None
			pw['rhs_intf'] = None
			pw['rhs_label'] = "0"
			pw['rhs_gre_ip'] = rhs_vtep.IP
			pw['rhs_gre_mac'] = ":".join(s.encode('hex') for s in rhs_vtep.MAC.decode('hex'))

			pws.append(pw)
			output.append((link1, vsflink1, vsflink2, None, None, None))
		
		self.addLineToVSCFG(pws, cid)

		if properties.net != None:
			toCompare = IPv4Network("%s/%s" %(temp[0], temp[1]))
			if self.last_ipnet.compare_networks(toCompare)<0:
				self.last_ipnet = toCompare	

		return output

	def addLineToVSCFG(self, pws, cid):
		self.vss_data.append({'cid':cid, 'pws':pws})

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
		#root.cmd('killall dhclient')

		info("*** Kill old processes\n")
		root.cmd('killall -r zebra')
		root.cmd('killall -r ospfd')
		root.cmd('killall sshd')
	
		cfile = '/etc/environment'
	  	line1 = 'VTYSH_PAGER=more\n'
	  	config = open( cfile ).read()
	  	if ( line1 ) not in config:
			info( '*** Adding %s to %s\n' %(line1.strip(), cfile))
			with open( cfile, 'a' ) as f:
		  		f.write( line1 )
		  	f.close();

		if os.path.exists(self.temp_cfg):
			os.remove(self.temp_cfg)
		
		#root.cmd('/etc/init.d/network-manager restart')
		#info("*** Stop Network Manager\n")
		#time.sleep(10)

	def start(self):

		self.fixEnvironment()

		if not self.built:
			self.build()

		ip_to_mac_file = open('/tmp/ip_to_mac.cfg', 'w')
		ip_to_mac_file.write(json.dumps(self.ip_to_mac, sort_keys=True, indent=4))
		ip_to_mac_file.close()

		info( '*** Starting %s cr oshis\n' % len(self.cr_oshis) )
		for cr_oshi in self.cr_oshis:
			cluster = self.nodes_to_cluster[cr_oshi.name]
			ctrls_names = []
			ctrls_names = self.cluster_to_ctrl[cluster]
			ctrls = []
			for ctrl_name in ctrls_names:
				ctrls.append(self.getNodeByName(ctrl_name))
			cr_oshi.start(ctrls, self.node_to_data[cr_oshi.name],  self.coex)

		coexFactory = CoexFactory()
		coex = coexFactory.getCoex(self.coex['coex_type'], self.coex['coex_data'], [], [], "", OSHI.OF_V)		
		
		info( '\n' )
		info( '*** Starting %s pe oshis\n' % len(self.pe_oshis) )
		for pe_oshi in self.pe_oshis:
			cluster = self.nodes_to_cluster[pe_oshi.name]
			ctrls_names = self.cluster_to_ctrl[cluster]
			ctrls = []
			for ctrl_name in ctrls_names:
				ctrls.append(self.getNodeByName(ctrl_name))
			pe_oshi.start(ctrls, self.node_to_data[pe_oshi.name],  self.coex)
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
		info( '*** Starting management server\n')
		self.mgmt.start(self.node_to_default_via[self.mgmt.name])
		info( '\n' )

		vscfg_file = open('vs_selector.cfg', 'w')
		vscfg = {}
		vscfg['tableSBP'] = coex.tableSBP
		vscfg['tableIP'] = coex.tableIP
		customers = {}
		for customer, vtep_allocator in self.customer_to_vtepallocator.iteritems():
			customers[customer]= vtep_allocator.next_hostAddress()
		vscfg['customers_vtep']=customers
		vscfg['last_ipnet']=self.last_ipnet.__str__()
		vscfg['vss']=self.vss_data
		vscfg_file.write(json.dumps(vscfg, sort_keys=True, indent=4))
		vscfg_file.close()

		if self.is_vs:
	
			"""
			if 'DISPLAY' not in os.environ:
				error( "Error starting terms: Cannot connect to display\n" )
				return
			info( "*** Running ctrls terms on %s\n" % os.environ[ 'DISPLAY' ] )
			cleanUpScreens()
			self.terms += makeTerms( self.ctrls, 'controller' )
			self.terms += makeTerms( self.ctrls, 'controller2' )

			info("*** Waiting for the creation of the file %s" % self.temp_cfg)
			info("\n")
			"""

			info("*** Starting VS selection\n")
			shutil.copyfile("vs_selector.cfg", "ext/vs_selector.cfg")
			controller = self.ctrls[0]
			
			info("*** Launch RYU Controller\n")
			controller.cmd('cd', MininetOSHI.RYU_PATH)
			controller.cmd('ryu-manager', '--observe-links', 'rest_topology.py', 'ofctl_rest.py', "&")
			controller.cmd('cd', "%s/ext/" % MininetOSHI.PROJECT_PATH)

			info("*** Launch VS Selector\n")
			while not os.path.exists(self.temp_cfg):
				controller.cmd('./vs_selector.py','--controller localhost:8080', MininetOSHI.VS_OPTION)
				time.sleep(5)
			root = Node( 'root', inNamespace=False )
			info("*** Kill all processes started\n")
			root.cmd('killall ryu-manager')
			self.configureVS()
			
			info( '*** Starting and configuring %s vss\n' % len(self.vss) )
			for vs in self.vss:
				vs.start(self.node_to_pw_data[vs.name])		
			info( '\n' )

		for cr_oshi in self.cr_oshis:
			cr_oshi.start_pw(coex.tableIP, self.node_to_pw_data[cr_oshi.name])		
		for pe_oshi in self.pe_oshis:
			pe_oshi.start_pw(coex.tableIP, self.node_to_pw_data[pe_oshi.name])
			

		vllcfg_file = open('vll_pusher.cfg','w')
		vllcfg = {}
		vllcfg['tableSBP'] = coex.tableSBP
		vllcfg['tableIP'] = coex.tableIP
		vllcfg['vlls'] = self.vlls
		vllcfg['pws'] = self.pws
		vllcfg_file.write(json.dumps(vllcfg, sort_keys=True, indent=4))
		vllcfg_file.close()

		info("*** Nodes are running sshd at the following addresses\n")
		path = './ip_node.json'
		if os.path.exists(path):
			os.remove(path)
		for host in self.hosts:
			if "vs" not in host.name: 
				info("*** %s is running sshd at the following address %s\n" %(host.name, host.IP()))
				self.store_ip_node(host.name,host.IP())


		

	def configureVS(self):
		
		if os.path.exists(self.temp_cfg):
			conf = open(self.temp_cfg,'r')
			cfg = json.load(conf)
			conf.close()

		else:
			error("temp.cfg does not exist - unable to configure VS")
			self.stop()
			exit(-1)

		info("#######################################\n")
		for vs in cfg['vss']:

			cid = vs['cid']
			id_ = vs['id']

			info("The VSS %s is composed by these PWs:" % id_)

			for pw in vs['pws']:

				lhs_id = pw['lhs_id'].upper().replace(":","")
				lhs_intf = pw['lhs_intf']
				lhs_vtep = VTEP(pw['lhs_gre_ip'], pw['lhs_gre_mac'].upper().replace(":",""))

				# Case PW among OSHI
				if pw['cer_id'] is None:
					lhs_id = pw['lhs_id'].upper().replace(":","")
					lhs_peo = self.getNodeById(lhs_id)
					lhs_vs = self.getVSByIDandPEO(id_,lhs_id)
				
					vslink1 = Mininet.addLink(self, lhs_peo, lhs_vs)
					data_lhs_vs = { 'eth': vslink1.intf2.name, 'remoteip': pw['rhs_gre_ip'], 'remotemac': pw['rhs_gre_mac'].upper().replace(":","")}
					self.node_to_pw_data[lhs_vs.name].append(data_lhs_vs)

					data_lhs_peo = { 'eth':None, 'v_eth1':None, 'v_eth2':vslink1.intf1.name}
					self.node_to_pw_data[lhs_peo.name].append(data_lhs_peo)
				
					vslink1.intf2.setIP(pw['lhs_gre_ip'])
					vslink1.intf2.setMAC(pw['lhs_gre_mac'].upper().replace(":",""))
					lhs_intf = vslink1.intf1.name



				rhs_id = pw['rhs_id'].upper().replace(":","")
				rhs_peo = self.getNodeById(rhs_id)
				rhs_vs = self.getVSByIDandPEO(id_,rhs_id)
			
				vslink2 = Mininet.addLink(self, rhs_peo, rhs_vs)
				data_rhs_vs = { 'eth': vslink2.intf2.name, 'remoteip': pw['lhs_gre_ip'], 'remotemac': pw['lhs_gre_mac'].upper().replace(":","")}
				self.node_to_pw_data[rhs_vs.name].append(data_rhs_vs)

				data_rhs_peo = { 'eth':None, 'v_eth1':None, 'v_eth2':vslink2.intf1.name}
				self.node_to_pw_data[rhs_peo.name].append(data_rhs_peo)
			
				vslink2.intf2.setIP(pw['rhs_gre_ip'])
				vslink2.intf2.setMAC(pw['rhs_gre_mac'].upper().replace(":",""))

				rhs_vtep = VTEP(pw['rhs_gre_ip'], pw['rhs_gre_mac'].upper().replace(":",""))

				info("(%s,%s)" %(lhs_intf,vslink2.intf1.name))

				self.addLineToPWCFG(lhs_id, lhs_intf, lhs_vtep, rhs_peo.dpid, vslink2.intf1.name, rhs_vtep)
			info("\n#######################################\n")		

	def getVSByIDandPEO(self, id_, peo):
		key = "%s-%s" %(id_,peo)
		vs = self.id_peo_to_vs.get(key, None)
		if not vs:
			name = self.newVsName()
			vs = Mininet.addHost(self, name, cls=VS)
			self.vss.append(vs)
			self.id_peo_to_vs[key]=vs
		return vs


	def cleanEnvironment(self):
		
		info("*** Clean environment\n")
		subprocess.call(["sudo", "mn", "-c"], stdout=None, stderr=None)
		
		root = Node( 'root', inNamespace=False )
		
		info("*** Restart network-manager\n")
		root.cmd('/etc/init.d/network-manager restart')
		
		info("*** Kill all processes started\n")
		root.cmd('killall ovsdb-server')
		root.cmd('killall ovs-vswitchd')
		root.cmd('killall -r zebra')
		root.cmd('killall -r ospfd')
		root.cmd('killall sshd')

		info("*** Restart Avahi, Open vSwitch, and sshd\n")	
		root.cmd('/etc/init.d/avahi-daemon start')

		
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
	
	def newVsName(self):
		index = str(len(self.vss) + 1)
		name = "vs%s" % index
		return name

	def newMgmtName(self):
		name = "mgm1"
		return name

	def store_ip_node(self,name,ip):
		# Store created vll attributes in local ./vlls_shp.json
		#datetime = time.asctime()
			
		ipParam = {'name': name, 'ip':ip}
		stro = json.dumps(ipParam)
		ipNode = open('./ip_node.json','a+')
		ipNode.write(stro+"\n")
		ipNode.close()
