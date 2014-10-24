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
# Deployer implementation able to parse JSON topologies realized with TopoDesigner.
#
# @author Pier Luigi Ventre <pl.ventre@gmail.com>
# @author Giuseppe Siracusano <a_siracusano@tin.it>
# @author Stefano Salsano <stefano.salsano@uniroma2.it>
#
#

import argparse
import sys
import os

from mininet_extensions import MininetOSHI
from utility import PropertiesGenerator
from coexistence_mechanisms import *
from ingress_classifications import *

from mininet.cli import CLI

parser_path = "../Dreamer-Topology-Parser-and-Validator/"
if parser_path == "":
	print "Error Set Environment Variable At The Beginning Of File"
	sys.exit(-2)

sys.path.append(parser_path)
from topo_parser import TopoParser

# XXX Build Topology From topo.json generated through TopologyDesigner and create Configuration File for VLL pusher	
def topo(topology):

	verbose = True
	if verbose:
		print "*** Build Topology From Parsed File"
	parser = TopoParser(topology, verbose = False)
	(ppsubnets, l2subnets) = parser.getsubnets()
	vlls = parser.getVLLs()
	# XXX
	if parser.generated == False:
		if verbose:
			print "*** No Autogenerated"

		generator = PropertiesGenerator(False)
		if verbose:
			print "*** Build Vertices Properties"
			cr_oshis_properties = generator.getVerticesProperties(parser.cr_oshis)
			for parser_cr_property, cr_property in zip(parser.cr_oshis_properties, cr_oshis_properties):
				parser_cr_property['loopback'] = cr_property.loopback
			pe_oshis_properties = generator.getVerticesProperties(parser.pe_oshis)
			for parser_pe_property, pe_property in zip(parser.pe_oshis_properties, pe_oshis_properties):
				parser_pe_property['loopback'] = pe_property.loopback
			#cers_properties = generator.getVerticesProperties(parser.cers)

		if verbose:
			print "*** Build Point-To-Point Links Properties"
		pp_properties = []
		for ppsubnet in ppsubnets:
			pp_properties.append(generator.getLinksProperties(ppsubnet.links))
		
		if verbose:
			print "*** Build VLLs Properties"
		vlls_properties = []
		for vll in vlls:
			vlls_properties.append(generator.getVLLProperties(vll))
			

	set_cr_oshis = parser.cr_oshis
	set_pe_oshis = parser.pe_oshis
	set_cers = parser.cers
	set_ctrls = parser.ctrls

	net = MininetOSHI(verbose)

	if verbose:
		print "*** Build CR OSHI"
	i = 0	
	for croshi in set_cr_oshis:
		net.addCrOSHI(parser.cr_oshis_properties[i], croshi)
		if verbose:
			print "*** %s - %s" %(croshi, parser.cr_oshis_properties[i])
		i = i + 1

	if verbose:
		print "*** Build PE OSHI"
	i = 0
	for peoshi in set_pe_oshis:
		net.addPeOSHI(parser.pe_oshis_properties[i], peoshi)
		if verbose:
			print "*** %s - %s" %(peoshi, parser.pe_oshis_properties[i])	
		i = i + 1

	net.addCoexistenceMechanism("COEXH", 0)

	if verbose:
		print "*** Build CONTROLLER"
	i = 0
	for ctrl in set_ctrls:
		net.addController(parser.ctrls_properties[i], ctrl)
		if verbose:
			print "*** %s - %s" %(ctrl, parser.ctrls_properties[i])	
		i = i + 1

#	if verbose:
#		print "*** Build CONTROLLER"
#	ctrl = net.addController(name="ctr1", tcp_port=6633)
#	croshi = net.getNodeByName(croshi)	
	
#	linkproperties = generator.getLinksProperties([(croshi.name, ctrl.name)])
#	linkproperties[0].ingr.type = "INGRB"
#	linkproperties[0].ingr.data = None
#	net.addLink(croshi, ctrl, linkproperties[0])
#	if verbose:			
#		print "*** Connect", ctrl.name, "To", croshi.name

#	if verbose:
#		print "*** Build CONTROLLER2"
#	ctrl2 = net.addController(name="ctr2", tcp_port=6633)	
#	croshi2 = net.getNodeByName(set_cr_oshis[0])
#	linkproperties = generator.getLinksProperties([(croshi2.name, ctrl2.name)])
#	linkproperties[0].ingr.type = "INGRB"
#	linkproperties[0].ingr.data = None
#	net.addLink(croshi2, ctrl2, linkproperties[0])
#	if verbose:			
#		print "*** Connect", ctrl2.name, "To", croshi2.name

	if verbose:
		print "*** Build CERS"
	i = 0
	for cer in set_cers:
		net.addCeRouter(0, parser.cers_properties[i],  name = cer)
		if verbose:
			print "*** %s - %s" %(cer, parser.cers_properties[i])
		i = i + 1

	if verbose:	
		print "*** Create Networks Point To Point"
	i = 0
	for ppsubnet in ppsubnets:
			links = ppsubnet.links
			if verbose:
				print "*** Subnet: Node %s - Links %s" %(ppsubnet.nodes, links)
			node1 = net.getNodeByName(links[0][0])
			node2 = net.getNodeByName(links[0][1])
			net.addLink(node1, node2, pp_properties[i][0])
			if verbose:			
				#print "*** Connect", node1, "To", node2
				print "*** Link Properties", pp_properties[i][0]
			i = i + 1

	if verbose:	
		print "*** Create Switched Networks"
	j = 0
	#for l2subnet in l2subnets:
	#		links = l2subnet.links
	#		if verbose:
	#				print "*** Subnet: Node %s - Links %s" %(l2subnet.nodes, links)
	#		i = 0
	#		for link in links:
	#			node1 = link[0]
	#			node2 = link[1]
	#			[(lhs_vi, lhs_tap, lhs_ospf_net), (rhs_vi, rhs_tap, rhs_ospf_net)] = testbed.addLink(node1, node2, l2_properties[j][i])
	#			if verbose:			
	#				print "*** Connect", node1, "To", node2
	#				print "*** Link Properties", l2_properties[j][i]
	#			i = i + 1
	#		j = j + 1

	i = 0
	for vll in vlls:
		node1 = net.getNodeByName(vll[0])
		node2 = net.getNodeByName(vll[1])
		net.addVLL(node1, node2, vlls_properties[i])
		if verbose:			
			print "*** VLLs Properties", vlls_properties[i]
		i = i + 1	
	
	net.start()
	CLI(net)
	net.stop()

def parse_cmd_line():
	parser = argparse.ArgumentParser(description='Mininet Extensions')
	parser.add_argument('--topology', dest='topoInfo', action='store', default='topo:topo1.json', help='topo:param see README for further details')
	args = parser.parse_args()
	if len(sys.argv)==1:
    		parser.print_help()
    		sys.exit(1)
	topo_data = args.topoInfo	
	return (topo_data)

if __name__ == '__main__':
	(topology) = parse_cmd_line()
	topo(topology)
