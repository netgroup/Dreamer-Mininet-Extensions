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
# Virtual Switch Selector.
#
# @author Pier Luigi Ventre <pl.ventre@gmail.com>
# @author Giuseppe Siracusano <a_siracusano@tin.it>
# @author Stefano Salsano <stefano.salsano@uniroma2.it>
#
#

import os
import json
import argparse
import sys
from random import randrange
import networkx as nx

from utility import *

cfg = {}
key_dst = "dst"
key_src = "src"
key_dpid = "dpid"
key_name = "name"

key_vss = "vss"
key_cer_id = "cer_id"
key_lhs_id = "lhs_id"
key_lhs_gre_ip = "lhs_gre_ip"
key_lhs_gre_mac = "lhs_gre_mac"
key_lhs_intf = "lhs_intf"
key_lhs_label = "lhs_label"
key_rhs_id = "rhs_id"
key_rhs_gre_ip = "rhs_gre_ip"
key_rhs_gre_mac = "rhs_gre_mac"
key_rhs_intf = "rhs_intf"
key_rhs_label = "rhs_label"
key_cid = "cid"
key_pws = "pws"
key_id = "id"
key_customers_vtep = "customers_vtep"

def load_cfg():
	global cfg

	print "*** Read Configuration File For VS Selector"
	path = "vs_selector.cfg"
	if os.path.exists(path):
		conf = open(path,'r')
		cfg = json.load(conf)
		conf.close()
	else:
		print "No Configuration File Find In %s" % path
		sys.exit(-2)	

def o_selection(args):

	load_cfg()
	controllerRestIp = args.controllerRestIp

	command = "curl -s http://%s/v1.0/topology/links | python -mjson.tool" % (controllerRestIp)
	result = os.popen(command).read()
	topology = json.loads(result)

	nx_topology = nx.MultiDiGraph()
	nx_topology_sp = nx.Graph()
	nx_topology_sp_exploded = nx.Graph()

	out_cfg = {}
	vss = []
	i = 0

	cid_to_vtep_allocator = {}

	for vs in cfg[key_vss]:

		cer_to_data = {}
		steiner_nodes = []


		i = i + 1 
		
		# First step (Building the topology with CERs - Steiner Nodes)
		nx_topology.clear()
		for link in topology:
			src =link[key_src][key_dpid]
			dst =link[key_dst][key_dpid]
			nx_topology.add_edge(src, dst, src_port=link[key_src][key_name], dst_port=link[key_src][key_name])

		j = 0
		for pw in vs[key_pws]:
				j = j + 1
				cer = pw[key_cer_id].replace(":","")
				oshi = pw[key_lhs_id].replace(":","")
				nx_topology.add_edge(cer, oshi,	src_port="cer-eth%s" %(j), dst_port="peo-eth%s" %(j))
				nx_topology.add_edge(oshi, cer,	src_port="peo-eth%s" %(j), dst_port="cer-eth%s" %(j))
				cer_to_data[cer]=pw
				steiner_nodes.append(cer)
	
		# Second Step (Building the topology of the shortest paths)
		j = 0
		sps = []
		for j in range(0,len(steiner_nodes)-1):
			for k in range(j + 1,len(steiner_nodes)):
				sp = nx.shortest_path(nx_topology, steiner_nodes[j], steiner_nodes[k])
				links = []
				sp_map = {}
				for z in range(0, len(sp)-1):
					link = nx_topology[sp[z]][sp[z+1]]
					index = randrange(len(link))
					links.append((sp[z], sp[z+1], link[index]['src_port'], link[index]['dst_port']))
					#links.append((sp[z+1], sp[z], link[index]['dst_port'], link[index]['src_port']))
					
				sp_map['lhs'] = steiner_nodes[j]
				sp_map['rhs'] = steiner_nodes[k]
				sp_map['path'] = links
				sp_map['cost'] = len(links)/2
				sps.append(sp_map)
		
		# Third Step (Building the Spannig tree of the shortest paths topology)
		nx_topology_sp.clear()
		for sp in sps:
			nx_topology_sp.add_edge(sp['lhs'], sp['rhs'], weight=int(sp['cost']))

		T=nx.minimum_spanning_tree(nx_topology_sp)
	
		# Fourth step (Exploding the previous spanning tree)
		nx_topology_sp_exploded.clear()
		for edge in T.edges(data=False):
			for z in range(0, len(sps)):
				if (sps[z]['lhs'] == edge[0] and sps[z]['rhs'] == edge[1]) or (sps[z]['lhs'] == edge[1] and sps[z]['rhs'] == edge[0]):
					for link in sps[z]['path']:
						nx_topology_sp_exploded.add_edge(link[0],link[1], src_port=link[2], dst_port=link[3])

		# Fifth step (Building the spanning tree of the previous topology)
		T2=nx.minimum_spanning_tree(nx_topology_sp_exploded)

		# Sixth step (Eliminating non-steiner leaf)
		j = 0
		end = len(T2.nodes(data=False))
		while j < end:
			node = T2.nodes(data=False)[j]
			if T2.degree(node) == 1 and node not in steiner_nodes:
				T2.remove_node(node)
				j = 0
				end = len(T2.nodes(data=False))
				continue
			j = j + 1 

		# Seventh step (Optimization)
		j = 0
		end = len(T2.nodes(data=False))
		while j < end:
			node = T2.nodes(data=False)[j]
			if T2.degree(node) == 2:
				first_link = None
				second_link = None
				first_index = 0
				second_index = 0
				for	edge in T2.edges(data=False):
					if node in edge:					
						if not first_link:
							first_link = edge
							if node is edge[0]:
								first_index = 1
							if node is edge[1]:
								first_index = 0
						elif not second_link:
							second_link = edge
							if node is edge[0]:
								second_index = 1
							if node is edge[1]:
								second_index = 0
						else:
							print "ERROR IMPOSSIBLE DEGREE 3"
							exit(-1)	
				T2.add_edge(first_link[first_index], second_link[second_index])
				T2.remove_node(node)
				j = 0
				end = len(T2.nodes(data=False))
				continue
			j = j + 1

		cid = str(vs[key_cid])
		allocator = cid_to_vtep_allocator.get(cid, None)
		if not allocator:
			used = cfg[key_customers_vtep][cid]
			allocator = VTEPAllocator(used)	
			cid_to_vtep_allocator[cid] = allocator

		# Generating temp.cfg
		out_vs = {}
		out_pws = []	

		for	edge in T2.edges(data=False):
			out_pw = {}
			if edge[0] in steiner_nodes:
				pw = cer_to_data[edge[0]]
				
				out_pw[key_cer_id] = pw[key_cer_id]
			
				out_pw[key_lhs_gre_ip] = pw[key_lhs_gre_ip]
				out_pw[key_lhs_gre_mac] = pw[key_lhs_gre_mac]
				out_pw[key_lhs_id] = pw[key_lhs_id]
				out_pw[key_lhs_label] = pw[key_lhs_label]
				out_pw[key_lhs_intf] = pw[key_lhs_intf]

				out_pw[key_rhs_gre_ip] = pw[key_rhs_gre_ip]
				out_pw[key_rhs_gre_mac] = pw[key_rhs_gre_mac]
				out_pw[key_rhs_id] = ":".join(s.encode('hex') for s in edge[1].decode('hex'))
				out_pw[key_rhs_label] = pw[key_rhs_label]
				out_pw[key_rhs_intf] = pw[key_rhs_intf]

			elif edge[1] in steiner_nodes:
				pw = cer_to_data[edge[1]]
				
				out_pw[key_cer_id] = pw[key_cer_id]
			
				out_pw[key_lhs_gre_ip] = pw[key_lhs_gre_ip]
				out_pw[key_lhs_gre_mac] = pw[key_lhs_gre_mac]
				out_pw[key_lhs_id] = pw[key_lhs_id]
				out_pw[key_lhs_label] = pw[key_lhs_label]
				out_pw[key_lhs_intf] = pw[key_lhs_intf]

				out_pw[key_rhs_gre_ip] = pw[key_rhs_gre_ip]
				out_pw[key_rhs_gre_mac] = pw[key_rhs_gre_mac]
				out_pw[key_rhs_id] = ":".join(s.encode('hex') for s in edge[0].decode('hex'))
				out_pw[key_rhs_label] = pw[key_rhs_label]
				out_pw[key_rhs_intf] = pw[key_rhs_intf]
	
			elif edge[0] not in steiner_nodes and edge[1] not in steiner_nodes:
				
				out_pw[key_cer_id] = None
				
				vtep = allocator.next_vtep()
			
				out_pw[key_lhs_gre_ip] = vtep.IP
				out_pw[key_lhs_gre_mac] = ":".join(s.encode('hex') for s in vtep.MAC.decode('hex'))
				out_pw[key_lhs_id] = ":".join(s.encode('hex') for s in edge[0].decode('hex'))
				out_pw[key_lhs_label] = '0'
				#TODO modificare per ofelia (simulare nomi)
				out_pw[key_lhs_intf] = None

				vtep = allocator.next_vtep()

				out_pw[key_rhs_gre_ip] = vtep.IP
				out_pw[key_rhs_gre_mac] = ":".join(s.encode('hex') for s in vtep.MAC.decode('hex'))
				out_pw[key_rhs_id] = ":".join(s.encode('hex') for s in edge[1].decode('hex'))
				out_pw[key_rhs_label] = '0'
				#TODO modificare per ofelia (simulare nomi)
				out_pw[key_rhs_intf] = None

			else:
				print "ERROR IMPOSSIBLE"
				exit(-1)
			out_pws.append(out_pw)

		out_vs[key_cid] = vs[key_cid]
		out_vs[key_pws] = out_pws
		out_vs[key_id] = i
		vss.append(out_vs)


	out_cfg[key_vss] = vss
	outcfg_file = open('../temp.cfg','w')
	outcfg_file.write(json.dumps(out_cfg, sort_keys=True, indent=4))
	outcfg_file.close()

def u_selection(args):

	load_cfg()
	controllerRestIp = args.controllerRestIp

	command = "curl -s http://%s/v1.0/topology/links | python -mjson.tool" % (controllerRestIp)
	result = os.popen(command).read()
	topology = json.loads(result)

	command = "curl -s http://%s/v1.0/topology/switches | python -mjson.tool" % (controllerRestIp)
	result = os.popen(command).read()
	oshies = json.loads(result)	


	out_cfg = {}
	vss = []

	i = 0
	for vs in cfg[key_vss]:

		i = i + 1
	
		out_vs = {}
		out_pws = []

		oshs = []
		endoshs = []

		for pw in vs[key_pws]:
			oshi = pw[key_lhs_id].replace(":","")
			if oshi not in endoshs:
				endoshs.append(oshi)

		for link in topology:
			if link[key_dst][key_dpid] not in oshs and link[key_dst][key_dpid] not in endoshs:
				oshs.append(link[key_dst][key_dpid])
			if link[key_src][key_dpid] not in oshs and link[key_src][key_dpid] not in endoshs:
				oshs.append(link[key_src][key_dpid])

		index = randrange(len(oshs))
		print "VS(%s) - Selection %s" %(i, oshs[index])


		for pw in vs[key_pws]:

			out_pw = {}
			out_pw[key_cer_id] = pw[key_cer_id]
			
			out_pw[key_lhs_gre_ip] = pw[key_lhs_gre_ip]
			out_pw[key_lhs_gre_mac] = pw[key_lhs_gre_mac]
			out_pw[key_lhs_id] = pw[key_lhs_id]
			out_pw[key_lhs_label] = pw[key_lhs_label]
			out_pw[key_lhs_intf] = pw[key_lhs_intf]

			out_pw[key_rhs_gre_ip] = pw[key_rhs_gre_ip]
			out_pw[key_rhs_gre_mac] = pw[key_rhs_gre_mac]
			out_pw[key_rhs_id] = ":".join(s.encode('hex') for s in oshs[index].decode('hex'))
			out_pw[key_rhs_label] = pw[key_rhs_label]
			out_pw[key_rhs_intf] = pw[key_rhs_intf]

			out_pws.append(out_pw)

		out_vs[key_cid] = vs[key_cid]
		out_vs[key_pws] = out_pws
		out_vs[key_id] = i

		
		vss.append(out_vs)


	out_cfg[key_vss] = vss
	outcfg_file = open('../temp.cfg','w')
	outcfg_file.write(json.dumps(out_cfg, sort_keys=True, indent=4))
	outcfg_file.close()
		
		
def parse_cmd_line():
	parser = argparse.ArgumentParser(description='Virtual Switch Selector')
	parser.add_argument('--controller', dest='controllerRestIp', action='store', default='localhost:8080', help='controller IP:RESTport, e.g., localhost:8080 or A.B.C.D:8080')
	parser.add_argument('-o', dest='selection', action='store_const', const='optimized', default='optimized', help='selection: optimized')
	parser.add_argument('-u', dest='selection', action='store_const', const='unoptimized', default='optimized', help='selection: unoptimized')
	args = parser.parse_args()
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	return args

if __name__ == '__main__':
	args = parse_cmd_line()
	if args.selection == "optimized":
		o_selection(args)
	elif args.selection == "unoptimized":
		u_selection(args)


	
