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
# Deployer implementation using Dreamer Extensions API.
#
# @author Pier Luigi Ventre <pl.ventre@gmail.com>
# @author Giuseppe Siracusano <a_siracusano@tin.it>
# @author Stefano Salsano <stefano.salsano@uniroma2.it>
#
#

from mininet_extensions import MininetOSHI
from utility import PropertiesGenerator
from mininet.cli import CLI




if __name__ == '__main__':

	verbose=True
	net = MininetOSHI(verbose)
	generator = PropertiesGenerator(False)
	cr_os = ["cro1","cro2","cro3"]
	pe_os = ["peo1","peo2","peo3"]
	ctrls = ["ctr1"]
	ce_os = ["cer1","cer2","cer3","cer4"]
	mgms = ["mgm1"]

	net1 = [("cro1","cro2")]
	net2 = [("cro2","cro3")]
	net3 = [("cro3","cro1")]
	net4 = [("peo1","cro1")]
	net5 = [("cro2","peo2")]
	net6 = [("peo3","cro3")]
	net7 = [("cer1","peo1")]
	net8 = [("cer2","peo2")]
	net9 = [("cer3","peo3")]
	net10 = [("cro1","ctr1")]
	net11 = [("peo1","cer4")]
	net12 = [("mgm1","cro2")]

	vlls = [("cer1","cer2"), ("cer2","cer3"), ("cer3","cer1"), ("cer1","cer4")]
	pws = [("cer1","cer2"), ("cer2","cer3"), ("cer3","cer1"), ("cer1","cer4")]
	
	cr_prop = generator.getVerticesProperties(cr_os)
	pe_prop = generator.getVerticesProperties(pe_os)
	ct_prop = generator.getVerticesProperties(ctrls)
	ce_prop = generator.getVerticesProperties(ce_os)
	mg_prop = generator.getVerticesProperties(mgms)
	
	net1_properties = generator.getLinksProperties(net1)
	net2_properties = generator.getLinksProperties(net2)
	net3_properties = generator.getLinksProperties(net3)
	net4_properties = generator.getLinksProperties(net4)
	net5_properties = generator.getLinksProperties(net5)
	net6_properties = generator.getLinksProperties(net6)
	net7_properties = generator.getLinksProperties(net7)
	net8_properties = generator.getLinksProperties(net8)
	net9_properties = generator.getLinksProperties(net9)
	net10_properties = generator.getLinksProperties(net10)
	net11_properties = generator.getLinksProperties(net11)
	net12_properties = generator.getLinksProperties(net12)
	
	# XXX Ctrl and mgmt special case
	net10_properties[0].ingr.type = "INGRB"
	net10_properties[0].ingr.data = None
	net12_properties[0].ingr.type = "INGRB"
	net12_properties[0].ingr.data = None

	vlls_properties = []
	for vll in vlls:
		vll_properties = generator.getVLLsProperties(vll)
		vlls_properties.append(vll_properties)

	pws_properties = []
	for pw in pws:
		pw_properties = generator.getVLLsProperties(pw)
		pws_properties.append(pw_properties)
	
	print "*** Create Core OSHI"
	i = 0
	for i in range(0, len(cr_os)):
		cr_oshi = net.addCrOSHI(name = cr_os[i], params = cr_prop[i])
		i = i + 1
	print "*** Create Provider Edge OSHI"
	i = 0
	for i in range(0, len(pe_os)):
		pe_oshi = net.addPeOSHI(name = pe_os[i], params = pe_prop[i])
		i = i + 1
	print "*** Create Controllers"
	i = 0
	for i in range(0, len(ctrls)):
		ctrl = net.addController(name = ctrls[i])
		i = i + 1
	print "*** Create Customer Edge Router"
	i = 0
	for i in range(0, len(ce_os)):
		ce_router = net.addCeRouter(cid = 0, name = ce_os[i])
		i = i + 1
	print "*** Create Management Server"
	i = 0
	for i in range(0, len(mgms)):
		mgmt = net.addManagement(name = mgms[i])
		i = i + 1

	i = 0
	for link in net1:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net1_properties[i])
		i = i + 1

	i = 0
	for link in net2:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net2_properties[i])
		i = i + 1

	i = 0
	for link in net3:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net3_properties[i])
		i = i + 1

	i = 0
	for link in net4:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net4_properties[i])
		i = i + 1

	i = 0
	for link in net5:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net5_properties[i])
		i = i + 1

	i = 0
	for link in net6:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net6_properties[i])
		i = i + 1

	i = 0
	for link in net7:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net7_properties[i])
		i = i + 1

	i = 0
	for link in net8:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net8_properties[i])
		i = i + 1

	i = 0
	for link in net9:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net9_properties[i])
		i = i + 1

	i = 0
	for link in net10:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net10_properties[i])
		i = i + 1

	i = 0
	for link in net11:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net11_properties[i])
		i = i + 1

	i = 0
	for link in net12:
		lhs = net.getNodeByName(link[0])
		rhs = net.getNodeByName(link[1])
		net.addLink(lhs, rhs, net12_properties[i])
		i = i + 1

	net.addCoexistenceMechanism("COEXH", 0)

	i = 0
	for vll in vlls:
		lhs_cer = net.getNodeByName(vll[0])
		rhs_cer = net.getNodeByName(vll[1])
		net.addVLL(lhs_cer, rhs_cer, vlls_properties[i])
		i = i + 1

	i = 0
	for pw in pws:
		lhs_cer = net.getNodeByName(pw[0])
		rhs_cer = net.getNodeByName(pw[1])
		net.addPW(lhs_cer, rhs_cer, pws_properties[i])
		i = i + 1
	
	net.start()
	CLI(net)
	net.stop()
