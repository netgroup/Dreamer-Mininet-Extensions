#!/usr/bin/python

from mininet_extensions import MininetOSHI
from utility import unmountAll, PropertiesGenerator
import subprocess


def test_add_nodes_and_add_link():

	verbose=True
	net = MininetOSHI(verbose)
	generator = PropertiesGenerator(False)
	cr_os = ["cro1","cro2","cro3"]
	pe_os = ["peo1","peo2","peo3"]
	ctrls = ["ctr1","ctr2","ctr3"]
	sws = ["swi1","swi2","swi3"]
	ce_os = ["cer1","cer2","cer3"]

	net1 = [("cro1","swi1"),("swi1","cro2"),("cro3","swi1")]
	net2 = [("peo1","cro1")]
	net3 = [("cro2","peo2")]
	net4 = [("peo3","cro3")]
	net5 = [("cer1","peo1")]
	net6 = [("cer2","peo2")]
	net7 = [("cer3","peo3")]
	net8 = [("cro1","ctr1")]
	net9 = [("ctr2","cro2")]
	net10 = [("cro3","ctr3")]

	vlls = [("cer1","cer2"), ("cer2","cer3"), ("cer3","cer1")]
	
	cr_prop = generator.getVerticesProperties(cr_os)
	pe_prop = generator.getVerticesProperties(pe_os)
	ct_prop = generator.getVerticesProperties(ctrls)
	sw_prop = generator.getVerticesProperties(sws)
	ce_prop = generator.getVerticesProperties(ce_os)
	
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

	vlls_properties = []
	for vll in vlls:
		vll_properties = generator.getVLLsProperties(vll)
		vlls_properties.append(vll_properties)
	
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
	print "*** Create LegacyL2Switch"
	i = 0
	for i in range(0, len(sws)):
		switch = net.addSwitch(name = sws[i])
		i = i + 1
	print "*** Create Controllers"
	i = 0
	for i in range(0, len(cr_os)):
		ctrl = net.addController(name = ctrls[i])
		i = i + 1
	print "*** Create Customer Edge Router"
	i = 0
	for i in range(0, len(ce_os)):
		ce_router = net.addCeRouter(name = ce_os[i])
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
	
	net.start()
	print "*** Press any key to continue"
	a=raw_input()
	net.stop()

	subprocess.call(["sudo", "mn", "-c"], stdout=None, stderr=None)
	unmountAll()


def test_properties_generator():

	verbose=True
	net = MininetOSHI(verbose)
	generator = PropertiesGenerator(False)
	cr_os = ["cro1","cro2","cro3"]
	pe_os = ["peo1","peo2","peo3"]
	ctrls = ["ctr1","ctr2","ctr3"]
	sws = ["swi1","swi2","swi3"]
	ce_os = ["cer1","cer2","cer3"]
	mgm_os = ["mgm1"]

	net1 = [("cro1","swi1"),("swi1","cro2"),("cro3","swi1")]
	net2 = [("peo1","cro1")]
	net3 = [("cro2","peo2")]
	net4 = [("peo3","cro3")]
	net5 = [("cer1","peo1")]
	net6 = [("cer2","peo2")]
	net7 = [("cer3","peo3")]
	net8 = [("cro1","mgm1")]
	
	print "Vertices Properties"
	cr_prop = generator.getVerticesProperties(cr_os)
	i = 0
	for cr_property in cr_prop:
		print "%s -> %s" %(cr_os[i], cr_property)
		i = i + 1
	i = 0
	pe_prop = generator.getVerticesProperties(pe_os)
	i = 0
	for pe_property in pe_prop:
		print "%s -> %s" %(pe_os[i], pe_property)
		i = i + 1
	i = 0	
	ct_prop = generator.getVerticesProperties(ctrls)
	i = 0
	for ct_property in ct_prop:
		print "%s -> %s" %(ctrls[i], ct_property)
		i = i + 1
	i = 0	
	sw_prop = generator.getVerticesProperties(sws)
	i = 0
	for sw_property in sw_prop:
		print "%s -> %s" %(sws[i], sw_property)
		i = i + 1
	i = 0
	ce_prop = generator.getVerticesProperties(ce_os)
	i = 0
	for ce_property in ce_prop:
		print "%s -> %s" %(ce_os[i], ce_property)
		i = i + 1
	i = 0
	mgm_prop = generator.getVerticesProperties(mgm_os)
	for mgm_property in mgm_prop:
		print "%s -> %s" %(mgm_os[i], mgm_property)
		i = i + 1
	print "###################################################"

	properties = generator.getLinksProperties(net1)
	print "Net1 Properties"
	i = 0
	for l_property in properties:
		print "%s -> %s" %(net1[i],l_property)
		i = i + 1

	properties = generator.getLinksProperties(net2)
	print "Net2 Properties"
	i = 0
	for l_property in properties:
		print "%s -> %s" %(net2[i],l_property)
		i = i + 1

	properties = generator.getLinksProperties(net3)
	print "Net3 Properties"
	i = 0
	for l_property in properties:
		print "%s -> %s" %(net3[i],l_property)
		i = i + 1

	properties = generator.getLinksProperties(net4)
	print "Net4 Properties"
	i = 0
	for l_property in properties:
		print "%s -> %s" %(net4[i],l_property)
		i = i + 1

	properties = generator.getLinksProperties(net5)
	print "Net5 Properties"
	i = 0
	for l_property in properties:
		print "%s -> %s" %(net5[i],l_property)
		i = i + 1

	properties = generator.getLinksProperties(net6)
	print "Net6 Properties"
	i = 0
	for l_property in properties:
		print "%s -> %s" %(net6[i],l_property)
		i = i + 1

	properties = generator.getLinksProperties(net7)
	print "Net7 Properties"
	i = 0
	for l_property in properties:
		print "%s -> %s" %(net7[i],l_property)
		i = i + 1
	properties = generator.getLinksProperties(net8)
	print "Net8 Properties"
	i = 0
	for l_property in properties:
		print "%s -> %s" %(net8[i],l_property)
		i = i + 1
	print "###################################################"

	print "VLLs Properties"
	vlls = [("cer1","cer2"), ("cer2","cer3"), ("cer3","cer1")]
	for vll in vlls:
		print "%s -> %s" %(vll, generator.getVLLsProperties(vll))
	print "###################################################"

	subprocess.call(["sudo", "mn", "-c"], stdout=None, stderr=None)
	unmountAll()


if __name__ == '__main__':

	test_properties_generator()
