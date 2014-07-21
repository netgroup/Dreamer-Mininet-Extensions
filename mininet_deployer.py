#!/usr/bin/python

from mininet_extensions import MininetOSHI
from utility import unmountAll, PropertiesGenerator
from mininet.cli import CLI




if __name__ == '__main__':

	verbose=True
	net = MininetOSHI(verbose)
	generator = PropertiesGenerator(False)
	cr_os = ["cro1","cro2","cro3"]
	pe_os = ["peo1","peo2","peo3"]
	ctrls = ["ctr1"]
	sws = ["swi1","swi2","swi3"]
	ce_os = ["cer1","cer2","cer3"]

	#net1 = [("cro1","cro2")]
	#net2 = [("cro2","cro3")]
	#net3 = [("cro3","cro1")]

	net1 = [("cro1","swi1"),("swi1","cro1"),("swi2","cro2"),("cro3","swi3"),("swi2","swi3"),("swi3","swi1"), ("swi2","swi1")]
	net2 = [("peo1","cro1")]
	net3 = [("cro2","peo2")]
	net4 = [("peo3","cro3")]
	net5 = [("cer1","peo1")]
	net6 = [("cer2","peo2")]
	net7 = [("cer3","peo3")]
	net8 = [("cro1","ctr1")]

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
	#net9_properties = generator.getLinksProperties(net9)
	#net10_properties = generator.getLinksProperties(net10)
	
	# XXX Ctrl special case
	net8_properties[0].ingr.type = "INGRB"
	net8_properties[0].ingr.data = None

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
	for i in range(0, len(ctrls)):
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

	"""i = 0
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
		i = i + 1"""

	net.addCoexistenceMechanism("COEXB", 0)

	i = 0
	for vll in vlls:
		lhs_cer = net.getNodeByName(vll[0])
		rhs_cer = net.getNodeByName(vll[1])
		net.addVLL(lhs_cer, rhs_cer, vlls_properties[i])
		i = i + 1
	
	net.start()
	CLI(net)
	net.stop()
