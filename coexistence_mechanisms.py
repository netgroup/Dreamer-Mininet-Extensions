#!/usr/bin/python

import sys

from mininet.log import error

class CoexistenceMechanism (object):

	prio_std_rules = 300
	prio_special_rules = 301
	prio_max = 32768
	
	def __init__(self, eths, vis, name):
		self.eths = eths
		self.vis = vis
		self.name = name

class CoexA(CoexistenceMechanism):

	tableIP = 1
	tableSBP = 0
	
	def __init__(self, vlan_id, eths, vis, name):
		if vlan_id > 4095:
			error("ERROR VLAN ID Not Valid\n")
			sys.exit(-2)
		self.vlanIP = vlan_id
		CoexistenceMechanism.__init__(self, eths, vis, name)
	
	def getOVSRules(self):

		rules = []

		rules.append('ovs-ofctl add-flow %s "table=0,hard_timeout=0,priority=%s,dl_vlan=%s,actions=resubmit(,%s)"' %(self.name, self.prio_std_rules, 
		self.vlanIP, self.tableIP))
		
		for eth, vi in zip(self.eths, self.vis):
			rules.append('ovs-ofctl add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, self.tableIP, 
			self.prio_std_rules, eth, vi))
			rules.append('ovs-ofctl add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, self.tableIP, 
			self.prio_std_rules, vi, eth))
    	
		rules.append('ovs-ofctl add-flow %s "table=%s,hard_timeout=0,priority=%s,dl_type=0x88cc,action=controller"' %(self.name, self.tableIP, 
		self.prio_special_rules))
		rules.append('ovs-ofctl add-flow %s "table=%s,hard_timeout=0,priority=%s,dl_type=0x8942,action=controller"' %(self.name, self.tableIP, 
		self.prio_special_rules))

		return rules

	def getIPCommands(self):
		
		commands = []

		for eth, vi in zip(self.eths, self.vis):

			commands.append('ifconfig %s 0' % eth)
			commands.append('ip link set %s up' % vi)
			commands.append('vconfig add %s %s' % (vi, self.vlanIP))

		return commands
			
	def getQuaggaInterfaces(self):

		interfaces = []

		for vi in self.vis:

			interfaces.append("%s.%s" %(vi, self.vlanIP))

		return interfaces


class CoexA_13(CoexA):

	
	def __init__(self, vlan_id, eths, vis, name):
		CoexA.__init__(self, vlan_id, eths, vis, name)
	
	def getOVSRules(self):

		rules = []

		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=0,hard_timeout=0,priority=%s,dl_vlan=%s,actions=goto_table:%s"' %(self.name, 
		self.prio_std_rules, self.vlanIP, self.tableIP))
		
		for eth, vi in zip(self.eths, self.vis):
			rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, 
			self.tableIP, self.prio_std_rules, eth, vi))
			rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, 
			self.tableIP, self.prio_std_rules, vi, eth))
    	
		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=%s,hard_timeout=0,priority=%s,dl_type=0x88cc,action=controller"' %(self.name, 
		self.tableIP, self.prio_special_rules))
		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=%s,hard_timeout=0,priority=%s,dl_type=0x8942,action=controller"' %(self.name, 
		self.tableIP, self.prio_special_rules))

		return rules


class CoexB(CoexistenceMechanism):
	
	tableIP = 1	
	tableSBP = 0

	def __init__(self, eths, vis, name):
		CoexistenceMechanism.__init__(self, eths, vis, name)

	def getOVSRules(self):

		rules = []

		rules.append('ovs-ofctl add-flow %s "table=0,hard_timeout=0,priority=%s,dl_vlan=%s,actions=resubmit(,%s)"' %(self.name, self.prio_std_rules, 
		"0xffff", self.tableIP))

		for eth, vi in zip(self.eths, self.vis):
			rules.append('ovs-ofctl add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, self.tableIP, 
			self.prio_std_rules, eth, vi))
			rules.append('ovs-ofctl add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, self.tableIP, 
			self.prio_std_rules, vi, eth))

		rules.append('ovs-ofctl add-flow %s "table=%s,hard_timeout=0,priority=%s,dl_type=0x88cc,action=controller"' %(self.name, self.tableIP, 
		self.prio_special_rules))
		rules.append('ovs-ofctl add-flow %s "table=%s,hard_timeout=0,priority=%s,dl_type=0x8942,action=controller"' %(self.name, self.tableIP, 
		self.prio_special_rules))		

		return rules

	def getIPCommands(self):
		
		commands = []

		for eth, vi in zip(self.eths, self.vis):

			commands.append('ifconfig %s 0' % eth)

		return commands
			
	def getQuaggaInterfaces(self):

		interfaces = self.vis

		return interfaces

class CoexB_13(CoexB):
		
	def __init__(self, eths, vis, name):
		CoexB.__init__(self, eths, vis, name)

	def getOVSRules(self):

		rules = []

		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=0,hard_timeout=0,priority=%s,dl_vlan=%s,actions=goto_table:%s"' %(self.name, 
		self.prio_std_rules, "0xffff", self.tableIP))

		for eth, vi in zip(self.eths, self.vis):
			rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, 
			self.tableIP, self.prio_std_rules, eth, vi))
			rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, 
			self.tableIP, self.prio_std_rules, vi, eth))

		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=%s,hard_timeout=0,priority=%s,dl_type=0x88cc,action=controller"' %(self.name, 
		self.tableIP, self.prio_special_rules))
		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=%s,hard_timeout=0,priority=%s,dl_type=0x8942,action=controller"' %(self.name, 
		self.tableIP, self.prio_special_rules))		

		return rules

class CoexH(CoexistenceMechanism):
	
	tableIP=0
	tableSBP = 1
	MPLS_UNICAST = "0x8847"
	MPLS_MULTICAST = "0x8848"

	def __init__(self, eths, vis, name):
		CoexistenceMechanism.__init__(self, eths, vis, name)

	def getOVSRules(self):

		rules = []

		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=0,hard_timeout=0,priority=%s,dl_type=%s,actions=goto_table:%s"' %(self.name, 
		self.prio_max, self.MPLS_UNICAST, self.tableSBP))
		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=0,hard_timeout=0,priority=%s,dl_type=%s,actions=goto_table:%s"' %(self.name, 
		self.prio_max, self.MPLS_MULTICAST, self.tableSBP))

		for eth, vi in zip(self.eths, self.vis):
			rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=0,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, 
			self.prio_std_rules, eth, vi))
			rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=0,hard_timeout=0,priority=%s,in_port=%s,action=output:%s"' %(self.name, 
			self.prio_std_rules, vi, eth))

		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=0,hard_timeout=0,priority=%s,dl_type=0x88cc,action=controller"' %(self.name, 
		self.prio_special_rules))
		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=0,hard_timeout=0,priority=%s,dl_type=0x8942,action=controller"' %(self.name,
		self.prio_special_rules))		

		return rules

	def getIPCommands(self):
		
		commands = []

		for eth, vi in zip(self.eths, self.vis):

			commands.append('ifconfig %s 0' % eth)

		return commands
			
	def getQuaggaInterfaces(self):

		interfaces = self.vis

		return interfaces


class CoexFactory(object):

	coex_types=["COEXA", "COEXB", "COEXH"]

	def getCoex(self, coex_type, coex_data, eths, vis, name, OF_V):
		if coex_type not in self.coex_types:
			error("ERROR %s not supported" % coex_type)
			sys.exit(-2)
		
		if coex_type == "COEXA":
			if OF_V == None:
				return CoexA(coex_data, eths, vis, name)
			elif OF_V == "OpenFlow13":
				return CoexA_13(coex_data, eths, vis, name)

		if coex_type == "COEXB":
			if OF_V == None:
				return CoexB(eths, vis, name)
			elif OF_V == "OpenFlow13":
				return CoexB_13(eths, vis, name)

		if coex_type == "COEXH":
			if OF_V == None:
				error("ERROR %s is not supported by OpenFlow 1.0" % coex_type)
				sys.exit(-2)
			elif OF_V == "OpenFlow13":
				return CoexH(eths, vis, name)
		
