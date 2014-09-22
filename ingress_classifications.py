#!/usr/bin/python

class IngressClassification (object):
	
	prio_std_rules = 300
	
	def __init__(self, eth, vi, name):
		self.eth = eth
		self.vi = vi
		self.name = name

class IngrB_CoexA(IngressClassification):

	tableIP =1

	def __init__(self, eth, vi, coexData, name):
		IngressClassification.__init__(self, eth, vi, name)
		self.vlanIP = coexData
	
	def getOVSRules(self):

		rules = []
		
		rules.append('ovs-ofctl add-flow %s "table=0,hard_timeout=0,priority=%s,in_port=%s,actions=mod_vlan_vid:%s,resubmit(,%s)"' %(self.name, 
		self.prio_std_rules, self.eth, self.vlanIP, self.tableIP))
		rules.append('ovs-ofctl add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,actions=strip_vlan,output:%s"' %(self.name, self.tableIP, 
		self.prio_std_rules, self.vi, self.eth))

		return rules

class IngrB_CoexA_13(IngrB_CoexA):

	def __init__(self, eth, vi, coexData, name):
		IngrB_CoexA.__init__(self, eth, vi, coexData, name)
	
	def getOVSRules(self):

		rules = []
		
		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=0,hard_timeout=0,priority=%s,in_port=%s,actions=mod_vlan_vid:%s,goto_table:%s"' %(self.name, 
		self.prio_std_rules, self.eth, self.vlanIP, self.tableIP))
		rules.append('ovs-ofctl -O OpenFlow13 add-flow %s "table=%s,hard_timeout=0,priority=%s,in_port=%s,actions=strip_vlan,output:%s"' %(self.name, self.tableIP, 
		self.prio_std_rules, self.vi, self.eth))

		return rules		

class IngrB_CoexB(IngressClassification):

	def __init__(self, eth, vi, name):
		IngressClassification.__init__(self, eth, vi, name)
	
	def getOVSRules(self):

		rules = []

		return rules

class IngrB_CoexH(IngressClassification):

	def __init__(self, eth, vi, name):
		IngressClassification.__init__(self, eth, vi, name)
	
	def getOVSRules(self):

		rules = []

		return rules

class IngressFactory(object):

	coex_types=["COEXA", "COEXB", "COEXH"]
	ingress_types=["INGRB"]

	def getIngr(self, coex_type, coex_data, ingress_type, ingress_data, eth, vi, name, OF_V):

		if coex_type not in self.coex_types:
			error("ERROR %s not supported" % coex_type)
			sys.exit(-2)

		if ingress_type not in self.ingress_types:
			error("ERROR %s not supported" % ingress_type)
			sys.exit(-2)
		
		if coex_type == "COEXA" and ingress_type == "INGRB":
			if OF_V == None:
				return IngrB_CoexA(eth, vi, coex_data, name)
			elif OF_V == "OpenFlow13":
				return IngrB_CoexA_13(eth, vi, coex_data, name)

		if coex_type == "COEXB" and ingress_type == "INGRB":
			return IngrB_CoexB(eth, vi, name)

		if coex_type == "COEXH" and ingress_type == "INGRB":
			if OF_V == None:
				error("ERROR %s is not supported by OpenFlow 1.0" % coex_type)
				sys.exit(-2)
			elif OF_V == "OpenFlow13":
				return IngrB_CoexH(eth, vi, name)

