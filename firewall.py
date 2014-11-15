#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct
import socket


# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
	rule_list = makeRuleList(config)

	print ("rule_list:")
	for rule in rule_list:
		print(rule.verdict, rule.proto, rule.ext_ip, rule.ext_port, rule.domain_name)

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
	
	geoip_file = open('geoipdb.txt' ,"r")
	geoip_str_list = geoip_file.readlines()
	ip_list = []
	for line in geoip_str_list:
		split_line = line.split(" ")
		ip_list.append(split_line)
		#ip_list[line[2][0:2]] = (line[0], line[1])

	self.ip_list = ip_list
	#print (ip_list)

        # TODO: Also do some initialization if needed.
	return

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.

	print ("hi")
	pkt_src = struct.unpack("!L", pkt[12:16])[0]
	print ("country: ", find_country2(pkt_src, self.ip_list))

	current_packet = Packet(pkt)	

        pass

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
class Rule:
	def __init__(self, string):
		rule_line = string.split(" ")

		#cleanup extra spaces
		i = 0
		while (i < len(rule_line)):
			string = rule_line[i]
			if (len(string) < 1):
				rule_line.remove(string)
			else:
				i += 1

		#allocate strings to fields
		self.verdict = rule_line[0]
		self.proto = rule_line[1]

		if (self.proto == 'dns'):
			self.ext_ip = None
			self.ext_port = None
			self.domain_name = rule_line[2]
		else:
			self.ext_ip = rule_line[2]
			self.ext_port = rule_line[3]
			self.domain_name = None
			


	def compare(header):
		if (self.proto == "dns"):
			print("ugh")
			#compare dns stuff
		else:
			print ("idk")
			#compare p/i/p stuff

class Packet:
	def __init__(self, pkt):
		print ("packet:")
		pkt_src = struct.unpack("!L", pkt[12:16])
		print (pkt_src)

		#pkt_proto_num = struct.unpack("!L", pkt[9:10])
		pkt_proto_num = "1"

		print("proto num: ", pkt_proto_num) 
		if (pkt_proto_num == "1"):
			pkt_proto = "icmp"
		elif (pkt_proto_num == "6"):
			pkt_proto = "tcp"
		elif (pkt_proto_num == "17"):
			pkt_proto = "udp"


def makeRuleList(config):
	config_file = open(config['rule'],"r")
	rule_str_list = config_file.readlines()
	i = 0
	while (i < len(rule_str_list)):
		line = rule_str_list[i]
		if (line[0] == '%' or len(line.split(" ")) < 3):
			rule_str_list.remove(line)
		else:
			i += 1

	rule_list = []

	i -= 1
	while (i > -1):
		rule_line = rule_str_list[i]
		rule_list.append(Rule(rule_line))
		i -= 1 

	return rule_list


#compares two ip values in string format
#return 1 if 1st ip is greater, -1 if 2nd ip is greater
def ip_compare(ip1, ip2):
	ip1_split = ip1.split('.')
	ip2_split = ip2.split('.')
	i = 0
	while (i < len(ip1_split)):
		ip1_curNum = ip1_split[i]
		ip2_curNum = ip2_split[i]
		if (ip1_curNum > ip2_curNum):
			return 1
		elif (ip1_curNum < ip2_curNum):
			return -1

	return 0

def ip_to_int(ip_str):
	split = ip_str.split('.')
	#return 100000000 #(split[0] * 16777216) + (split[1] * 65536) + (split[2] * 256) + (split[3])
	return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def find_country(ip, geoip_list):
	for line in geoip_list:
		#print(line)
		min_ip = ip_to_int(line[0])
		max_ip = ip_to_int(line[1])
		print("ip:    ", ip)
		print("min_ip:", min_ip)
		print("max_ip:", max_ip)
		print("min is below:", min_ip <= ip)
		print("max is above:", max_ip >= ip)
		print
		if (min_ip <= ip and max_ip >= ip):
			print("FOUND COUNTRY")
			return line[2]
	return "No country found"
		


def find_country2(ip, geoip_list):
	ip_str = socket.inet_ntoa(struct.pack("!I", ip))  
	for line in geoip_list:
		min_cmp = ip_compare(ip_str, line[0])
		max_cmp = ip_compare(ip_str, line[1])

		#print(line)
		#print(ip_str)
		#print("min_cmp:", min_cmp)
		#print("max_cmp:", max_cmp)
		#print

		if ((min_cmp == 1 and max_cmp == -1) or min_cmp == 0 or max_cmp == 0):
			return line[2]
		


