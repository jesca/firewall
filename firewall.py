#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct


# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Packet:
    def __init__(self, pkt, pkt_dir):
        pkt_proto_num = struct.unpack("!B", pkt[9:10])
        self.drop_pkt = false


        #last four bits of first byte
        ip_header_len =  struct.unpack("!B", pkt[0:1]) & 0x0F
        if ip_header_len < 5:
            drop_pkt = true
        else:
            #beginning of next header == headerlen * 4
            #this is where the next header begins
            self.next_header_begin = ip_header_len * 4

        #after getting the protocols, get the source and destination ports from the right places
        if (pkt_proto_num == "1"):
            self.pkt_proto = "icmp"
            self.port = self.getType()
        elif (pkt_proto_num == "6"):
            self.pkt_proto = "tcp"
            self.port = self.getPorts()
        elif (pkt_proto_num == "17"):
            self.pkt_proto = "udp"
            self.port = self.getPorts()
        else:
            self.pkt_proto = "any"
            # just pass this


    def dropPacket():
        #drop packet under certain conditions
        return self.drop_pkt


    def getPorts():
        byte_begin = self.next_header_begin
        if (pkt_dir == 'incoming'):
            # incoming, examine source (0:2)
            port = struct.unpack("!H", pkt[byte_begin:(byte_begin + 2)])

        else:
            #outgoing, examine destination (2:4)
            port = struct.unpack("!H", pkt[(byte_begin + 2):(byte_begin+4)])

    # for ICMP, the type is the port
    def getImcpType():
        # high 4 bits (0:1) >> 4
        byte_begin = self.next_header_begin
        port = struct.unpack("!L", pkt[byte_begin:(byte_begin + 1)]) >> 4

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



    def compare(cur_packet):
        return 1


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

 	    self.rule_list = makeRuleList(config)
	    print ("rule_list:")
	    for rule in rule_list:
            print(rule.verdict, rule.proto, rule.ext_ip, rule.ext_port, rule.domain_name)

	    self.ip_list = self.getGeoList()

    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.

        # country src
	    pkt_src = struct.unpack("!L", pkt[12:16])[0]

        if current_packet.drop():
            # packet needs to be dropped for whatever reason before comparing the rules
            self.iface_int.send_ip_packet()
        else:
            # compare packet details to the rules
            if (len(self.rule_list) > 0):
                for rule in self.rule_list:
                    decision = rule.compare(current_packet)
                    if decision == -1:
                        #packet should be dropped
                        self.iface_int.send_ip_packet()
                    elif decision == 1:
                        # allow packet to pass
                        print 'Passing Packet'
                        if pkt_dir == PKT_DIR_INCOMING:
                            self.iface_int.send_ip_packet(pkt)
                        elif pkt_dir == PKT_DIR_OUTGOING:
                            self.iface_ext.send_ip_packet(pkt)
            else:
                # no rules, pass all packets
                print("empty rule list")
                    if pkt_dir == PKT_DIR_INCOMING:
                        self.iface_int.send_ip_packet(pkt)
                    elif pkt_dir == PKT_DIR_OUTGOING:
                        self.iface_ext.send_ip_packet(pkt)




    # Helper method to get the country codes
    def getGeoList():
        geoip_file = open('geoipdb.txt' ,"r")
        geoip_str_list = geoip_file.readlines()
        ip_list = []
        for line in geoip_str_list:
            split_line = line.split(" ")
            ip_list.append(split_line)
        return ip_list

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
        return (split[0] * 16777216) + (split[1] * 65536) + (split[2] * 256) + (split[3])


    def find_country(ip, geoip_list):
        for line in geoip_list:
            print(line)
            min_ip = ip_to_int(line[0])
            max_ip = ip_to_int(line[1])
            if (ip >= min_ip and ip <= max_ip):
                return line[2]



    def find_country2(ip, geoip_list):
        for line in geoip_list:
            min_cmp = ip_compare(ip, line[0])
            max_cmp = ip_compare(ip, line[1])
            if ((min_cmp == 1 and max_cmp == -1) or min_cmp == 0 or max_cmp == 0):
                return line[2]
