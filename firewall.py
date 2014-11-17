#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct
import socket


# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Packet:
    def __init__(self, pkt, pkt_dir):
        pkt_proto_num = struct.unpack("!B", pkt[9:10])[0]
        self.pkt = pkt
        self.drop_pkt = False
        self.pkt_dir = pkt_dir


        #last four bits of first byte
        ip_header_len =  struct.unpack("!B", pkt[0:1])[0] & 0x0F
        if ip_header_len < 5:
            drop_pkt = true
        else:
            #beginning of next header == headerlen * 4
            #this is where the next header begins
            self.next_header_begin = ip_header_len * 4



      #set external_ip
        if pkt_dir == PKT_DIR_INCOMING:
            self.ext_ip = struct.unpack('!L', pkt[12:16])[0]
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.ext_ip = struct.unpack('!L', pkt[16:20])[0]

        #after getting the protocols, get the source and destination ports from the right places
        if (pkt_proto_num == 1):
            self.pkt_proto = "icmp"
            self.port = self.getType(pkt)
        elif (pkt_proto_num == 6):
            self.pkt_proto = "tcp"
            self.port = self.getPorts(pkt, pkt_dir)
        elif (pkt_proto_num == 17):
            self.pkt_proto = "udp"
            self.port = self.getPorts(pkt, pkt_dir)
        else:
            self.pkt_proto = "other"
            #it doesn't matter what the port is if the pkt_proto is 'any'
            self.port = 'other'
            # just pass this


    def drop(self):
        #drop packet under certain conditions
        return self.drop_pkt


    def getPorts(self, pkt, pkt_dir):
        byte_begin = self.next_header_begin
        if (pkt_dir == 'incoming'):
            # incoming, examine source (0:2)
            return struct.unpack("!H", pkt[byte_begin:(byte_begin + 2)])[0]

        else:
            #outgoing, examine destination (2:4)
            return struct.unpack("!H", pkt[(byte_begin + 2):(byte_begin+4)])[0]

    # for ICMP, the type is the port
    def getType(self, pkt):

        byte_begin = self.next_header_begin
        return struct.unpack("!B", pkt[byte_begin:(byte_begin + 1)])[0]

class Rule:
    def __init__(self, string, geoip_list):
        self.geoip_list = geoip_list
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
        self.proto = rule_line[1].lower()

        if (self.proto == 'dns'):
            self.ext_ip = None
            self.ext_port = None
            self.domain_name = rule_line[2]
        else:
            self.ext_ip = rule_line[2]
            self.ext_port = rule_line[3]
            self.domain_name = None



    def compare(self,cur_packet):
        #if packet protocol is not tcp, icmp, or udp, just pass

        #pass the packet if the current packet proto is any
        if (cur_packet.pkt_proto == 'other'):
            return 1

        if (self.proto == 'dns'):
            if (cur_packet.pkt_dir == PKT_DIR_OUTGOING and cur_packet.port == 53):

                #dns information after ipv4 header and udp header = ~20 bytes + 8 bytes
                byte_dns_begin = cur_packet.next_header_begin + 8
                byte_dns_header_ends = cur_packet.next_header_begin + 8 + 12
                #examine qd count in header
                qd_count = struct.unpack("!H", cur_packet.pkt[(byte_dns_begin + 4):(byte_dns_begin + 6)])[0]


                if (qd_count == 1):

                    #You apply DNS rules only for DNS query packets
                    byte_dns_begin = cur_packet.next_header_begin + 8
                    byte_dns_header_ends = cur_packet.next_header_begin + 8 + 12
                    # It is an outgoing UDP packet with destination port 53
                    qd_count = struct.unpack("!B", cur_packet.pkt[(byte_dns_begin + 4):(byte_dns_begin + 5)])[0]
                    qname_index = byte_dns_header_ends
                    qname_i_holder = qname_index
                    result_str = ""
                    punct_countdown = ord(cur_packet.pkt[qname_index])
                    qname_index += 1
                    while ord(cur_packet.pkt[qname_index])!= 00:

                        if (punct_countdown != 0):
                            result_str += chr(ord(cur_packet.pkt[qname_index]))
                        else:
                            result_str += '.'
                            punct_countdown = ord(cur_packet.pkt[qname_index]) + 1
                        qname_index += 1
                        punct_countdown -= 1

                    index_diff = qname_index - qname_i_holder
                    qtype = struct.unpack("!H", cur_packet.pkt[(qname_index + 1):(qname_index + 3)])[0]

                    if (qtype == 1 or qtype == 28):
                        qclass = struct.unpack("!H", cur_packet.pkt[(qname_index + 3):(qname_index + 5)])[0]

                        if qclass == 1:
                            # apply dns rules to this packet
                            matching = False

                            if (self.domain_name == 'any' or self.domain_name == 'any\n'):
                                matching = True
                            else :


                                if ('\n' in self.domain_name):
                                    self.domain_name = self.domain_name[:-1]

                                astk_pos = self.domain_name.find('*')

                                if (astk_pos != -1):
                                    matching = result_str.find(self.domain_name[1:]) != -1
                                else:
                                    if ('www.' in result_str):
                                        matching = result_str[4:] == self.domain_name
                                    else:
                                        matching = result_str == self.domain_name

                            if (matching):
                                if (self.verdict == 'drop'):
                                    #drop if rest of the rules match
                                    return -1
                                elif (self.verdict == 'pass'):
                                    #pass if rest of the rules match
                                    return 1
                            else:
                                return 0

            return 0



        else:
            compare_array = []
            if (self.proto == cur_packet.pkt_proto):
                compare_array.append(1)
            if (self.port_compare(self.ext_port,cur_packet.port)==1):
                compare_array.append(1)
            if (self.ext_ip_compare(self.ext_ip, cur_packet.ext_ip) == 1):
                compare_array.append(1)

            if (len(compare_array) == 3):
                # rule match!
                if (self.verdict == 'drop'):
                    #drop if rest of the rules match
                    return -1
                elif (self.verdict == 'pass'):
                    #pass if rest of the rules match
                    return 1
            # didn't match the entire rule, doesn't apply, move on to next rule
            return 0


    def port_compare(self,rule_port, packet_port):
        if (rule_port == 'any' or rule_port == 'any\n'):
            return 1

        elif (rule_port.find('-') == -1):
            # single value
            if (rule_port == packet_port):
                return 1
        elif (rule_port.find('-') != -1):
            #range of ports
            nums = rule_port.split('-')
            if (packet_port>=nums[0] and packet_port <= nums[1]):
                # packet_port in between the rule_port, inclusive
                return 1
            else:
                return -1




    def ext_ip_compare(self, rule_ip, packet_ip):
        slash_position = rule_ip.find('/')
        if (rule_ip == 'any'):
            return 1
        elif (len(rule_ip) == 2):
            #country code
            return self.does_ip_match_country(packet_ip, rule_ip, self.geoip_list)
        elif (slash_position != -1):
            #range of packets
            set_bits = int(rule_ip[slash_position + 1:], 10)
            mask = form_mask(set_bits)
            min_str = rule_ip[:slash_position]
            min_int = self.ip_to_int(min_str)

            max_int = min_int | mask

            packet_ip = self.ip_to_int(packet_ip)
            return packet_ip >= min_int and packet_ip <= max_int
        else:
            #rule is just a regular ip
            int_rule_ip = self.ip_to_int(rule_ip)
            return int_rule_ip == packet_ip


    def form_mask(bits_set):
        result = ""
        i = 0
        while i < 32:
            if (i < bits_set):
                result += "0"
            else:
                result += "1"
            i += 1
        return int(result, 2)



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
            i += 1

        return 0



    def does_ip_match_country(self, ip_int, country, geoip_list):
        ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
        coun_upper = country.upper()
        for line in geoip_list:
            if (line[2][0] == coun_upper[0] and line[2][1] == coun_upper[1]):
                if (line[0] <= ip_str and line[1] >= ip_str):
                    return 1
        return 0


    def ip_to_int(self, ip_str):
        split = ip_str.split('.')
        return (int(split[0]) * 16777216) + (int(split[1]) * 65536) + (int(split[2]) * 256) + (int(split[3]))



class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.ip_list = self.getGeoList()

        self.rule_list = self.makeRuleList(config)



    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        current_packet = Packet(pkt, pkt_dir)

        if not current_packet.drop():
            # compare packet details to the rules
            if (len(self.rule_list) > 0):
                i = 0
                for rule in self.rule_list:
                    i +=1

                    decision = rule.compare(current_packet)
                    if decision == 1:
                        # allow packet to pass
                        if pkt_dir == PKT_DIR_INCOMING:
                            self.iface_int.send_ip_packet(pkt)
                        elif pkt_dir == PKT_DIR_OUTGOING:
                            self.iface_ext.send_ip_packet(pkt)
                    elif decision == -1:
                        return


            # doesn't match any rule ... pass
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)


    # Helper method to get the country codes
    def getGeoList(self):
        geoip_file = open('geoipdb.txt' ,"r")
        geoip_str_list = geoip_file.readlines()
        ip_list = []
        for line in geoip_str_list:
            split_line = line.split(" ")
            ip_list.append(split_line)
        return ip_list

    def makeRuleList(self,config):
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
            rule_list.append(Rule(rule_line, self.ip_list))
            i -= 1

        return rule_list


