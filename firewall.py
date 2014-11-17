#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct


# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Packet:
    def __init__(self, pkt, pkt_dir):
        pkt_proto_num = struct.unpack("!B", pkt[9:10])[0]
        self.drop_pkt = False
        self.pkt_dir = pkt_dir


        #last four bits of first byte
        #ord(a)???
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
            print 'setting port to via type.', self.port
        elif (pkt_proto_num == 6):
            self.pkt_proto = "tcp"
            self.port = self.getPorts(pkt, pkt_dir)
            print 'setting port to via getport', self.port
        elif (pkt_proto_num == 17):
            self.pkt_proto = "udp"
            self.port = self.getPorts(pkt, pkt_dir)
            print 'setting port to via getport', self.port
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
        #returns -1 to drop
        #else return 1 go pass

        #check port, ext port, ext ip address

        print 'packet_proto:', cur_packet.pkt_proto, ' packet_ip: ', cur_packet.ext_ip, ' packet_port: ',  cur_packet.port
        print 'rule_proto:', self.proto, 'rule_ip', self.ext_ip, ' rule_port:', self.ext_port
        #if packet protocol is not tcp, icmp, or udp, just pass

        #pass the packet if the current packet proto is any
        if (cur_packet.pkt_proto == 'other'):
            "other type of packet we aren't dealing with"
            return 1

        if (self.proto == 'dns'):
            #You apply DNS rules only for DNS query packets
            dns_rule = False
            # It is an outgoing UDP packet with destination port 53
            print "dns..."
            if (current_packet.pkt_dir == 'outgoing' and current_packet.port == 53):
                """ It has exactly one DNS question entry.
                ○ There may be other non­empty sections (Answer, Authority, and Additional)
                ● The query type of the entry is either A or AAAA (QTYPE == 1 or QTYPE == 28), and
                ● The class of the entry is Internet (QCLASS == 1).
                """

                #dns information after ipv4 header and udp header = ~20 bytes + 8 bytes
                byte_dns_begin = cur_packet.next_header_begin + 8
                byte_dns_header_ends = cur_packet.next_header_begin + 8 + 12
                #examine qd count in header
                qd_count = struct.unpack("!B", pkt[(byte_dns_begin + 4):(byte_dns_begin + 5)])[0]
                print 'got qd count: ', qd_count
                if (qd_count == 1):
                      #assuming the qtype is 2 bits away ... there may be a bug here
                      qtype = struct.unpack("!H", pkt[(byte_dns_header_ends + 2):(byte_dns_header_ends+4)])[0]
                      if (qtype == 1 or qtype == 28):
                          qclass = struct.unpack("!H", pkt[(byte_dns_header_ends + 4):(byte_dns_header_ends+6)])[0]
                          if qclass == 1:
                              # apply dns rules to this packet
                              dns_rule = True

            if (dns_rule == True):
                #criteria met, do the dns thing
                






        else:
            compare_array = []
            if (self.proto == cur_packet.pkt_proto):
                print 'protos same'
                compare_array.append(1)
            if (self.port_compare(self.ext_port,cur_packet.port)==1):
                print 'ports same'
                compare_array.append(1)
            if (self.ext_ip_compare(self.ext_ip, cur_packet.ext_ip) == 1):
                print 'ext same'
                compare_array.append(1)

            print "heres the compare_array", compare_array
            if (len(compare_array) == 3):
                # rule match!
                if (self.verdict == 'drop'):
                    print 'everything matched, verdict drop'
                    #drop if rest of the rules match
                    return -1
                elif (self.verdict == 'pass'):
                    print 'everything matched, verdict pass'
                    #pass if rest of the rules match
                    return 1
            # didn't match the entire rule, doesn't apply, move on to next rule


            return 0


    def port_compare(self,rule_port, packet_port):
        print 'comparing ports:', packet_port, rule_port
        if (rule_port == 'any' or rule_port == 'any\n'):
            print 'rule port is any'
            return 1

        #shouldn't reach here because compare should have returned by now
        #if (packet_port == 'other'):
            #not tcp, imcp, or udp, just pass it
        #    return 1
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
        else:
            print "port_compare error, unrecognizable rule port type"




    def ext_ip_compare(self, rule_ip, packet_ip):
        slash_position = rule_ip.find('/')
        if (rule_ip == 'any'):
            return 1
        elif (rule_ip.isupper() and len(rule_ip) == 2):
            #country code
            return find_country2(packet_ip) == rule_ip.upper()
        elif (slash_position != -1):
            #range of packets
            print("range mode")
            set_bits = rule_ip[slash_position + 1:]
            mask = form_mask(set_bits)
            min_str = rule_ip[:slash_position]
            min_int = ip_to_int(min_str)

            max_int = min_int | mask
            return packet_ip >= lower_int and packet_ip <= upper_int
        else:
            #rule is just a regular ip
            int_rule_ip = ip_to_int(rule_ip)
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


    def find_country2(ip, geoip_list):
        for line in geoip_list:
            min_cmp = ip_compare(ip, line[0])
            max_cmp = ip_compare(ip, line[1])
            if ((min_cmp == 1 and max_cmp == -1) or min_cmp == 0 or max_cmp == 0):
                return line[2]

    def ip_to_int(ip_str):
        split = ip_str.split('.')
        return (int(split[0]) * 16777216) + (int(split[1]) * 65536) + (int(split[2]) * 256) + (int(split[3]))



class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rule_list = self.makeRuleList(config)

        print ("rule_list:")
        for rule in self.rule_list:
            print(rule.verdict, rule.proto, rule.ext_ip, rule.ext_port, rule.domain_name)

        self.ip_list = self.getGeoList()

    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        current_packet = Packet(pkt, pkt_dir)

        if not current_packet.drop():
            # compare packet details to the rules
            if (len(self.rule_list) > 0):
                i = 0
                for rule in self.rule_list:
                    print "rule", i
                    i +=1

                    decision = rule.compare(current_packet)
                    if decision == 1:
                        # allow packet to pass
                        print 'Passing Packet bc decision 1'
                        if pkt_dir == PKT_DIR_INCOMING:
                            self.iface_int.send_ip_packet(pkt)
                        elif pkt_dir == PKT_DIR_OUTGOING:
                            self.iface_ext.send_ip_packet(pkt)
                    elif decision == -1:
                        print "handle packet dropping packet because -1"
                        return


            # doesn't match any rule ... pass
            print("didn't match anything on rule list")
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
            rule_list.append(Rule(rule_line))
            i -= 1

        return rule_list



    def find_country(ip, geoip_list):
        for line in geoip_list:
            print(line)
            min_ip = ip_to_int(line[0])
            max_ip = ip_to_int(line[1])
            if (ip >= min_ip and ip <= max_ip):
                return line[2]
