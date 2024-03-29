#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct
import socket



class Packet:
    def __init__(self, pkt, pkt_dir):
        self.pkt_proto_num = struct.unpack("!B", pkt[9:10])[0]
        self.pkt = pkt
        self.drop_pkt = False
        self.pkt_dir = pkt_dir
        self.qtype = -1

        #added by jessica part 2
        self.ipv4_header = IPV4_header(pkt)


        #last four bits of first byte
        #self.ip_header_len = struct.unpack("!B", pkt[0:1])[0] & 0x0F on piazza
        #changed by jessica to ord(a) & 0x0f (00001111b) will leave only the last 4 bits.
        self.ip_header_len = ord(pkt[0:1]) & 0xf0
        print "ip header len: ", self.ip_header_len

        if ip_header_len < 5:
            drop_pkt = true
        else:
            #beginning of next header == headerlen * 4
            #this is where the next header begins
            self.next_header_begin = ip_header_len * 4

       #set external_ip
        if pkt_dir == PKT_DIR_INCOMING:
            self.ext_ip = socket.inet_ntoa(pkt[12:16])

        elif pkt_dir == PKT_DIR_OUTGOING:
            self.ext_ip = socket.inet_ntoa(pkt[16:20])


        #added by jessica part 2
        self.src_ip = socket.inet_ntoa(pkt[12:16])
        self.dest_ip = socket.inet_ntoa(pkt[16:20])

        #after getting the protocols, get the source and destination ports from the right places
        if (pkt_proto_num == 1):
            self.pkt_proto = "icmp"
            self.port = self.getType(pkt)
        elif (pkt_proto_num == 6):
            self.pkt_proto = "tcp"
            # the port we use to send stuff out
            self.port = self.getPorts(pkt, pkt_dir)
        elif (pkt_proto_num == 17):
            self.pkt_proto = "udp"
            self.port = self.getPorts(pkt, pkt_dir)
        else:
            self.pkt_proto = "other"
            #it doesn't matter what the port is if the pkt_proto is 'any'
            self.port = 'other'
            # just pass this

    #added by jessica part 2
    def getIp4v(self, pkt):
        # Get all necessary information out of the packet, create the ipv4 headers, and tcp headers, then generate the packet
        self.ipv4_header = IPV4_header(pkt)


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
            return struct.unpack("!H", pkt[byte_begin:(byte_begin + 2)])[0]



    # for ICMP, the type is the port
    def getType(self, pkt):
        byte_begin = self.next_header_begin
        return struct.unpack("!B", pkt[byte_begin:(byte_begin + 1)])[0]



class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.ip_list = self.getGeoList()
        self.rule_list = self.makeRuleList(config)

        #added by jessica part2


    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        current_packet = Packet(pkt, pkt_dir)

        if not current_packet.drop():
            # compare packet details to the rules
            if (len(self.rule_list) > 0):
                i = 0
                for rule in self.rule_list:
                    i +=1

                    decision = rule.compare(current_packet, self.iface_int, self.iface_ext)
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



############################ VVV New Methods VVV #####################################

   def send_deny_tcp(self, rec_pkt):
       """stuff we need"""
       rec_pkt_src_port = struct.unpack('!H', rec_pkt.next_header_begin:rec_pkt.next_header_begin + 2])[0]
       rec_pkt_dest_port = struct.unpack('!H', rec_pkt.next_header_begin + 2:rec_pkt.next_header_begin + 4])[0]
       ihl = rec_pkt.ipv4_header.tot_len
       # 4 bytes
       rec_pkt_seqno = struct.unpack('!L', packet[ihl + 4:ihl + 8])[0]

       """pack all new things for deny packet"""
       # default value for ttl
       ttl = struct.pack('!B', 64)
       #set src port to rec packet's dst, vice versa
       deny_src_port = struct.pack('!H', rec_pkt_dest_port)
       deny_dest_port = struct.pack('!H', rec_pkt_src_port)
       deny_ack_num = struct.pack('!L', rec_pkt_seqno + 1)
       # ack : 0x10, 0x04
       tcp_flags = struct.pack('!B', 0x10 + 0x04)
       deny_checksum = struct.pack('!H', self.checksum2(rec_pkt.ipv4_header.checksum))

       """append shit together"""
       #first do the ipv4 header shit --- up til ihl bytes
       new_deny_packet = rec_pkt[0:8] + ttl + rec_pkt[9:12] + socket.inet_aton(rec_pkt.dest_ip) + socket.inet_aton(rec_pkt.src_ip) + rec_pkt[20:]

       # now do the tcp shit, up to 14 bytes
       #Your ACK number should be previous packet's SEQ number + 1.
       new_deny_packet = new_deny_packet[0:ihl] + deny_src_port + deny_dst_port + new_deny_packet[ihl+4:ihl+8] + deny_ack_num + tcp_flags + new_deny_packet[ihl + 14:]

       # TODO: checksum for ipv4 and tcp hasn't been set!!!!!!!!!!!

       if (rec_pkt.pkt_dir == PKT_DIR_INCOMING):
           self.iface_ext.send_ip_packet(new_deny_packet)
       else:
           self.iface_int.send_ip_packet(new_deny_packet)
       print ("Denying tcp packet")


    def send_deny_dns(self, rec_pkt):
        """stuff we need"""
        rec_pkt_src_port = struct.unpack('!H', rec_pkt.next_header_begin:rec_pkt.next_header_begin + 2])[0]
        rec_pkt_dest_port = struct.unpack('!H', rec_pkt.next_header_begin + 2:rec_pkt.next_header_begin + 4])[0]
        ihl = rec_pkt.ipv4_header.tot_len
        #dns after udp header
        dns_start_byte = rec_pkt.next_header_begin + 8
        # set the qr bit to 1 to indicate that it's a response. the qr bit is a 1 bit field
        byte_with_qr = struct.unpack('!B', packet[dns_start_byte + 2 ])[0] | 128

        #stuff we need in the answer section
        question_field = packet[dns_start_byte + 12:]
        dns_ttl = struct.pack('!L', 1)
        rdlen=struct.pack('!H', 4) #should always be 4 in this case
        rdata = socket.inet_aton('54.173.224.150')

        """pack all new things for deny packet"""
        # default value for ttl
        ttl = struct.pack('!B', 64)
        #set src port to rec packet's dst, vice versa
        deny_src_port = struct.pack('!H', rec_pkt_dest_port)
        deny_dest_port = struct.pack('!H', rec_pkt_src_port)
        header_qr_bytes = struct.unpack('!H', packet[dns_start_byte + 2:dns_start_byte + 4])[0]
        # set ancount to 1, ns count to 0, arcount to 0
        ancount = struct.pack('!H', 1)
        nscount = struct.pack('!H', 0)
        arcount = struct.pack('!H', 0)


        newval = struct.pack("!B", byte_with_qr)

        """append shit"""
        """ipv4""""
        new_deny_packet = rec_pkt[0:8] + ttl + rec_pkt[9:12] + socket.inet_aton(rec_pkt.dest_ip) + socket.inet_aton(rec_pkt.src_ip) + rec_pkt[20:]
        """udp""""
        new_deny_packet = new_deny_packet[0:ihl] + deny_src_port + deny_dst_port + new_deny_packet[ihl + 4:]
        """ dns """

        #header
        #inclusive in front, exclusive at end
        new_deny_packet = new_deny_packet[dns_start_byte + 2] + new_val + new_deny_packet[dns_start_byte+3:dns_start_byte+6] + ancount + nscount +arcount + new_deny_packet[12:]

        """break here to find the qname length"""
        byte_dns_header_ends = rec_pkt.next_header_begin + 8 + 12
        qname_index = byte_dns_header_ends
        qname_i_holder = qname_index
        qname_index += 1
        while ord(cur_packet.pkt[qname_index])!= 00:
            qname_index += 1
        """end break"""

        #question and #answer section should have name,type,class,ttl,rdlength,rdata
        #see http://www.tcpipguide.com/free/t_DNSMessageResourceRecordFieldFormats-2.htm

        #not sure if + 5 is correct. I want to add 4 bytes to where qname_index ends..
        new_deny_packet = new_deny_packet[0:qname_index+5] + dns_ttl + rdlen + rdata



        """Finally send the packet """
        if (rec_pkt.pkt_dir == PKT_DIR_INCOMING):
            self.iface_ext.send_ip_packet(new_deny_packet)
        else:
            self.iface_int.send_ip_packet(new_deny_packet)
        print ("Denying dns packet")


    """

    def send_deny_tcp(rec_pkt, iface_int, iface_ext):
        #create packet

        #24 bytes in tcp header
        #therefore tcp packet with no data should be 48 bytes large
        deny_packet = generate_empty_packet(48)
        #set version to 4 (0100-0000 as one byte = 64)
        #set IHL to 24/4 = 6
        deny_packet[0] = struct.pack('!B', 64 + 6)
        #set protocol to tcp (6)
        deny_packet[9] = struct.pack('!B', 6)
        #set RST flag
        deny_packet[24 + 13] = struct.pack('!B', 4)

        if (rec_pkt.pkt_dir == PKT_DIR_INCOMING):
            rec_pkt_src = rec_pkt.pkt[16:20]
        else:
            rec_pkt_src = rec_pkt.pkt[12:16]

        i = 0
        while i < 4:
            deny_packet[16 + i] = rac_pkt_src[i]
            i += 1

        #set destination to source of received packet
        #set checksum
        if (rec_pkt.pkt_dir == PKT_DIR_INCOMING):
            self.iface_ext.send_ip_packet(pkt)
        else:
            self.iface_int.send_ip_packet(pkt)
        print ("Denying tcp")
    """

    """In addition to dropping a matching TCP packet, respond to the initiator (src	add, src port) with a
    TCP packet with the RST flag set to 1.

    If you simply drop these packets (with a drop rule), then the client application will try sending SYN
    packets several times over the course of a minute or so before giving up. However, if you also send a RST
    packet to the client (with a deny rule), the application will give up immediately."""

    def send_deny_dns(rec_pkt, iface_int):
        #if Qtype is AAAA, do nothing
        if (rec_pkt.qtype == 28):
            return
        #create packet
        #set answer section to A
        #set TTL to 1 second
        #copy ID field as appropriate (??)
        #copy RCODE as appropriate (??)
        #send response to "the internal interface pointing to the fixed IP address 54.173.224.150."
        print ("Denying dns")



    """
    def generate_empty_packet(size):
        result = ""
        i = 0
        while i < size:
            result += '\x00'
            i += 1
        #might as well set version and ihl here
        #https://piazza.com/class/hz9lw7aquvu2r9?cid=1341
        result[3] = struct.pack('!B', 0x45)
        return result
    """


    #val is an integer
    def checksum1(val):
        shrinking_val = val
        result = 0
        while shrinking_val > 0:
            result += shrinking_val & 1
            shrinking_val = shrinking_val >> 1
        return result


    #input is now a string
    def checksum2(str):
        result = 0
        for elem in str:
            shrinking_val = struct.unpack('!B', elem)[0]
            bits_in_elem = 0
            while shrinking_val > 0:
                bits_in_elem += shrinking_val & 1
                shrinking_val = shrinking_val >> 1
            result += bits_in_elem
        return result


class IPV4_header:
    def __init__(self, pkt):

        #unpacking the bytes
        self.version_length = struct.unpack('!B', pkt[0:1])[0]
        self.tos = struct.unpack('!B', pkt[1:2])[0]
        self.tot_len = struct.unpack('!H', pkt[2:4])[0]
        self.ttl = struct.unpack('!B', pkt[8:9])[0]
        self.checksum = struct.unpack('!H', pkt[10:12])[0]
        self.protocol = pkt.pkt_proto_num
        self.src_ip = pkt.src_ip
        self.dest_ip = pkt.dest_ip


class Http_Transaction:
    def __init__(self, ext_ip):
        self.ext_ip = ext_ip
        self.req = ""
        self.res = ""
        self.req_expected = -1
        self.res_expected = -1
        self.req_remaining = -1
        self.res_remaining = -1

    def add_to_req(self, pkt):
        #if pkt received is ahead of expected, drop it and don't log it
        #if pkt received is behind expected, just don't log it
        #add new elements of req header into self.req
        if (self.req_remaining == 0 and self.res_remaining == 0):
            log_http()


    def add_to_res(self, pkt):
        #if pkt received is ahead of expected, drop it and don't log it
        #if pkt received is behind expected, just don't log it
        #add new elements of res header into self.res
        if (self.req_remaining == 0 and self.res_remaining == 0):
            log_http()


    def log_http(self):
        #host_name   method  path    version status_code object_size
        log_info = []

        #determine packet host_name
        #determine packet method
        #determine packet path
        #determine packet version
        #determine packet status_code
        #determine packet object_size

        #open log file
        f = open(‘http.log’, ‘a’)
        #write each element in log_info on new line
        i = 0
        while i < len(log_info):
            f.write(log_info[i])
            #add a space or new line
            if (i == len(log_info) - 1):
                f.write(" ")
            else:
                f.write('\n')
            i += 1

        #flush file
        f.flush()
        #close file?
        f.close()
        print ("logging http")


############################ ^^^ New Methods ^^^ #####################################








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



    def compare(self,cur_packet, iface_int, iface_ext):
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
                    cur_packet.qtype = qtype

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
                                elif (self.verdict == 'deny'):
                                    #send dns deny then drop
                                    send_deny_dns(cur_packet, iface_int, iface_ext)
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
                elif (self.verdict == 'deny' and self.proto == 'tcp'):
                    #send tcp deny then drop
                    send_deny_tcp(cur_packet, iface_int)
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
