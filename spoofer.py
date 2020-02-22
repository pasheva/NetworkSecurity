from scapy.layers.inet import *
from scapy.packet import *
from scapy.all import *
import sys


def send_packet(src_ip, dest_ip, dst_port, payload)->None:
    # Payload has to be less than 150B
    sizeP = sys.getsizeof(payload) #returning in Bytes
    if(sizeP <= 150):
        # 1. Create spoofed UDP packet with payload
        packet = IP(dst=dest_ip,src=src_ip)/UDP(dport=dst_port)/payload
        # 2. Send it over.
        send(packet)
    else:
        print("Payload size larger than 150B")
