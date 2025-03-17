from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.tls.all import TLS13ClientHello
from datetime import datetime, time
import requests

class Sniffer:
    
    def __init__(self, interface,userActivityTracker):
        self.interface = interface
        self.messageSent = False
        self.target = ""
        conf.promisc = False
        self.userActivityTracker = userActivityTracker
        self.curfew = {
            "start_time" : time(22, 0, 0),
            "end_time" : time(9, 0, 0),
        }

    def get_os_from_user_agent(self, user_agent):
        if 'Windows' in user_agent:
            return 'Windows'
        elif 'Macintosh' in user_agent or 'Mac OS' in user_agent:
            return 'Mac OS'
        elif 'Linux' in user_agent:
            return 'Linux'
        elif 'Android' in user_agent:
            return 'Android'
        elif 'iPhone' in user_agent or 'iPad' in user_agent:
            return 'iOS'
        else:
            return 'Unknown OS'

    def get_os_from_tcp(self, packet):
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if tcp_layer.window == 5840:
                return "Windows"
            elif tcp_layer.window == 8192:
                return "Linux"
            elif tcp_layer.window == 29200:
                return "Mac OS"
            elif tcp_layer.window == 64240:
                return "FreeBSD"
            elif tcp_layer.window == 16384: 
                return "iOS (iPhone or iPad)"
            elif tcp_layer.window == 65535:
                return "iOS (iPhone or iPad)"
        
        return "Unknown OS"

    def http_packet_callback(self, packet):
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            host = http_layer.Host.decode() if http_layer.Host else 'Unknown Host'
            path = http_layer.Path.decode() if http_layer.Path else '/'
            full_url = f"http://{host}{path}"
            user_agent = http_layer.User_Agent.decode('utf-8', errors='ignore') if http_layer.User_Agent else 'Unknown User-Agent'
            os_type = self.get_os_from_user_agent(user_agent)

            print(f"[+] HTTP URL: {full_url} | OS: {os_type} | User-Agent: {user_agent} | Source IP: {packet[IP].src} | Destination IP : {packet[IP].dst}")

    def dns_packet_callback(self, packet):
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS request
            dns_query = packet[DNSQR].qname.decode('utf-8')
            print(f"[+] DNS Query: {dns_query} | Source IP: {packet[IP].src} | Destination IP : {packet[IP].dst}")

    def tls_packet_callback(self, packet):
        if packet.haslayer(TLS13ClientHello):
            sni = packet[TLS13ClientHello].servernames
            if sni:
                print(f"[+] HTTPS SNI (Domain): {sni[0].servername.decode('utf-8')} | Source IP: {packet[IP].src} | Destination IP : {packet[IP].dst}")

    def start_sniffing(self):
        conf.promisc  = True
        sniff(iface=self.interface, prn=self.packet_handler, store=0)

    def set_target(self,target):
        self.target = target

    def packet_handler(self, packet):
        try:
            if packet.haslayer(IP):
                if packet[IP].src == self.target:  
                    print("[!] WARNING THE MONITORED USER IS CURRENTLY BROWSING THE INTERNET...") 
                    
                    if self.check_time():
                        if not self.messageSent:
                            self.send_message()
                            self.messageSent = True

            if packet.haslayer(DNS):  
                self.dns_packet_callback(packet)
            elif packet.haslayer(HTTPRequest):  
                self.http_packet_callback(packet)
            elif packet.haslayer(TLS13ClientHello):  
                self.tls_packet_callback(packet)
        except Exception as e:
            print(f"Error : {e}")
            print(packet)

    def set_curfew(self,start_time,end_time):
        self.curfew = {
            "start_time" : datetime.strptime(start_time,"%H:%M").time(),
            "end_time" : datetime.strptime(end_time,"%H:%M").time(),
        }

        print(f"\n[+] New Curfew : Start Time={start_time} , End Time={end_time}")

    def check_time(self):
        current_time = datetime.now().time()

        return self.curfew["start_time"] <= current_time or current_time <= self.curfew["end_time"]

    def send_message(self):
        phone = ""
        apikey = ""
        url = f"https://api.callmebot.com/whatsapp.php?phone={phone}&text=INTERNET+ACTIVITY+DETECTED+FROM+MONITORED+USER+[+{self.target}+]&apikey={apikey}"

        try:
            response = requests.get(url)

            if response.status_code == 200:
                print("[+] MESSAGE SENT!")
                SnifferGuard.messageSent = True
            else:
                print(f"Failed to call the URL. Status code: {response.status_code}")
        except Exception as e:
            print(f"An error occurred: {e}")
