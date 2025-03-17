from scapy.all import ARP, Ether, srp, Dot11, Dot11Elt, sendp, sniff, RandMAC
import requests
from tabulate import tabulate
from scapy.all import *

#TODO add bluetooth discovery

class Discoverer:
    def __init__(self, interface,userActivityTracker):
        self.devices = []
        self.interface = interface 
        conf.promisc = False
        self.userActivityTracker = userActivityTracker

    def scan_network(self, network):
        conf.promisc = False
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list, unanswered_list = srp(arp_request_broadcast, timeout=2, iface=self.interface, verbose=False)  # Specify the interface
        
        # Parse the response and extract IP and MAC addresses
        for sent, received in answered_list:
            mac = received.hwsrc
            ip = received.psrc
            manufacturer = self.get_mac_manufacturer(mac)
            
            self.devices.append({'ip': ip, 'mac': mac, 'manufacturer': manufacturer})
            self.userActivityTracker.logEntry(ip,mac,manufacturer)
        
    
    def get_mac_manufacturer(self, mac_address):
        url = f"https://api.macvendors.com/{mac_address}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
            else:
                return "Unknown Vendor"
        except requests.RequestException:
            return "Unknown Vendor"
    
    def detect_os(self, ip):
        # Use Nmap to perform OS detection on the given IP
        try:
            self.nm.scan(ip, arguments='-O')  # -O for OS detection
            if 'osclass' in self.nm[ip]:
                os_info = ', '.join([os['osfamily'] for os in self.nm[ip]['osclass']])
            elif 'osmatch' in self.nm[ip]:
                os_info = self.nm[ip]['osmatch'][0]['name']
            else:
                os_info = 'Unknown'
            
            # Update the device information with OS info
            for device in self.devices:
                if device['ip'] == ip:
                    device['os'] = os_info
                    break
        except Exception as e:
            print(f"Could not detect OS for {ip}: {e}")

    def display_devices(self):
        rows = [
        [device['ip'], device['mac'], device['manufacturer']]
        for device in self.devices
        ]
        headers = ["IP Address", "MAC Address", "Manufacturer"]

        print("\nAvailable devices in the network:")
        print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))
    
    def discover_networks(self):
        print("Sending probe requests...")
        conf.promisc = True
        dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())
        ssid = Dot11Elt(ID="SSID", info="")
        packet = dot11 / ssid
        
        sendp(packet, iface=self.interface, count=10)  # Use the specified interface
        print("Probe requests sent. Now sniffing for responses...")
        sniff(iface=self.interface, prn=self.packet_callback, store=0)

    def packet_callback(self, packet):
        print(packet)
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 4:  # Probe responses
            ssid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else "Hidden SSID"
            bssid = packet[Dot11].addr2
            print(f"SSID: {ssid} | BSSID: {bssid}")

