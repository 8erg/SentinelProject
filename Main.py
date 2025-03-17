from Sniffer import Sniffer
from Deauther import Deauther
from Discoverer import Discoverer
from UserActivityTracker import UserActivityTracker
import pyfiglet

def print_title():
    title = pyfiglet.figlet_format("Sentinel", font="speed")
    print(title)

def display_menu():
    print("1. Monitor User Internet Activity       2. Discovering your surroundings")
    print("3. Disconnecting users                  4. Sniff The Network")
    print("5. Show Logs                            6. Exit")

def main():

    print("\n[+] Starting application...")
    
    userActivityTracker = UserActivityTracker()

    while True:
        print_title()
        display_menu()
        
        choice = input("\nEnter your choice (1-6): ")

        if choice == "1":

            print("\n=======================================================================\n")
            
            interface = input("\nEnter the name of the interface you want to sniff on : ")
            sniffer = Sniffer(interface, userActivityTracker) 
            target = input("Enter the IP of the user you want to monitor: ")
            option = input("Will you set a new curfew, if no the default one will be used [Y/N] : ")
            
            sniffer.set_target(target)

            if option.lower() == "y":
                start_time = input("Enter the start time : [Ex: 5:00 for AM or 17:00 for PM] : ")
                end_time = input("Enter the end time : [Ex: 5:00 for AM or 17:00 for PM] : ")

                sniffer.set_curfew(start_time,end_time)

            print(f"\n[+] Starting packet capture on interface: {interface}")
            
            sniffer.start_sniffing()
            
            print("\n=======================================================================\n")

        elif choice == "2":
           
            print("\n=======================================================================\n")
            print("\n1. Discovering users on the network       2. Discovering Networks")
            
            choice = input("\nEnter your choice (1-2): ")
            interface = input("Enter the name of the interface : ")
            discoverer = Discoverer(interface, userActivityTracker)
            
            if choice == "1":
                range = input("Enter the network range (Ex: 10.0.0.1/24) : ")
                
                print(f"\n[+] Starting discovering of users on the network : {range}...\n")
                
                discoverer.scan_network(range)
                discoverer.display_devices()
            elif choice == "2":
                discoverer.discover_networks()
            
            print("\n=======================================================================\n")

        elif choice == "3":
            
            print("\n=======================================================================\n")
            print("\n1. Disconnect a user       2. Disconnect all users")
            
            choice = input("\nEnter your choice (1-2): ")
            interface = input("Enter the name of the interface : ")
            deauther = Deauther(interface)

            if choice == "1":
                target = input("Enter the MAC address of the user you want to disconnect: ")
                deauther.disconnect_user(target,"d4:e2:cb:e2:d9:c0")
            elif choice == "2":
                deauther.disconnect_all_users()
            
            print("\n=======================================================================\n")
        
        elif choice =="4":
            
            print("\n=======================================================================\n")
            
            interface = input("\nEnter the name of the interface you want to sniff on : ")
            sniffer = Sniffer(interface,userActivityTracker) 

            print(f"\n[+] Starting sniffing on : {interface}")
            
            sniffer.start_sniffing()
            
            print("\n=======================================================================\n")
        
        elif choice =="5":

            print("\n=======================================================================\n")
            
            userActivityTracker.showLogs()
            
            print("\n=======================================================================\n")
        
        elif choice =="6":
            userActivityTracker.closeConnection()
            print("[+] Goodbye!\n")
            break
        else:
            print("\n[!] Invalid choice. Please select a valid option.\n")

if __name__ == "__main__":
    main()