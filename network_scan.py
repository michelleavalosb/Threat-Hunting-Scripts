# goal: scan a network and display IC and MAC addresses of all active devices in specified range


# Scapy: tool for network packet manipulation (sending ARP requests and receieving respones)
import scapy.all as scapy

def scan_network(ip_range): #funtion that will perfom the network scan with a parameter of the ranges of IP that will be scanned
    arp_request = scapy.ARP(pdst=ip_range) #which devices are using these ip addresses? #pdst=protocol destination
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #send the ARP request to everyone in the network
    arp_request_broadcast = broadcast/arp_request # "/" is used to stack multiple layers of packets (combining the ethernet frame and ARP request)
    
    #sends packet over the network and wait for response and collects the reponses
    responses = scapy.srp(arp_request_broadcast,timeout=1, verbose=False)[0]
    
    if not responses:
        print("No devices found in the spcified range.")

    print("IP\t\t\tMAC Address")
    print("--------------------------------")

    # looping through the responses from the devices on the network that answered to ARP request
    for packet in responses:
        ip_address = packet[1].psrc #extract ip of responding device

        mac_address = packet[1].hwsrc #extract MAC of responding device

        print(ip_address + '\t\t' + mac_address)

ip_range = "192.168.1.1/24"
scan_network(ip_range)



