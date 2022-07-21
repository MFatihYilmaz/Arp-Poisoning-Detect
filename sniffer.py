import binascii
import os  
import sys 
import time 
import socket 
import struct 

timestamp = time.time

class ArpDetect:
   
    def __init__(self, data):
        self.timestamp = timestamp()
        
        self.data   = data[14:]


    def parse(self):

        self.protocol=self.data[9]

        if(self.protocol==74):
            self.arp()

        
    def arp(self):
        
        arp_header = self.data[:28]
        arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
        print ("Source MAC:      ", binascii.hexlify(arp_detailed[5]))
        print ("Source IP:       ", socket.inet_ntoa(arp_detailed[6]))
        print ("Dest MAC:        ", binascii.hexlify(arp_detailed[7]))
        print ("Dest IP:         ", socket.inet_ntoa(arp_detailed[8]))
        print( "-----------------------------------------------------")
        

        if(socket.inet_ntoa(arp_detailed[6])=="192.168.0.1"):
             if(str(binascii.hexlify(arp_detailed[5]))!="b'fc4ae9608c44'"):
                print("ARP POİSONİNG DETECTED")

    
  

def parse(data):
    try:
        packet = ArpDetect(data)
        packet.parse()

    except:
        pass

def listen(intf):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(0x0003))
    try:
        sock.bind((intf, 3))
    except OSError:
        sys.exit(f'Baglanamadi : {intf}!')
    else:
        print(f'Dinleniyor {intf}!')

    while True:
        try:
            data = sock.recv(2048)
        except OSError:
            pass

        else:
            parse(data)

if __name__ == '__main__':
    if os.geteuid():
        sys.exit('Root olarak çalıştırın')

    listen('wlan0')