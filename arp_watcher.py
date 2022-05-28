

from scapy.all import sniff, ARP, conf
from signal import signal, SIGINT
import sys


arp_watcher_db_file = "arp-watcher.db"
ip_mac ={}

def sign_int_handler(signum, frame):
	print(">> GOT SIGNINT. SAVING ARP DATABASE...")
	try:
		f = open(arp_watcher_db_file,'w')

		for (ip, mac) in ip_mac.items():
			f.write(ip + " " + mac + "\n")
		f.close()
		print("[:)] DONE!")
	except IOError:
		print("[!] Cannot write file {}".format(arp_watcher_db_file))
		sys.exit(1)

def watch_arp(pkt):
	if pkt[ARP].op == 2:
		print(pkt[ARP].hwsrc + " " + pkt[ARP].psrc)

		if ip_mac.get(pkt[ARP].psrc) == None:
			print("[+] Found New Device :" + \
				pkt[ARP].hwsrc + " " + \
				pkt[ARP].psrc)
			ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc

	elif ip_mac.get(pkt[ARP].psrc) and ip_mac[pkt[ARP].psrc] != pkt[ARP].hwsrc:
		print(pkt[ARP].hwsrc + \
			" Has got new IP : " + \
			pkt[ARP].psrc + \
			" (old " + ip_mac[pkt[ARP].psrc] + ")")
		ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc


signal(SIGINT, sign_int_handler)


try:
	fh = open(arp_watcher_db_file,'r')
except IOError:
	print("CANNOT READ FILE :{}".format(arp_watcher_db_file))
	sys.exit(1)

for line in fh:
	line.rstrip()
	(ip, mac) = line.split(" ")
	ip_mac[ip] = mac

sniff(prn=watch_arp,
	filter="arp",
	iface=conf.iface,
	store=0)
