#!/usr/bin/env python3

import sys
from scapy.all import *
 
ports = [i for i in range(1,1025)]
ICMP_FILTERED_CODES = [1,2,9,10,13]
ip = sys.argv[1]

def write_to_csv(line):
	with open(f'scan_{ip}.csv','a') as fd:
		fd.write(line)



write_to_csv("port,protocolo,estado,flags\n")

for i in ports:

	#TCP:
	tcp_packet = IP(dst=ip)/TCP(dport=i, flags='S')
	print(i, end='')
	estado = ''
	flags = ''
	resp = sr1(tcp_packet, verbose=False, timeout=1.0)
	if resp is None:
		print(" filtrado")
		estado = 'filtrado'
	elif resp.haslayer(TCP):
		tcp_layer = resp.getlayer(TCP)
		if tcp_layer.flags == 0x12:
			estado = 'abierto'
			print(" abierto", tcp_layer.flags)
			sr1(IP(dst=ip)/TCP(dport=ports, flags='AR'), verbose=False, timeout=1) 
		elif tcp_layer.flags == 0x14:
			estado = 'cerrado'
			print(" cerrado", tcp_layer.flags)
		flags = tcp_layer.flags

	write_to_csv(f'{i},tcp,{estado},{flags}\n')

	#UDP:
	udp_packet = IP(dst=ip)/UDP(dport=i)
	print(i ,end=' ')
	resp = sr1(udp_packet, verbose=False, timeout=1.0)
	if resp is None:
		estado = 'abierto|filtrado' # https://nmap.org/book/scan-methods-udp-scan.html
	elif resp.haslayer(UDP):
		estado = 'abierto'
	elif resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 3:
		if resp.getlayer(ICMP).code == 3:
			estado = 'cerrado'
		elif resp.getlayer(ICMP).code in ICMP_FILTERED_CODES:
			estado = 'filtrado'
	print(estado)

	write_to_csv(f'{i},udp,{estado},\n')

#	https://scapy.readthedocs.io/en/latest/usage.html#send-and-receive-packets-sr
#	https://scapy.readthedocs.io/en/latest/usage.html#udp-ping
#	https://scapy.readthedocs.io/en/latest/usage.html#tcp-port-scanning