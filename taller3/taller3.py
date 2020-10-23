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
	tcp_packet = IP(dst=ip)/TCP(dport=i, flags='S')
	print(i, end='')
	estado = ''
	resp = sr1(tcp_packet, verbose=False, timeout=1.0) # "Send packets at layer 3 and return only the first answer". Meh, devuelve un paquete de nivel 3 obvio, despues lo vas a desmenuzar pa analizar. 
	if resp is None:
		print(" filtrado")
		estado = 'filtrado'
		flags = ''
	elif resp.haslayer(TCP):
		tcp_layer = resp.getlayer(TCP)
		if tcp_layer.flags == 0x12: # por eso en el interprete, te salta que tiene Flag 18 (SA)
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


# y ahora pa escanear paquetes UDP? acá nmap lo explica: https://nmap.org/book/scan-methods-udp-scan.html

#	elif resp.haslayer(UDP): ... OOOO resp.haslayer(ICMP) y ver si el mensaje es Port Unreachable (o sea, ver resp.getlayer(UDP).type == 3 y code == 3)
# podes chusmear con el interprete, hacer probe = blabla y probe.show().

# queremos un csv con... port,protocolo,estado,flags


#	https://scapy.readthedocs.io/en/latest/usage.html#send-and-receive-packets-sr
#	 https://scapy.readthedocs.io/en/latest/usage.html#udp-ping
#	https://scapy.readthedocs.io/en/latest/usage.html#tcp-port-scanning