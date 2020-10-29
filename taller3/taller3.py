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












# opcional:

# dns = DNS(rd=1,qd=DNSQR(qname="www.dc.uba.ar"))
# udp = UDP(sport=RandShort(), dport=53)
# ip = IP(dst="199.9.14.201")

# answer = sr1( ip / udp / dns , verbose=0, timeout=10)

# if answer.haslayer(DNS) and answer[DNS].qd.qtype == 1:
# 	print("AUTHORITY")
# 	for i in range(answer[DNS].arcount):
# 		print(answer[DNS].ar[i].rrname, answer[DNS].ar[i].rdata)
# 	print("NAME SERVERS")
# 	for i in range(answer[DNS].nscount):
# 		print(answer[DNS].ns[i].rrname, answer[DNS].ns[i].rdata)
# 	print("ANSWER")
# 	for i in range(answer[DNS].ancount):
# 		print(answer[DNS].an[i].rrname, answer[DNS].an[i].rdata)


# nombre de dominio = todo lo que va despues de @.
# en la capa de aplicacion, el protocolo para mail es SMTP [RFC2821], en capa de transporte es TCP de toda la vida.
# usa el puerto 25!!!!!!!!!!!!
# deberias agarrar un registro y ver si register.type = MX.

# 	Adaptar el código anterior de manera que, a través de sucesivas consultas iterativas se obtenga el registro
# 	MX de un dominio dado. Para esto, tener en cuenta que en cada consulta DNS puede tener 3 tipos de respuestas:
# 	i) nos devuelven los servidores DNS a los cuales seguir preguntando, ii) nos devuelven la respuesta
# 	a la consulta que estamos haciendo o iii) nos devuelven el registro SOA de la zona indicando que el registro
# 	solicitado no forma parte de la base de datos de nombres de la zona.

# 	Usando la herramienta desarrollada, consultar por los servidores de mail que atienden los correos del
# 	dominio de una universidad (su nombre de dominio) en algún lugar del mundo. Se deben probar tantos
# 	dominios como integrantes en el grupo participen de la parte optativa. Analizar si los servidores de mail
# 	tienen nombres en el mismo dominio que el de la universidad o pertenecen a otro dominio. Si es posible,
# 	averiguar también si dichos servidores de mail se encuentran en la misma zona geográfica, indicando de
# 	forma aproximada si es el mismo país, misma región o mismo continente.

#smtp = SMTP(rd=1,qd=DNSQR(qname="www.dc.uba.ar"))
#tcp = TCP(sport=RandShort(), dport=25)
#ip = IP(dst="199.9.14.201")
#answer = sr1( ip / tcp / smtp, verbose=0, timeout=10)

#if answer.haslayer(DNS) and answer[DNS].qd.qtype == 1: # TOCAR