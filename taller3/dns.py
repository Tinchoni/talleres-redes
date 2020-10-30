#!/usr/bin/env python3

from scapy.all import *

dns = DNS(rd=1,qd=DNSQR(qname="www.dc.uba.ar"))
udp = UDP(sport=RandShort(), dport=53)
ip = IP(dst="199.9.14.201")

answer = sr1( ip / udp / dns , verbose=0, timeout=10)

if answer.haslayer(DNS) and answer[DNS].qd.qtype == 1:
	print("AUTHORITY")
	for i in range(answer[DNS].arcount):
		print(answer[DNS].ar[i].rrname, answer[DNS].ar[i].rdata)
	print("NAME SERVERS")
	for i in range(answer[DNS].nscount):
		print(answer[DNS].ns[i].rrname, answer[DNS].ns[i].rdata)
	print("ANSWER")
	for i in range(answer[DNS].ancount):
		print(answer[DNS].an[i].rrname, answer[DNS].an[i].rdata)


# nombre de dominio = todo lo que va despues de @.
# deberias agarrar un registro y ver si register.type = MX?
# rompete un sudo python3 y ahi podes hacer answer.show() y chusmear Question Record y los campos arcount, nscount y ancount.
# sino un help(DNS) y te tira 22147129321 cositas ricas.



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