#!/usr/bin/env python3

from scapy.all import *
import sys

dst = sys.argv[1]
types = {1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 15:"MX", 28:"AAAA"}

print(f"\nIniciando la búsqueda de {dst} IN MX", end="\n\n")

dns = DNS(rd=1,qd=DNSQR(qname=dst,qtype="MX")) # con eso tas modificando el DNS Question Record, o sea qué chota vas a buscar.
udp = UDP(sport=RandShort(), dport=53) # DNS usa el puerto 53 porque si.
ip = IP(dst="199.9.14.201") # les pinto harcodear la ip de b.root-servers.net, que es uno de los 13 root name servers (enunciado pag 4).
answer = sr1( ip / udp / dns, verbose=0, timeout=10)

if answer.haslayer(DNS) and answer[DNS].qd.qtype == 15: # 15 es el tipo MX. Asi lo dice RFC 1035.
	print("AUTHORITY (llamado additional section en dig)")
	for i in range(answer[DNS].arcount): # arcount es la cantidad de autoridades? RFC1035 dice "the number of resource records in the additional records section". 
		print(f"{answer[DNS].ar[i].rrname}\t{types[answer[DNS].ar[i].type]}\t{answer[DNS].ar[i].rdata}") # te tira las que aparecen en ADITTIONAL SECTION en el enunciado (pag 5). 
	print("\nNAME SERVERS (llamdo authority section en dig)")
	for i in range(answer[DNS].nscount): # nscount es la cantidad de nameservers? El coso dice "the number of name server resource records in the authority records section".
		print(f"{answer[DNS].ns[i].rrname}\t{types[answer[DNS].ns[i].type]}\t{answer[DNS].ns[i].rdata}") # te tira las que aparecen en AUTHORITY SECTION en el enunciado (pag 5).
	
	#esto deberias hacerlo solo si ancount > 0 supongo.	Aparte no existe an[i].rdata eh, tiene que ser an[i].exchange
	print("\nANSWER")
	for i in range(answer[DNS].ancount): #ancount es la cantidad de potenciales respuestas? El coso dice "the number of resource records in the answer section."
		print(f"{answer[DNS].an[i].rrname}\t{types[answer[DNS].an[i].type]}\t{answer[DNS].an[i].exchange}") # no te tira answer rey porque tenés que seguir la busqueda.

############################################################################################################################################

print("")
print("************************************************************************")
print("")
print(f"hasta aca pasaste por el root name server, ahora vas a probar siguiendo por: {answer[DNS].ns[0].rdata}", end="\n\n")

# Debemos resolver la ip de este nameserver para continuar iterativamente la búsqueda:
ip = IP(dst=sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=answer[DNS].ns[0].rdata)))[DNS].an[0].rdata)

answer = sr1( ip / udp / dns , verbose=0, timeout=10)
print("")

if answer.haslayer(DNS) and answer[DNS].qd.qtype == 15: 
	print("AUTHORITY (llamado additional section en dig)")
	for i in range(answer[DNS].arcount):  
		print(f"{answer[DNS].ar[i].rrname}\t{types[answer[DNS].ar[i].type]}\t{answer[DNS].ar[i].rdata}") 
	print("\nNAME SERVERS (llamdo authority section en dig)")
	for i in range(answer[DNS].nscount):
		print(f"{answer[DNS].ns[i].rrname}\t{types[answer[DNS].ns[i].type]}\t{answer[DNS].ns[i].rdata}")
	
	print("\nANSWER")
	for i in range(answer[DNS].ancount):
		print(f"{answer[DNS].an[i].rrname}\t{types[answer[DNS].an[i].type]}\t{answer[DNS].an[i].exchange}")

############################################################################################################################################

print("")
print("************************************************************************")
print("")
print(f"Ya pasaste por un nameserver, ahora vas a seguir por: {answer[DNS].ns[0].rdata}")

# Nuevamente, resolvemos la ip de este segundo nameserver:
ip = IP(dst=sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=answer[DNS].ns[0].rdata)))[DNS].an[0].rdata)

answer = sr1( ip / udp / dns , verbose=0, timeout=10)
print("")

if answer.haslayer(DNS) and answer[DNS].qd.qtype == 15: 
	print("AUTHORITY (llamado additional section en dig)")
	for i in range(answer[DNS].arcount):  
		print(f"{answer[DNS].ar[i].rrname}\t{types[answer[DNS].ar[i].type]}\t{answer[DNS].ar[i].rdata}") 
	print("\nNAME SERVERS (llamdo authority section en dig)")
	for i in range(answer[DNS].nscount):
		print(f"{answer[DNS].ns[i].rrname}\t{types[answer[DNS].ns[i].type]}\t{answer[DNS].ns[i].rdata}")
	
	print("\nANSWER")
	for i in range(answer[DNS].ancount):
		print(f"{answer[DNS].an[i].rrname}\t{types[answer[DNS].an[i].type]}\t{answer[DNS].an[i].exchange}")


# TODO: 
# Meter todo en un rico for chequeando estas 3 condiciones blabla
# en cada consulta DNS puede tener 3 tipos de respuestas:
# i) nos devuelven los servidores DNS a los cuales seguir preguntando
# ii) nos devuelven la respuesta a la consulta que estamos haciendo o 
# iii) nos devuelven el registro SOA de la zona indicando que el registro solicitado no forma parte de la base de datos de nombres de la zona.

# TODO2:
# rompete funciones chetas como printSeparator (?)
# te conviene imrpimir nivelesRecorridos cantidadDeNombresDeServidoresDeMail
# ver si podes automatizar el resto de las preguntas.

# https://tools.ietf.org/html/rfc1034
# https://tools.ietf.org/html/rfc1035
# https://scapy.readthedocs.io/en/latest/usage.html#dns-requests