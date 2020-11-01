#!/usr/bin/env python3

from scapy.all import *
import sys

domain_name = sys.argv[1]
types = {1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 15:"MX", 28:"AAAA"}

def print_authority(answer):
	print("\nAUTHORITY (llamado additional section en dig)")
	for i in range(answer[DNS].arcount): # arcount = cantidad de autoridades. "the number of resource records in the additional records section". 
		print(f"{answer[DNS].ar[i].rrname}\t{types[answer[DNS].ar[i].type]}\t{answer[DNS].ar[i].rdata}")

def print_name_servers(answer):
	print("\nNAME SERVERS (llamdo authority section en dig)")
	for i in range(answer[DNS].nscount): # nscount = cantidad de nameservers. "the number of name server resource records in the authority records section".
			print(f"{answer[DNS].ns[i].rrname}\t{types[answer[DNS].ns[i].type]}\t{answer[DNS].ns[i].rdata}")

def print_answers(answer):
	print("\nANSWER")
	if answer[DNS].ancount == 0:
		print("-", end="")
	else:
		for i in range(answer[DNS].ancount): #ancount = cantidad de potenciales respuestas. "the number of resource records in the answer section."
			print(f"{answer[DNS].an[i].rrname}\t{types[answer[DNS].an[i].type]}\t{answer[DNS].an[i].exchange}")
	print("")

def print_delimiter(name_server):
	print("\n*********************************************************************\n")
	print(f"Siguiente iteración por: {name_server}", end="\n\n")

def resolve_ip(name):
	ip_layer = IP(dst="8.8.8.8")
	udp_layer = UDP(sport=RandShort(), dport=53)
	dns_layer = DNS(rd=1,qd=DNSQR(qname=name))
	return sr1(ip_layer/udp_layer/dns_layer, verbose=0)[DNS].an[0].rdata


# CODIGO PRINCIPAL:

print(f"\nIniciando la búsqueda de {domain_name} IN MX comenzando por: b.root-servers.net")

dns = DNS(rd=1,qd=DNSQR(qname=domain_name,qtype="MX")) # modificamos el Question Record para que busque registros de tipo MX.
udp = UDP(sport=RandShort(), dport=53)
ip = IP(dst="199.9.14.201") # la ip de b.root-servers.net (uno de los 13 root name servers). Es posible parametrizarla.
answer = sr1( ip / udp / dns, verbose=0, timeout=10)

server_levels_visited = 1
got_mail_server_name = False
mail_server_names_with_university_domain = 0
mail_server_name_ips = {}

while not got_mail_server_name:
	if answer.haslayer(DNS) and answer[DNS].qd.qtype == 15: # 15 es el tipo MX segun RFC 1035.
		print_authority(answer)
		print_name_servers(answer)
		print_answers(answer)
		
		if answer[DNS].ancount > 0: # caso ii)
			got_mail_server_name = True
			for i in range(answer[DNS].ancount):
				mail_server_name_ips[(answer[DNS].an[i].exchange).decode("utf-8")] = resolve_ip(answer[DNS].an[i].exchange)
				if domain_name in str(answer[DNS].an[i].exchange):
					mail_server_names_with_university_domain += 1
			print(f"\nNiveles recorridos: {server_levels_visited}")
			print(f"Cantidad de nombres de servidores de mail encontrados: {answer[DNS].ancount}")
			print(f"Cantidad de nombres en el mismo dominio de la universidad: {mail_server_names_with_university_domain}")
			print("Direcciones ip de los servidores de mail:",mail_server_name_ips)

		elif answer[DNS].nscount > 0: # caso i)
			print_delimiter((answer[DNS].ns[0].rdata).decode("utf-8")) # para que no se imprima como bytes-like object, que se yo. Cositas de Python.
			name_server_ip = resolve_ip(answer[DNS].ns[0].rdata)
			ip = IP(dst=name_server_ip)
			answer = sr1( ip / udp / dns , verbose=0, timeout=10)
			server_levels_visited += 1

		elif answer[DNS].an[0].type == 6: # caso iii)
			print("Qué se yo rey, el registro no está en la database de esta zona. F.")

print("\n\n  ______________________________________________________________")
print("/ Congrats, no te explotó la compu con toda la falopa que codeé. \\\n\\ Me fui a dormir rey.                                           /")
print("  ──────────────────────────────────────────────────────────────")
print("\t       \\\n\t\t\\   ^__^\n\t\t \\  (oo)\\_______\n\t\t    (__)\\       )\\/\\\n\t\t\t||----w |\n\t\t\t||     ||")

print("                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒")

# https://tools.ietf.org/html/rfc1034
# https://tools.ietf.org/html/rfc1035
# https://scapy.readthedocs.io/en/latest/usage.html#dns-requests