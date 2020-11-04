#!/usr/bin/env python3

from scapy.all import *
import sys

domain_name = sys.argv[1]
types = {1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 15:"MX", 28:"AAAA"}


# FUNCIONES AUXILIARES:

def print_authority(answer):
	print("\nAUTHORITY (llamado additional section en dig)")
	for i in range(answer[DNS].arcount):
		print(f"{answer[DNS].ar[i].rrname}\t{types[answer[DNS].ar[i].type]}\t{answer[DNS].ar[i].rdata}")

def print_name_servers(answer):
	print("\nNAME SERVERS (llamado authority section en dig)")
	for i in range(answer[DNS].nscount):
			print(f"{answer[DNS].ns[i].rrname}\t{types[answer[DNS].ns[i].type]}\t{answer[DNS].ns[i].rdata}")

def print_answers(answer):
	print("\nANSWER")
	if answer[DNS].ancount == 0:
		print("-", end="")
	else:
		for i in range(answer[DNS].ancount):
			print(f"{answer[DNS].an[i].rrname}\t{types[answer[DNS].an[i].type]}\t{answer[DNS].an[i].exchange}")
	print("")

def print_delimiter(name_server):
	print("\n*********************************************************************\n")
	print(f"Siguiente iteración por: {name_server}", end="\n\n")

def print_summary():
	print("\n\n  ────────────────────────────────────────────────────────────────────")
	print(f"| Niveles recorridos: {server_levels_visited}")
	print(f"| Cantidad de nombres de servidores de mail encontrados: {answer[DNS].ancount}")
	print(f"| Cantidad de nombres en el mismo dominio de la universidad: {mail_server_names_with_university_domain}")
	print(f"| Direcciones ip de los servidores de mail:\n| {mail_server_name_ips} ")
	print(f"| Todos contestaron: {everyone_answered}")
	print("  ────────────────────────────────────────────────────────────────────")
	print("\t       \\\n\t\t\\   ^__^\n\t\t \\  (oo)\\_______\n\t\t    (__)\\       )\\/\\\n\t\t\t||----w |\n\t\t\t||     ||")

	print("                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒")


def process_mail_server_names(answer):
	# Agrega cada respuesta al diccionario y contabiliza si tiene el mismo dominio que su universidad:
	for i in range(answer[DNS].ancount):
		mail_server_name_ips[(answer[DNS].an[i].exchange).decode("utf-8")] = find_ip_in_name_server(answer, answer[DNS].an[i].exchange)
		if domain_name in str(answer[DNS].an[i].exchange):
			mail_server_names_with_university_domain += 1

def check_if_each_name_server_answers(answer):
	# Envía paquetes a todos los name servers de la zona y chequea si todos respondieron o por lo menos uno de ellos devolvió "None"
	res = True
	for i in range(answer[DNS].nscount):
		try:
			ip_aux = IP(dst=resolve_ip(answer[DNS].ns[i].rdata)) # Utilizamos resolve_ip y no find_ip_in_name_server porque simplemente nos interesa ver si el name server contesta, no buscarlo iterativamente
			answer_aux = sr1( ip_aux / udp / dns, verbose=0, timeout=5)
			res = res and (answer_aux is not None)
		except:
			print("El name server",(answer[DNS].ns[i].rdata).decode("utf-8"), "no responde.")
			res = False
	return res

def resolve_ip(name):
	# Intenta resolver la ip de name utilizando el server público de Google:
	ip_layer = IP(dst="8.8.8.8")
	udp_layer = UDP(sport=RandShort(), dport=53)
	dns_layer = DNS(rd=1,qd=DNSQR(qname=name))
	return sr1(ip_layer/udp_layer/dns_layer, verbose=0)[DNS].an[0].rdata

def find_ip_in_name_server(answer, name):
	# Busca la ip de name en los registros de tipo A del name server actual:
	res = None
	for i in range(answer[DNS].arcount):
		if answer[DNS].ar[i].rrname == name and answer[DNS].ar[i].type == 1:
			res = answer[DNS].ar[i].rdata
	return res

# CODIGO PRINCIPAL:

print(f"\nIniciando la búsqueda de {domain_name} IN MX comenzando por: b.root-servers.net")

dns = DNS(rd=1,qd=DNSQR(qname=domain_name,qtype="MX"))
udp = UDP(sport=RandShort(), dport=53)
ip = IP(dst="199.9.14.201") # la ip de b.root-servers.net (uno de los 13 root name servers). Es posible parametrizarla.
answer = sr1( ip / udp / dns, verbose=0, timeout=10)

got_mail_server_name = False
server_levels_visited = 1
everyone_answered = True
mail_server_name_ips = {}
mail_server_names_with_university_domain = 0
index = 0

while not got_mail_server_name:
	if answer.haslayer(DNS) and answer[DNS].qd.qtype == 15: # 15 es el tipo MX segun RFC 1035.
		print_authority(answer)
		print_name_servers(answer)
		print_answers(answer)
		
		if answer[DNS].ancount > 0: # caso ii)
			got_mail_server_name = True
			process_mail_server_names(answer)
			print_summary()

		elif answer[DNS].nscount > 0: # caso i)
			everyone_answered = everyone_answered and check_if_each_name_server_answers(answer)
			print_delimiter((answer[DNS].ns[index].rdata).decode("utf-8"))

			# Define answer para la proxima iteracion:
			next_name_server_ip = find_ip_in_name_server(answer, answer[DNS].ns[index].rdata)
			if next_name_server_ip is None: # la ip no se encontró en el viejo name server.
				print("La ip de",(answer[DNS].ns[index].rdata).decode("utf-8"), "no se encuentra en el name server.")
				index += 1
			else:
				ip = IP(dst=next_name_server_ip)
				possible_answer = sr1( ip / udp / dns, verbose=0, timeout=5)
				if possible_answer is None: # la ip se encontró en el viejo name server pero el nuevo name server no responde.
					print("El name server",(answer[DNS].ns[index].rdata).decode("utf-8"), "no responde.")
					index += 1
				else: # la ip se encontró en el viejo name server y el nuevo name server responde normalmente.
					answer = possible_answer
					server_levels_visited += 1
					index = 0

			# Version chanta usando el server publico de Google pa resolver ip:
			# try:
			# 	next_name_server_ip = resolve_ip(answer[DNS].ns[index].rdata)
			# 	ip = IP(dst=next_name_server_ip)
			# 	answer = sr1( ip / udp / dns, verbose=0, timeout=10)
			# 	server_levels_visited += 1
			# 	index = 0
			# except:
			# 	index += 1
			# 	continue
		elif answer[DNS].an[0].type == 6: # caso iii)
			print("El registro buscado no está en la base de datos de esta zona. F.")

# https://tools.ietf.org/html/rfc1034
# https://tools.ietf.org/html/rfc1035
# https://scapy.readthedocs.io/en/latest/usage.html#dns-requests