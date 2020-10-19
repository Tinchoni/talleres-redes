#!/usr/bin/env python3

import sys
from scapy.all import *

ports = [19, 20, 21, 22, 23, 53, 80]
ip = sys.argv[1]

for i in ports:
	p = IP(dst=ip)/TCP(dport=i, flags='S')
	print(i ,end='')

	resp = sr1(p, verbose=False, timeout=1.0)
	if resp is None:
		print(" filtrado")
	elif resp.haslayer(TCP):
		tcp_layer = resp.getlayer(TCP)
		if tcp_layer.flags == 0x12:
			print(" abierto", tcp_layer.flags)
			sr1(IP(dst=ip)/TCP(dport=ports, flags='AR'), verbose=False, timeout=1)
		elif tcp_layer.flags == 0x14:
			print(" cerrado", tcp_layer.flags)

# si lo quieren probar, rompanse un sudo python3 taller3.py 157.92.15.1	(como se invoca en el enunciado no sirve)