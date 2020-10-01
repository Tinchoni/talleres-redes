#!/usr/bin/env python3
import sys
from scapy.all import *
from statistics import mean 
from time import *
responses = {}

def get_ip_mas_frecuente(response):
     apariciones=list(map(lambda x: len(x),list(response.values())))
     k=list(response.keys())
     return k[apariciones.index(max(apariciones))]

def write_traceroute_to_csv(ip_destino,responses):
    with open(f'Traceroute_{ip_destino}.csv','w') as fd:
        fd.write("ttl,ip,promedio,max,min\n")
        for i,ttl in responses.items():
            ip_mas_frecuente = get_ip_mas_frecuente(ttl)
            rtt_promedio = mean(ttl[ip_mas_frecuente])
            rtt_max = max(ttl[ip_mas_frecuente])
            rtt_min = min(ttl[ip_mas_frecuente])
            fd.write(f"{i},{ip_mas_frecuente},{rtt_promedio},{rtt_max},{rtt_min}\n")

for i in range(2):
    print()
for ttl in range(1,25):
    for _ in range(1,30):
        probe = IP(dst=sys.argv[1], ttl=ttl) / ICMP()
        t_i = time()
        ans = sr1(probe, verbose=False, timeout=0.8)
        t_f = time()
        rtt = (t_f - t_i)*1000
        if ans is not None:
            if ttl not in responses:
                responses[ttl] = {}
                responses[ttl][ans.src] = [rtt]
            if ttl in responses:
                if ans.src not in responses[ttl]:
                    responses[ttl][ans.src] = [rtt]
                else:
                    responses[ttl][ans.src].append(rtt)
    if ttl in responses:
        IP_mas_frecuente = get_ip_mas_frecuente(responses[ttl])
        rtt_promedio = mean(responses[ttl][IP_mas_frecuente])
        print(f"Salto {ttl}: {IP_mas_frecuente} - RTT Promedio: {rtt_promedio}")
        print('\n')

write_traceroute_to_csv(sys.argv[1],responses)