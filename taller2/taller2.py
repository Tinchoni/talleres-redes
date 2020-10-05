#!/usr/bin/env python3
import sys
from scapy.all import *
from statistics import mean 
from time import *
responses = {}

def get_ip_mas_frecuente(response):
    apariciones=list(map(lambda x: len(x) if x != 'No Response' else 0,list(response.values())))
    k=list(response.keys())
    return k[apariciones.index(max(apariciones))]



def write_traceroute_to_csv(ip_destino,responses):
    with open(f'Traceroute_{ip_destino}.csv','w') as fd:
        fd.write("ttl,ip,promedio,max,min,intersalto\n")
        rtt_promedio = 0
        rtt_promedio_anterior = 0
        ip_mas_frecuente_anterior = ''
        ip_mas_frecuente = ''
        for ttl,response in responses.items():
            if ttl > 1:
                ip_mas_frecuente_anterior = ip_mas_frecuente
            ip_mas_frecuente = get_ip_mas_frecuente(response)
            if ttl > 1 and ip_mas_frecuente_anterior != 'No Response' :
                rtt_promedio_anterior = rtt_promedio
            rtt_promedio = mean(response[ip_mas_frecuente])
            rtt_max = max(response[ip_mas_frecuente])
            rtt_min = min(response[ip_mas_frecuente])
            rtt_inter_salto = rtt_promedio - rtt_promedio_anterior
            fd.write(f"{ttl},{ip_mas_frecuente},{rtt_promedio},{rtt_max},{rtt_min},{rtt_inter_salto if rtt_inter_salto > 0 else 0}\n")

for ttl in range(1,30):
    ip_valida = False
    for _ in range(1,30):
        probe = IP(dst=sys.argv[1], ttl=ttl) / ICMP()
        t_i = time()
        ans = sr1(probe, verbose=False, timeout=0.8)
        t_f = time()
        rtt = (t_f - t_i)*1000
        if ans is not None:
            ip_valida = True
            if ttl not in responses:
                responses[ttl] = {}
                responses[ttl][ans.src] = [rtt]
            if ttl in responses:
                if ans.src not in responses[ttl]:
                    responses[ttl][ans.src] = [rtt]
                else:
                    responses[ttl][ans.src].append(rtt)
        else:
            if ttl not in responses:
                responses[ttl] = {}
                responses[ttl]['No Response'] = [rtt]
            else:
                if 'No Response' in responses[ttl]:
                    responses[ttl]['No Response'].append(rtt)
                else:
                    responses[ttl]['No Response'] = [rtt]

    if ttl in responses:
        IP_mas_frecuente = get_ip_mas_frecuente(responses[ttl])
        rtt_promedio = mean(responses[ttl][IP_mas_frecuente])
        print(f"Salto {ttl}: {IP_mas_frecuente} - RTT Promedio: {rtt_promedio}")
        print('\n')

write_traceroute_to_csv(sys.argv[1],responses)