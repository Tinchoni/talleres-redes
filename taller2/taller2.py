#!/usr/bin/env python3
import sys
from scapy.all import *
from statistics import mean 
from statistics import stdev
from time import *

responses = {}
muestra_de_saltos = {}
modified_thompson_tau = [0.0000, 0.0000, 0.0000, 1.1511, 1.4250, 1.5712, 1.6563, 1.7110, 1.7491, 1.7770,
                         1.7984, 1.8153, 1.8290, 1.8403, 1.8498, 1.8579, 1.8649, 1.8710, 1.8764, 1.8811,
                         1.8853, 1.8891, 1.8926, 1.8957, 1.8985, 1.9011, 1.9035, 1.9057, 1.9078, 1.9096,
                         1.9114, 1.9130, 1.9146, 1.9160, 1.9174, 1.9186, 1.9198, 1.9209, 1.9220, 1.9230]


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
            if ttl > 1 and ip_mas_frecuente_anterior != 'No Response':
                rtt_promedio_anterior = rtt_promedio
            rtt_promedio = mean(response[ip_mas_frecuente])
            rtt_max = max(response[ip_mas_frecuente])
            rtt_min = min(response[ip_mas_frecuente])
            rtt_inter_salto = rtt_promedio - rtt_promedio_anterior
            fd.write(f"{ttl},{ip_mas_frecuente},{rtt_promedio},{rtt_max},{rtt_min},{rtt_inter_salto if rtt_inter_salto > 0 else 0}\n")
            # Para el ejercicio opcional:
            if ttl > 1 and ip_mas_frecuente != ip_mas_frecuente_anterior:
                muestra_de_saltos[ttl] = rtt_inter_salto if (rtt_inter_salto > 0 and ip_mas_frecuente != 'No Response') else 0


def only_second_elements(pairs):
    res = []
    for elem in pairs:
        res.append(elem[1])
    return res

def write_rtt_and_normalized_rtt_to_csv(rtts):
    promedio = mean(only_second_elements(rtts))
    desviacion_estandar = stdev(only_second_elements(rtts))

    with open(f'Traceroute_{sys.argv[1]}_outliers.csv','w') as fd:
        fd.write("ttl,intersalto,normalizado\n")
        for ttl,rtt in rtts:
            intersalto_normalizado = abs(rtt - promedio) / desviacion_estandar
            fd.write(f"{ttl},{rtt},{intersalto_normalizado}\n")

def find_outliers():
    rtts = list(muestra_de_saltos.items())
    hay_posibles_outliers = True
    outliers = []
    iteratorFiltered = filter(lambda pair: pair[1] != 0, rtts) # quitamos los saltos con rtt negativo o correspondientes a No Response's
    rtts = list(iteratorFiltered)   

    # esto es para el grafico que sugiere el enunciado, lo de |x - promedio|/S
    write_rtt_and_normalized_rtt_to_csv(rtts)

    rtts.sort(key = lambda par: par[1]) # ordenamos los pares (ttl, rtt) segun el rtt entre saltos
    while hay_posibles_outliers:
        n = len(rtts)
        posible_outlier = rtts[-1][1]
        promedio = mean(only_second_elements(rtts))
        desviacion_estandar = stdev(only_second_elements(rtts))
        desviacion_del_rtt = abs(posible_outlier - promedio)
        tau = modified_thompson_tau[n]

        if desviacion_del_rtt > tau * desviacion_estandar:
            outliers.append(rtts[-1])
            rtts.remove(rtts[-1]) # contabilizamos a rtt como outlier y seguimos buscando ya sin rtt. Debemos recalcular n, el promedio, la desviacion, etc.
            if not rtts:
                hay_posibles_outliers = False
        else:
            hay_posibles_outliers = False # podemos dejar de buscar outliers porque si el de mayor rtt no lo era, entonces los de menor rtt tampoco.
    
    print("\nbueno mastercard, estos son los saltos outlier con sus respectivos rtts:\n")
    print(outliers)



# Codigo principal:

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

find_outliers()