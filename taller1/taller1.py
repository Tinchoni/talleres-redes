#!/usr/bin/env python3
from scapy.all import *
from math import log2
from datetime import datetime
import sys
import pandas as pd
#S= [clave1:valor1]   -----> simbolos = [(clave1,valor1)]

def mostrar_fuente(S):
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    print("\n".join([ " %s : %.5f informacion %.5f" % (d,k/N, -log2(k/N)) for d,k in simbolos ]))
    print(f"entropia:{entropy(S,N)}")
    print(f"#Paquetes: {N}")
    print()
    

    #I(d) = -log2(k/N)
    #H(S) = -sum( k/N * log2(k/N) )

def entropy(S, N):
    resultadoEntropia = 0.0
    for s in S.values():
        resultadoEntropia += s/N * log2(s/N)
    return resultadoEntropia  if resultadoEntropia == 0 else -resultadoEntropia

def callback(pkt):
    global S1
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = (dire, proto) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0
    
def actualizar_tabla(tabla, S1, hora_inicio):
    N = sum(S1.values())
    entropia = entropy(S1, N)
    simbolos = sorted(S1.items(), key=lambda x: x[0][1])
    horario = f"{hora_inicio.hour}:{hora_inicio.minute}"
    Unicast = 0
    fuentes = {2048:0, 2054:0, 33024:0, 34999:0, 34525:0}
    for simbolo in simbolos:
        if simbolo[0][1] in fuentes.keys():
            fuentes[simbolo[0][1]] += simbolo[1]/N
        if simbolo[0][0] == "UNICAST":
            Unicast += simbolo[1]
    Broadcast = (N - Unicast)/N
    Unicast = Unicast / N
    fuentes = [fuentes[key] for key in sorted(fuentes.keys())]
    fila = [entropia, Unicast , Broadcast, N ] +  fuentes
    tabla.loc[horario] = fila
    print(tabla)
    print()



if __name__ == "__main__": 
    #Esta pensado para que corra una iteracion x hora unas 24 veces
    tabla = pd.DataFrame(columns=["Entropia","Uni%","Broad%","Paquetes", "2048%", " 2054%"," 33024%","34999%"," 34525%"])   
    for i in range(0, 5): 
        hora_inicio = datetime.today()
        S1 = {}
        sniff(prn=callback, timeout=3600) #timeout esta en segundos
        #mostrar_fuente(S1)
        actualizar_tabla(tabla, S1, hora_inicio)
        tabla.to_csv("tabla_red1.csv")


