#!/usr/bin/env python3
from scapy.all import *
from math import log2
from datetime import datetime
import sys
import pandas as pd

# Propongo que el modelo de fuente lo armemos asi: 
# <IP emisor, IP receptor, tipo>

def mostrar_fuente(S):
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    print("\n".join([ " %s probabilidad: %.5f informacion: %.5f" % (d,k/N, -log2(k/N)) for d,k in simbolos ]))
    print(f"entropia:{entropy(S,N)}")
    print(f"#Paquetes: {N}")
    print()

    # simbolos = [ ((emisor1, receptor1, tipo1), #apariciones1) , ..., ((emisorN, receptorN, tipoN), #aparicionesN)]

def entropy(S, N):
    resultadoEntropia = 0.0
    for s in S.values():
        resultadoEntropia += s/N * log2(s/N)
    return resultadoEntropia  if resultadoEntropia == 0 else -resultadoEntropia

def callback(pkt):
    global S1
    if pkt.haslayer(ARP):
        #print(pkt.show())
        emisor = pkt[ARP].psrc
        receptor = pkt[ARP].pdst
        tipo = "REQUEST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "REPLY" # es analogo a asignarle a dire el valor BROADCAST o UNICAST, me parecio mas apropiado al contexto del punto 3 poner request o reply (?)
        s_i = (emisor, receptor, tipo) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0



    
def actualizar_tabla(tabla, S1, hora_inicio):
    # el modelo de fuente que me parecio razonable es que cada simbolo sea del tipo <IP emisor, IP receptor, tipo>.
    # la gracia del punto opcional es reconocer nodos distinguidos. Por lo que lei en los mails, el distinguido es el que más ARPs maneja.
    # todos reciben ARPs cuando algun host hace un request porque lo hace mediante un broadcast, asi que lo interesante es ver el host que envia más ARPs
    # en el dataframe, antes era fija la cantidad de columnas: ["Entropia","Uni%","Broad%","Paquetes", "2048%", " 2054%"," 33024%","34999%"," 34525%"]
    # ahora estaria bueno que en el .csv podamos ver qué IP es la que más ARP envió (reply) porque ese dispositivo seria el distinguido.
    # entonces estaría bueno tener columnas ["Entropia","Reply","Request","Paquetes", IP 1, IP 2, IP 3, ...]
    # el problema es que esas IPs van apareciendo de la nada. La cantidad de columnas del dataframe va aumentando con el tiempo :(
    # es lo unico que faltaria, poder agregar columnas correctamente a un dataframe a medida que aparecen nuevas IPs.
    # sino podemos harcodear una columna que se llame "router", llevar la cuenta de los reply que hizo y fue. Se supone que "router" va a hacer tantos replies como replies totales haya en toda la red...
    
    N = sum(S1.values())
    entropia = entropy(S1, N)

    simbolos = sorted(S1.items(), key=lambda x: -x[1]) # simbolos esta ordenado segun IP emisor. Se supone que la IP del router va a quedar arriba de todo porque es la que hace más hace reply. Chequear.
    horario = f"{hora_inicio.hour}:{hora_inicio.minute}"
    tabla.loc[horario,'Entropia'] = entropia
    Reply = 0
    Requests = 0
    #emisores = {}

    for simbolo in simbolos:
        # todo lo comentado acá abajo es un intento fallido de agregar una columna nueva. También intenté con .assign y .combine pero fallé.
        
        emisorActual = simbolo[0][0]
        
        
        #emisorActual not in emisores.keys(): # si el emisor no estaba en emisores, lo inicializamos.
        #    emisorActual = 0.0
        #    nuevaColumna = [0] * tabla.Entropia.size()
        #    nuevaColumna.append(simbolo[1]/N)
        #    en algun momento habria que hacer algo tipo tabla.[emisorActual] = nuevaColumna (?)
        #else
            
        #emisores[emisorActual] += simbolo[1]/N
        if simbolo[0][2] == "REPLY":
			if not f"{emisorActual}-Reply" in tabla.columns:
				tabla.loc[horario,f"{emisorActual}-Reply"] = simbolo[1]
			else:
				tabla.loc[horario,f"{emisorActual}-Reply"] = simbolo[1]
            Reply += simbolo[1]  
        else:
			if not f"{emisorActual}-Request" in tabla.columns:
				tabla.loc[horario,f"{emisorActual}-Request"] = simbolo[1]
			else:
				tabla.loc[horario,f"{emisorActual}-Request"] = simbolo[1]
			Requests += simbolo[1]


    
    tabla.loc[horario,'Request'] = Requests
    tabla.loc[horario,'Reply'] = Reply    
    tabla.loc[horario,'Paquetes'] = N
    print(tabla)
    print()



if __name__ == "__main__": 
    #Esta pensado para que corra una iteracion x hora unas 24 veces
    tabla = pd.DataFrame(columns=["Entropia","Reply","Request","Paquetes"]) 
    for i in range(0, 1): #ni a palos vamos a estar 24 horas corriendo esto (?) o si? hay tiempo?
        hora_inicio = datetime.today()
        S1 = {}
        sniff(prn=callback, timeout=1800, filter="arp") #timeout esta en segundos y solo se sniffean los paquetes de protocolo ARP.
        #ojo que asi como esta, cada minuto se borra la fuente anterior y se crea una nueva. Digo por si hay que chequear algo
        mostrar_fuente(S1)
        actualizar_tabla(tabla, S1, hora_inicio)
        tabla.to_csv("tabla_red1_arp.csv")