import asyncio
import pyshark
import socket
import matplotlib.pyplot as plt

#fonction qu'on va utiliser sur chaque itération de packet, recup l'adresse IP de destination
async def analyze_packet(packet):
    if 'IP' in packet:
        dest_address = packet['IP'].dst
        destination_addresses[dest_address] = destination_addresses.get(dest_address, 0) + 1

#on recup les infos sur les packets
capture = pyshark.FileCapture("analyse1\capture1.pcapng")
destination_addresses = {}
loop = asyncio.get_event_loop()
tasks = []
for packet in capture:
    tasks.append(loop.create_task(analyze_packet(packet)))
loop.run_until_complete(asyncio.wait(tasks))
#on trie les adresses
sorted_dest_addresses = sorted(destination_addresses.items(), key=lambda x: x[1], reverse=True)

labels = []
values = []
#recupere les noms de domaine correspondant au adresse IP, plus simple à visualiser
for address, count in sorted_dest_addresses[:10]:
    try:
        domain = socket.gethostbyaddr(address)[0]
    except socket.herror:
        domain = address
    labels.append(domain)
    values.append(count)

# Créer le graphe
plt.pie(values, labels=labels, autopct='%1.1f%%')
plt.axis('equal')
plt.savefig("graphe_des_requetes.jpg",dpi=1000)
plt.show()
capture.close()