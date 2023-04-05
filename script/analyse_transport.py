import asyncio
import pyshark
import socket
import matplotlib.pyplot as plt


capture = pyshark.FileCapture("analyse1\capture1.pcapng")
protocols = {}

for packet in capture:
    if hasattr(packet, 'transport_layer'):
        protocol = packet.transport_layer
    protocols[protocol] = protocols.get(protocol, 0) + 1
capture.close()

proto = list(protocols.keys())
freq = list(protocols.values())

# Créer un graphique en camembert
plt.pie(freq, labels=proto, autopct='%1.1f%%')
plt.title('Protocoles utilisés')
plt.axis('equal')
plt.savefig("protocole de transport",dpi=300)
plt.show()

