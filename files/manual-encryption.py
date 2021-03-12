#!/usr/bin/env python
# -*- coding: utf-8 -*-


from scapy.all import *
import binascii
from rc4 import RC4
#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

m = binascii.hexlify(b'Message forged')

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

#La seed correspond à l'iv concaténé avec la clé
seed = arp.iv+key
#Instantiation de la classe RC4
cipher = RC4(seed, streaming=False)


#On utilise la lib binascii qui implémente crc32 pour le "checksum" 
icv = (binascii.crc32(m)).to_bytes(4, sys.byteorder)

#On utilise la méthode crypt qui est la même pour chiffrer ou déchiffrer
arp.wepdata = cipher.crypt(m+icv)
wrpcap("trames_chiffrees.pcap", arp)