#!/usr/bin/python3.9
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

import zlib

from scapy.all import *
import binascii
from rc4 import RC4
#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
message =b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x10\xc0\xa8\x01\xc8"

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]
# rc4 seed est composé de IV+clé
seed = arp.iv+key

# chiffrement rc4
cipher = RC4(seed, streaming=False)
# calcul de l'ICV
icv = binascii.crc32(message)
#Chiffre le message + l'ICV
arp.wepdata=cipher.crypt(message+icv.to_bytes(4,sys.byteorder))

wrpcap("encrypted.cap",arp)



