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
def fragment (seed,fragment,messages):
    fragments= []
    cipher = RC4(seed, streaming=False)
    for i in range(len(messages)):
        # sinon modifie le fragment fourni et les autres packets seront mal formé
        packet = fragment.copy()
        if(i<len(messages)-1):

            packet.FCfield.MF = True
        icv = binascii.crc32(messages[i])
        # Chiffre le message + l'ICV
        packet.wepdata= cipher.crypt(messages[i] + icv.to_bytes(4, sys.byteorder))
        packet.SC = fragment.SC+i
        #forme moche pour supprimer le fichier a chaque fois
        if(i ==0 ):
            wrpcap("encrypted_with_fragment.cap", packet)
        else:
            wrpcap("encrypted_with_fragment.cap", packet,append=True)

key= b'\xaa\xaa\xaa\xaa\xaa'
# messages random issue du messsage original, quelques modification dans chaque message
message =[b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x10\xc0\xa8\x01\xc8",
          b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x33\xc0\xa8\x01\xc8",
          b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x05\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x10\xc0\xa8\x01\xc8",
          b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x10\x30\xa8\x01\xc8"]
#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]
# rc4 seed est composé de IV+clé
seed = arp.iv+key
fragment(seed,arp.copy(),message)


