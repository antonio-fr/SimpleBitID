#! /usr/bin/env python

# SimpleBitID
# Copyright (C) 2014  Antoine FERRON

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


import sys
import base64
import keymanag
from ECDSA_BTC import *
import bitidpy
from time import sleep
import _winreg as wreg #for installer

print "\n SimpleBitID v0.02\n\n"
try:
	raw_uri=sys.argv[1]
	assert raw_uri[0:8] == "bitid://"
except:
	print "ERROR : bad or absent argument !"
	sys.exit()

# If No Key  : Creates One
if keymanag.openkey()==None:
	keymanag.createkey()
	
print "Key Loading"
key=keymanag.openkey()


# PIN? Key encrypted with AES?


secret = int(key,16) 
pubkey = Public_key( g, g * secret )
privkey = Private_key( pubkey, secret )
address = pub_base58_hex( pubkey.point.x(), pubkey.point.y() )
print "Using address",address,"\n"



print "Message Signing\n"
signature = bitcoin_sign( privkey, raw_uri, randoml(g) )
signature_str = bitcoin_encode_sig( signature )
signature64 = base64.b64encode( signature_str )

print "Sending to Server\n"
code_back = bitidpy.postserv( raw_uri, address, signature64 )

if code_back==200:
	print "GRANTED, SUCCESS!"
else:
	print "FAILURE!"

sleep(2)
