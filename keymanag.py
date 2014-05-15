#! /usr/bin/env python

# KeyManager of SimpleBitID
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


# Private 256bits Key Management
#generate with os.urandom
#store in %APPDATA%\SimpleBitID\user_priv_key as hex

import os

def randomforkey():
	candint = 0
	r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
	while candint<1 or candint>=r:
		cand=os.urandom(32).encode('hex')
		candint=int(cand,16)
	return cand

def openkey():
	if os.name=='nt':
		pathf=os.getenv('APPDATA')+"\\SimpleBitID\\"
	else:
		pathf="./"
	try:
		f = open(pathf+'user_priv_key', 'rb')
	except IOError:
		return None
	privkey=f.read(32)
	f.close()
	return privkey

def createkey():
	print "Key Creation in Progress"
	privkey=randomforkey()
	if os.name=='nt':
		pathf=os.getenv('APPDATA')+"\\SimpleBitID\\"
	else:
		pathf="./"
	try:
		f = open(pathf+'user_priv_key', 'wb')
	except IOError:
		os.makedirs(pathf)
		f = open(pathf+'user_priv_key', 'wb')
	f.write(privkey)
	f.close()
	print "New Key Generated"
