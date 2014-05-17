#! /usr/bin/env python

# BitID API of SimpleBitID
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


import httplib
import json

def postserv(uri,address,signature):
	#Return Error code of the HTTP server or 1
	# 200:OK, 401:denied
	# see W3C RFC2616 w3.org/Protocols/rfc2616/rfc2616-sec10.html
	#Return 1 if other error as connection or bad argument
	headers = {"Content-type": "application/json"}
	try:
		data = { "uri"      : uri      ,  # string of BitID full URI (link clicked) "bitid://server.dom/[dir1/dir2/...]/callback?x=abcdef?u=1"
                 "address"  : address  ,  # string of the public key hash
                 "signature": signature } # string of the URI signed (Qt compliant) in base64
		paramsj = json.dumps(data)
		server_url = uri.split('/',3)
		assert server_url[0]=="bitid:"
		page = server_url[3].split('?')[0]
		conni = httplib.HTTPConnection(server_url[2],80,timeout=4)
		conni.request("POST","/"+page,paramsj,headers)
		rep = conni.getresponse()
		conni.close()
		return rep.status
	except:
		return 1