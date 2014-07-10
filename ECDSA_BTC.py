#! /usr/bin/env python

# ECDSA BTC of SimpleBitID
# Copyright (C) 2014  Antoine FERRON
# Some portions based on :
# "python-ecdsa" Copyright (C) 2010 Brian Warner (MIT Licence)
# "Simple Python elliptic curves and ECDSA" Copyright (C) 2005 Peter Pearson (public domain)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


# Focus on signature generation
#This is optimized for speed
#sent to a server, no need for lot of verification

# Signature is done with a random k
# from os.urandom

import os
from B58 import *
import binascii

class CurveFp( object ):
  def __init__( self, p, b ):
    self.__p = p
    self.__b = b

  def p( self ):
    return self.__p

  def b( self ):
    return self.__b

  def contains_point( self, x, y ):
    return ( y * y - ( x * x * x + self.__b ) ) % self.__p == 0

class Point( object ):
  def __init__( self, x, y, order = None ):
    self.__x = x
    self.__y = y
    self.__order = order

  def __eq__( self, other ):
    if self.__x == other.__x   \
     and self.__y == other.__y:
      return True
    else:
      return False

  def __add__( self, other ):
    if other == INFINITY: return self
    if self == INFINITY: return other
    p=curve_256.p()
    if self.__x == other.__x:
      if ( self.__y + other.__y ) % p == 0:
        return INFINITY
      else:
        return self.double()
    l = ( ( other.__y - self.__y ) * inverse_mod( other.__x - self.__x, p ) ) % p
    x3 = ( l * l - self.__x - other.__x ) % p
    y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
    return Point( x3, y3 )

  def __mul__( self, other ):
    e = other
    if self.__order: e = e % self.__order
    if e == 0: return INFINITY
    if self == INFINITY: return INFINITY
    assert e > 0
    e3 = 3 * e
    negative_self = Point( self.__x, -self.__y, self.__order )
    i = 0x100000000000000000000000000000000000000000000000000000000000000000L
    while i > e3: i >>= 1L
    result = self
    while i > 2L:
      i >>= 1L
      result = result.double()
      ei = e&i
      if (e3&i)^ei : 
        if ei==0L    : result += self
        else         : result += negative_self
    return result

  def __rmul__( self, other ):
   return self * other

  def __str__( self ):
    if self == INFINITY: return "infinity"
    return "(%d,%d)" % ( self.__x, self.__y )

  def double( self ):
    p=curve_256.p()
    if self == INFINITY:
      return INFINITY
    xyd=((self.__x*self.__x)*inverse_mod(2*self.__y,p))%p
    x3=(9*xyd*xyd-2*self.__x)%p
    y3=(3*xyd*(self.__x-x3)-self.__y)%p
    return Point( x3, y3 )

  def x( self ):
    return self.__x

  def y( self ):
    return self.__y

  def curve( self ):
    return self.__curve
  
  def order( self ):
    return self.__order
    
INFINITY = Point( None, None )

def inverse_mod( a, m ):
  if a < 0 or m <= a: a = a % m
  c, d = a, m
  uc, vc, ud, vd = 1, 0, 0, 1
  while c != 0:
    q, c, d = divmod( d, c ) + ( c, )
    uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
  assert d == 1
  if ud > 0: return ud
  else: return ud + m

# secp256k1
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
# a= 0x0
_Gx= 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy= 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

def dsha256(message):
  if type(message) is unicode: message=message.encode('utf-8')
  hash1=hashlib.sha256(message).digest()
  return int(hashlib.sha256(hash1).hexdigest(),16)

class Signature( object ):
  def __init__( self, pby, r, s ):
    self.r = r
    self.s = s
    self.pby = pby

  def encode(self):
    sigr = binascii.unhexlify(("%064x" % self.r).encode())
    sigs = binascii.unhexlify(("%064x" % self.s).encode())
    return sigr+sigs

class Public_key( object ):
  def __init__( self, generator, point ):
    self.generator = generator
    self.point = point
    n = generator.order()
    if not n:
      raise RuntimeError, "Generator point must have order."
    if not n * point == INFINITY:
      raise RuntimeError, "Generator point order is bad."
    if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
      raise RuntimeError, "Generator point has x or y out of range."

class Private_key( object ):
  def __init__( self, public_key, secret_multiplier ):
    self.public_key = public_key
    self.secret_multiplier = secret_multiplier

  def sign( self, msg_asig, k ):
    hash=dsha256(msg_asig)
    G = self.public_key.generator
    n = G.order()
    p1 = k * G
    r = p1.x()
    if r == 0: raise RuntimeError, "amazingly unlucky random number r"
    s = ( inverse_mod( k, n ) * ( hash + ( self.secret_multiplier * r ) % n ) ) % n
    if s == 0: raise RuntimeError, "amazingly unlucky random number s"
    if s > (n>>1):
        s = n - s
        pby = (p1.y()+1)&1
    else:
        pby = (p1.y())&1
    return Signature( pby, r, s )

def randoml(pointgen):
  cand = 0
  while cand<1 or cand>=pointgen.order():
    cand=int(os.urandom(32).encode('hex'), 16)
  return cand

def bitcoin_sign(privkey, message, k):
  return privkey.sign( "\x18Bitcoin Signed Message:\n" \
                       + chr(len(message)) + message  , 
                       k )

def bitcoin_encode_sig(signature):
  return chr( 27 + signature.pby ) + signature.encode()

curve_256 = CurveFp( _p, _b )
generator_256 = Point( _Gx, _Gy, _r )
g = generator_256