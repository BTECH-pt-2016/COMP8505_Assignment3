import base64
from Crypto.Cipher import AES
from Crypto import Random
import binascii
import string
import random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def int2base(a, base, numerals="0123456789abcdefghijklmnopqrstuvwxyz"):
    baseit = lambda a=a, b=base: (not a) and numerals[0]  or baseit(a-a%b,b*base)+numerals[a%b%(base-1) or (a%b) and (base-1)]
    return baseit()

def encrypt( text, key ):
    #key = pad(key)
    text = pad(text)
    iv = Random.new().read( AES.block_size )
    cipher = AES.new( key, AES.MODE_CBC, iv )
    return binascii.hexlify(iv + cipher.encrypt( text ) )

def decrypt( encText, key ):
    #key = pad(key)
    enc = binascii.unhexlify(encText)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( enc[16:] ))

def generate_password():
    charlen =  string.digits + "abcdef"
    return ''.join(random.choice(charlen) for _ in range(BS))

def parse_port_to_data(sport):
    sport_hex = hex(sport)
        if sport > 4095:
            return chr(int(sport_hex[2:4],16)), chr(int(sport_hex[4:], 16))
                else:
                    return chr(int(sport_hex[2],16)), chr(int(sport_hex[3:], 16))
