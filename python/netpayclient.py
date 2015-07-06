#!/bin/env python
#encoding=utf8

import binascii
import hashlib
import ConfigParser
import gmpy2
from Crypto.Cipher import DES

DES_KEY = 'SCUBEPGW'
HASH_PAD = '0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a05000414'

PRIVATE_KEY = {}
def hex2bin(hexdata):
    return binascii.a2b_hex(hexdata)

def bin2hex(bindata):
    return binascii.b2a_hex(bindata)

def bcdechex(hecdata):
    '''
    base = [str(x) for x in range(10)] + [ chr(x) for x in range(ord('A'),ord('A')+6)]
    num = int(hecdata)
    mid = []
    while True:
        if num == 0: break
        num,rem = divmod(num, 16)
        mid.append(base[rem])

    return ''.join([str(x) for x in mid[::-1]])
    '''

    #return hex(int(hecdata,10))
    #return str(hex(hecdata))[2:].strip('L')
    return '%x' % hecdata

def padstr(src, length = 256, char = '0', d = 'L'):
    src = src.strip(' ')
    padlen = length - len(src)
    if padlen > 0:
        pad = char * padlen
        if d.upper() == 'L':
            src = pad + src
        else:
            src = src + pad

    return src

def bin2int(bindata):
    return int(bin2hex(bindata).upper(),16)

def bchexdec(hexdata):
    return int(hexdata, 16)

def sign(msg):
    if "MERID" not in PRIVATE_KEY:
        return False

    hb = sha1_128(msg)
    return rsa_encrypt(hb)

def rsa_encrypt(_input):
    p = bin2int(PRIVATE_KEY['prime1'])
    q = bin2int(PRIVATE_KEY['prime2'])
    u = bin2int(PRIVATE_KEY['coefficient'])
    dP = bin2int(PRIVATE_KEY['prime_exponent1'])
    dQ = bin2int(PRIVATE_KEY['prime_exponent2'])
    c = bin2int(_input)

    cp = c % p
    cq = c % q

    a = int(gmpy2.powmod(cp, dP, p))
    b = int(gmpy2.powmod(cq, dQ, q))

    if a >= b:
        result = a - b
    else:
        result = b - a
        result = p - result

    result = result % p
    result = result * u
    result = result % p
    result = result * q
    result = result + b

    ret = bcdechex(result)
    ret = padstr(ret).upper()
    if len(ret) == 256:
        return ret
    else:
        return False

def buildKey(key):
    global PRIVATE_KEY
    if len(PRIVATE_KEY) > 0:
        PRIVATE_KEY = {}

    try:
        cf = ConfigParser.ConfigParser()
        cf.optionxform = str
        cf.read(key)
    except ConfigParser.MissingSectionHeaderError,e:
        print e
        return False

    #remove sections,same key will be overrided by later.
    options = {}
    for section in cf.sections():
        for k,v in cf.items(section):
            options[k] = v
    h = ""
    ret = False
    if "MERID" in options:
        ret = options['MERID']
        PRIVATE_KEY['MERID'] = options['MERID']
        h = options['prikeyS'][80:]
    elif 'PGID' in options:
        ret = options['PGID']
        PRIVATE_KEY['PGID'] = options['PGID']
        h = options['pubkeyS'][48:]
    else:
        return ret
    b = hex2bin(h)
    PRIVATE_KEY['modulus'] = b[:128]
    #see http://docs.python-guide.org/en/latest/scenarios/crypto/
    iv = "\x00" * 8
    prime1 = b[384:384+64]
    enc = DES.new(DES_KEY, DES.MODE_CBC, iv)
    PRIVATE_KEY['prime1'] = enc.decrypt(prime1)

    prime2 = b[448:448+64]
    enc = DES.new(DES_KEY, DES.MODE_CBC, iv)
    PRIVATE_KEY['prime2'] = enc.decrypt(prime2)

    prime_exponent1 = b[512:512+64]
    enc = DES.new(DES_KEY, DES.MODE_CBC, iv)
    PRIVATE_KEY['prime_exponent1'] = enc.decrypt(prime_exponent1)

    prime_exponent2 = b[576:576+64]
    enc = DES.new(DES_KEY, DES.MODE_CBC, iv)
    PRIVATE_KEY['prime_exponent2'] = enc.decrypt(prime_exponent2)

    coefficient = b[640:640+64]
    enc = DES.new(DES_KEY, DES.MODE_CBC, iv)
    PRIVATE_KEY['coefficient'] = enc.decrypt(coefficient)

    return ret

def rsa_decrypt(_input):
    check = bchexdec(_input)
    modulus = bin2int(PRIVATE_KEY['modulus'])
    exponent = int("010001", 16)
    result = int(gmpy2.powmod(check, exponent, modulus))
    rb = bcdechex(result)
    return padstr(rb).upper()

def sha1_128(string):
    h = hashlib.sha1(string).hexdigest()
    sha_bin = hex2bin(h)
    sha_pad = hex2bin(HASH_PAD)

    return '%s%s' % (sha_pad, sha_bin)

def verify(plain, check):
    if "PGID" not in PRIVATE_KEY:
        return False
    if len(check) != 256:
        return False

    hb = sha1_128(plain)
    hbhex = bin2hex(hb).upper()
    rbhex = rsa_decrypt(check)
    return hbhex == rbhex

def verifyTransResponse(merid, ordno, amout, curyid, transdate, transtype, ordstatus, check):
    if len(merid) != 15:
        return False
    if len(ordno) != 16:
        return False
    if len(amout) != 12:
        return False
    if len(curyid) != 3:
        return False
    if len(transdate) != 8:
        return False
    if len(transtype) != 4:
        return False
    if len(ordstatus) != 4:
        return False
    if len(check) != 256:
        return False

    plain = '%s%s%s%s%s%s%s' % (merid, ordno, amout, curyid, transdate, transtype, ordstatus)
    return verify(plain, check)
