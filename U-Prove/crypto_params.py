from Crypto.Util.number import  long_to_bytes, bytes_to_long, getPrime
from Crypto.Random.random import randint
from Crypto.Hash import SHA256
from sympy import primitive_root


attr = []
q = getPrime(256)
g = primitive_root(q)
m_point = pow(g,randint(2,q),q)



def hash_func(m: tuple):
    m_bytes = b''
    for a in m:
        if type(a) == int:
            m_bytes+=long_to_bytes(a)
        else:
            m_bytes+=a
    return bytes_to_long(SHA256.new(m_bytes).digest())%q