from collections import namedtuple
from random import randint

public_key = namedtuple("public_key", ("e", "n"))
private_key = namedtuple("private_key", ("d", "n"))

class RSA:
    """A simple implementation of RSA(Rivest–Shamir–Adleman) algorithm in Python 3

    Attributes:
        p, q 		Prime numbers.
        n   		n = p * q.
        phi 		Totient for n ( phi(n) = (p-1) * (q-1) ).
        e   		Coprime of phi that is greater than 1 and less than n.
        d   		Modular multiplicative inverse of e.
        pbk 		Public key(e, n)
        pvk 		Private key(d, n)
    """

    def __init__(self, gt=1000):
        p, q = RSA.generate_primes(gt=gt)
        self.set_primes(p, q)

    def set_primes(self, p, q):
        self.p = p
        self.q = q
        self.calc_keys()

    def calc_n(self):
        self.n = self.p * self.q

    def calc_totient(self):
        self.phi = (self.p - 1) * (self.q - 1)

    def calc_e(self):
        e = randint(2, self.n-1)
        while(not RSA.is_coprime(e, self.phi)):
            e = randint(2, self.n-1)
        self.e = e

    def calc_d(self):
        self.d = RSA.modinv(self.e, self.phi)

    def calc_keys(self):
        self.calc_n()
        self.calc_totient()
        self.calc_e()
        self.calc_d()
        self.__pbk = public_key(self.e, self.n)
        self.__pvk = private_key(self.d, self.n)

    @property
    def pbk(self):
        return self.__pbk

    @property
    def pvk(self):
        return self.__pvk

    def encrypt_block(self, m):
        c = RSA.modinv(m**self.e, self.n)
        return c

    def decrypt_block(self, c):
        m = RSA.modinv(c**self.d, self.n)
        return m

    def encrypt_string(self, s):
        return "".join(chr(self.encrypt_block(ord(x))) for x in list(s))

    def decrypt_string(self, s):
        return ''.join([chr(self.decrypt_block(ord(x))) for x in list(s)])

    @staticmethod
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = RSA.egcd(b % a, a)
            return g, x - (b // a) * y, y

    @staticmethod
    def is_coprime(a, b):
        g, x, y = RSA.egcd(a, b)
        if g != 1:
            return False
        else:
            return True

    @staticmethod
    def modinv(a, m):
        g, x, y = RSA.egcd(a, m)
        if g != 1:
            return None
        else:
            return x % m
    @staticmethod
    def generate_primes(gt=1000):
        p = RSA.generate_prime(gt=gt)
        q = RSA.generate_prime(gt=p+1)
        return p, q

    @staticmethod
    def generate_prime(gt=1000):
        p = randint(gt+1, 2*gt)
        while(not RSA.is_prime(p)):
            p += 1
        return p

    @staticmethod
    def is_prime(x):
        if x<=1:
            return False
        if x<=3:
            return True
        if (x%2== 0 or x%3==0) :
            return False
        i = 5
        while(i*i<=x):
            if(x%i== 0 or x%(i+2)==0):
                return False
            i = i + 6
        return True
