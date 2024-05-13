from Crypto.Random.random import randint
from crypto_params import q,g, h
from crypto_params import f1, f2

class Issuer():
    def __init__(self, ID):
        self.ID = ID
        self.sk = randint(2,q)
        self.pk = pow(g,self.sk,q)
        
    def first_message(self,m_point):
        self.a = randint(0,q)
        self.b = randint(0,q)
        self.y = randint(1,q)
        A = (pow(g,self.a,q)*m_point)%q
        B = (pow(g,self.b,q)*pow(h,self.y,q))%q
        
        return A,B   


    def third_message(self,c,flag):
        if flag==1: 
            z = (self.a + f1(c,self.y)*self.sk)%(q-1)
        if flag==2:
            z = (self.a + f2(c,self.y)*self.sk)%(q-1)
        return z, self.b, self.y
    



