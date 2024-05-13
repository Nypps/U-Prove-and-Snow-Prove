from Crypto.Random.random import randint
from crypto_params import q,g


class Issuer():
    def __init__(self, ID):
        self.ID = ID
        self.sk = randint(2,q)
        self.pk = pow(g,self.sk,q)
        
    def first_message(self,m_point):
        sigma_z = pow(m_point,self.sk,q)
        w = randint(0,q)
        self.w = w
        sigma_a = pow(g,w,q)
        sigma_b = pow(m_point,w,q)
        
        return sigma_z, sigma_a, sigma_b


    def third_message(self,sigma_c):
        sigma_r = (sigma_c*self.sk+self.w)%(q-1)
        return sigma_r
    



