from Crypto.Random.random import randint
from crypto_params import q,g, hash_func
from Issuer import Issuer




class Token():
    def __init__(self,UID_i,token_pk,TI,PI,signature):
        self.TI = TI
        self.UID_p = UID_i
        self.token_pk = token_pk
        self.PI = PI
        self.signature = signature

    def show(self):
        print('###Token### \n\
                [*] Token information field: {0} \n\
                [*] Token public key: {1} \n\
                [*] Prover information field {2} \n\
                [*] Signature {3}'.format(self.TI,self.token_pk,self.PI,self.signature))

class Prover():
    def __init__(self, PI):
        self.PI = PI
        
    def second_message(self,z,a,b,m_point,up_issuer: Issuer):
        self.s = randint(1,q)
        self.u = randint(0,q)
        self.v = randint(0,q)
        
        self.m = pow(m_point,self.s,q)
        
        self.token_sk = pow(self.s,-1,q)
        self.z_point = pow(z,self.s,q)
        a_point = (pow(up_issuer.pk,self.u,q)*pow(g,self.v,q)*a)%q
        b_point = (pow(self.z_point,self.u,q)*pow(self.m,self.v,q)*pow(b,self.s,q))%q
        
        self.c_point = hash_func((self.m,
                                  self.PI,
                                  self.z_point,
                                  a_point,
                                  b_point))
        c = (self.c_point + self.u)%(q-1)
        
        return c
                    
    
    def token_generation(self,r,TI, up_issuer: Issuer):
        self.r_point = (r+self.v)%(q-1)
        self.T = Token(up_issuer.ID,self.m,TI,self.PI,(self.z_point,
                                                  self.c_point,
                                                  self.r_point)
                  )
        
        
        #self.T.show()
        

