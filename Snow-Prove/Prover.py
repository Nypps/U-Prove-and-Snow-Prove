from Crypto.Random.random import randint
from Crypto.Util.number import GCD as gcd
from crypto_params import q,g, hash_func
from Issuer import Issuer






class Token():
    def __init__(self,UID_i,token_pk,TI,PI,signature) -> None:
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
        
    def bs_f1_1(self,pk,m_point,A,B):
        self.alpha = randint(1,q)
        while gcd(self.alpha,q-1)!=1:
            self.alpha = randint(1,q)
        self.r = randint(0,q)
        self.beta = randint(0,q)
        self.R_sign = (pow(g,self.r,q)* 
                       pow(A,pow(self.alpha,5,q-1),q)* 
                       pow(pk,pow(self.alpha,5,q-1)*self.beta,q)* 
                       pow(B,self.alpha,q) )%q
        
        self.m = pow(m_point, pow(self.alpha,5,q-1),q)
        self.token_sk = pow(self.alpha,-5,q-1)
        
        c_sign = hash_func((pk,self.m,self.PI,self.R_sign))
        
        c = (c_sign*self.token_sk + self.beta)%(q-1)
        return c
        
        
    def bs_f1_2(self,z,b,y):
        self.z_sign = (self.r + pow(self.alpha,5,q-1)*z + self.alpha*b)%(q-1)
        self.y_sign = (self.alpha*y)%(q-1)
        
    
    def bs_f2_1(self,pk,m_point,A,B):
        self.alpha = randint(1,q)
        while gcd(self.alpha,q-1)!=1:
            self.alpha = randint(1,q)
        self.r = randint(0,q)
        self.beta = randint(1,q)
        while gcd(self.beta,q-1)!=1:
            self.beta = randint(1,q)
        self.R_sign = (pow(g,self.r,q)* pow(A,self.alpha*pow(self.beta,-1,q-1),q)* pow(B,self.alpha,q) )%q
        
        self.m = pow(m_point, self.alpha*pow(self.beta,-1,q-1),q)
        self.token_sk = (self.beta * pow(self.alpha,-1,q-1))%(q-1)
        
        c_sign = hash_func((pk,self.m,self.PI,self.R_sign))
        
        c = (c_sign*self.beta )%(q-1)
        return c
        
    def bs_f2_2(self,z,b,y):
        self.z_sign = (self.r + self.alpha*pow(self.beta,-1,q-1)*z + self.alpha*b)%(q-1)
        self.y_sign = (self.alpha*y)%(q-1)
        
    
    def second_message(self,A,B,m_point,up_issuer: Issuer,flag):
        if flag==1:
            c = self.bs_f1_1(up_issuer.pk,m_point,A,B)
        if flag==2:
            c = self.bs_f2_1(up_issuer.pk,m_point,A,B)
        return c
        
                    
    
    def token_generation(self,z,b,y,TI, up_issuer: Issuer, flag):
        
        if flag==1:
            self.bs_f1_2(z,b,y)
        if flag==2:
            self.bs_f2_2(z,b,y)

        self.T = Token(up_issuer.ID,self.m,TI,self.PI,(self.R_sign, self.z_sign, self.y_sign))
        #self.T.show()
        
