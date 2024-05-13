from Prover import Token
from crypto_params import hash_func,g,q, h, f1, f2
from Issuer import Issuer

def verify_token_sign(T: Token,I: Issuer,flag):
    R_sign,z_sign,y_sign = T.signature
    c_sign = hash_func((I.pk,T.token_pk,T.PI,R_sign))
    if y_sign==0:
        return 0
    
    if flag==1:
        f = f1(c_sign, y_sign)
    if flag==2:
        f = f2(c_sign, y_sign)  
    
    if (R_sign*pow(I.pk,f,q))%q == (pow(g,z_sign,q)*pow(h,y_sign,q)*T.token_pk)%q:
        return 1
    else:
        return 0