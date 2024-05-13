from Prover import Token
from crypto_params import hash_func,g,q
from Issuer import Issuer

def verify_token_sign(T: Token,I: Issuer):
    z_point,c_point,r_point = T.signature
    if T.token_pk==1:
        return 0
    if c_point==hash_func((
        T.token_pk,
        T.PI,
        z_point,
        (pow(g,r_point,q)*pow(I.pk,-c_point,q))%q,
        (pow(T.token_pk,r_point,q)*pow(z_point,-c_point,q))%q
    )):
        return 1
    else:
        return 0
        
        
        