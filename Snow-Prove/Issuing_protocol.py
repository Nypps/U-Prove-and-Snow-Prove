from Issuer import Issuer
from Prover import Prover
from crypto_params import m_point, g, q
from Verify import verify_token_sign
from time import time

up_issuer = Issuer(12345)
up_prover = Prover(1234561)

flag = 2


print('[*] gamma:',m_point)
print('[*] g:', g)
print('[*] q:', q)

arr = []

for i in range(100):

    start = time()

    A, B = up_issuer.first_message(m_point)

    c = up_prover.second_message(A,B,m_point, up_issuer, flag)

    z,b,y = up_issuer.third_message(c,flag)

    up_prover.token_generation(z,b,y,123,up_issuer,flag)
    
    finish = time()
    
    arr.append(finish-start)

    if verify_token_sign(up_prover.T, up_issuer, flag)==0:
        print('[*] incorrect signature')
        
average_time = sum(arr)/len(arr)
print('[*] average time:', average_time)
test=open('test_time.txt', 'a')
test.write(str(average_time)+'\n')
test.close()
