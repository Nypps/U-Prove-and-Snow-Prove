from Issuer import Issuer
from Prover import Prover
from crypto_params import m_point, q, g
from Verify import verify_token_sign
from time import time

print('[*] gamma:',m_point)
print('[*] q:',q)
print('[*] g:',g)

arr = []

up_issuer = Issuer(12345)
up_prover = Prover(1234561)

for i in range(100):
    
    start = time()

    z,a,b = up_issuer.first_message(m_point)

    c = up_prover.second_message(z,a,b,m_point, up_issuer)

    r = up_issuer.third_message(c)

    up_prover.token_generation(r, 123, up_issuer)

    if verify_token_sign(up_prover.T, up_issuer)==0:
        print('incorrect signature')
        exit()
    
    finish = time()
    
    arr.append(finish-start)


average_time = sum(arr)/len(arr)
print('[*] average time:', average_time)
test=open('test_time.txt', 'a')
test.write(str(average_time)+'\n')
test.close()