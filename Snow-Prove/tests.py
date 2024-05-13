import subprocess

for _ in range(10):
    subprocess.run(['python', 'Issuing_protocol.py'])

f = open('test_time.txt')
arr_g = [float(a) for a in f.readlines()]
print(sum(arr_g)/len(arr_g))
f.close()
with open('test_time.txt', 'w'):
    pass


