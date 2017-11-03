import random
import md5

a = []
for i in range(0, 128):
    a.append(random.randint(0, 2**128))
    m = md5.new()
    m.update('random.randint(0, 2**128)')
    d = m.hexdigest()
    b = bin(int(d, 16))[2:].zfill(128)
    print a[i], bin(a[i]), b
