# flag{here_it_is_a8036d2f57ec7cecf8acc2fe6d330a71}
# https://crypto.stackexchange.com/questions/7904/attack-on-dsa-with-signatures-made-with-k-k1-k2
# ghetto input
def s(h1, h2, s1, s2, r1, r2):
    return s1*((h2 - s2 - (h1*r2)/r1)/(s2-s1*r2/r1))/r1 - h1/r1

q = Integer(input("q: "))
G = GF(q)
p = Integer(input("p: "))
g = Integer(input("g: "))
h1 = h2 = G(input("h: "))
r1 = G(input("r1: "))
s1 = G(input("s1: "))
r2 = G(input("r2: "))
s2 = G(input("s2: "))

x = s(h1, h2, s1, s2, r1, r2)
k = 1
r = G(pow(g, k, p))
s = pow(k, q-2, q) * (G(input("Ht: ")) + x * r)
print("r", r)
print("s", s)
