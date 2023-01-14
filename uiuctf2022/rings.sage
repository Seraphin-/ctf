# wrinting rings
# looks like this script dumps the secret? have to connect to the server yourself
# uiuctf{turn5_0ut_th4t_th3_1nt3g3r5_4l50_5uck}

R = PolynomialRing(QQ, 'x') 
x = """[(1, 98874)
       (2, 4146758)
       (3, 91226380)
       (4, 877201320)
       (5, 5205390902)
       (6, 22611506194)
       (7, 78985679928)
       (9, 617287397650)
       (10, 1470531678462)]""".replace("\n", ",")
x=eval(x)
from tqdm import tqdm
for secret in tqdm(range(500_000)):
    c = R.lagrange_polynomial([(0, secret)]+x).coefficients()
    if any(r > 500_000 for r in c) or any(r.denominator() != 1 for r in c):
        continue
    print(c)
