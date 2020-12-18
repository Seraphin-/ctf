n = Integer(raw_input("N:"), 16)
e = 0x10001
bad_s = Integer(raw_input("Bad signature:"), 16)

m = Integer(raw_input("Message:"), 16)
target = Integer(raw_input("Target:"), 16)

p = gcd(pow(bad_s, e)-m, n)
q = n // p
phi = (p-1)*(q-1)
d_p = inverse_mod(e, p-1)
d_q = inverse_mod(e, q-1)
inv_q = inverse_mod(q, p)

s_p = int(pow(target, d_p, p))
s_q = int(pow(target, d_q, q))
s = s_q + q * ((inv_q * (s_p - s_q)) % p)

print(hex(s))
