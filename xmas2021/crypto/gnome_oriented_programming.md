# Gnome Oriented Programming (crypto 93)

A very simple crypto challenge. The challenge encrypts the flag with a "one-time-pad" and lets us specify an alphanumeric string to encrypt with the same key. Because of XOR's basic properties, we can decrypt the flag using the output.

```math
C_{flag} = \text{flag} \oplus K
C_{input} = \text{input} \oplus K
\text{flag} \oplus \text{input} = (\text{input} \oplus K) \oplus (\text{flag} \oplus K)
\text{flag} = (\text{flag} \oplus \text{input}) \oplus \text{input}
```

## Flag
`X-MAS{D0n7_Y0u_3v3r_Wr1te_S1n6leton5_F0r_0tp_G3ner4tor5_08hdj12}`
