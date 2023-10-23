# Yahtzee

The random number generator does not provide remotely enough randomness, so there is a good chance to get multiple ciphertexts with the same nonce. I collected a good amount of pairs and determined the pairs with the smallest hamming distance - that is, likely closest plaintext and same nonce.

Crib dragging can then solve for the keystream which both of the ciphertexts are encrypted with.

flag: `flag{0h_W41t_ther3s_nO_3ntr0py}`
