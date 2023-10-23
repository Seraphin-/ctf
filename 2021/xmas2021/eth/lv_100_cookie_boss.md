# lvl 100 cookie boss (eth 454)

The "Cookie" contract is created with a secret password on challenge launch. We need to identify the password to "unlock" the box and solve the challenge:

```
    function unlockCookieBox(string memory _password) public {
        if (keccak256(abi.encodePacked(password)) == keccak256(abi.encodePacked(_password))) {
            owner = msg.sender;
        }
    }
```

Since nothing is secret on the blockchain, we can obtain the password by calling `getBlock` to find the current block number then `getBlockByNumber` to obtain its transaction data, which includes the password on construction.

## Flag
`X-MAS{y0nd_w4s7_My_c00ki3_f0r_th3_c0nf1rmed_c0mmun1ty}`
