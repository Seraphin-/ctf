# CaramelPooler (eth 499)
The challenge implements a weird king-of-the-hill system where you need the total supply of value in the contract to solve. The balances in the contract are spread out accross 10 accounts, whose addresses are "missing" in the Setup contract, but otherwise the pool can be funded directly if you know holders' address.

```
contract CaramelPool {
    constructor (address[] memory _depositors) {
        for ( uint i = 0; i < _depositors.length; i++ ) { 
            uint256 _amount = 100000 * (uint256(10) * decimals); // 1-10th
            balanceOf[_depositors[i]] = _amount;
        }
    }
    function isContract(address _addr) private view returns (bool is_contract) {
        uint length;
        assembly {
            length := extcodesize(_addr) // broken
        }
        return length > 0;
    }

    function fundPool(address _from) public {
        require(!isContract(msg.sender), "No contractz allowed.");
        uint256 _balance = balanceOf[_from];
        balanceOf[_from] = 0;
        withdrawAmount += _balance; 
    }

    function withdrawFromPool() public {
        require(!isContract(msg.sender), "You can't withdraw from the pool");
        require(withdrawAmount <= totalSupply, "Don't try to hack the pool");
        balanceOf[msg.sender] = withdrawAmount;
        withdrawAmount = 0;
    }

    function becomeCaramelShogun() public {
        require(balanceOf[msg.sender] >= totalSupply, "You don't have enough tokens to become the Caramel Shogun");
        caramelShogun = msg.sender;
    }
}
```

The challenge attempts to verify the interactee is not a contract using `extcodesize()`. However, this does not work if the sender is calling the contract in its constructor. Unintentionally, this does not matter because there is no need to even use an attack contract to solve - the challenge should be solvable by just calling fundPool on each of the depositor addresses and then withdrawing from the pool.

We can obtain the depositor addresses by decompiling the challenge bytecode on creation using the same technique as in "lv 100 cookie boss" to obtain the code. Here they are (note that some are not really valid):
```
0x0136439830e1abe0296b764691eb3fc296d145bf
0x122e53f0444ac267371a0cf63d15cd782d8bb1c6
0x00000000219ab540356cbb839cbe05303d7705fa
0x4452552736041bcc3fe0f35647e56f2c4fdf956e
0x0001e0515bc0b5c2df1abc2842b42b29994f44d0
0x97eebf4908c5c08eb09196579fc6451585d1b9a6
0x1352cb6ccec784dd765ac55f0413cadfa4946cfd
0x14db6558f0dfcd940dae566c20f694d2f0454ca8
0x13182312eed5a75d62e45b726b63639b6a8f25bc
0x1337cee91653179667c33affdbc28264c50c40b0

```

I am dumb and solved it by transferring 5 depositors each to a malicious contract and 5 to me, then having the malicious contract transfer its amount to me. I misread the "require" in withdrawFromPool as having a `<`, not `<=`.

## Flag
`X-MAS{G00d_j0b_y0u_4r3_Hideyoshis_h31r}`
