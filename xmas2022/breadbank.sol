pragma solidity 0.8.17;

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/master/contracts/token/ERC20/ERC20.sol";


contract FakeBankPair {
    address public owner;
    ERC20 public underlying;
    constructor(ERC20 _underlying, uint256 amount) {
        owner = msg.sender;
        underlying = _underlying;
    }

    function mint(address to, uint256 amount) external {
    }

    function burn(address from, uint256 amount) external {
    }

    function balanceOf(address) public returns (uint256) {
        return underlying.balanceOf(msg.sender);
    }
}

