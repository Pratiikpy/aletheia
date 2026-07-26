// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal self-contained ERC-20 honeypot: buyable, but non-owner CANNOT sell (transfer to pair reverts).
/// Used ONLY as a deterministic test fixture to validate Verity's honeypot simulation.
contract Honeypot {
    string public name = "TrapCoin";
    string public symbol = "TRAP";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    address public owner;
    address public pair;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 supply) {
        owner = msg.sender;
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function setPair(address _pair) external {
        require(msg.sender == owner, "only owner");
        pair = _pair;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= value, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - value;
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(balanceOf[from] >= value, "balance");
        // THE TRAP: any transfer INTO the pair (i.e. a SELL) from a non-owner reverts.
        require(!(to == pair && from != owner), "cannot sell");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
