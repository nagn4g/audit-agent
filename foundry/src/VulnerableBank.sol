// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title VulnerableBank
/// @notice Intentionally vulnerable demo contract for the AuditAgent hackathon.
///         withdraw() performs the external call BEFORE zeroing the balance,
///         which allows a classic reentrancy drain.
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] = 0;
    }

    receive() external payable {}
}
