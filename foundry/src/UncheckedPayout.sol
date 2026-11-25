// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title UncheckedPayout
/// @notice Intentionally vulnerable demo contract for AuditAgent.
///         pay() performs a low-level call and ignores whether it succeeded,
///         then records the payout as complete either way.
contract UncheckedPayout {
    mapping(address => uint256) public balances;
    mapping(address => bool) public paid;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Pays the caller's full balance to `recipient`.
    /// @dev BUG: the bool returned by the low-level call is ignored. Even when
    ///      the recipient rejects the ETH (receive() reverts), we still mark the
    ///      payout as done and zero the sender's balance, so the funds are stuck.
    function pay(address payable recipient) external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to pay");

        // Sender's balance is zeroed regardless of the transfer outcome.
        balances[msg.sender] = 0;

        // BUG: the bool returned by this low-level call is ignored entirely.
        // There is no `(bool ok, ) = ...` and no `require(ok)`, so a failed
        // transfer is treated exactly like a success.
        recipient.call{value: amount}("");

        // Recorded as done even though the ETH never moved.
        paid[recipient] = true;
    }

    receive() external payable {}
}
