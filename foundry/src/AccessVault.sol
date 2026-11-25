// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AccessVault
/// @notice Intentionally vulnerable demo contract for AuditAgent.
///         The constructor records an owner, but the privileged drain()
///         function never checks msg.sender against that owner.
contract AccessVault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        // Deposits are credited to the vault balance, not to a per-user ledger.
    }

    /// @notice Privileged function: drains the whole vault to the caller.
    /// @dev BUG: there is NO access-control check here. No onlyOwner modifier,
    ///      no require(msg.sender == owner), nothing. Any address can call
    ///      drain() and walk away with every depositor's ETH.
    function drain() external {
        uint256 amount = address(this).balance;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "drain failed");
    }

    /// @notice Allows the vault to be funded directly with plain ETH transfers.
    receive() external payable {}
}
