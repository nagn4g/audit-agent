// SPDX-License-Identifier: MIT
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
