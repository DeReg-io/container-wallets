// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {MultisigWallet} from "src/MultisigWallet.sol";

/// @author philogy <https://github.com/philogy>
contract WalletTest is Test {
    MultisigWallet factory;

    function setUp() public {
        factory = new MultisigWallet();
    }

    function testCreation() public {
        address[] memory members = new address[](3);
        members[0] = makeAddr("user1");
        members[1] = makeAddr("user2");
        members[2] = makeAddr("user3");

        address wallet = factory.createWallet(members, 2, bytes32(0));
        emit log_named_address("wallet", wallet);
    }
}
