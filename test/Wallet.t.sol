// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {MultisigWallet, Sig} from "src/MultisigWallet.sol";

/// @author philogy <https://github.com/philogy>
contract WalletTest is Test {
    MultisigWallet factory;

    function setUp() public {
        factory = new MultisigWallet();
    }

    function testCreation() public {
        uint256[] memory keys = new uint[](3);
        address[] memory members = new address[](3);
        (members[0], keys[0]) = makeAddrAndKey("user1");
        (members[1], keys[1]) = makeAddrAndKey("user2");
        (members[2], keys[2]) = makeAddrAndKey("user3");

        address rec = makeAddr("recipient");

        MultisigWallet wallet = MultisigWallet(payable(factory.createWallet(members, 2, bytes32(0))));
        vm.deal(address(wallet), 10 ether);

        Sig[] memory sigs = new Sig[](2);
        bytes32 hash = wallet.getSendHash(rec, 5 ether);
        sigs[0] = sign(hash, keys[0]);
        sigs[1] = sign(hash, keys[1]);

        wallet.sendETH(rec, 5 ether, sigs);
    }

    function sign(bytes32 hash, uint256 key) internal returns (Sig memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        return Sig(v, r, s);
    }
}
