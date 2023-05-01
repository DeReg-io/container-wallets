// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {StorageBytesLib, StorageBytes} from "src/utils/StorageBytesLib.sol";

/// @author philogy <https://github.com/philogy>
contract StorageBytesLibTest is Test {
    using StorageBytesLib for StorageBytes;

    StorageBytes internal s;

    function testDefaultLengthZero() public {
        assertEq(s.length(), 0);
    }

    function test_fuzzWrite(bytes calldata contents) public {
        vm.assume(contents.length <= StorageBytesLib.MAX_BYTES_LENGTH);
        s.write(contents);
        assertEq(s.read(), contents);
    }

    function test_fuzzDelete(bytes calldata contents) public {
        vm.assume(contents.length <= StorageBytesLib.MAX_BYTES_LENGTH);
        s.write(contents);
        s.wipe();
        assertEq(s.read(), "");
        assertEq(s.length(), 0);
    }

    function test_fuzzDeleteSet(bytes calldata contents) public {
        vm.assume(contents.length <= StorageBytesLib.MAX_BYTES_LENGTH);
        s.write(contents);
        s.wipeSet();
        assertEq(s.read(), "");
        assertEq(s.length(), 0);
    }
}
