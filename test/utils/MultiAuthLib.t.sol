// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {MultiAuthLib} from "src/utils/MultiAuthLib.sol";
import {FixedPointMathLib as Math} from "solady/utils/FixedPointMathLib.sol";
import {LibSort} from "solady/utils/LibSort.sol";
import {console2} from "forge-std/console2.sol";
import {safelog} from "forge-safe-log/safelog.sol";

/// @author philogy <https://github.com/philogy>
contract MultiAuthLibTest is Test {
    function testLargeConfig() public {
        uint256 threshold = 256;
        uint256 length = 1800;
        inner_test_fuzzGetConfig(
            generateRandomSorted(length, uint256(keccak256("DN is where it's at (testLargeConfig)"))), threshold
        );
    }

    function test_fuzzGetConfig(uint256 authsLength, uint256 authsSeed, uint256 threshhold) public {
        /// @dev Limited to 256 to prevent test failing due to `MemoryLimitOOG` error and make it run fast.
        authsLength = bound(authsLength, 1, 256);
        uint256 thresholdBound = Math.min(authsLength, MultiAuthLib.MAX_THRESHOLD);
        threshhold = bound(threshhold, 1, thresholdBound);
        address[] memory auths = generateRandomSorted(authsLength, authsSeed);
        inner_test_fuzzGetConfig(auths, threshhold);
    }

    function testBasicAuth() public {
        vm.pauseGasMetering();
        address[] memory addrs = generateRandomSorted(5, uint256(keccak256("yeet (testBasicAuth)")));
        uint256 t = 3;
        bytes memory config = MultiAuthLib.buildConfigMem(addrs, t);
        address[] memory validators = new address[](t);
        validators[0] = addrs[0];
        validators[1] = addrs[1];
        validators[2] = addrs[3];
        vm.resumeGasMetering();

        assertTrue(MultiAuthLib.isAuth(config, validators));
    }

    function testDoesNotAcceptDuplicateAuth() public {
        vm.pauseGasMetering();
        address[] memory addrs = generateRandomSorted(7, uint256(keccak256("yeet (testBasicAuth)")));
        uint256 t = 4;
        bytes memory config = MultiAuthLib.buildConfigMem(addrs, t);
        address[] memory validators = new address[](t);
        validators[0] = addrs[1];
        validators[1] = addrs[2];
        validators[2] = addrs[5];
        validators[3] = addrs[5];
        vm.resumeGasMetering();

        assertFalse(MultiAuthLib.isAuth(config, validators));
    }

    function buildConfig(address[] calldata auths, uint256 t) external pure returns (bytes memory) {
        return MultiAuthLib.buildConfig(auths, t);
    }

    function inner_test_fuzzGetConfig(address[] memory auths, uint256 threshhold) internal {
        bytes memory libConfig = MultiAuthLib.buildConfigMem(auths, threshhold);
        bytes memory naiveConfig = abi.encodePacked(uint8(threshhold - 1));
        for (uint256 i = 0; i < auths.length; i++) {
            naiveConfig = abi.encodePacked(naiveConfig, auths[i]);
        }
        assertEq(libConfig, naiveConfig);
    }

    function generateRandomSorted(uint256 len, uint256 seed) internal pure returns (address[] memory addrs) {
        addrs = new address[](len);
        address addr = address(0);
        uint256 maxAddrDelta = 0x00ffffffffffffffffffffffffffffffffffffffff / len;
        for (uint256 i; i < len; i++) {
            assembly {
                mstore(0x00, seed)
                seed := keccak256(0x00, 0x20)
                let gain := mod(seed, maxAddrDelta)
                addr := add(add(addr, 1), gain)
            }
            addrs[i] = addr;
        }
    }
}
