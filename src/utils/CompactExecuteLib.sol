// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

struct Call {
    address target;
    uint256 value;
    bytes callData;
}

/// @author philogy <https://github.com/philogy>
library CompactExecuteLib {
    /**
     * @dev Payload layout (1 section, multiple calls are concatenated together).
     * +------+-----------+--------------------------------------------------+
     * | Bits | Bit Range |                   Description                    |
     * +------+-----------+--------------------------------------------------+
     * | 1    |   0-0     | 0 = sends ETH; 1 = no ETH                        |
     * | 1    |   1-1     | 0 = new target; 1 = reuse previous               |
     * | 14   |   2-15    | Calldata size (in bytes)                         |
     * | 160  |   ?-?     | Target (if flag set)                             |
     * | 80   |   ?-?     | Value in wei (if flag set)                       |
     * | 0+   |   ?-?     | Calldata                                         |
     * +------+-----------+--------------------------------------------------+
     */

    uint256 internal constant HAS_VALUE_MASK = 0x0001;
    uint256 internal constant REUSE_MASK = 0x0002;
    uint256 internal constant ADDR_MASK = 0x00ffffffffffffffffffffffffffffffffffffffff;
    uint256 internal constant VALUE_MASK = 0xffffffffffffffffffff;

    /**
     * @dev Helper function that encodes payloads to be called by `exec`
     */
    function encode(Call[] memory calls) internal view returns (bytes memory payload) {
        uint256 pointer;
        assembly {
            payload := mload(0x40)
            pointer := add(payload, 0x20)
        }
        for (uint256 i; i < calls.length; i++) {
            address target = calls[i].target;
            uint256 value = calls[i].value;
            require(value <= VALUE_MASK, "Value above max");
            bytes memory callData = calls[i].callData;
            uint256 length = callData.length;
            require(length <= 0x3fff, "Calldata length above max");
            assembly {
                let callHead := shl(2, length)
                if iszero(value) { callHead := or(callHead, HAS_VALUE_MASK) }
                if iszero(target) { callHead := or(callHead, REUSE_MASK) }
                mstore(pointer, shl(240, callHead))
                pointer := add(pointer, 2)
                if value {
                    mstore(pointer, shl(176, value))
                    pointer := add(pointer, 10)
                }
                if target {
                    mstore(pointer, shl(96, target))
                    pointer := add(pointer, 20)
                }
                pop(staticcall(gas(), 0x4, add(callData, 0x20), length, pointer, length))
                pointer := add(pointer, length)
            }
        }

        assembly {
            let totalLen := sub(sub(pointer, payload), 0x20)
            mstore(payload, totalLen)
            mstore(0x40, and(add(add(payload, 0x3f), totalLen), 0xffffffe0))
        }
    }

    function exec(bytes calldata payload) internal {
        assembly {
            let pointer := payload.offset
            let end := add(pointer, payload.length)
            let target := address()
            for {} lt(pointer, end) {} {
                // Read first word of data
                let cword := calldataload(pointer)
                let op := shr(0xf0, cword)
                // Decode callvalue.
                let hasValue := iszero(and(op, HAS_VALUE_MASK))
                let value := mul(hasValue, and(shr(160, cword), VALUE_MASK))
                // Decode and update target.
                let pointerShift := add(2, mul(hasValue, 10))
                let reuse := iszero(and(op, REUSE_MASK))
                if reuse { target := shr(96, shl(shl(3, pointerShift), cword)) }
                // Read length.
                let len := shr(2, op)
                // Update pointer.
                pointer := add(add(pointer, pointerShift), mul(reuse, 20))
                // Prepare calldata.
                calldatacopy(0, pointer, len)
                if iszero(call(gas(), target, value, 0, len, 0, 0)) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
                pointer := add(pointer, len)
            }
            return(0, 0)
        }
    }
}
