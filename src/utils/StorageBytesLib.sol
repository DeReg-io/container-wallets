// SPDX-License-Identifier: MIT
pragma solidity ^0.8.8;

struct StorageBytes {
    uint256 __placeholder__;
}

/// @author philogy <https://github.com/philogy>
library StorageBytesLib {
    uint256 internal constant MAX_BYTES_LENGTH = 0xffff;

    function length(StorageBytes storage self) internal view returns (uint256 len) {
        assembly {
            mstore(0x00, self.slot)
            let slot := keccak256(0x00, 0x20)
            len := shr(0xf0, sload(slot))
        }
    }

    function write(StorageBytes storage self, bytes memory content) internal {
        assembly {
            // Derive slot.
            mstore(0x00, self.slot)
            let slot := keccak256(0x00, 0x20)
            let len := mload(content)
            // Cap maximum length and store length + first 30 bytes.
            // `max(len, MAX_BYTES_LENGTH)`
            len := xor(mul(xor(len, MAX_BYTES_LENGTH), gt(len, MAX_BYTES_LENGTH)), len)
            sstore(slot, mload(add(0x1e, content)))

            // Store remainder.
            let offset := add(content, 0x20)
            for { let i := 0x1e } lt(i, len) { i := add(i, 0x20) } {
                slot := add(slot, 1)
                sstore(slot, mload(add(offset, i)))
            }
        }
    }

    function wipe(StorageBytes storage self) internal {
        assembly {
            mstore(0x00, self.slot)
            let slot := keccak256(0x00, 0x20)
            let slot1 := sload(slot)
            sstore(slot, 0)
            let offset := 0x1e
            for { let len := shr(0xf0, slot1) } lt(offset, len) { offset := add(offset, 0x20) } {
                slot := add(slot, 1)
                sstore(slot, 0)
            }
        }
    }

    function wipeSetInit(StorageBytes storage self, uint256 len) internal {
        assembly {
            mstore(0x00, self.slot)
            let slot := keccak256(0x00, 0x20)
            sstore(slot, 1)
            let offset := 0x1e
            for {} lt(offset, len) { offset := add(offset, 0x20) } {
                slot := add(slot, 1)
                sstore(slot, 1)
            }
        }
    }

    function wipeSet(StorageBytes storage self) internal {
        assembly {
            mstore(0x00, self.slot)
            let slot := keccak256(0x00, 0x20)
            let slot1 := sload(slot)
            sstore(slot, 1)
            let offset := 0x1e
            for { let len := shr(0xf0, slot1) } lt(offset, len) { offset := add(offset, 0x20) } {
                slot := add(slot, 1)
                sstore(slot, 1)
            }
        }
    }

    function read(StorageBytes storage self) internal view returns (bytes memory value) {
        assembly {
            // Derive slot.
            mstore(0x00, self.slot)
            let slot := keccak256(0x00, 0x20)
            // Load length and initial bytes.
            let slot1 := sload(slot)
            // Allocate bytes object.
            value := mload(0x40)
            let len := shr(0xf0, slot1)
            mstore(0x40, and(add(0x3f, add(value, len)), 0xffffffe0))
            // Store length and initial bytes.
            mstore(value, 0)
            mstore(add(value, 0x1e), slot1)
            // Load & Store remaining bytes.
            let vOffset := add(value, 0x20)
            for { let offset := 0x1e } lt(offset, len) { offset := add(offset, 0x20) } {
                slot := add(slot, 1)
                mstore(add(vOffset, offset), sload(slot))
            }
            // Override dirty bytes & ensure padded with zeros.
            mstore(add(vOffset, len), 0)
        }
    }
}
