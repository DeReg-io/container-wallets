// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author philogy <https://github.com/philogy>
library MultisigWalletDataLib {
    uint256 internal constant ERC1967_IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    uint256 internal constant CONTAINER_INIT_HASH = 0xb926d5f9997ae396c520af832d4f8bfc53f8b1d5e2d7f106c55c91180ee6430a;

    error MaxConfigNonce();

    /**
     * @dev Storage layout
     * +---------+---------+-------------------------+
     * | Bits    | Type    | Description             |
     * +---------+---------+-------------------------+
     * | 0-159   | address | Proxy implementation    |
     * | 160-191 | uint32  | Wallet nonce            |
     * | 192-223 | uint32  | Last used timestamp     |
     * | 224-231 | uint8   | Config size (EVM words) |
     * | 232-255 | uint24  | Config nonce            |
     * +---------+---------+-------------------------+
     */
    function getCoreData() internal pure returns (uint256 value) {
        assembly {
            value := calldataload(sub(calldatasize(), 0x20))
        }
    }

    function loadCoreData() internal view returns (uint256 value) {
        assembly {
            value := sload(ERC1967_IMPL_SLOT)
        }
    }

    function updateImplementation(uint256 coreData, address implementation) internal pure returns (uint256) {
        return (coreData & 0xffffffffffffffffffffffff0000000000000000000000000000000000000000)
            | uint256(uint160(implementation));
    }

    function updateConfigSize(uint256 coreData, uint8 wordSize) internal pure returns (uint256) {
        return
            (coreData & 0xffffff00ffffffffffffffffffffffffffffffffffffffffffffffffffffffff) | (uint256(wordSize) << 224);
    }

    function updateConfig(uint256 coreData, uint8 wordSize)
        internal
        pure
        returns (uint256 newCoreData, uint256 configNonce)
    {
        newCoreData =
            (coreData & 0xffffff00ffffffffffffffffffffffffffffffffffffffffffffffffffffffff) | (uint256(wordSize) << 224);
        unchecked {
            newCoreData += 0x10000000000000000000000000000000000000000000000000000000000;
        }
        configNonce = newCoreData >> 232;
        if (configNonce == 0) {
            revert MaxConfigNonce();
        }
    }

    function updateExtraData(uint256 coreData, uint64 extraData) internal pure returns (uint256) {
        return
            (coreData & 0xffffffff0000000000000000ffffffffffffffffffffffffffffffffffffffff) | (uint256(extraData) << 64);
    }

    function saveCoreData(uint256 coreData) internal {
        assembly {
            sstore(ERC1967_IMPL_SLOT, coreData)
        }
    }

    function getConfig(uint256 coreData, address deployer) internal view returns (bytes memory config) {
        assembly {
            // Allocate config and load values.
            config := mload(0x40)
            let len := and(shr(0xdb, coreData), 0x1fe0)
            mstore(config, len)
            let configDataOffset := add(config, 0x20)
            mstore(0x40, add(configDataOffset, len))
            let nonce := shr(232, coreData)

            // Determine container address (Credit [Solady](https://github.com/Vectorized/solady/blob/main/src/utils/LibClone.sol)).
            mstore8(0x00, 0xff)
            mstore(0x35, CONTAINER_INIT_HASH)
            let salt := or(shl(96, address()), nonce)
            mstore(0x01, shl(96, deployer))
            mstore(0x15, salt)
            let container := keccak256(0x00, 0x55)
            mstore(0x35, 0)

            // Load container contents.
            extcodecopy(container, configDataOffset, 0, len)
        }
    }

    function updateNonce(uint256 coreData) internal pure returns (uint256, uint256 nonce) {
        assembly {
            nonce := and(shr(160, coreData), 0xffffffff)
            coreData := add(coreData, 0x10000000000000000000000000000000000000000)
        }
        return (coreData, nonce);
    }

    function getNonce(uint256 coreData) internal pure returns (uint256) {
        return (coreData >> 160) & 0xffffffff;
    }

    function updatePing(uint256 coreData) internal view returns (uint256 newCoreData) {
        assembly {
            newCoreData :=
                or(and(coreData, 0xffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffff), shl(192, timestamp()))
        }
    }

    function getPing(uint256 coreData) internal pure returns (uint256) {
        return (coreData >> 192) & 0xffffffff;
    }

    uint256 private constant MALLEABILITY_THRESHOLD = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 private constant ECRECOVER = 0x1;

    function getSigners(bytes32 hash, bytes calldata sig) internal view returns (address[] memory signers) {
        assembly {
            let packedV := calldataload(sig.offset)
            // Get length.
            let totalSigners := shr(6, sig.length)
            // Allocate array.
            signers := mload(0x40)
            mstore(signers, totalSigners)
            let signerOffset := add(signers, 0x20)

            // Prepare ecrecover calldata.
            mstore(0x00, hash)

            let rsOffset := add(sig.offset, 0x20)

            for { let i := 0 } lt(i, totalSigners) { i := add(i, 1) } {
                // Set v.
                mstore(0x20, add(27, and(shr(i, packedV), 1)))
                // Set r + s.
                calldatacopy(0x40, add(rsOffset, shl(6, i)), 0x40)
                // Get signer, can be 0 if invalid, `isAuth` will check.
                let signerDest := add(signerOffset, shl(5, i))
                mstore(signerDest, 0)
                pop(staticcall(gas(), ECRECOVER, 0x00, 0x80, signerDest, 0x20))
            }

            mstore(0x40, add(signerOffset, shl(5, totalSigners)))
            mstore(0x60, 0)
        }
    }
}
