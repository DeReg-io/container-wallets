// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author philogy <https://github.com/philogy>
library WalletCoreDataLib {
    uint256 internal constant ERC1967_IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    error MaxConfigNonce();

    // Core Functions

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

    // Default Wallet Specific
    function updateNonce(uint256 coreData) internal pure returns (uint256 newCoreData, uint256 nonce) {
        nonce = (coreData >> 160) & 0xffffffff;
        unchecked {
            newCoreData = coreData + 0x010000000000000000000000000000000000000000;
        }
    }

    function updatePing(uint256 coreData, uint32 time) internal pure returns (uint256) {
        return (coreData & 0xffffffff00000000ffffffffffffffffffffffffffffffffffffffffffffffff) | (uint256(time) << 192);
    }
}
