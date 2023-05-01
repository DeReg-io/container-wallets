// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {StorageBytesLib, StorageBytes} from "../utils/StorageBytesLib.sol";

/// @author philogy <https://github.com/philogy>
abstract contract ContainerFactory {
    using StorageBytesLib for StorageBytes;

    uint256 internal constant MAX_CONTAINER_WORDS = 255;
    uint256 internal constant MAX_CONTAINER_SIZE = MAX_CONTAINER_WORDS * 32;

    StorageBytes private containerContents;

    address internal immutable FACTORY = address(this);

    modifier walletMethod() {
        if (address(this) == FACTORY) revert NotDelegatecall();
        _;
    }

    modifier factoryMethod() {
        if (address(this) != FACTORY) revert Delegatecall();
        _;
    }

    error NotDelegatecall();
    error Delegatecall();
    error ContainerExceedsMaxSize(uint256 contentSize);
    error ContainerAlreadyDeployed();

    constructor() {
        containerContents.wipeSetInit(MAX_CONTAINER_WORDS);
    }

    function getContainerContents() external view factoryMethod {
        bytes memory contents = containerContents.read();
        assembly {
            return(add(contents, 0x20), mload(contents))
        }
    }

    function _createContainer(bytes32 salt, bytes memory contents) internal {
        if (contents.length > MAX_CONTAINER_SIZE) revert ContainerExceedsMaxSize(contents.length);
        // TODO: Replace `containerContents` with transient storage once EIP-1153 is live.
        containerContents.write(contents);
        assembly {
            // Deploy bytecode of `../ContainerCreator.huff`.
            mstore(0x00, 0x6365d6aa8a600052600060006004601c335afa3d600060003e3d6000f3)
            let container := create2(0, 0x3, 0x1d, salt)
            if iszero(container) {
                // Signature of `ContainerAlreadyDeployed()`.
                mstore(0x00, 0x98a76186)
                revert(0x1c, 0x04)
            }
        }
        containerContents.wipeSet();
    }
}
