// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {StorageBytesLib, StorageBytes} from "../utils/StorageBytesLib.sol";
import {DualSelfImpl} from "./DualSelfImpl.sol";

/// @author philogy <https://github.com/philogy>
abstract contract ContainerFactory is DualSelfImpl {
    using StorageBytesLib for StorageBytes;

    uint256 internal constant MAX_CONTAINER_WORDS = 255;
    uint256 internal constant MAX_CONTAINER_SIZE = MAX_CONTAINER_WORDS * 32;

    StorageBytes private containerContents;

    error ContainerExceedsMaxSize(uint256 contentSize);
    error ContainerAlreadyDeployed();

    constructor() {
        containerContents.wipeSetInit(MAX_CONTAINER_SIZE);
    }

    function getContainerContents() external view onlyCall {
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
            mstore(0x00, 0x6365d6aa8a5f525f5f6004601c335afa3d5f5f3e3d5ff3)

            let container := create2(0, 0x9, 0x17, salt)
            if iszero(container) {
                // Signature of `ContainerAlreadyDeployed()`.
                mstore(0x00, 0x98a76186)
                revert(0x1c, 0x04)
            }
        }
        containerContents.wipeSet();
    }
}
