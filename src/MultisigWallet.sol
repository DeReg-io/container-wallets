// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {StorageBytesLib, StorageBytes} from "./utils/StorageBytesLib.sol";
import {WalletCoreDataLib} from "./utils/WalletCoreDataLib.sol";

/// @author philogy <https://github.com/philogy>
contract MultisigWallet {
    using StorageBytesLib for StorageBytes;
    using WalletCoreDataLib for uint256;

    address internal immutable _THIS = address(this);

    uint256 internal constant MAX_CONTAINER_WORDS = 255;
    uint256 internal constant MAX_CONTAINER_SIZE = MAX_CONTAINER_WORDS * 32;
    /// @dev `keccak256("wallet-factory.container-contents") + 1`.
    uint256 internal constant CONTAINER_CONTENTS_SLOT =
        0x41a22856eaf8451f1035ea39682180b4c57706c0400ccad81da3c8d3b7eba068;

    /// @dev 255 * 32 / 20 = 408 (no remainder) => (-1) 407
    uint256 internal constant MAX_MEMBERS = 407;
    uint256 internal constant MAX_THRESHHOLD = 256;

    bytes internal constant WALLET_CODE =
        hex"337f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc55609580602e6000396000f360007f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc548060db1c6101fe16806000363059526055600b60ff81538660e81c59527fb926d5f9997ae396c520af832d4f8bfc53f8b1d5e2d7f106c55c91180ee6430a5952203c36600060003780360190815281816020015260400160006000925af43d600060003e610090573d6000fd5b3d6000f3";
    StorageBytes internal containerContents;

    error ContainerExceedsMaxSize();
    error ContainerAlreadyDeployed();
    error NotDelegatecall();
    error Delegatecall();
    error InvalidThreshhold();
    error TooManyMembers();
    error NoMembers();
    error MembersNotSorted();

    constructor() {
        containerContents.wipeSetInit(MAX_CONTAINER_WORDS);
    }

    modifier onlyDelegatecall() {
        if (address(this) == _THIS) revert NotDelegatecall();
        _;
    }

    modifier onlyCall() {
        if (address(this) != _THIS) revert Delegatecall();
        _;
    }

    function createWallet(address[] calldata members, uint256 threshhold, bytes32 salt)
        external
        onlyCall
        returns (address wallet)
    {
        uint256 totalMembers = members.length;
        if (threshhold > totalMembers || threshhold == 0 || threshhold > MAX_THRESHHOLD) revert InvalidThreshhold();
        if (totalMembers > MAX_MEMBERS) revert TooManyMembers();
        if (totalMembers == 0) revert NoMembers();
        address prevMember = members[0];
        for (uint256 i = 1; i < totalMembers;) {
            address newMember = members[i];
            if (newMember <= prevMember) revert MembersNotSorted();
            prevMember = newMember;
            // forgefmt: disable-next-item
            unchecked { ++i; }
        }
        bytes memory walletDeployCode = WALLET_CODE;
        bytes memory config = abi.encodePacked(uint8(threshhold - 1), members);
        assembly {
            let configSize := mload(config)
            mstore(config, salt)
            let fullSalt := keccak256(config, add(0x20, configSize))
            mstore(config, configSize)
            wallet := create2(0, add(walletDeployCode, 0x20), mload(walletDeployCode), fullSalt)
        }
        if (wallet == address(0)) {
            assembly {
                let initHash := keccak256(add(walletDeployCode, 0x20), mload(walletDeployCode))
                mstore8(0x00, 0xff)
                mstore(0x35, initHash)
                mstore(0x01, shl(96, address()))
                mstore(0x15, salt)
                wallet := keccak256(0x00, 0x55)
                mstore(0x35, 0)
            }
        } else {
            MultisigWallet(wallet).initialize(config);
        }
    }

    function initialize(bytes calldata contents) external onlyDelegatecall {
        // Ensures wasn't called before by checking that zero-container wasn't already deployed.
        _createContainer(0, contents);

        // forgefmt: disable-next-item
        WalletCoreDataLib.loadCoreData()
            .updateImplementation(_THIS)
            .updatePing(uint32(block.timestamp))
            .updateConfigSize(uint8((contents.length + 31) / 32))
            .saveCoreData();
    }

    function getContainerContents() external view onlyDelegatecall {
        bytes memory contents = containerContents.read();
        assembly {
            return(add(contents, 0x20), mload(contents))
        }
    }

    function _createContainer(uint24 nonce, bytes calldata contents) internal {
        if (contents.length > MAX_CONTAINER_SIZE) revert ContainerExceedsMaxSize();
        // TODO: Replace with transient storage once EIP-1153 is live.
        containerContents.write(contents);
        assembly {
            // Deploy bytecode of `./ContainerCreator.huff`.
            mstore(0x00, 0x6365d6aa8a600052600060006004601c335afa3d600060003e3d6000f3)
            let container := create2(0, 0x3, 0x1d, nonce)
            if iszero(container) {
                // Signature of `ContainerAlreadyDeployed()`.
                mstore(0x00, 0x98a76186)
                revert(0x1c, 0x04)
            }
        }
        containerContents.wipeSet();
    }
}
