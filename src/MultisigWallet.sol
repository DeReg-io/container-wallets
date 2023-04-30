// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {StorageBytesLib, StorageBytes} from "./utils/StorageBytesLib.sol";
import {WalletCoreDataLib} from "./utils/WalletCoreDataLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

struct Sig {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

/// @author philogy <https://github.com/philogy>
contract MultisigWallet {
    using StorageBytesLib for StorageBytes;
    using WalletCoreDataLib for uint256;

    address internal immutable _FACTORY = address(this);

    uint256 internal constant MAX_CONTAINER_WORDS = 255;
    uint256 internal constant MAX_CONTAINER_SIZE = MAX_CONTAINER_WORDS * 32;
    /// @dev `keccak256("wallet-factory.container-contents") + 1`.
    uint256 internal constant CONTAINER_CONTENTS_SLOT =
        0x41a22856eaf8451f1035ea39682180b4c57706c0400ccad81da3c8d3b7eba068;

    /// @dev 255 * 32 / 20 = 408 (no remainder) => (-1) 407
    uint256 internal constant MAX_MEMBERS = 407;
    uint256 internal constant MAX_THRESHHOLD = 256;

    bytes internal constant WALLET_CODE =
        hex"337f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc55604b80602e6000396000f336600060003760007f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc548036523660200160006000925af43d600060003e610046573d6000fd5b3d6000f3";

    StorageBytes internal containerContents;

    error ContainerExceedsMaxSize();
    error ContainerAlreadyDeployed();
    error NotDelegatecall();
    error Delegatecall();
    error InvalidThreshhold();
    error TooManyMembers();
    error NoMembers();
    error MembersNotSorted();
    error AlreadyInitialized();

    receive() external payable onlyDelegatecall {}

    constructor() {
        containerContents.wipeSetInit(MAX_CONTAINER_WORDS);
    }

    modifier onlyDelegatecall() {
        if (address(this) == _FACTORY) revert NotDelegatecall();
        _;
    }

    modifier onlyCall() {
        if (address(this) != _FACTORY) revert Delegatecall();
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
            MultisigWallet(payable(wallet)).initialize(config.length);
            _createContainer(wallet, 0, config);
        }
    }

    function initialize(uint256 contentLength) external onlyDelegatecall {
        uint256 coreData = WalletCoreDataLib.getCoreData();

        if (coreData.getPing() != 0) revert AlreadyInitialized();

        // forgefmt: disable-next-item
        coreData
            .updatePing(uint32(block.timestamp))
            .updateConfigSize(uint8((contentLength + 31) / 32))
            .saveCoreData();
    }

    function getConfig() external view onlyDelegatecall returns (bytes memory) {
        return WalletCoreDataLib.getCoreData().getConfig(_FACTORY);
    }

    function getSendHash(address to, uint256 amount) public view returns (bytes32) {
        return keccak256(abi.encode(keccak256("SEND_WOW"), to, amount));
    }

    function sendETH(address to, uint256 amount, Sig[] calldata sigs) external onlyDelegatecall {
        uint256 coreData = WalletCoreDataLib.getCoreData();
        bytes memory config = coreData.getConfig(_FACTORY);
        uint256 threshhold = uint256(uint8(config[0])) + 1;
        uint256 validated = 0;
        uint256 i = 0;
        uint256 j = 0;
        uint256 totalMembers = config.length / 0x20;
        address prevValidated = address(0);
        bytes32 hash = getSendHash(to, amount);
        while (i < sigs.length && validated < threshhold && j < totalMembers) {
            address signer = ECDSA.recover(hash, sigs[i].v, sigs[i].r, sigs[i].s);
            require(signer > prevValidated, "OUT_OF_ORDER");
            assembly {
                let member := 0
                for {} and(lt(j, totalMembers), iszero(eq(member, signer))) { j := add(j, 1) } {
                    member := mload(add(config, add(shl(5, j), 0x21)))
                }
                if eq(member, signer) {
                    i := add(i, 1)
                    validated := add(validated, 1)
                    prevValidated := signer
                }
            }
        }

        require(validated >= threshhold, "NO_VALIDATION");

        (bool success,) = to.call{value: amount}("");
        require(success, "NO_SUCC");
    }

    function getContainerContents() external view onlyCall {
        bytes memory contents = containerContents.read();
        assembly {
            return(add(contents, 0x20), mload(contents))
        }
    }

    function _createContainer(address wallet, uint24 nonce, bytes memory contents) internal {
        if (contents.length > MAX_CONTAINER_SIZE) revert ContainerExceedsMaxSize();
        // TODO: Replace with transient storage once EIP-1153 is live.
        containerContents.write(contents);
        assembly {
            // Deploy bytecode of `./ContainerCreator.huff`.
            mstore(0x00, 0x6365d6aa8a600052600060006004601c335afa3d600060003e3d6000f3)
            let salt := or(shl(96, wallet), nonce)
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
