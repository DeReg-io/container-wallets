// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {MultiAuthLib} from "../../utils/MultiAuthLib.sol";
import {CompactExecuteLib} from "../../utils/CompactExecuteLib.sol";
import {ContainerFactory} from "../../base/ContainerFactory.sol";
import {MultisigWalletDataLib} from "./MultisigWalletDataLib.sol";
import {IAccount, UserOperation} from "account-abstraction/interfaces/IAccount.sol";

struct Call {
    address target;
    uint256 value;
    bytes callData;
}

/// @author philogy <https://github.com/philogy>
contract Multisig is ContainerFactory, IAccount {
    using MultisigWalletDataLib for uint256;

    address public immutable ENTRY_POINT;

    /// @dev 255 * 32 / 20 = 408 (no remainder) => (-1) 407
    uint256 internal constant MAX_MEMBERS = 407;

    bytes internal constant WALLET_CODE =
        hex"337f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc55604280602c5f395ff3365f5f375f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc54803652366020015f5f925af43d5f5f3e61003e573d5ffd5b3d5ff3";

    error TooManyMembers();
    error NoMembers();
    error MembersNotSorted();
    error AlreadyInitialized();
    error NotEntryPoint();
    error NotWallet();

    constructor(address entryPoint) {
        ENTRY_POINT = entryPoint;
    }

    function createWallet(address[] calldata members, uint256 threshold, bytes32 salt)
        external
        onlyCall
        returns (address wallet)
    {
        _checkMembers(members);
        bytes memory walletDeployCode = WALLET_CODE;
        bytes memory config = MultiAuthLib.buildConfig(members, threshold);
        bytes32 fullSalt;
        assembly {
            let configSize := mload(config)
            mstore(config, salt)
            fullSalt := keccak256(config, add(0x20, configSize))
            mstore(config, configSize)
            wallet := create2(0, add(walletDeployCode, 0x20), mload(walletDeployCode), fullSalt)
        }
        if (wallet == address(0)) {
            assembly {
                let initHash := keccak256(add(walletDeployCode, 0x20), mload(walletDeployCode))
                mstore8(0x00, 0xff)
                mstore(0x35, initHash)
                mstore(0x01, shl(96, address()))
                mstore(0x15, fullSalt)
                wallet := keccak256(0x00, 0x55)
                mstore(0x35, 0)
            }
        } else {
            Multisig(payable(wallet)).initialize(config.length);
            _storeConfig(wallet, 0, config);
        }
    }

    function predictDeploy(address[] calldata members, uint256 threshold, bytes32 salt)
        external
        view
        onlyCall
        returns (address wallet)
    {
        _checkMembers(members);
        bytes memory walletDeployCode = WALLET_CODE;
        bytes memory config = MultiAuthLib.buildConfig(members, threshold);
        bytes32 fullSalt;
        assembly {
            let configSize := mload(config)
            mstore(config, salt)
            fullSalt := keccak256(config, add(0x20, configSize))
            mstore(config, configSize)
            let initHash := keccak256(add(walletDeployCode, 0x20), mload(walletDeployCode))
            mstore8(0x00, 0xff)
            mstore(0x35, initHash)
            mstore(0x01, shl(96, address()))
            mstore(0x15, fullSalt)
            wallet := keccak256(0x00, 0x55)
            mstore(0x35, 0)
        }
    }

    function createConfig(uint24 nonce, bytes calldata config) external onlyCall {
        _storeConfig(msg.sender, nonce, config);
    }

    // -- Wallet Functions

    modifier onlyEntryPoint() {
        if (msg.sender != ENTRY_POINT) revert NotEntryPoint();
        _;
    }

    modifier onlyWallet() {
        if (msg.sender != address(this)) revert NotWallet();
        _;
    }

    receive() external payable onlyDelegate {}

    function initialize(uint256 contentLength) external onlyDelegate {
        uint256 coreData = MultisigWalletDataLib.getCoreData();

        if (coreData.getPing() != 0) revert AlreadyInitialized();

        // forgefmt: disable-next-item
        coreData
            .updatePing()
            .updateConfigSize(uint8((contentLength + 31) / 32))
            .saveCoreData();
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, address, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        onlyDelegate
        returns (uint256 validationData)
    {
        uint256 coreData = MultisigWalletDataLib.getCoreData();
        // Get signers from signatures.
        address[] memory signers = MultisigWalletDataLib.getSigners(userOpHash, userOp.signature);
        // Verify signers.
        bytes memory config = coreData.getConfig(_THIS);

        bool valid = MultiAuthLib.isAuth(config, signers);

        uint256 nonce;
        (coreData, nonce) = coreData.updatePing().updateNonce();

        coreData.saveCoreData();

        uint256 iniLen = userOp.initCode.length;
        uint256 opNonce = userOp.nonce;
        assembly {
            // bool valid = valid && nonce == opNonce && (nonce == 0 || initCode.length == 0)
            // validationData = valid ? 0 : 1
            validationData := iszero(and(valid, and(eq(nonce, opNonce), or(iszero(nonce), iszero(iniLen)))))

            if missingAccountFunds { pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0)) }
        }
    }

    function execute(bytes calldata payload) external onlyEntryPoint onlyDelegate {
        CompactExecuteLib.exec(payload);
    }

    function updateAuth(address[] calldata members, uint256 threshold) external onlyDelegate onlyWallet {
        _checkMembers(members);
        bytes memory config = MultiAuthLib.buildConfig(members, threshold);

        uint256 coreData = MultisigWalletDataLib.getCoreData();
        uint256 configNonce;
        (coreData, configNonce) = coreData.updateConfig(uint8((config.length + 31) / 32));
        coreData.saveCoreData();

        Multisig(payable(_THIS)).createConfig(uint24(configNonce), config);
    }

    function updateImplementation(address newImplementation, bytes memory initCall) external onlyDelegate onlyWallet {
        // forgefmt: disable-next-item
        MultisigWalletDataLib
            .getCoreData()
            .updateImplementation(newImplementation)
            .saveCoreData();

        assembly {
            if iszero(delegatecall(gas(), newImplementation, add(initCall, 0x20), mload(initCall), 0, 0)) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }

    function getNonce() external view onlyDelegate returns (uint256) {
        return MultisigWalletDataLib.getCoreData().getNonce();
    }

    function lastPing() external view onlyDelegate returns (uint256) {
        return MultisigWalletDataLib.getCoreData().getPing();
    }

    function getConfig() external view onlyDelegate returns (bytes memory) {
        return MultisigWalletDataLib.getCoreData().getConfig(_THIS);
    }

    function _storeConfig(address wallet, uint24 configNonce, bytes memory config) internal {
        bytes32 containerSalt;
        assembly {
            containerSalt := or(shl(96, wallet), configNonce)
        }
        _createContainer(containerSalt, config);
    }

    function _checkMembers(address[] calldata members) internal pure {
        uint256 totalMembers = members.length;
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
    }
}
