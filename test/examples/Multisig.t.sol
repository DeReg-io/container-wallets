// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {Multisig, Call} from "src/examples/multisig/Multisig.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {LibSort} from "solady/utils/LibSort.sol";
import {LibString} from "solady/utils/LibString.sol";

/// @author philogy <https://github.com/philogy>
contract MultisigTest is Test {
    using LibString for uint256;

    Multisig internal factory;
    EntryPoint internal entryPoint;

    address trnsfrRec = makeAddr("transfer recipient");
    address callRec = makeAddr("sponsor");

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new Multisig(address(entryPoint));
    }

    function testDirectWalletCreation() public {
        (Multisig wallet, address[] memory signers,) = createWallet("signer_", 3, 2, bytes32(0));

        assertEq(address(wallet), factory.predictDeploy(signers, 2, bytes32(0)));
        assertEq(wallet.getNonce(), 0);
    }

    function testERC4337Deployment() public {
        uint256 threshold = 2;
        bytes32 salt = bytes32(0);
        uint256 snapshot = vm.snapshot();
        (Multisig wallet, address[] memory signers, uint256[] memory sk) = createWallet("signer_", 3, threshold, salt);
        vm.revertTo(snapshot);

        vm.deal(address(wallet), 10 ether);

        Call[] memory calls = new Call[](1);
        uint256 amount = 1 ether;
        calls[0] = Call({target: trnsfrRec, value: amount, callData: new bytes(0)});

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: address(wallet),
            nonce: 0,
            initCode: abi.encodePacked(factory, abi.encodeCall(wallet.createWallet, (signers, threshold, salt))),
            callData: abi.encodeCall(wallet.execute, calls),
            callGasLimit: 2e6,
            verificationGasLimit: 2e6,
            preVerificationGas: 2e6,
            maxFeePerGas: 20 gwei,
            maxPriorityFeePerGas: 0.1 gwei,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        bytes32 opHash = entryPoint.getUserOpHash(ops[0]);
        ops[0].signature = signAndEncode(opHash, sk, abi.decode(abi.encode(0x20, 2, 0, 2), (uint256[])));

        entryPoint.handleOps(ops, payable(callRec));

        assertEq(trnsfrRec.balance, amount);
        // assertEq(wallet.getNonce(), 1);
    }

    function testERC4337Operation() public {
        (Multisig wallet, address[] memory signers, uint256[] memory sk) = createWallet("signer_", 3, 2, bytes32(0));
        assertEq(wallet.getNonce(), 0);
        vm.deal(address(wallet), 10 ether);

        Call[] memory calls = new Call[](1);
        uint256 amount = 1 ether;
        calls[0] = Call({target: trnsfrRec, value: amount, callData: new bytes(0)});

        UserOperation memory op = UserOperation({
            sender: address(wallet),
            nonce: wallet.getNonce(),
            initCode: new bytes(0),
            callData: abi.encodeCall(wallet.execute, calls),
            callGasLimit: 2e6,
            verificationGasLimit: 2e6,
            preVerificationGas: 2e6,
            maxFeePerGas: 20 gwei,
            maxPriorityFeePerGas: 0.1 gwei,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        bytes32 opHash = entryPoint.getUserOpHash(op);
        uint256[] memory indices = new uint[](2);
        indices[0] = 0;
        indices[1] = 2;
        op.signature = signAndEncode(opHash, sk, indices);

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;

        entryPoint.handleOps(ops, payable(callRec));

        assertEq(trnsfrRec.balance, amount);
        assertEq(wallet.getNonce(), 1);
    }

    function createWallet(string memory name, uint256 signerCount, uint256 threshold, bytes32 salt)
        internal
        returns (Multisig wallet, address[] memory signers, uint256[] memory sk)
    {
        (signers, sk) = getSigners(name, signerCount);
        wallet = Multisig(payable(factory.createWallet(signers, threshold, salt)));
    }

    function getSigners(string memory name, uint256 signerCount)
        internal
        returns (address[] memory signers, uint256[] memory sk)
    {
        signers = new address[](signerCount);
        sk = new uint[](signerCount);
        for (uint256 i; i < signerCount; i++) {
            (signers[i], sk[i]) = makeAddrAndKey(string(abi.encodePacked(name, i.toString())));
        }
        // Dumb Sort (Bubble Sort).
        for (uint256 i = 0; i < signerCount; i++) {
            for (uint256 j = i + 1; j < signerCount; j++) {
                if (signers[i] > signers[j]) {
                    (signers[i], signers[j]) = (signers[j], signers[i]);
                    (sk[i], sk[j]) = (sk[j], sk[i]);
                }
            }
        }
    }

    function signAndEncode(bytes32 opHash, uint256[] memory sk, uint256[] memory indices)
        internal
        returns (bytes memory)
    {
        uint256 packedV;
        bytes32[] memory packedRS = new bytes32[](indices.length * 2);

        for (uint256 i; i < indices.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk[indices[i]], opHash);
            packedV = packedV | (uint256(v - 27) << i);
            packedRS[i * 2] = r;
            packedRS[i * 2 + 1] = s;
        }

        return abi.encodePacked(packedV, packedRS);
    }
}
