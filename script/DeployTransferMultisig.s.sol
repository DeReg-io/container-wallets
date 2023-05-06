// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Script} from "forge-std/Script.sol";
import {MultisigTest} from "test/examples/Multisig.t.sol";
import {Multisig} from "src/examples/multisig/Multisig.sol";
import {CompactExecuteLib, Call} from "src/utils/CompactExecuteLib.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {safelog} from "forge-safe-log/safelog.sol";

/// @author philogy <https://github.com/philogy>
contract DeployTransferMultisig is Script, MultisigTest {
    function run() public {
        uint256 depSk = vm.envUint("PRIV_KEY");
        address dep = vm.addr(depSk);

        safelog.log("bal: %d", dep.balance);

        vm.startBroadcast(depSk);

        EntryPoint entryPoint = new EntryPoint();
        Multisig factory = new Multisig(address(entryPoint));

        (address[] memory signers, uint256[] memory sk) = getSigners("signer_", 3);

        Multisig wallet = Multisig(payable(factory.predictDeploy(signers, 2, bytes32(0))));

        (bool success,) = address(wallet).call{value: 5 ether}("");

        Call[] memory calls = new Call[](2);
        uint256 amount = 1 ether;
        calls[0] = Call({target: makeAddr("rec_1"), value: amount, callData: new bytes(0)});
        calls[1] = Call({target: address(entryPoint), value: 0.1 ether, callData: new bytes(0)});

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: address(wallet),
            nonce: 0,
            initCode: abi.encodePacked(factory, abi.encodeCall(wallet.createWallet, (signers, 2, bytes32(0)))),
            callData: abi.encodeCall(wallet.execute, CompactExecuteLib.encode(calls)),
            callGasLimit: 1e6,
            verificationGasLimit: 300_000,
            preVerificationGas: 100_000,
            maxFeePerGas: 20 gwei,
            maxPriorityFeePerGas: 0.1 gwei,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        uint256[] memory sigIndices = new uint[](2);
        sigIndices[0] = 0;
        sigIndices[1] = 2;
        ops[0].signature = signAndEncode(entryPoint.getUserOpHash(ops[0]), sk, sigIndices);

        entryPoint.handleOps{gas: 3e6}(ops, payable(dep));

        amount = 0.8 ether;
        calls = new Call[](1);
        address recipient = makeAddr("rec_2");
        (success,) = recipient.call{value: 1 wei}("");
        success;

        calls[0] = Call({target: recipient, value: amount, callData: new bytes(0)});

        ops[0] = UserOperation({
            sender: address(wallet),
            nonce: wallet.getNonce(),
            initCode: new bytes(0),
            callData: abi.encodeCall(wallet.execute, CompactExecuteLib.encode(calls)),
            callGasLimit: 50_000,
            verificationGasLimit: 100_000,
            preVerificationGas: 100_000,
            maxFeePerGas: 20 gwei,
            maxPriorityFeePerGas: 0.1 gwei,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        ops[0].signature = signAndEncode(entryPoint.getUserOpHash(ops[0]), sk, sigIndices);
        entryPoint.handleOps{gas: 3e6}(ops, payable(dep));

        vm.stopBroadcast();
    }
}
// e4 404
