// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

struct UserOp {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes sig;
}

/// @author philogy <https://github.com/philogy>
interface IAccount {
    function validateUserOp(UserOp calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData);
}
