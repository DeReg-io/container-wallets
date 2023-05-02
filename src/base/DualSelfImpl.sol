// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author philogy <https://github.com/philogy>
abstract contract DualSelfImpl {
    address internal immutable _THIS = address(this);

    error NotDelegatecall();
    error Delegatecall();

    modifier onlyDelegate() {
        if (address(this) == _THIS) revert NotDelegatecall();
        _;
    }

    modifier onlyCall() {
        if (address(this) != _THIS) revert Delegatecall();
        _;
    }
}
