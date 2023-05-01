// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author philogy <https://github.com/philogy>
library MultiAuthLib {
    /// @dev Ensures `t` fits in 1-byte.
    uint256 internal constant MAX_THRESHOLD = 256;

    error ThresholdAboveMax(uint256 threshold);
    error ThresholdZero();
    error ThresholdGreaterThanAuthorizers(uint256 threshold, uint256 totalAuths);
    error AuthorizersNotSortedUnique();
    error MultiAuthFailed();

    /**
     * @dev Validates `threshold` and tightly packs `authorizers` and the `threshhold` into
     * one byte-string.
     * @param authorizers Set of authorized addresses to be packed. Must be sorted, unique and not
     * contain the zero-address.
     * @param threshold The minimum amount of authorizers that will be required from the set to
     * authorize an action.
     */
    function buildConfig(address[] calldata authorizers, uint256 threshold)
        internal
        pure
        returns (bytes memory config)
    {
        assembly {
            // Check threshhold
            let t := sub(threshold, 1)
            let totalAuths := authorizers.length
            if iszero(and(lt(t, MAX_THRESHOLD), gt(totalAuths, t))) {
                if iszero(threshold) {
                    // Selector of `ThresholdZero()`.
                    mstore(0x00, 0x9dd75d79)
                    revert(0x1c, 0x04)
                }
                mstore(0x20, threshold)
                if iszero(gt(MAX_THRESHOLD, t)) {
                    // Selector of `ThresholdAboveMax(uint)`.
                    mstore(0x00, 0xb28f7142)
                    revert(0x1c, 0x24)
                }
                // Selector of `ThresholdGreaterThanAuthorizers(uint, uint)`.
                mstore(0x00, 0xcba6c6fe)
                mstore(0x40, totalAuths)
                revert(0x1c, 0x44)
            }
            // Allocate config bytes.
            let configSize := add(mul(totalAuths, 20), 1)
            config := mload(0x40)
            mstore(add(config, 1), t)
            mstore(config, configSize)
            mstore(0x40, and(add(0x3f, add(config, configSize)), 0xffffffe0))

            // Check and store authorizers.
            let validAuthOrder := 1
            let lastAuth := 0
            let cdOffset := authorizers.offset
            let endOffset := add(cdOffset, shl(5, totalAuths))
            // Can underflow, will act as negative integer.
            let memOffset := add(config, 0x21)
            for { let offset := cdOffset } lt(offset, endOffset) { offset := add(offset, 32) } {
                let auth := shl(96, calldataload(offset))
                validAuthOrder := and(validAuthOrder, gt(auth, lastAuth))
                lastAuth := auth
                mstore(memOffset, auth)
                memOffset := add(memOffset, 20)
            }
            //
            if iszero(validAuthOrder) {
                // Selector of `AuthorizersNotSortedUnique()`.
                mstore(0x00, 0x8235eaf1)
                revert(0x1c, 0x04)
            }
        }
    }

    function buildConfigMem(address[] memory authorizers, uint256 threshold)
        internal
        pure
        returns (bytes memory config)
    {
        assembly {
            // Check threshhold
            let t := sub(threshold, 1)
            let totalAuths := mload(authorizers)
            if iszero(and(lt(t, MAX_THRESHOLD), gt(totalAuths, t))) {
                if iszero(threshold) {
                    // Selector of `ThresholdZero()`.
                    mstore(0x00, 0x9dd75d79)
                    revert(0x1c, 0x04)
                }
                mstore(0x20, threshold)
                if iszero(gt(MAX_THRESHOLD, t)) {
                    // Selector of `ThresholdAboveMax(uint)`.
                    mstore(0x00, 0xb28f7142)
                    revert(0x1c, 0x24)
                }
                // Selector of `ThresholdGreaterThanAuthorizers(uint, uint)`.
                mstore(0x00, 0xcba6c6fe)
                mstore(0x40, totalAuths)
                revert(0x1c, 0x44)
            }
            // Allocate config bytes.
            let configSize := add(mul(totalAuths, 20), 1)
            config := mload(0x40)
            mstore(add(config, 1), t)
            mstore(config, configSize)
            mstore(0x40, and(add(0x3f, add(config, configSize)), 0xffffffe0))

            // Check and store authorizers.
            let validAuthOrder := 1
            let lastAuth := 0
            let authOffset := add(authorizers, 0x20)
            let endOffset := add(authOffset, shl(5, totalAuths))
            let memOffset := add(config, 0x21)
            for { let offset := authOffset } lt(offset, endOffset) { offset := add(offset, 32) } {
                let auth := shl(96, mload(offset))
                validAuthOrder := and(validAuthOrder, gt(auth, lastAuth))
                lastAuth := auth
                mstore(memOffset, auth)
                memOffset := add(memOffset, 20)
            }
            //
            if iszero(validAuthOrder) {
                // Selector of `AuthorizersNotSortedUnique()`.
                mstore(0x00, 0x8235eaf1)
                revert(0x1c, 0x04)
            }
        }
    }

    function isAuth(bytes memory config, address[] memory validators) internal pure returns (bool authorized) {
        assembly {
            let threshold := add(and(mload(add(config, 1)), 0xff), 1)
            let validated := 1

            let validatorOffset := add(validators, 0x20)
            let totalValidators := mload(validators)

            let validatorEndOffset := add(validatorOffset, shl(5, totalValidators))
            let lastValidator := 0

            let memberOffset := add(config, 0x21)
            let memberEndOffset := add(memberOffset, mload(config))

            for {} and(lt(validatorOffset, validatorEndOffset), lt(memberOffset, memberEndOffset)) {} {
                let validator := mload(validatorOffset)
                validatorOffset := add(validatorOffset, 0x20)

                for {} lt(memberOffset, memberEndOffset) {} {
                    let member := shr(96, mload(memberOffset))
                    memberOffset := add(memberOffset, 20)
                    if iszero(sub(member, validator)) {
                        validated := add(validated, gt(validator, lastValidator))
                        lastValidator := validator
                        break
                    }
                }
            }

            authorized := and(gt(validated, threshold), gt(validated, totalValidators))
        }
    }

    function checkAuth(bytes memory config, address[] memory validators) internal pure {
        assembly {
            let threshold := add(and(mload(add(config, 1)), 0xff), 1)
            let validated := 1

            let validatorOffset := add(validators, 0x20)
            let totalValidators := mload(validators)

            let validatorEndOffset := add(validatorOffset, shl(5, totalValidators))
            let lastValidator := 0

            let memberOffset := add(config, 0x21)
            let memberEndOffset := add(memberOffset, mload(config))

            for {} and(lt(validatorOffset, validatorEndOffset), lt(memberOffset, memberEndOffset)) {} {
                let validator := mload(validatorOffset)
                validatorOffset := add(validatorOffset, 0x20)

                for {} lt(memberOffset, memberEndOffset) {} {
                    let member := shr(96, mload(memberOffset))
                    memberOffset := add(memberOffset, 20)
                    if iszero(sub(member, validator)) {
                        validated := add(validated, gt(validator, lastValidator))
                        lastValidator := validator
                        break
                    }
                }
            }

            if iszero(and(gt(validated, threshold), gt(validated, totalValidators))) {
                // Selector of `MultiAuthFailed()`.
                mstore(0x00, 0x11b03786)
                revert(0x1c, 0x04)
            }
        }
    }
}
