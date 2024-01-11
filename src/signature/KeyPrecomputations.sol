// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "../cryptography/FCL_Elliptic.sol";

contract KeyPrecomputations {
    uint256 public precomputations_offset;

    constructor(uint256 _offset) {
        precomputations_offset = _offset;
    }

    function isSignatureValid(
        bytes32 message,
        uint256[2] calldata rs
    ) public returns (bool) {
        return
            FCL_Elliptic_ZZ.ecdsa_precomputed_hackmem(
                message,
                rs,
                precomputations_offset
            );
    }
}
