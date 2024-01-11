// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "../static/Base64URL.sol";
import "../static/Structs.sol";
import "./KeyPrecomputations.sol";

library SignatureValidation {
    error InvalidClientData();

    function isSignatureValid(
        P256Signature memory signature,
        AuthenticatorAssertionResponse memory assertion,
        address _precomputationsAddress,
        bytes memory challenge
    ) internal returns (bool) {
        KeyPrecomputations precomputations = KeyPrecomputations(
            _precomputationsAddress
        );

        // messageHash is computed as sha256(authenticatorData || sha256(clientData))
        // both authenticatorData bytes and clientDataJSON hex values are provided in userop

        // 1. Validate challenge is same as the account's challenge
        _validateChallenge(
            assertion.clientData,
            challenge,
            assertion.clientChallengeDataOffset
        );

        // 2. Build message hash from device auth data
        bytes memory verifyData = new bytes(
            assertion.authenticatorData.length + 32
        );

        _copyBytes(
            assertion.authenticatorData,
            0,
            assertion.authenticatorData.length,
            verifyData,
            0
        );

        _copyBytes(
            abi.encodePacked(sha256(assertion.clientData)),
            0,
            32,
            verifyData,
            assertion.authenticatorData.length
        );

        bytes32 messageHash = sha256(verifyData);

        // 3. Verify signature
        bool isValid = precomputations.isSignatureValid(
            messageHash,
            [signature.R, signature.S]
        );

        return isValid;
    }

    function _validateChallenge(
        bytes memory clientData,
        bytes memory challenge,
        uint32 clientChallengeDataOffset
    ) internal pure {
        // Encode the expected account challenge based on smart contract data
        bytes memory challengeEncoded = abi.encodePacked(
            Base64URL.encode32(challenge)
        );

        // Extract the challenge from the client data
        bytes memory challengeExtracted = new bytes(challengeEncoded.length);

        _copyBytes(
            clientData,
            clientChallengeDataOffset,
            challengeExtracted.length,
            challengeExtracted,
            0
        );

        // Verify that challenge is the same
        if (keccak256(challengeEncoded) != keccak256(challengeExtracted)) {
            revert InvalidClientData();
        }
    }

    function _copyBytes(
        bytes memory _from,
        uint _fromOffset,
        uint _length,
        bytes memory _to,
        uint _toOffset
    ) internal pure returns (bytes memory _copiedBytes) {
        uint minLength = _length + _toOffset;
        require(_to.length >= minLength); // Buffer too small. Should be a better way?
        uint i = 32 + _fromOffset; // NOTE: the offset 32 is added to skip the `size` field of both bytes variables
        uint j = 32 + _toOffset;
        while (i < (32 + _fromOffset + _length)) {
            assembly {
                let tmp := mload(add(_from, i))
                mstore(add(_to, j), tmp)
            }
            i += 32;
            j += 32;
        }
        return _to;
    }
}
