// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

struct ECDSASignature {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

struct P256Signature {
    uint256 R;
    uint256 S;
}

struct DevicePublicKey {
    uint256 x;
    uint256 y;
}

struct AuthenticatorAssertionResponse {
    bytes authenticatorData;
    bytes clientData;
    uint32 clientChallengeDataOffset;
}
