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
