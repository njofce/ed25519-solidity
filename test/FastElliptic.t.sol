// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/FastElliptic.sol";

contract FastEllipticCurveTest is Test {
    FastElliptic public ec;

    function setUp() public {
        ec = new FastElliptic();
    }

    function testValidateSignature_Valid() public {
        bool res = ec.ecdsa_verify(
            0xfb7edfd2016f07021f538da7d26d67509c1369cb5ef729db71143528b17aa069,
            [
                0x9bd9ebe8b6ec5aa98729d8de2a361a79cc21aedc5942385a992a2f1ccfd5e62a,
                0x18efff3a995d00cc55392ed677717de60de87192fde4196545e26e162940b69a
            ],
            [
                0x1a65071a68a5c7a8b5d1e381c0b0f808e201660d2221cf15f8cdf9a71c97ab66,
                0xb457062eb11298f074d4d63cacd23a796d1e2c45c68007797289189620d9e846
            ]
        );

        assertTrue(res);
    }

    function testValidateSignature_Invalid() public {
        bool res = ec.ecdsa_verify(
            0xfb7edfd2016f07121f538da7d26d67509c1369cb5ef729db71143528b17aa069,
            [
                0x9bd9ebe8b6ec5aa98729d8de2a361a79cc21aedc5942385a992a2f1ccfd5e62a,
                0x18efff3a995d00cc55392ed677717de60de87192fde4196545e26e162940b69a
            ],
            [
                0x1a65071a68a5c7a8b5d1e381c0b0f808e201660d2221cf15f8cdf9a71c97ab66,
                0xb4570622b11298f074d4d63cacd23a796d1e2c45c68007797289189620d9e846
            ]
        );

        assertFalse(res);
    }
}
