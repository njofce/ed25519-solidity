// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../src/cryptography/FastElliptic.sol";
import "../../src/precompiled/fcl_ecdsa_precbytecode.sol";

import "../../src/cryptography/FCL_elliptic.sol";

//echo "itsakindofmagic" | sha256sum, used as a label to find precomputations inside bytecode
uint256 constant _MAGIC_ENCODING = 0x9a8295d6f225e4f07313e2e1440ab76e26d4c6ed2d1eb4cbaa84827c8b7caa8d;

contract Wrap_ecdsa_precal_hackmem {
    uint256 public precomputations;

    //compute the coefficients for multibase exponentiation, then their wnaf representation
    //note that this function can be implemented in the front to reduce tx cost

    function wrap_ecdsa_core(
        bytes32 message,
        uint256[2] calldata rs
    ) public returns (bool) {
        return
            FCL_Elliptic_ZZ.ecdsa_precomputed_hackmem(
                message,
                rs,
                precomputations
            );
    }

    function wrap_ecdsa_core_addr(
        bytes32 message,
        uint256[2] calldata rs,
        address shamir
    ) public returns (bool) {
        return FCL_Elliptic_ZZ.ecdsa_precomputed_verify(message, rs, shamir);
    }

    //provide the offset of precomputations in the contract
    constructor(uint256 offset_bytecode) {
        precomputations = offset_bytecode;
    }

    function change_offset(uint256 new_offset) public {
        precomputations = new_offset;
    }
}

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

    function testValidateSignature_WithPrecomputations_Valid() public {

        string memory deployData = vm.readFile(
            "./src/precompiled/fcl_ecdsa_precbytecode.json"
        );
        bytes memory prec = abi.decode(
            vm.parseJson(deployData, ".Bytecode"),
            (bytes)
        );
        uint256 estimated_size = 12; //sizeof contract, to be estimated

        uint256 checkpointGasLeft;
        uint256 checkpointGasLeft2;

        bytes memory bytecode = abi.encodePacked(
            type(Wrap_ecdsa_precal_hackmem).runtimeCode
        );

        bytes memory bytecodeC = abi.encodePacked(
            type(Wrap_ecdsa_precal_hackmem).creationCode,
            abi.encode(0)
        );
        bytecodeC = bytes.concat(bytecodeC, prec);

        estimated_size = bytecode.length;

        console.log("size contract=", estimated_size);
        console.log("size contract+prec=", bytecodeC.length);
        checkpointGasLeft = gasleft();
        // vm.etch(i_address, bytecode);

        address deployed;
        assembly {
            deployed := create2(
                callvalue(),
                add(bytecodeC, 0x20),
                mload(bytecodeC),
                11
            )
        }

        console.log("Deployed", deployed);
        console.logBytes(deployed.code);
        console.log("Deployed length", deployed.code.length);

        checkpointGasLeft2 = gasleft();
        console.log(
            "deployment of precomputation cost:",
            checkpointGasLeft - checkpointGasLeft2 - 100
        );

        Wrap_ecdsa_precal_hackmem wrap2 = Wrap_ecdsa_precal_hackmem(deployed);

        uint256 offset = find_offset(bytecodeC, _MAGIC_ENCODING);
        console.log("offsetFound", offset);
        wrap2.change_offset(offset);

        uint256 verifyGas1;
        uint256 verifyGas2;
        verifyGas1 = gasleft();
        bool res = wrap2.wrap_ecdsa_core(
            0xfb7edfd2016f07021f538da7d26d67509c1369cb5ef729db71143528b17aa069,
            [
                0x9bd9ebe8b6ec5aa98729d8de2a361a79cc21aedc5942385a992a2f1ccfd5e62a,
                0x18efff3a995d00cc55392ed677717de60de87192fde4196545e26e162940b69a
            ]
        );
        verifyGas2 = gasleft();

        console.log(
            "gas cost for precomputed verify:",
            verifyGas1 - verifyGas2 - 100
        );

        assertTrue(res);
    }

    function find_offset(
        bytes memory bytecode,
        uint256 magic_value
    ) public returns (uint256 offset) {
        uint256 read_value;
        uint256 offset;
        uint256 offset2;
        uint256 px; //x elliptic point
        uint256 py; //y elliptic point

        for (uint256 i = 0; i < bytecode.length; i += 1) {
            assembly {
                read_value := mload(add(bytecode, i))
            }
            if (read_value == magic_value) {
                offset = i - 32;
            }
        }

        //check precomputations are correct, all points on curve P256
        for (uint256 i = 1; i < 256; i++) {
            offset2 = offset + 64 * i;

            assembly {
                //  	extcodecopy(deployed, px, offset, 64)
                px := mload(add(bytecode, offset2))
                py := mload(add(bytecode, add(offset2, 32)))
            }

            assertEq(ec.ecAff_isOnCurve(px, py), true);
        }
        console.log("Offset correct");
        return offset;
    }
}
