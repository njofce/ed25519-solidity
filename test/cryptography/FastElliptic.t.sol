// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../src/account/KeyPrecomputations.sol";
import "../../src/cryptography/FastElliptic.sol";
import "../../src/precompiled/fcl_ecdsa_precbytecode.sol";

//echo "itsakindofmagic" | sha256sum, used as a label to find precomputations inside bytecodeR
uint256 constant _MAGIC_ENCODING = 0x9a8295d6f225e4f07313e2e1440ab76e26d4c6ed2d1eb4cbaa84827c8b7caa8d;

contract Wrap_ecdsa_precal_hackmem {
    uint256 public precomputations;

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
    constructor(uint256 offset_bytecodeR) {
        precomputations = offset_bytecodeR;
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

    function testValidateSignatureNew() public {
        string memory precomputationBytecodeFile = vm.readFile(
            "./src/precompiled/fcl_ecdsa_precbytecode.json"
        );
        bytes memory precomputationBytecode = abi.decode(
            vm.parseJson(precomputationBytecodeFile, ".Bytecode"),
            (bytes)
        );

        bytes memory bytecodeR = abi.encodePacked(
            type(KeyPrecomputations).runtimeCode
        );

        uint precomputationsOffset = bytecodeR.length;

        // uint initBytecodeLength = 95;
        // replaced 071b (length of runtime bytecode) with len(bytecodeR) + len(precomputationBytecode) = 1819 + 16384 = 471B (HEX)

        // replaced 077a (offset of constructor argument) with 477a -> len(bytecodeR) + len(precomputationBytecode) + len(init)
        bytes
            memory initBytecode = hex"608060405234801561001057600080fd5b5060405161477a38038061477a83398101604081905261002f91610037565b600055610050565b60006020828403121561004957600080fd5b5051919050565b61471b8061005f6000396000f3fe";

        initBytecode = bytes.concat(initBytecode, bytecodeR);
        initBytecode = bytes.concat(initBytecode, precomputationBytecode);
        initBytecode = bytes.concat(
            initBytecode,
            abi.encode(precomputationsOffset)
        );

        address deployed;
        assembly {
            deployed := create(
                callvalue(),
                add(initBytecode, 0x20),
                mload(initBytecode)
            )
        }

        KeyPrecomputations precomputations = KeyPrecomputations(deployed);

        bool res = precomputations.isSignatureValid(
            0xfb7edfd2016f07021f538da7d26d67509c1369cb5ef729db71143528b17aa069,
            [
                0x9bd9ebe8b6ec5aa98729d8de2a361a79cc21aedc5942385a992a2f1ccfd5e62a,
                0x18efff3a995d00cc55392ed677717de60de87192fde4196545e26e162940b69a
            ]
        );

        assertTrue(res);
    }

    function testValidateSignature_WithPrecomputations_Valid() public {
        address i_address = address(64);

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

        bytes memory bytecodeR = abi.encodePacked(
            type(Wrap_ecdsa_precal_hackmem).runtimeCode
        );

        bytes memory bytecodeC = abi.encodePacked(
            type(Wrap_ecdsa_precal_hackmem).creationCode,
            abi.encode(0)
        );

        bytes memory init_bytecode = get_concatenated_init_bytecode();
        init_bytecode = bytes.concat(init_bytecode, bytecodeR);
        init_bytecode = bytes.concat(init_bytecode, prec);

        estimated_size = bytecodeR.length;
        bytecodeR = bytes.concat(bytecodeR, prec);

        // console.logBytes(bytecodeR);
        console.log("size contract=", estimated_size);
        console.log("size contract+prec=", bytecodeR.length);
        checkpointGasLeft = gasleft();

        address deployed;
        assembly {
            deployed := create(
                callvalue(),
                add(init_bytecode, 0x20),
                mload(init_bytecode)
            )
        }

        checkpointGasLeft2 = gasleft();
        console.log(
            "deployment of precomputation cost:",
            checkpointGasLeft - checkpointGasLeft2 - 100
        );

        Wrap_ecdsa_precal_hackmem wrap2 = Wrap_ecdsa_precal_hackmem(deployed);
        wrap2.change_offset(estimated_size);

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

    function get_concatenated_init_bytecode()
        public
        pure
        returns (bytes memory)
    {
        // new runtime bytecode length is 4E0F (replaced 0e0f with 4e0f)
        return
            hex"608060405234801561001057600080fd5b50604051610e6e380380610e6e83398101604081905261002f91610037565b600055610050565b60006020828403121561004957600080fd5b5051919050565b614E0F8061005f6000396000f3fe";
    }

    function find_offset(
        bytes memory bytecodeR,
        uint256 magic_value
    ) public returns (uint256 offset) {
        uint256 read_value;
        uint256 offset;
        uint256 offset2;
        uint256 px; //x elliptic point
        uint256 py; //y elliptic point

        for (uint256 i = 0; i < bytecodeR.length; i += 1) {
            assembly {
                read_value := mload(add(bytecodeR, i))
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
                px := mload(add(bytecodeR, offset2))
                py := mload(add(bytecodeR, add(offset2, 32)))
            }

            assertEq(ec.ecAff_isOnCurve(px, py), true);
        }
        console.log("Offset correct");
        return offset;
    }
}
