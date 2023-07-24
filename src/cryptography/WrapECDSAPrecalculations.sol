//********************************************************************************************/
//  ___           _       ___               _         _    _ _
// | __| _ ___ __| |_    / __|_ _ _  _ _ __| |_ ___  | |  (_) |__
// | _| '_/ -_|_-< ' \  | (__| '_| || | '_ \  _/ _ \ | |__| | '_ \
// |_||_| \___/__/_||_|  \___|_|  \_, | .__/\__\___/ |____|_|_.__/
//                                |__/|_|
///* Copyright (C) 2022 - Renaud Dubois - This file is part of FCL (Fresh CryptoLib) project
///* License: This software is licensed under MIT License
///* This Code may be reused including license and copyright notice.
///* See LICENSE file at the root folder of the project.
///* FILE: FCL_elliptic.sol
///*
///*
///* DESCRIPTION: modified XYZZ system coordinates for EVM elliptic point multiplication
///*  optimization
///*
//**************************************************************************************/
//* WARNING: this code SHALL not be used for non prime order curves for security reasons.
// Code is optimized for a=-3 only curves with prime order, constant like -1, -2 shall be replaced
// if ever used for other curve than sec256R1
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./FCL_Elliptic.sol";

contract WrapECDSAPrecalculations {
    uint256 public precomputations;

    //compute the coefficients for multibase exponentiation, then their wnaf representation
    //note that this function can be implemented in the front to reduce tx cost

    function isSignatureValid(
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

    //provide the offset of precomputations in the contract
    constructor(uint256 offset_bytecode) {
        precomputations = offset_bytecode;
    }

    function change_offset(uint256 new_offset) public {
        precomputations = new_offset;
    }
}
