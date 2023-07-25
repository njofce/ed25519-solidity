// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./static/Structs.sol";

/**
 * @title   IMFAAccount.
 * @notice  The base interface for smart contract accounts that need to perform multi-factor authorization. The first authentication factor is not fixed, and can be EOA signature validation.
 * The second authentication factor is a WebAuthn device signature.
 */

interface IMFAAccount {
    /**
     * @notice  Initialize the MFA account.
     * @param   _owner  Address of the owner account.
     */
    function initialize(address _owner) external;

    /**
     * @notice  Associate a new WebAuthn device with the account. Throws an error if another device is already associated with the account.
     * @param   _deviceId  The id of the WebAuthn device that will be linked to the account.
     * @param   _precomutations  The precomputed bytecode with an 8-dimensional table for Shamir's trick from device's public key.
     * @param   _signature  The signature associated with the account. This is not a device signature, but the signature associated with the account.
     */
    function addDevice(uint32 _deviceId, bytes memory _precomutations, bytes memory _signature) external;

    /**
     * @notice  Remove an existing WebAuthn device that is linked to the account.
     * @param   _signature  A valid WebAuthn signature associated with the device that is being removed.
     */
    function removeDevice(bytes memory _signature) external;

    /**
     * @notice  Get the id of the currently linked device with the account.
     * @return  uint32  The id of the linked device.
     */
    function getDevice() external view returns (uint32);

    /**
     * @notice  Validate WebAuthn device signature. Throws an error if signature is invalid.
     * @param   _hash  The message hash.
     * @param   _signature  The provided WebAuthn signature.
     * @return  bytes4  Returns the magic bytes if signature is invalid.
     */
    function isValidDeviceSignature(bytes32 _hash, P256Signature calldata _signature) external returns (bytes4);
}
