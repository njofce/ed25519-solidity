// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "./static/Structs.sol";

/**
 * @title   IWebAuthnAddOn.
 * @notice  The base interface for smart contract accounts that need to perform multi-factor authorization. The first authentication factor is not fixed, and can be EOA signature validation.
 * The second authentication factor is a WebAuthn credential signature, which can be used as an add-on.
 */

interface IWebAuthnAddOn {
    /**
     * @notice  Initialize the MFA account.
     * @param   _owner  Address of the owner account.
     */
    function initialize(address _owner) external;

    /**
     * @notice  Associate a new WebAuthn credential with the account. Throws an error if another credential is already associated with the account.
     * @param   _credentialId  The id of the WebAuthn credential that will be linked to the account.
     * @param   _precomputationsInitCode  The precomputed bytecode with an 8-dimensional table for Shamir's trick from credential's public key.
     */
    function addCredential(
        string memory _credentialId,
        bytes memory _precomputationsInitCode
    ) external;

    /**
     * @notice  Remove an existing WebAuthn credential that is linked to the account.
     * @param   _assertionResponse  The message hash.
     * @param   _signature  A valid WebAuthn signature associated with the credential that is being removed.
     */
    function removeCredential(
        AuthenticatorAssertionResponse memory _assertionResponse,
        P256Signature memory _signature,
        string memory _challenge
    ) external;

    /**
     * @notice  Get the id of the currently linked credential with the account.
     * @return  string  The id of the linked credential.
     */
    function getCredentailId() external view returns (string memory);

    /**
     * @notice  Validate WebAuthn credential signature based on the data from the assertion. Throws an error if signature is invalid.
     * @param   _assertionResponse  The message hash.
     * @param   _signature  The provided WebAuthn signature.
     * @return  bytes4  Returns the magic bytes if signature is invalid.
     */
    function isValidCredentialSignature(
        AuthenticatorAssertionResponse memory _assertionResponse,
        P256Signature memory _signature,
        string memory _challenge
    ) external returns (bytes4);
}
