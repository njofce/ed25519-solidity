// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "./IMFAAccount.sol";
import "./static/Structs.sol";
import "./cryptography/WrapECDSAPrecalculations.sol";
import "./signature/KeyPrecomputations.sol";
import "./signature/SignatureValidation.sol";

/**
 * @title   WebAuthnMFAAccount.
 * @notice  This contract should serve as an example for integrating MFA capabilities into a smart contract account 
 * where a second factor of authentication is a WebAuthn device. It provides the necessary constructs for adding/removing 
 * devices with the valid signature
 */
contract WebAuthnMFAAccount is IMFAAccount {
    string public constant name = "WebAuthnMFAAccount";

    // bytes4(keccak256("isValidCredentialSignature(AuthenticatorAssertionResponse,P256Signature)")
    bytes4 internal constant MAGICVALUE = 0xae16b27e; 

    /// A credential is already connected to this account. You need to remove the existing credential and link a new one.
    /// @param credentialId the id of the currently linked credentail
    error CredentialAlreadyConnected(string credentialId);

    /// No device is connected to the current account.
    error CredentialNotConnected();

    /// The provided credential signature is invalid.
    error InvalidCredentialSignature();

    /// A device WebAuthn signature is invalid
    /// @param deviceId the id of the provided device whose signature is invalid
    error CredentialSignatureInvalid(uint32 deviceId);

    string constant NULL = "";

    address _owner;

    address _precomputationsAddress;

    string _credentialId;

    modifier onlyOwner() {
        require(msg.sender == _owner);
        _;
    }

    function initialize(address owner) external {
        _credentialId = NULL;
        _owner = owner;
    }

    function addCredential(
        string memory credentialId,
        bytes memory precomputationsInitCode
    ) external onlyOwner {
        if (keccak256(bytes(_credentialId)) != keccak256(bytes(NULL))) {
            revert CredentialAlreadyConnected(_credentialId);
        }

        bytes32 salt = keccak256(bytes(credentialId));

        address precomputationsAddress;
        assembly {
            precomputationsAddress := create2(
                callvalue(),
                add(precomputationsInitCode, 0x20),
                mload(precomputationsInitCode),
                salt
            )
        }

        _credentialId = credentialId;
        _precomputationsAddress = precomputationsAddress;
    }

    function removeCredential(
        AuthenticatorAssertionResponse memory _assertionResponse,
        P256Signature memory _signature,
        string memory _challenge
    ) external onlyOwner {
        if (keccak256(bytes(_credentialId)) == keccak256(bytes(NULL))) {
            revert CredentialNotConnected();
        }

        if (
            isValidCredentialSignature(_assertionResponse, _signature, _challenge) !=
            MAGICVALUE
        ) {
            revert InvalidCredentialSignature();
        }

        _credentialId = NULL;
    }

    function getCredentailId() public view returns (string memory) {
        return _credentialId;
    }

    function isValidCredentialSignature(
        AuthenticatorAssertionResponse memory _assertionResponse,
        P256Signature memory _signature,
        string memory _challenge
    ) public returns (bytes4) {
        bool isValid = SignatureValidation.isSignatureValid(
            _signature,
            _assertionResponse,
            _precomputationsAddress,
            abi.encodePacked(_challenge)
        );
        if (isValid) {
            return MAGICVALUE;
        } else {
            return 0xffffffff;
        }
    }
}
