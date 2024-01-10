// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./IMFAAccount.sol";
import "./static/Structs.sol";
import "./cryptography/WrapECDSAPrecalculations.sol";
import "./signature/KeyPrecomputations.sol";
import "./signature/SignatureValidation.sol";

/**
 * @title   WebAuthnMFAAccount.
 * @notice  A base implementation.
 */

// TODO: We need a proxy-based deployment for this.
// TODO: We need an example factory for deploying this contract alongside the AA account contract.
// TODO: We need to provide UserOp callData examples that specify adding of a device, removing a device, and validating device signature

abstract contract WebAuthnMFAAccount is IMFAAccount {
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
        P256Signature memory _signature
    ) external onlyOwner {
        if (keccak256(bytes(_credentialId)) == keccak256(bytes(NULL))) {
            revert CredentialNotConnected();
        }

        // TODO: Validate device signature
        if (
            isValidCredentialSignature(_assertionResponse, _signature) !=
            MAGICVALUE
        ) {
            revert InvalidCredentialSignature();
        }

        _credentialId = NULL;
    }

    function getCredentailId() public view returns (string memory) {
        return _credentialId;
    }

    function getChallenge() external view virtual returns (string memory);

    function isValidCredentialSignature(
        AuthenticatorAssertionResponse memory _assertionResponse,
        P256Signature memory _signature
    ) public returns (bytes4) {
        bool isValid = SignatureValidation.isSignatureValid(
            _signature,
            _assertionResponse,
            _precomputationsAddress,
            abi.encodePacked(getChallenge())
        );
        if (isValid) {
            return MAGICVALUE;
        } else {
            return 0xffffffff;
        }
    }
}
