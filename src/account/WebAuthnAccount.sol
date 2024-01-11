// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import "openzeppelin-contracts/contracts/utils/Strings.sol";
import "account-abstraction/interfaces/UserOperation.sol";
import "account-abstraction/interfaces/IAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

import "../signature/KeyPrecomputations.sol";
import "../signature/SignatureValidation.sol";
import "../static/Structs.sol";
import "../static/Base64URL.sol";

/// @title WebAuthn Account
/// @author nasi
/// @notice A smart contract account with optimised on-chain sec256r1 verification on chain.
contract WebAuthnAccount is IAccount, Initializable {
    using UserOperationLib for UserOperation;

    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    DevicePublicKey _publicKey;

    string _credentialId;

    uint192 _nonceKeyId;

    address _precomputationsAddress;

    IEntryPoint private immutable _entryPoint;

    error InvalidClientData();

    event WebAuthnAccountInitialized(
        address indexed accountAddress,
        address indexed precomputationsAddress
    );

    function entryPoint() public view virtual returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * Return the account nonce.
     * This method returns the next sequential nonce.
     * For a nonce of a specific key, use `entrypoint.getNonce(account, key)`
     */
    function getNonce() public view virtual returns (uint256) {
        return entryPoint().getNonce(address(this), _nonceKeyId);
    }

    /**
     * Return the WebAuthn device credential ID associated with this smart contract account.
     */
    function getCredentialId() public view returns (string memory) {
        return _credentialId;
    }

    /**
     * Return the Precomputations contract address associated with this smart contract account.
     */
    function getPrecomputationsAddress() public view returns (address) {
        return _precomputationsAddress;
    }

    constructor(IEntryPoint entryPoint) {
        _entryPoint = entryPoint;
        _disableInitializers();
    }

    modifier onlyEntryPoint() {
        require(
            msg.sender == address(entryPoint()),
            "account: not from EntryPoint"
        );
        _;
    }

    receive() external payable {}

    function initialize(
        DevicePublicKey memory devicePublicKey,
        string memory credentialId,
        address precomputationsAddress
    ) public virtual initializer {
        _publicKey = devicePublicKey;
        _credentialId = credentialId;

        bytes32 credentialHash = keccak256(bytes(_credentialId));
        _nonceKeyId = uint192(uint256(credentialHash) >> 64); // Take the first 192 bits of the hash

        _precomputationsAddress = precomputationsAddress;
        emit WebAuthnAccountInitialized(address(this), _precomputationsAddress);
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        virtual
        override
        onlyEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    /**
    *
    * Validate a signature generated from a WebAuthn device, where the account nonce is used as a challenge.
    *
    */
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 _userOpHash
    ) internal virtual returns (uint256 validationData) {
        (
            bytes memory authenticatorData,
            bytes memory clientData,
            uint32 clientChallengeDataOffset
        ) = abi.decode(userOp.callData, (bytes, bytes, uint32));

        AuthenticatorAssertionResponse
            memory assertion = AuthenticatorAssertionResponse(
                authenticatorData,
                clientData,
                clientChallengeDataOffset
            );

        P256Signature memory signature = abi.decode(
            userOp.signature,
            (P256Signature)
        );
        bool isValid = SignatureValidation.isSignatureValid(
            signature,
            assertion,
            _precomputationsAddress,
            abi.encodePacked(Strings.toString(getNonce()))
        );

        if (!isValid) {
            return SIG_VALIDATION_FAILED;
        }

        return 0;
    }

    function _payPrefund(uint256 missingAccountFunds) internal virtual {
        if (missingAccountFunds != 0) {
            (bool success, ) = payable(msg.sender).call{
                value: missingAccountFunds,
                gas: type(uint256).max
            }("");
            (success);
            //ignore failure (its EntryPoint's job to verify, not account.)
        }
    }
}
