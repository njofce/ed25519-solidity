// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import "account-abstraction/interfaces/UserOperation.sol";
import "account-abstraction/interfaces/IAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

import "./KeyPrecomputations.sol";
import "../static/Structs.sol";
import "../static/Base64URL.sol";

contract WebAuthnAccount is IAccount, Initializable {
    using UserOperationLib for UserOperation;

    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    DevicePublicKey _publicKey;

    string _credentialId;

    address _precomputationsAddress;

    IEntryPoint private immutable _entryPoint;

    error InvalidClientData();

    event WebAuthnAccountInitialized(
        IEntryPoint indexed entryPoint,
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
        return entryPoint().getNonce(address(this), 0);
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

        _precomputationsAddress = precomputationsAddress;
        emit WebAuthnAccountInitialized(_entryPoint, _precomputationsAddress);
    }

    function getCredentialId() public view returns (string memory) {
        return _credentialId;
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
        // _payPrefund(missingAccountFunds); // TODO: Enable this
    }

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 _userOpHash
    ) internal virtual returns (uint256 validationData) {
        P256Signature memory signature = abi.decode(
            userOp.signature,
            (P256Signature)
        );

        KeyPrecomputations precomputations = KeyPrecomputations(
            _precomputationsAddress
        );

        // messageHash is computed as sha256(authenticatorData || sha256(clientData))
        // both authenticatorData bytes and clientDataJSON bytes are provided in userop

        (
            bytes memory authenticatorData,
            bytes memory clientData,
            uint32 clientChallengeDataOffset
        ) = abi.decode(userOp.callData, (bytes, bytes, uint32));

        // 1. Validate challenge is same as the next nonce.
        _validateChallenge(clientData, clientChallengeDataOffset);

        // // 2. Build message hash from device auth data
        bytes memory verifyData = new bytes(authenticatorData.length + 32);
        _copyBytes(
            authenticatorData,
            0,
            authenticatorData.length,
            verifyData,
            0
        );

        _copyBytes(
            abi.encodePacked(sha256(clientData)),
            0,
            32,
            verifyData,
            authenticatorData.length
        );

        bytes32 messageHash = sha256(verifyData);

        // 3. Verify signature
        bool isValid = precomputations.isSignatureValid(
            messageHash,
            [signature.R, signature.S]
        );

        if (!isValid) {
            return SIG_VALIDATION_FAILED;
        }

        return 0;
    }

    function _validateChallenge(
        bytes memory clientData,
        uint32 clientChallengeDataOffset
    ) internal view {
        // Encode the expected account challenge based on smart contract data
        bytes memory challengeEncoded = abi.encodePacked(
            Base64URL.encode32(
                abi.encodePacked("nonce2") // TODO: Challenge must be some concatenation of address:nonce or just sc nonce
            )
        );

        // Extract the challenge from the client data
        bytes memory challengeExtracted = new bytes(challengeEncoded.length);

        _copyBytes(
            clientData,
            clientChallengeDataOffset,
            challengeExtracted.length,
            challengeExtracted,
            0
        );

        // Verify that challenge is the same
        if (
            keccak256(challengeEncoded) !=
            keccak256(abi.encodePacked(challengeExtracted))
        ) {
            revert InvalidClientData();
        }
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

    /*
    The following function has been written by Alex Beregszaszi (@axic), use it under the terms of the MIT license
    */
    function _copyBytes(
        bytes memory _from,
        uint _fromOffset,
        uint _length,
        bytes memory _to,
        uint _toOffset
    ) internal pure returns (bytes memory _copiedBytes) {
        uint minLength = _length + _toOffset;
        require(_to.length >= minLength); // Buffer too small. Should be a better way?
        uint i = 32 + _fromOffset; // NOTE: the offset 32 is added to skip the `size` field of both bytes variables
        uint j = 32 + _toOffset;
        while (i < (32 + _fromOffset + _length)) {
            assembly {
                let tmp := mload(add(_from, i))
                mstore(add(_to, j), tmp)
            }
            i += 32;
            j += 32;
        }
        return _to;
    }
}
