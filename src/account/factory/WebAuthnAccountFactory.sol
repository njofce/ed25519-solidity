// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

/**
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 */

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../WebAuthnAccount.sol";

/// @title WebAuthn Account Factory
/// @author nasi
/// @notice This factory needs to be deployed just once at the beginning, and then used for creation of WebAuthn Wallets.
contract WebAuthnAccountFactory {
    WebAuthnAccount public immutable accountImplementation;

    constructor(IEntryPoint _entryPoint) {
        accountImplementation = new WebAuthnAccount(_entryPoint);
    }

    /// @notice Create a WebAuthnAccount by deploying Precomputations bytecode first.
    /// @param devicePublicKey The byte representation of the WebAuthn device public key.
    /// @param credentialId The generated credential ID from the WebAuthn device.
    /// @param precomputationsInitCode The init bytecode for precomputations that will be used to be deployed as a separate contract.
    /// @return The deployed WebAuthn account
    function createAccount(
        bytes memory devicePublicKey,
        string memory credentialId,
        bytes memory precomputationsInitCode
    ) public returns (WebAuthnAccount ret) {
        bytes32 salt = keccak256(bytes(credentialId));

        address precomputationsAddress = Create2.deploy(0, salt, precomputationsInitCode);

        address addr = getAddress(
            devicePublicKey,
            credentialId,
            precomputationsAddress,
            salt
        );

        uint codeSize = addr.code.length;

        if (codeSize > 0) {
            return WebAuthnAccount(payable(addr));
        }

        DevicePublicKey memory pubKey = abi.decode(
            devicePublicKey,
            (DevicePublicKey)
        );

        ret = WebAuthnAccount(
            payable(
                new ERC1967Proxy{salt: salt}(
                    address(accountImplementation),
                    abi.encodeCall(
                        WebAuthnAccount.initialize,
                        (pubKey, credentialId, precomputationsAddress)
                    )
                )
            )
        );
    }

    /// @notice Deterministically compute the address where the Precomputations bytecode will be deployed.
    /// @param credentialId The generated credential ID from the WebAuthn device.
    /// @param precomputationsInitCode The init bytecode for precomputations that will be used to be deployed as a separate contract.
    /// @return The Precomputations address
    function getPrecomputationsAddress(string memory credentialId, bytes memory precomputationsInitCode) public view returns (address) {
        bytes32 salt = keccak256(bytes(credentialId));
        return Create2.computeAddress(salt, keccak256(abi.encodePacked(precomputationsInitCode)));
    }

    /// @notice Deterministically compute the address where the WebAuthn account will be deployed.
    /// @param devicePublicKey The byte representation of the WebAuthn device public key.
    /// @param credentialId The generated credential ID from the WebAuthn device.
    /// @param precomputationsAddress The address where precomputations are deployed as a separate contract.
    /// @param salt A unique salt which is computed as keccak256(bytes(credentialId)).
    /// @return The Precomputations address
    function getAddress(
        bytes memory devicePublicKey,
        string memory credentialId,
        address precomputationsAddress,
        bytes32 salt
    ) public view returns (address) {
        DevicePublicKey memory pubKey = abi.decode(
            devicePublicKey,
            (DevicePublicKey)
        );
        return
            Create2.computeAddress(
                salt,
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            address(accountImplementation),
                            abi.encodeCall(
                                WebAuthnAccount.initialize,
                                (pubKey, credentialId, precomputationsAddress)
                            )
                        )
                    )
                )
            );
    }
}
