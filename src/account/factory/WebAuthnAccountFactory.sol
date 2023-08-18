// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 */

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../WebAuthnAccount.sol";

/**
 *
 * This factory needs to be deployed just once at the beginning, and then used for creation of WebAuthn Wallets.
 */
contract WebAuthnAccountFactory {
    WebAuthnAccount public immutable accountImplementation;

    constructor(IEntryPoint _entryPoint) {
        accountImplementation = new WebAuthnAccount(_entryPoint);
    }

    function createAccount(
        bytes memory devicePublicKey,
        string memory credentialId,
        bytes memory precomputationsInitCode
    ) public returns (WebAuthnAccount ret) {
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
