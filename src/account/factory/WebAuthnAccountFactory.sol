/**
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 */

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../WebAuthnAccount.sol";

/**
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory). `initCode` contains 20 bytes of factory address, followed by calldata.
 *
 * This factory needs to be deployed just once at the beginning, and then used for creation of SC Wallets.
 */
contract WebAuthnAccountFactory {
    WebAuthnAccount public immutable accountImplementation;

    constructor(IEntryPoint _entryPoint) {
        accountImplementation = new WebAuthnAccount(_entryPoint);
    }

    function createAccount(
        bytes memory devicePublicKey,
        string memory credentialId, // Doese it make sense for salt = uint(hash(credentialId))?
        address precomputationsAddress,
        uint256 salt
    ) public returns (WebAuthnAccount ret) {
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
                new ERC1967Proxy{salt: bytes32(salt)}(
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
        uint256 salt
    ) public view returns (address) {
        DevicePublicKey memory pubKey = abi.decode(
            devicePublicKey,
            (DevicePublicKey)
        );
        return
            Create2.computeAddress(
                bytes32(salt),
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
