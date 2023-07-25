// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./IMFAAccount.sol";
import "./static/Structs.sol";
import "./cryptography/WrapECDSAPrecalculations.sol";

/**
 * @title   WebAuthnMFAAccount.
 * @notice  A base implementation.
 */

contract WebAuthnMFAAccount is IMFAAccount {
    // bytes4(keccak256("isValidDeviceSignature(bytes32,P256Signature)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; // TODO: Compute

    /// A device is already connected to this account. You need to remove the existing device and link a new one.
    /// @param deviceId the id of the currently linked device
    error DeviceConnected(uint32 deviceId);

    /// No device is connected to the current account.
    error DeviceNotConnected();

    /// A device WebAuthn signature is invalid
    /// @param deviceId the id of the provided device whose signature is invalid
    error DeviceSignatureInvalid(uint32 deviceId);

    uint32 constant NULL = 0;

    address owner;

    address precomputationsAddress;
    uint256 precomputationsOffset;
    uint32 deviceId;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function initialize(address _owner) external {
        deviceId = NULL;
        owner = _owner;
    }

    function addDevice(uint32 _deviceId, bytes memory _precomutations, bytes memory _signature) external onlyOwner {
        if (deviceId != NULL) {
            revert DeviceConnected(deviceId);
        }
        // TODO: Validate the provided _account_ signature?

        bytes memory precalcContractBytecodeRuntime = abi.encodePacked(type(WrapECDSAPrecalculations).runtimeCode);

        uint256 _precomputationsOffset = precalcContractBytecodeRuntime.length;

        bytes memory precalcContractBytecode = abi.encodePacked(type(WrapECDSAPrecalculations).creationCode);

        precalcContractBytecode = bytes.concat(precalcContractBytecode, _precomutations);

        address deployed;
        assembly {
            deployed := create(0, add(precalcContractBytecode, 0x20), mload(precalcContractBytecode))
        }

        WrapECDSAPrecalculations precomputed = WrapECDSAPrecalculations(deployed);
        precomputed.change_offset(_precomputationsOffset);

        deviceId = _deviceId;
        precomputationsAddress = deployed;
        precomputationsOffset = _precomputationsOffset;
    }

    function removeDevice(bytes memory _signature) external onlyOwner {
        if (deviceId == NULL) {
            revert DeviceNotConnected();
        }

        // TODO: Validate device signature

        deviceId = NULL;
    }

    function getDevice() external view returns (uint32) {
        return deviceId;
    }

    // TODO: this needs to be view ideally, check the smart contract for details.
    function isValidDeviceSignature(bytes32 hash, P256Signature calldata signature) external returns (bytes4) {
        WrapECDSAPrecalculations precomputed = WrapECDSAPrecalculations(precomputationsAddress);

        bool isValid = precomputed.isSignatureValid(hash, [signature.R, signature.S]);

        if (isValid) {
            return MAGICVALUE;
        } else {
            return 0xffffffff;
        }
    }
}
