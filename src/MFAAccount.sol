// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./IMFAAccount.sol";
import "./static/Structs.sol";
import "./cryptography/WrapECDSAPrecalculations.sol";

/**
 * @title   WebAuthnMFAAccount.
 * @notice  A base implementation.
 */

// TODO: We need a proxy-based deployment for this.
// TODO: We need an example factory for deploying this contract alongside the AA account contract.
// TODO: We need to provide UserOp callData examples that specify adding of a device, removing a device, and validating device signature

contract WebAuthnMFAAccount is IMFAAccount {
    string public constant name = "WebAuthnMFAAccount";

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

    function addDevice(
        uint32 _deviceId,
        bytes memory _precomutations,
        bytes memory _signature
    ) external onlyOwner {
        if (deviceId != NULL) {
            revert DeviceConnected(deviceId);
        }

        bytes memory precalcContractBytecode = abi.encodePacked(
            type(WrapECDSAPrecalculations).creationCode
        );

        bytes memory precalcContractBytecodeRuntime = abi.encodePacked(
            type(WrapECDSAPrecalculations).runtimeCode
        );

        uint256 _precomputationsOffset = precalcContractBytecodeRuntime.length;

        precalcContractBytecode = bytes.concat(
            precalcContractBytecode,
            _precomutations
        );

        // TODO: Provide precomputations address as a function argument.
        address _precomputationsAddress = address(64);

        address deployed;
        assembly {
            deployed := create(
                0,
                add(precalcContractBytecode, 0x20),
                mload(precalcContractBytecode)
            )
        }

        WrapECDSAPrecalculations precomputed = WrapECDSAPrecalculations(
            _precomputationsAddress
        );
        precomputed.change_offset(_precomputationsOffset);

        deviceId = _deviceId;
        precomputationsAddress = _precomputationsAddress;
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
    function isValidDeviceSignature(
        bytes32 hash,
        P256Signature calldata signature
    ) external returns (bytes4) {
        WrapECDSAPrecalculations precomputed = WrapECDSAPrecalculations(
            precomputationsAddress
        );

        bool isValid = precomputed.isSignatureValid(
            hash,
            [signature.R, signature.S]
        );

        if (isValid) {
            return MAGICVALUE;
        } else {
            return 0xffffffff;
        }
    }
}
