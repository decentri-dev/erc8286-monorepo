// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC8286FrameAccount} from "./ERC8286FrameAccount.sol";
import {IFrameOpcodeAdapter} from "./IFrameOpcodeAdapter.sol";

/// @title ERC8286FrameAccountFactory
/// @notice Minimal CREATE2 factory for ERC8286 frame accounts.
contract ERC8286FrameAccountFactory {
    IFrameOpcodeAdapter public immutable adapter;

    event AccountCreated(address indexed account, bytes32 indexed salt, address indexed initialValidator);

    error InvalidAdapter();

    constructor(IFrameOpcodeAdapter adapter_) {
        if (address(adapter_) == address(0)) revert InvalidAdapter();
        adapter = adapter_;
    }

    function createAccount(bytes32 salt, address initialValidator, bytes calldata validatorInitData)
        external
        returns (address account)
    {
        account = address(new ERC8286FrameAccount{salt: salt}(adapter, initialValidator, validatorInitData));
        emit AccountCreated(account, salt, initialValidator);
    }

    function getAddress(bytes32 salt, address initialValidator, bytes calldata validatorInitData)
        external
        view
        returns (address)
    {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(ERC8286FrameAccount).creationCode, abi.encode(adapter, initialValidator, validatorInitData)
            )
        );

        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)))));
    }
}
