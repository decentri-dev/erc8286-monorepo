// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IFrameOpcodeAdapter} from "./IFrameOpcodeAdapter.sol";
import {IERC7579Module, IERC8286FrameAccount} from "./IERC8286FrameAccount.sol";
import {IFrameValidator} from "./IFrameValidator.sol";

/// @title ERC8286FrameAccount
/// @notice Minimal ERC-8286 account that routes VERIFY-frame validation to an
///         installed ERC-7579 validator module, then applies APPROVE through the
///         singleton Yul opcode adapter.
contract ERC8286FrameAccount is IERC8286FrameAccount {
    uint8 internal constant APPROVE_NONE = 0x00;
    uint8 internal constant APPROVE_PAYMENT = 0x01;
    uint8 internal constant APPROVE_EXECUTION = 0x02;
    uint8 internal constant APPROVE_SCOPE_MASK = 0x03;

    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;

    uint256 internal constant TX_PARAM_SIG_HASH = 0x08;
    uint256 internal constant TX_PARAM_FRAME_COUNT = 0x09;
    uint256 internal constant TX_PARAM_FRAME_INDEX = 0x0a;
    uint256 internal constant TX_PARAM_SENDER = 0x02;

    uint256 internal constant FRAME_PARAM_RESOLVED_TARGET = 0x00;
    uint256 internal constant FRAME_PARAM_MODE = 0x02;
    uint256 internal constant FRAME_PARAM_ALLOWED_SCOPE = 0x06;
    uint256 internal constant FRAME_PARAM_ATOMIC_BATCH = 0x07;

    uint8 internal constant MODE_VERIFY = 1;
    uint8 internal constant MODE_SENDER = 2;

    bytes1 internal constant CALLTYPE_SINGLE = 0x00;
    bytes1 internal constant CALLTYPE_BATCH = 0x01;
    bytes1 internal constant EXECTYPE_DEFAULT = 0x00;
    bytes1 internal constant EXECTYPE_TRY = 0x01;

    address internal constant ENTRY_POINT = address(uint160(0xaa));

    IFrameOpcodeAdapter public immutable adapter;

    mapping(uint256 moduleTypeId => mapping(address module => bool installed)) private _installedModules;

    error InvalidAdapter();
    error InvalidModule();
    error InvalidVerifyData();
    error NotEntryPoint(address caller);
    error NotVerifyFrame(uint8 mode);
    error NoApprovalScope();
    error UnsupportedApprovalMode(uint8 approvalMode);
    error ApproveDelegatecallFailed();
    error Unauthorized();
    error UnsupportedModuleType(uint256 moduleTypeId);
    error ModuleAlreadyInstalled(uint256 moduleTypeId, address module);
    error ModuleNotInstalled(uint256 moduleTypeId, address module);
    error ModuleTypeMismatch(uint256 moduleTypeId, address module);

    modifier onlySelf() {
        if (msg.sender != address(this)) revert Unauthorized();
        _;
    }

    constructor(IFrameOpcodeAdapter adapter_, address initialValidator, bytes memory validatorInitData) {
        if (address(adapter_) == address(0)) revert InvalidAdapter();
        adapter = adapter_;

        if (initialValidator != address(0)) {
            _installModule(MODULE_TYPE_VALIDATOR, initialValidator, validatorInitData);
        }
    }

    receive() external payable {}

    /// @notice ERC-8286 VERIFY-frame entrypoint.
    /// @dev `data` is validator-address-prefixed: first 20 bytes are the
    ///      validator, remaining bytes are passed through unchanged. Each
    ///      validator owns its own tail format — see {PasskeyFrameValidator}
    ///      and {MultiSignerFrameValidator}, both of which `abi.decode` it.
    function verify(bytes calldata data) external override returns (uint8 approvalMode) {
        if (msg.sender != ENTRY_POINT) revert NotEntryPoint(msg.sender);
        if (data.length < 20) revert InvalidVerifyData();

        uint256 frameIndex = adapter.txParam(TX_PARAM_FRAME_INDEX);
        uint8 mode = uint8(adapter.frameParam(frameIndex, FRAME_PARAM_MODE));
        if (mode != MODE_VERIFY) revert NotVerifyFrame(mode);

        address validator = address(bytes20(data[0:20]));
        if (!_installedModules[MODULE_TYPE_VALIDATOR][validator]) {
            revert ModuleNotInstalled(MODULE_TYPE_VALIDATOR, validator);
        }

        bytes calldata validatorData = data[20:];
        uint8 allowedScope = uint8(adapter.frameParam(frameIndex, FRAME_PARAM_ALLOWED_SCOPE)) & APPROVE_SCOPE_MASK;
        bytes32 sigHash = bytes32(adapter.txParam(TX_PARAM_SIG_HASH));

        approvalMode = IFrameValidator(validator).validateFrame(sigHash, frameIndex, allowedScope, validatorData);
        approvalMode = approvalMode & allowedScope;

        if ((approvalMode & APPROVE_EXECUTION) != 0) {
            approvalMode = _clampExecutionApproval(frameIndex, approvalMode);
        }

        if (approvalMode == APPROVE_NONE) revert NoApprovalScope();
        if (!supportsApprovalMode(approvalMode)) revert UnsupportedApprovalMode(approvalMode);

        _approve(approvalMode);
    }

    function supportsApprovalMode(uint8 approvalMode) public pure override returns (bool) {
        return approvalMode <= APPROVE_SCOPE_MASK;
    }

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external override onlySelf {
        _installModule(moduleTypeId, module, initData);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        external
        override
        onlySelf
    {
        _requireSupportedModuleType(moduleTypeId);
        if (!_installedModules[moduleTypeId][module]) {
            revert ModuleNotInstalled(moduleTypeId, module);
        }

        _installedModules[moduleTypeId][module] = false;
        IERC7579Module(module).onUninstall(deInitData);
        emit ModuleUninstalled(moduleTypeId, module);
    }

    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata)
        external
        view
        override
        returns (bool)
    {
        return _installedModules[moduleTypeId][module];
    }

    function accountId() external pure override returns (string memory) {
        return "erc8286.frame-account.0.3.0";
    }

    function supportsExecutionMode(bytes32 encodedMode) external pure override returns (bool) {
        return _supportsExecutionMode(encodedMode);
    }

    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function _installModule(uint256 moduleTypeId, address module, bytes memory initData) internal {
        _requireSupportedModuleType(moduleTypeId);
        if (module == address(0)) revert InvalidModule();
        if (_installedModules[moduleTypeId][module]) {
            revert ModuleAlreadyInstalled(moduleTypeId, module);
        }
        if (!IERC7579Module(module).isModuleType(moduleTypeId)) {
            revert ModuleTypeMismatch(moduleTypeId, module);
        }

        _installedModules[moduleTypeId][module] = true;
        IERC7579Module(module).onInstall(initData);
        emit ModuleInstalled(moduleTypeId, module);
    }

    function _clampExecutionApproval(uint256 frameIndex, uint8 approvalMode) internal view returns (uint8) {
        address resolvedTarget = address(uint160(adapter.frameParam(frameIndex, FRAME_PARAM_RESOLVED_TARGET)));
        address txSender = address(uint160(adapter.txParam(TX_PARAM_SENDER)));

        if (resolvedTarget != txSender || !_senderFramesSupported()) {
            return approvalMode & APPROVE_PAYMENT;
        }

        return approvalMode;
    }

    function _senderFramesSupported() internal view returns (bool) {
        uint256 frameCount = adapter.txParam(TX_PARAM_FRAME_COUNT);
        uint256 senderFrames;
        bool hasAtomic;
        bool hasNonAtomic;

        for (uint256 i = 0; i < frameCount; i++) {
            if (adapter.frameParam(i, FRAME_PARAM_MODE) != MODE_SENDER) continue;

            senderFrames++;
            if (adapter.frameParam(i, FRAME_PARAM_ATOMIC_BATCH) == 0) {
                hasNonAtomic = true;
            } else {
                hasAtomic = true;
            }
        }

        if (senderFrames == 0) return true;

        bytes1 callType = senderFrames == 1 ? CALLTYPE_SINGLE : CALLTYPE_BATCH;
        if (hasAtomic && !_supportsExecutionMode(_encodeExecutionMode(callType, EXECTYPE_DEFAULT))) return false;
        if (hasNonAtomic && !_supportsExecutionMode(_encodeExecutionMode(callType, EXECTYPE_TRY))) return false;

        return true;
    }

    function _supportsExecutionMode(bytes32 encodedMode) internal pure returns (bool) {
        bytes1 callType = encodedMode[0];
        bytes1 execType = encodedMode[1];
        bool knownCallType = callType == CALLTYPE_SINGLE || callType == CALLTYPE_BATCH;
        bool knownExecType = execType == EXECTYPE_DEFAULT || execType == EXECTYPE_TRY;
        bool noCustomMode = (uint256(encodedMode) & uint256(type(uint240).max)) == 0;
        return knownCallType && knownExecType && noCustomMode;
    }

    function _encodeExecutionMode(bytes1 callType, bytes1 execType) internal pure returns (bytes32) {
        return bytes32((uint256(uint8(callType)) << 248) | (uint256(uint8(execType)) << 240));
    }

    function _approve(uint8 approvalMode) internal {
        (bool success,) = address(adapter).delegatecall(abi.encodeCall(IFrameOpcodeAdapter.approve, (approvalMode)));
        if (!success) revert ApproveDelegatecallFailed();
    }

    function _requireSupportedModuleType(uint256 moduleTypeId) internal pure {
        if (moduleTypeId != MODULE_TYPE_VALIDATOR) revert UnsupportedModuleType(moduleTypeId);
    }
}
