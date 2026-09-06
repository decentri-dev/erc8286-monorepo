// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC7579Module {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
}

interface IERC7579AccountConfig {
    function accountId() external view returns (string memory accountImplementationId);
    function supportsExecutionMode(bytes32 encodedMode) external view returns (bool);
    function supportsModule(uint256 moduleTypeId) external view returns (bool);
}

interface IERC7579ModuleConfig {
    event ModuleInstalled(uint256 moduleTypeId, address module);
    event ModuleUninstalled(uint256 moduleTypeId, address module);

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external;
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external;
    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext)
        external
        view
        returns (bool);
}

interface IERC8286FrameAccount is IERC7579AccountConfig, IERC7579ModuleConfig {
    function verify(bytes calldata data) external returns (uint8 approvalMode);

    function supportsApprovalMode(uint8 approvalMode) external view returns (bool);
}
