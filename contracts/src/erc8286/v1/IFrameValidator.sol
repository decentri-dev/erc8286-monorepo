// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Module} from "./IERC8286FrameAccount.sol";

/// @notice ERC-8286 validator module interface for EIP-8141 frame validation.
interface IFrameValidator is IERC7579Module {
    /// @dev Returns APPROVE_NONE (0x0) on failure. The account clamps the return
    ///      value to the VERIFY frame's allowed scope before calling APPROVE.
    function validateFrame(bytes32 sigHash, uint256 frameIndex, uint8 allowedScope, bytes calldata data)
        external
        view
        returns (uint8 approvalMode);
}
