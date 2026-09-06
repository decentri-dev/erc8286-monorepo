// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IFrameOpcodeAdapter
/// @notice ABI surface for the singleton Yul bridge around the Hegotá
///         frame-transaction opcode family (EIP-8141/8250/8272/7906).
/// @dev Read helpers are expected to be called normally/staticcalled. Approval
///      helpers must be delegatecalled by the resolved target account.
///      txTrace/txDiff/eventDataCopy are protocol-gated to POST_TX frame
///      subtrees and exceptional-halt (consuming the call's gas) elsewhere.
interface IFrameOpcodeAdapter {
    /// @notice Only nonce_keys[0] is retrievable on the Hegotá devnet.
    error NonceKeyOutOfRange();
    error NonceKeyNotExposed();
    error RecentRootRefOutOfRange();

    function txParam(uint256 param) external view returns (uint256 value);

    function frameDataLoad(uint256 frameIndex, uint256 offset) external view returns (bytes32 value);

    function frameDataCopy(uint256 frameIndex, uint256 offset, uint256 length) external view returns (bytes memory data);

    function frameData(uint256 frameIndex) external view returns (bytes memory data);

    function frameDataHash(uint256 frameIndex) external view returns (bytes32 value);

    function frameParam(uint256 frameIndex, uint256 param) external view returns (uint256 value);

    function sigParam(uint256 signatureIndex, uint256 param) external view returns (uint256 value);

    function approve(uint8 scope) external;

    function approveWithData(bytes calldata data, uint8 scope) external;

    /// @notice The transaction's nonce key at `index`.
    /// @dev The protocol exposes only key 0 (TXPARAM 0x10 on the devnet).
    ///      Reverts NonceKeyOutOfRange when `index >= nonceKeyCount()` and
    ///      NonceKeyNotExposed for 0 < index < count. `txParam(0x01)` returns
    ///      the shared `nonce_seq`.
    function nonceKey(uint256 index) external view returns (uint256);

    /// @notice `len(tx.nonce_keys)` (TXPARAM 0x0D).
    function nonceKeyCount() external view returns (uint256);

    /// @notice Canonical `nonce_keys_hash(tx)` (TXPARAM 0x0E):
    ///         keccak256(be32(len) || be32(k0) || ...). Commits count + keys.
    function nonceKeysHash() external view returns (bytes32);

    /// @notice Pre-state legacy sender nonce (TXPARAM 0x0C), fixed at tx entry.
    function legacySenderNonce() external view returns (uint256);

    /// @notice `len(tx.recent_root_references)` (TXPARAM 0x0F on the devnet).
    function recentRootRefCount() external view returns (uint256);

    /// @notice The declared reference tuple at `index` (from the signed
    ///         envelope; already consensus-verified against RECENT_ROOT_ADDRESS).
    function recentRootRef(uint256 index) external view returns (bytes32 sourceId, uint256 slot, bytes32 root);

    /// @notice Raw RECENTROOTREFLOAD passthrough: field 0 source_id, 1 slot,
    ///         2 root. Out-of-bounds index or field > 2 exceptional-halts.
    function recentRootRefLoad(uint256 index, uint256 field) external view returns (uint256 value);

    /// @notice TXTRACE passthrough (POST_TX frames only). `in2` is an index for
    ///         indexed params and must be 0 for scalar params.
    function txTrace(uint256 param, uint256 in2) external view returns (uint256 value);

    /// @notice TXDIFF keyed lookup (POST_TX frames only). `in3` is the storage
    ///         slot key for params 0x00/0x01 and must be 0 for scalar params.
    function txDiff(uint256 param, address account, uint256 in3) external view returns (uint256 value);

    /// @notice EVENTDATACOPY passthrough (POST_TX frames only). Reads past the
    ///         event's data length exceptional-halt (no zero-fill).
    function eventDataCopy(uint256 eventIndex, uint256 dataOffset, uint256 length)
        external
        view
        returns (bytes memory data);
}
