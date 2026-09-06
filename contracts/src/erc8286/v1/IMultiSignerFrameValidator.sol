// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ArgConstraint, CapabilityRule} from "./CapabilityLib.sol";
import {IFrameValidator} from "./IFrameValidator.sol";
import {PasskeyAssertion} from "./IntentLib.sol";
import {Signer} from "./Signer.sol";

/// @notice One counted approval inside a `validateFrame` payload: the
///         `tx.signatures` entry it references, the Merkle proof that its
///         effective signer belongs to the account's roster, and — for
///         passkey signers only — the WebAuthn assertion binding it to the
///         intent digest. EOA approvals leave the assertion's byte fields
///         empty (their binding is the signature entry's explicit `msg`).
struct SignerApproval {
    /// @dev Index into `tx.signatures`.
    uint256 sigIndex;
    /// @dev Sorted-pair Merkle proof of roster membership for the entry's
    ///      effective signer (OpenZeppelin StandardMerkleTree, `["address"]`).
    bytes32[] merkleProof;
    /// @dev WebAuthn assertion; ignored for SECP256K1 entries.
    PasskeyAssertion assertion;
}

/// @title IMultiSignerFrameValidator
/// @notice Threshold validator over a Merkle-rooted signer roster, using the
///         light-hash intent scheme (see {IntentLib}) with one EIP-8250 nonce
///         lane per proposal, gated by a per-account capability policy (see
///         {CapabilityLib}).
interface IMultiSignerFrameValidator is IFrameValidator {
    /// @notice Emitted when an account's roster config is installed or updated.
    event ConfigUpdated(address indexed account, uint8 threshold, uint8 rosterSize, bytes32 signersRoot);

    /// @notice Emitted when an account is installed with a capability root that
    ///         arrived pre-computed in its init data.
    /// @dev Separate from {CapabilityPolicySet}, which promises the complete
    ///      rule list. Init data carries only the root, and call traces are not
    ///      observable, so without this event the root would never appear on
    ///      chain at all.
    event CapabilityRootInstalled(address indexed account, bytes32 root);

    /// @notice Emitted when an account's capability policy is installed or
    ///         replaced, carrying the complete rule list.
    /// @dev The rules are emitted in full, not just the root, and the contract
    ///      has rebuilt `root` from them before emitting — so this event is an
    ///      authoritative record of the whole policy rather than an annotation.
    ///      It is also the *only* record an indexer can rely on: a VERIFY frame
    ///      executes under `STATICCALL` (EIP-8141 §Behavior) and can emit
    ///      nothing, so there is no event at check time from any design.
    event CapabilityPolicySet(address indexed account, bytes32 root, CapabilityRule[] rules);

    error NotInitialized();
    error AlreadyInitialized();
    error InvalidConfig();
    /// @notice The caller is not the account's designated capability admin.
    error NotCapabilityAdmin(address account, address admin);
    /// @notice A threshold no roster of the declared size could ever meet,
    ///         which would brick the account permanently.
    error ThresholdExceedsRoster(uint8 threshold, uint8 rosterSize);

    /// @notice Replaces the caller's threshold and roster root. The caller is
    ///         the account itself, so a change requires a passing proposal.
    /// @dev Leaves `capabilityRoot` and `admin` untouched: an account rotates
    ///      its own roster, but must never be able to widen its own policy.
    ///      Reverts when `newThreshold > newRosterSize` — the one permanent
    ///      lockout the contract is able to refuse.
    function updateConfig(uint8 newThreshold, uint8 newRosterSize, bytes32 newRoot) external;

    /// @notice Replaces `account`'s capability policy, and publishes the rules.
    ///
    /// @dev Callable only by the account's capability admin — which is the
    ///      whole point of the layer. A policy its own subject could edit is
    ///      theatre: widen it in frame 1, act in frame 2, one atomic batch, and
    ///      the compliance-change path already assembles exactly that shape.
    ///      An admin of `address(0)` means the account self-administers, which
    ///      is where the recursion terminates (the Owner account) and what the
    ///      console's nullable `adminAccountId` maps onto.
    ///
    ///      The root is rebuilt from `rules` rather than supplied, so the stored
    ///      root and the emitted list cannot disagree. Rules must be canonical
    ///      and sorted ascending by leaf hash.
    function setCapabilityPolicy(address account, CapabilityRule[] calldata rules) external;

    /// @notice The full config for `account`.
    /// @return threshold Approvals required.
    /// @return rosterSize Signers the roster is declared to hold.
    /// @return signersRoot Roster Merkle root.
    /// @return capabilityRoot Policy Merkle root; zero means unrestricted.
    /// @return admin The account that may rewrite the policy; zero means self.
    function getConfig(address account)
        external
        view
        returns (uint8 threshold, uint8 rosterSize, bytes32 signersRoot, bytes32 capabilityRoot, address admin);

    /// @notice The roster Merkle leaf for an effective signer address.
    function leafOf(address effectiveSigner) external pure returns (bytes32);

    /// @notice The policy Merkle leaf for a capability rule. Exposed so the
    ///         console can assert its own tree against the chain's encoding
    ///         rather than assume the two agree.
    function capabilityLeafOf(CapabilityRule calldata rule) external pure returns (bytes32);

    /// @notice The policy root a rule list would produce, without setting it.
    ///         Lets a caller check a policy before proposing it.
    function capabilityRootOf(CapabilityRule[] calldata rules) external pure returns (bytes32);

    /// @notice The `argsHash` a constraint list produces. Exposed for the same
    ///         reason as {capabilityLeafOf}: so the rule builder can assert its
    ///         encoding against the chain's rather than assume they agree.
    function capabilityArgsHashOf(ArgConstraint[] calldata constraints) external pure returns (bytes32);

    /// @notice The Merkle leaf for one permitted value of an `IN_SET` bound.
    ///         `address` and `uint256` sets share an encoding, so one function
    ///         serves both.
    function capabilityValueLeafOf(uint256 value) external pure returns (bytes32);

    /// @notice The EIP-8141 effective signer address for `signer`: the EOA
    ///         address itself, or `keccak256(qx || qy)[12:]` for a passkey.
    function effectiveSignerOf(Signer calldata signer) external pure returns (address);

    /// @notice The EIP-8250 nonce key (lane) for an intent digest. Backends
    ///         put this in the envelope's `nonce_keys` (with `nonce_seq = 0`).
    function intentLaneKey(bytes32 intentDigest) external pure returns (uint256);
}
