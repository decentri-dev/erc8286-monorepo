// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ArgConstraint, CapabilityGrant, CapabilityLib, CapabilityRule} from "./CapabilityLib.sol";
import {IFrameOpcodeAdapter} from "./IFrameOpcodeAdapter.sol";
import {IERC7579Module} from "./IERC8286FrameAccount.sol";
import {IFrameValidator} from "./IFrameValidator.sol";
import {IMultiSignerFrameValidator, SignerApproval} from "./IMultiSignerFrameValidator.sol";
import {CommittedCall, IntentLib} from "./IntentLib.sol";
import {Signer} from "./Signer.sol";

/// @title MultiSignerFrameValidator
/// @notice ERC-7579 validator module (type id `1`) implementing an n-of-m
///         threshold over a Merkle-rooted roster of EOA (secp256k1) and
///         passkey (P-256) signers, for ERC-8286 frame accounts on the
///         Hegotá devnet.
///
/// @dev Two roots sit side by side. `signersRoot` answers *who may agree*;
///      `capabilityRoot` answers *what this account may ever do*, and is the
///      only layer that can refuse a unanimous quorum. ERC-8286 requires the
///      second one: EIP-8141 has no execution-time enforcement point for
///      `SENDER` frames, so all execution policy MUST be enforced during
///      validation.
///
///      - **Roster**: membership is proven per validation with a Merkle proof
///        over effective signer addresses (see {IntentLib.leafOf}), so roster
///        changes are O(1) storage writes and revocation is instant — a removed
///        signer's proof stops verifying against the new root.
///
///      - **Capability**: every committed frame's `(target, selector)` must be
///        admitted by a rule proven against `capabilityRoot`; a zero root means
///        unrestricted. The policy is written by `admin` — a *different*
///        account — because a self-editable policy is theatre. See
///        {setCapabilityPolicy}.
///
///      - **Light hash**: signers approve the gas-independent intent digest
///        defined in {IntentLib}, so a signature collected on Monday is valid
///        whatever fees the relayer attaches on Friday. Frame `gas_limit`s ARE
///        committed (execution budget is intent, not a network condition), and
///        so is `maxCost`, a ceiling in wei on what the transaction may charge
///        the account.
///
///      - **Lanes (EIP-8250)**: each proposal runs on its own keyed-nonce
///        lane derived from the intent digest, at `nonce_seq == 0`. Proposals
///        on different lanes are replay-independent, so a stuck proposal
///        never blocks the next one. The lane gate also makes an intent
///        single-use: once included, the bundle can never be replayed.
///
///      - **Scope**: validation grants whatever scope the frame allows
///        (execution and/or payment), so a funded account can pay for its
///        own transaction without a separate paymaster frame — bounded by the
///        cost cap.
///
///      This is a shared, multi-tenant singleton: deploy once per chain. All
///      per-account state is namespaced by `msg.sender`.
///
///      ⚠ No recovery validator is installed at construction. Module management
///      on the account is self-called, so an account left with only this module
///      and an unusable config has no way back. {_requireCoherentRoster} refuses
///      the one such config it can detect; it is not a general safety net.
contract MultiSignerFrameValidator is IMultiSignerFrameValidator {
    uint8 internal constant APPROVE_NONE = 0x00;
    uint8 internal constant APPROVE_PAYMENT = 0x01;
    uint8 internal constant APPROVE_EXECUTION = 0x02;

    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;

    /// @dev `threshold != 0` doubles as the initialized sentinel: a valid
    ///      config always has a non-zero threshold.
    ///
    ///      `threshold`, `rosterSize` and `admin` share one slot (1 + 1 + 20
    ///      bytes), so the capability layer costs one extra cold SLOAD per
    ///      validation and only when a policy exists.
    struct AccountConfig {
        uint8 threshold;
        /// @dev How many signers `signersRoot` commits to.
        ///
        ///      Declared, not proven: a root reveals nothing about its leaf
        ///      count. What it buys is the coherence check the contract could
        ///      not otherwise make — `threshold <= rosterSize` — which catches
        ///      a fat-fingered threshold of 5 against a 3-person roster,
        ///      silently bricking the account forever because module management
        ///      is self-called and no quorum can ever form again. A caller that
        ///      lies here can already do worse.
        uint8 rosterSize;
        /// @dev Who may rewrite `capabilityRoot`. Zero means the account
        ///      self-administers.
        ///
        ///      Zero rather than the account's own address, because the address
        ///      is not knowable when the value is chosen: `validatorInitData`
        ///      feeds the CREATE2 initcode hash, so an account cannot name
        ///      itself in its own constructor arguments. This is also the exact
        ///      shape of the console's nullable `adminAccountId`.
        address admin;
        bytes32 signersRoot;
        /// @dev Zero means unrestricted — the authority the roster alone gives.
        bytes32 capabilityRoot;
    }

    IFrameOpcodeAdapter public immutable adapter;

    mapping(address account => AccountConfig config) internal _configs;

    error InvalidAdapter();

    constructor(IFrameOpcodeAdapter adapter_) {
        if (address(adapter_) == address(0)) revert InvalidAdapter();
        adapter = adapter_;
    }

    /// @inheritdoc IERC7579Module
    /// @dev `data` is `abi.encode(uint8 threshold, uint8 rosterSize,
    ///      bytes32 signersRoot, bytes32 capabilityRoot, address admin)`.
    ///
    ///      A zero `capabilityRoot` installs an unrestricted account; a zero
    ///      `admin` makes it self-administering. Both are legitimate for an
    ///      Owner account and neither can be repaired by upgrade, since these
    ///      arguments land in the CREATE2 initcode hash — the account's address
    ///      is a commitment to what it started as.
    function onInstall(bytes calldata data) external override {
        (uint8 threshold, uint8 rosterSize, bytes32 signersRoot, bytes32 capabilityRoot, address admin) =
            abi.decode(data, (uint8, uint8, bytes32, bytes32, address));

        if (_configs[msg.sender].threshold != 0) revert AlreadyInitialized();
        _requireCoherentRoster(threshold, rosterSize, signersRoot);

        _configs[msg.sender] = AccountConfig({
            threshold: threshold,
            rosterSize: rosterSize,
            admin: admin,
            signersRoot: signersRoot,
            capabilityRoot: capabilityRoot
        });

        emit ConfigUpdated(msg.sender, threshold, rosterSize, signersRoot);
        if (capabilityRoot != bytes32(0)) {
            // Root only, no rule list: it arrives pre-computed here. See
            // {IMultiSignerFrameValidator.CapabilityRootInstalled}.
            emit CapabilityRootInstalled(msg.sender, capabilityRoot);
        }
    }

    /// @inheritdoc IERC7579Module
    function onUninstall(bytes calldata) external override {
        delete _configs[msg.sender];
    }

    /// @inheritdoc IERC7579Module
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function updateConfig(uint8 newThreshold, uint8 newRosterSize, bytes32 newRoot) external override {
        AccountConfig storage config = _configs[msg.sender];
        if (config.threshold == 0) revert NotInitialized();
        _requireCoherentRoster(newThreshold, newRosterSize, newRoot);

        // Field-wise, never a whole-struct assignment: overwriting the struct
        // here would silently clear `capabilityRoot` and `admin`, handing every
        // account an unrestricted policy on its next roster rotation.
        config.threshold = newThreshold;
        config.rosterSize = newRosterSize;
        config.signersRoot = newRoot;

        emit ConfigUpdated(msg.sender, newThreshold, newRosterSize, newRoot);
    }

    /// @dev The one permanent lockout the contract is able to refuse; it trusts
    ///      the declared size, see {AccountConfig.rosterSize}.
    function _requireCoherentRoster(uint8 threshold, uint8 rosterSize, bytes32 signersRoot) internal pure {
        if (threshold == 0 || signersRoot == bytes32(0)) revert InvalidConfig();
        if (threshold > rosterSize) revert ThresholdExceedsRoster(threshold, rosterSize);
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function setCapabilityPolicy(address account, CapabilityRule[] calldata rules) external override {
        AccountConfig storage config = _configs[account];
        if (config.threshold == 0) revert NotInitialized();

        address admin = config.admin == address(0) ? account : config.admin;
        if (msg.sender != admin) revert NotCapabilityAdmin(account, admin);

        // Rebuilt, not trusted: the stored root and the published rules are then
        // provably the same policy, which is what makes the event usable as the
        // audit record. An empty list clears the policy back to unrestricted —
        // a widening, and deliberately the admin's call to make.
        bytes32 root = rules.length == 0 ? bytes32(0) : CapabilityLib.computeRoot(rules);

        config.capabilityRoot = root;

        emit CapabilityPolicySet(account, root, rules);
    }

    /// @inheritdoc IFrameValidator
    /// @dev `data` is `abi.encode(bytes32 salt, uint256 maxCost,
    ///      SignerApproval[] approvals, CapabilityGrant[] grants)`, with
    ///      approvals sorted strictly ascending by effective signer address
    ///      (this is also the dedupe rule), and one grant per committed frame in
    ///      frame order. Any invalid entry rejects the whole payload — the
    ///      backend assembles it and is responsible for its coherence. Returns
    ///      APPROVE_NONE on any policy failure.
    ///
    ///      `salt` and `maxCost` are not trusted: both feed the intent digest,
    ///      so misreporting either produces a digest no collected signature
    ///      matches.
    ///
    ///      Reverts on an undecodable payload, which ERC-8286 permits
    ///      explicitly ("MAY revert to indicate failures not related to the
    ///      core validation logic directly, e.g. decoding errors").
    function validateFrame(bytes32, uint256, uint8 allowedScope, bytes calldata data)
        external
        view
        override
        returns (uint8)
    {
        AccountConfig memory config = _configs[msg.sender];
        if (config.threshold == 0) return APPROVE_NONE; // not installed for this account

        // Only validate frames of the account's own transaction: SENDER
        // frames execute as tx.sender, so approving on behalf of any other
        // sender would authorize a different account's execution.
        if (adapter.txParam(IntentLib.TX_PARAM_SENDER) != uint256(uint160(msg.sender))) {
            return APPROVE_NONE;
        }

        (bytes32 salt, uint256 maxCost, SignerApproval[] memory approvals, CapabilityGrant[] memory grants) =
            abi.decode(data, (bytes32, uint256, SignerApproval[], CapabilityGrant[]));

        if (!_approvesIntent(config, salt, maxCost, approvals, grants)) return APPROVE_NONE;

        // The signers approved an action and a ceiling on what it may cost the
        // account. Over that ceiling, only payment is withdrawn — execution was
        // approved on its own terms, and the transaction then fails with the
        // payer unset rather than looking like a failed validation.
        uint8 mode = allowedScope & (APPROVE_EXECUTION | APPROVE_PAYMENT);
        if ((mode & APPROVE_PAYMENT) != 0 && !IntentLib.costWithinCap(adapter, maxCost)) {
            mode &= ~APPROVE_PAYMENT;
        }

        return mode;
    }

    /// @dev Everything the signers' agreement has to satisfy: the digest is
    ///      buildable, the transaction is on the intent's lane, the roster met
    ///      threshold, and the account is permitted the calls. Split from
    ///      {validateFrame} because the two together exceed the reachable stack.
    function _approvesIntent(
        AccountConfig memory config,
        bytes32 salt,
        uint256 maxCost,
        SignerApproval[] memory approvals,
        CapabilityGrant[] memory grants
    ) internal view returns (bool) {
        (bool ok, bytes32 intentDigest, CommittedCall[] memory calls) =
            IntentLib.buildIntentDigest(adapter, msg.sender, salt, maxCost);
        if (!ok) return false;

        if (!IntentLib.laneMatches(adapter, intentDigest)) return false;

        if (!_thresholdMet(config, intentDigest, approvals)) return false;

        // Last, and independent of everything above: the roster having agreed
        // is exactly what this check is allowed to override.
        return CapabilityLib.admitsAll(adapter, config.capabilityRoot, calls, grants);
    }

    /// @dev Counts distinct roster members with an intent-bound signature.
    ///      Distinctness is enforced by requiring strictly ascending effective
    ///      signer addresses across approvals.
    function _thresholdMet(AccountConfig memory config, bytes32 intentDigest, SignerApproval[] memory approvals)
        internal
        view
        returns (bool)
    {
        uint256 sigCount = adapter.txParam(IntentLib.TX_PARAM_SIG_COUNT);
        uint256 counted;
        address previousSigner;

        for (uint256 i = 0; i < approvals.length; i++) {
            SignerApproval memory approval = approvals[i];
            if (approval.sigIndex >= sigCount) return false;

            address signer = address(uint160(adapter.sigParam(approval.sigIndex, IntentLib.SIG_PARAM_SIGNER)));
            if (signer <= previousSigner) return false; // enforces ordering and dedupe
            previousSigner = signer;

            if (!IntentLib.verifyMembership(approval.merkleProof, config.signersRoot, signer)) return false;

            uint256 scheme = adapter.sigParam(approval.sigIndex, IntentLib.SIG_PARAM_SCHEME);
            if (scheme == IntentLib.SCHEME_SECP256K1) {
                if (!IntentLib.eoaBindsIntent(adapter, approval.sigIndex, intentDigest)) return false;
            } else if (scheme == IntentLib.SCHEME_P256) {
                if (!IntentLib.passkeyBindsIntent(adapter, approval.sigIndex, approval.assertion, intentDigest)) {
                    return false;
                }
            } else {
                return false;
            }

            unchecked {
                counted++;
            }
            if (counted >= config.threshold) return true;
        }

        return false;
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function getConfig(address account)
        external
        view
        override
        returns (uint8 threshold, uint8 rosterSize, bytes32 signersRoot, bytes32 capabilityRoot, address admin)
    {
        AccountConfig memory config = _configs[account];
        return (config.threshold, config.rosterSize, config.signersRoot, config.capabilityRoot, config.admin);
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function leafOf(address effectiveSigner) external pure override returns (bytes32) {
        return IntentLib.leafOf(effectiveSigner);
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function capabilityLeafOf(CapabilityRule calldata rule) external pure override returns (bytes32) {
        return CapabilityLib.leafOf(rule);
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function capabilityRootOf(CapabilityRule[] calldata rules) external pure override returns (bytes32) {
        return rules.length == 0 ? bytes32(0) : CapabilityLib.computeRoot(rules);
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function capabilityArgsHashOf(ArgConstraint[] calldata constraints) external pure override returns (bytes32) {
        return constraints.length == 0 ? bytes32(0) : keccak256(abi.encode(constraints));
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function capabilityValueLeafOf(uint256 value) external pure override returns (bytes32) {
        return CapabilityLib.valueLeafOf(value);
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function effectiveSignerOf(Signer calldata signer) external pure override returns (address) {
        return signer.effectiveSigner();
    }

    /// @inheritdoc IMultiSignerFrameValidator
    function intentLaneKey(bytes32 intentDigest) external pure override returns (uint256) {
        return IntentLib.laneKey(intentDigest);
    }
}
